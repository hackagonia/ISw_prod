from __future__ import annotations

import os
import sys
import argparse
import sqlite3
import uuid
from datetime import datetime, date
from pathlib import Path

from flask import (
    Flask, request, jsonify, send_from_directory, g, send_file, session
)
from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash

# -----------------------------------------------------------------------------
# Flask app & config
# -----------------------------------------------------------------------------
app = Flask(__name__, static_folder='.', static_url_path='')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 25 MB upload cap
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', '4rfv5tgb$RFV%TGB')

# If served over HTTPS (Render is HTTPS by default), these help secure cookies.
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# -----------------------------------------------------------------------------
# Paths (Render-friendly)
# -----------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent

# Use a persistent disk when on Render (DATA_DIR), else project root.
DATA_DIR = Path(os.getenv("DATA_DIR", str(ROOT)))
DATA_DIR.mkdir(parents=True, exist_ok=True)

UPLOAD_DIR = DATA_DIR / 'uploads'
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / 'app.db'

# -----------------------------------------------------------------------------
# Admin credentials
# -----------------------------------------------------------------------------
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")

# Preferred: use a hash (set ADMIN_PASSWORD_HASH in env)
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")

if not ADMIN_PASSWORD_HASH:
    raise RuntimeError(
        "ADMIN_PASSWORD_HASH environment variable must be set. "
        "Generate one with: python app.py --hash 'YourPassword'"
    )

def _admin_password_ok(username: str, password: str) -> bool:
    if username != ADMIN_USERNAME:
        return False
    return check_password_hash(ADMIN_PASSWORD_HASH, password)


def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('is_admin'):
            return jsonify({'error': 'unauthorized'}), 401
        return fn(*args, **kwargs)
    return wrapper

# -----------------------------------------------------------------------------
# Game categories / points (server authority)
# -----------------------------------------------------------------------------
CATEGORY_POINTS = {
    "sign": 5,              # Military Sign (5)
    "vehicle": 10,          # Military Vehicle (10)
    "location": 15,         # Military Location (15)
    "uniform": 20,          # Uniform (Consent) (20)
    "uniform_face": 50,     # Uniform + Face (Consent) (50)
}

# -----------------------------------------------------------------------------
# DB helpers
# -----------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if 'db' not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS submissions (
            id TEXT PRIMARY KEY,
            uid TEXT,
            alias TEXT,
            category TEXT,
            points INTEGER DEFAULT 0,
            description TEXT,
            image TEXT NOT NULL,
            thumb TEXT NOT NULL,
            day_key TEXT,
            created_at TEXT
        )
        """
    )
    db.commit()
    # migrate: ensure description column exists
    cols = {r['name'] for r in db.execute("PRAGMA table_info(submissions)")}
    if 'description' not in cols:
        db.execute("ALTER TABLE submissions ADD COLUMN description TEXT")
        db.commit()


def backfill_points():
    db = get_db()
    for cat, pts in CATEGORY_POINTS.items():
        db.execute(
            "UPDATE submissions SET points=? WHERE (points IS NULL OR points=0) AND category=?",
            (pts, cat),
        )
    db.commit()

# -----------------------------------------------------------------------------
# Image utilities
# -----------------------------------------------------------------------------
def _is_image(file_storage) -> bool:
    try:
        Image.open(file_storage.stream).verify()
        file_storage.stream.seek(0)
        return True
    except UnidentifiedImageError:
        return False
    except Exception:
        return False


def _to_rgb_no_alpha(img: Image.Image) -> Image.Image:
    if img.mode in ('RGBA', 'LA'):
        alpha = img.getchannel('A') if 'A' in img.getbands() else None
        bg = Image.new('RGB', img.size, (255, 255, 255))
        if alpha is not None:
            bg.paste(img.convert('RGB'), mask=alpha)
        else:
            bg.paste(img.convert('RGB'))
        return bg
    if img.mode == 'P':
        if 'transparency' in img.info:
            return img.convert('RGBA').convert('RGB')
        return img.convert('RGB')
    if img.mode != 'RGB':
        return img.convert('RGB')
    return img


def _save_image_make_thumb(fs_obj, out_base: Path):
    img = Image.open(fs_obj.stream)
    img = ImageOps.exif_transpose(img)
    img = _to_rgb_no_alpha(img)

    main_name = f"{out_base.stem}.jpg"
    main_path = UPLOAD_DIR / main_name
    img.save(main_path, format='JPEG', quality=88, optimize=True)

    thumb_name = f"{out_base.stem}_thumb.jpg"
    thumb_path = UPLOAD_DIR / thumb_name
    thumb = img.copy()
    thumb.thumbnail((200, 200))
    thumb.save(thumb_path, format='JPEG', quality=85, optimize=True)

    return f"/uploads/{main_name}", f"/uploads/{thumb_name}"

# -----------------------------------------------------------------------------
# Pages
# -----------------------------------------------------------------------------
@app.route('/')
def home():
    # Default page = leaderboard
    return send_file(ROOT / 'leaderboard.html')


@app.route('/upload')
def upload_page():
    return send_file(ROOT / 'upload.html')


@app.route('/admin')
def admin_page():
    return send_file(ROOT / 'admin.html')

# -----------------------------------------------------------------------------
# Public APIs
# -----------------------------------------------------------------------------
@app.route('/api/submit', methods=['POST'])
def submit():
    init_db()
    backfill_points()

    if 'image' not in request.files:
        return jsonify({'error': 'missing file field "image"'}), 400
    file = request.files['image']
    if not file or file.filename == '':
        return jsonify({'error': 'empty file'}), 400
    if not _is_image(file):
        return jsonify({'error': 'unsupported file type'}), 400

    uid = (request.form.get('uid') or str(uuid.uuid4())).strip()
    alias = (request.form.get('alias') or 'guest').strip()
    category = (request.form.get('category') or 'general').strip()
    description = (request.form.get('description') or '').strip()

    points = CATEGORY_POINTS.get(category, 0)

    sub_id = str(uuid.uuid4())
    image_rel, thumb_rel = _save_image_make_thumb(file, UPLOAD_DIR / sub_id)

    now = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
    day_key = date.today().isoformat()

    db = get_db()
    db.execute(
        """
        INSERT INTO submissions
          (id, uid, alias, category, points, description, image, thumb, day_key, created_at)
        VALUES (?,  ?,   ?,     ?,        ?,      ?,           ?,     ?,     ?,       ?)
        """,
        (sub_id, uid, alias, category, points, description,
         image_rel.lstrip('/'), thumb_rel.lstrip('/'), day_key, now)
    )
    db.commit()

    return jsonify({
        'id': sub_id, 'uid': uid, 'alias': alias,
        'category': category, 'points': points,
        'description': description,
        'image': image_rel, 'thumb': thumb_rel,
        'day_key': day_key, 'created': now,
    }), 201


@app.route('/api/leaderboard', methods=['GET'])
def leaderboard():
    init_db()
    backfill_points()
    db = get_db()

    # Per-user aggregate
    users = db.execute(
        """
        SELECT uid, COALESCE(alias,'guest') AS alias,
               SUM(points) AS total_points,
               COUNT(*) AS submissions
        FROM submissions
        GROUP BY uid, alias
        ORDER BY total_points DESC, submissions DESC, alias ASC
        """
    ).fetchall()

    all_rows = []
    rank = 0
    last_points = None
    place = 0
    for r in users:
        place += 1
        if r['total_points'] != last_points:
            rank = place
            last_points = r['total_points']
        all_rows.append({
            'rank': rank,
            'alias': r['alias'],
            'uid': r['uid'],
            'total_points': int(r['total_points'] or 0),
            'submissions': int(r['submissions'] or 0),
        })
    top3 = all_rows[:3]

    # Individual uploads (newest first)
    up = db.execute(
        """
        SELECT id, uid, COALESCE(alias,'guest') AS alias, category, points, description,
               image, thumb, created_at
        FROM submissions
        ORDER BY datetime(created_at) DESC
        """
    ).fetchall()
    uploads = [{
        'id': r['id'],
        'uid': r['uid'],
        'alias': r['alias'],
        'category': r['category'],
        'points': r['points'],
        'description': r['description'] or '',
        'image': '/' + r['image'].lstrip('/'),
        'thumb': '/' + r['thumb'].lstrip('/'),
        'created': r['created_at'],
    } for r in up]

    return jsonify({'top3': top3, 'uploads': uploads})


@app.route('/uploads/<path:filename>')
def uploads(filename):
    # Serve from persistent upload dir
    return send_from_directory(UPLOAD_DIR, filename)


@app.route('/manifest.json')
def manifest():
    return send_file(ROOT / 'manifest.json')


@app.route('/sw.js')
def sw():
    return send_file(ROOT / 'sw.js')

# -----------------------------------------------------------------------------
# Admin APIs
# -----------------------------------------------------------------------------
@app.route('/api/admin/me', methods=['GET'])
def admin_me():
    return jsonify({
        'is_admin': bool(session.get('is_admin')),
        'user': ADMIN_USERNAME if session.get('is_admin') else None
    })


@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    if _admin_password_ok(username, password):
        session['is_admin'] = True
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': 'invalid credentials'}), 401


@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/admin/list', methods=['GET'])
@admin_required
def admin_list():
    init_db()
    db = get_db()
    rows = db.execute(
        """
        SELECT id, uid, COALESCE(alias,'guest') AS alias, category, points, description,
               image, thumb, created_at
        FROM submissions
        ORDER BY datetime(created_at) DESC
        """
    ).fetchall()
    out = []
    for r in rows:
        out.append({
            'id': r['id'],
            'uid': r['uid'],
            'alias': r['alias'],
            'category': r['category'],
            'points': r['points'],
            'description': r['description'] or '',
            'image': '/' + r['image'].lstrip('/'),
            'thumb': '/' + r['thumb'].lstrip('/'),
            'created': r['created_at'],
        })
    return jsonify(out)


@app.route('/api/admin/update', methods=['POST'])
@admin_required
def admin_update():
    """
    Body (JSON): {id, alias?, description?, category?}
    Recomputes points if category changes.
    """
    data = request.get_json(silent=True) or {}
    sub_id = (data.get('id') or '').strip()
    if not sub_id:
        return jsonify({'error': 'missing id'}), 400

    fields = []
    values = []
    if 'alias' in data:
        fields.append('alias=?'); values.append((data.get('alias') or '').strip())
    if 'description' in data:
        fields.append('description=?'); values.append((data.get('description') or '').strip())
    if 'category' in data:
        cat = (data.get('category') or '').strip()
        fields.append('category=?'); values.append(cat)
        fields.append('points=?'); values.append(CATEGORY_POINTS.get(cat, 0))

    if not fields:
        return jsonify({'error': 'no fields to update'}), 400

    values.append(sub_id)
    db = get_db()
    cur = db.execute(f"UPDATE submissions SET {', '.join(fields)} WHERE id=?", values)
    db.commit()
    if cur.rowcount == 0:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'ok': True})


@app.route('/api/admin/delete', methods=['POST'])
@admin_required
def admin_delete():
    """
    Body (JSON): {id}
    Deletes DB row and associated image files.
    """
    data = request.get_json(silent=True) or {}
    sub_id = (data.get('id') or '').strip()
    if not sub_id:
        return jsonify({'error': 'missing id'}), 400

    db = get_db()
    row = db.execute(
        "SELECT image, thumb FROM submissions WHERE id=?", (sub_id,)
    ).fetchone()
    if not row:
        return jsonify({'error': 'not found'}), 404

    # Remove files from disk (stored relative like '/uploads/xxxx.jpg')
    def _rm(relpath: str):
        p = DATA_DIR / relpath.lstrip('/')
        try:
            if p.is_file():
                p.unlink()
        except Exception:
            pass

    _rm(row['image'])
    _rm(row['thumb'])

    db.execute("DELETE FROM submissions WHERE id=?", (sub_id,))
    db.commit()
    return jsonify({'ok': True})

# -----------------------------------------------------------------------------
# CLI helper & dev server (WSGI servers import `app` directly)
# -----------------------------------------------------------------------------
def _cli():
    parser = argparse.ArgumentParser(description="SpotOps app")
    parser.add_argument('--hash', metavar='PASSWORD', help='Print a password hash for ADMIN_PASSWORD_HASH and exit')
    parser.add_argument('--run-dev', action='store_true', help='Run the development server')
    args = parser.parse_args()

    if args.hash is not None:
        print(generate_password_hash(args.hash))
        sys.exit(0)

    if args.run_dev:
        debug = os.getenv('FLASK_DEBUG', '1') not in ('0', 'false', 'False')
        app.run(host='127.0.0.1', port=5000, debug=debug)


if __name__ == '__main__':
    _cli()
