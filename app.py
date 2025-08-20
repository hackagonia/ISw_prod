from __future__ import annotations

import os
import sys
import io
import json
import argparse
import sqlite3
import uuid
import subprocess
from datetime import datetime, date
from pathlib import Path

from flask import (
    Flask, request, jsonify, send_from_directory, g, send_file, session
)
from PIL import Image, ImageOps, UnidentifiedImageError  # still used for thumbnail generation
from werkzeug.security import check_password_hash, generate_password_hash

# -----------------------------------------------------------------------------
# Flask app & config
# -----------------------------------------------------------------------------
app = Flask(__name__, static_folder='.', static_url_path='')
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25 MB upload cap
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')
app.config.update(
    SESSION_COOKIE_SECURE=True,   # Render is HTTPS
    SESSION_COOKIE_SAMESITE='Lax'
)

# -----------------------------------------------------------------------------
# Paths (Render-friendly)
# -----------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(ROOT)))
DATA_DIR.mkdir(parents=True, exist_ok=True)

UPLOAD_DIR = DATA_DIR / 'uploads'
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / 'app.db'

# Path to local exiftool binary (you placed it next to app.py)
EXIFTOOL_PATH = str((ROOT / "exiftool").resolve())

# -----------------------------------------------------------------------------
# Admin credentials (hash-only; no plaintext fallback)
# -----------------------------------------------------------------------------
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")  # set this in env

def _admin_password_ok(username: str, password: str) -> bool:
    if username != ADMIN_USERNAME:
        return False
    if not ADMIN_PASSWORD_HASH:
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
# Game categories / points
# -----------------------------------------------------------------------------
CATEGORY_POINTS = {
    "sign": 5,
    "vehicle": 10,
    "location": 15,
    "uniform": 20,
    "uniform_face": 50,
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
            image TEXT NOT NULL,     -- kept for backward compat (mirrors 'original')
            thumb TEXT NOT NULL,
            day_key TEXT,
            created_at TEXT,
            metadata TEXT,           -- JSON blob (now: {exiftool_text, exiftool_json})
            original TEXT             -- untouched original file relative path
        )
        """
    )
    db.commit()
    # migrations for older DBs
    cols = {r['name'] for r in db.execute("PRAGMA table_info(submissions)")}
    if 'description' not in cols:
        db.execute("ALTER TABLE submissions ADD COLUMN description TEXT")
    if 'metadata' not in cols:
        db.execute("ALTER TABLE submissions ADD COLUMN metadata TEXT")
    if 'original' not in cols:
        db.execute("ALTER TABLE submissions ADD COLUMN original TEXT")
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
# Image utilities (for thumbnails only)
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

def _save_original_and_thumb(file, sub_id: str) -> tuple[str, str]:
    """
    Save the original bytes untouched (keeps all metadata, format, etc.)
    and generate a JPEG thumbnail for UI display.
    Returns (original_relpath, thumb_relpath).
    """
    # Save original
    orig_ext = Path(file.filename).suffix.lower() or ""
    if not orig_ext or len(orig_ext) > 6:
        orig_ext = ".bin"  # fallback
    orig_name = f"{sub_id}{orig_ext}"
    orig_path = UPLOAD_DIR / orig_name

    file.stream.seek(0)
    with open(orig_path, 'wb') as f:
        f.write(file.stream.read())

    # Make a JPEG thumbnail
    file.stream.seek(0)
    thumb_rel = f"/uploads/{orig_name}"  # fallback to original if we fail to render
    try:
        img = Image.open(file.stream)
        img = ImageOps.exif_transpose(img)
        img = _to_rgb_no_alpha(img)
        thumb_name = f"{sub_id}_thumb.jpg"
        thumb_path = UPLOAD_DIR / thumb_name
        img.thumbnail((200, 200))
        img.save(thumb_path, format='JPEG', quality=85, optimize=True)
        thumb_rel = f"/uploads/{thumb_name}"
    except Exception:
        pass

    return f"/uploads/{orig_name}", thumb_rel

# -----------------------------------------------------------------------------
# ExifTool integration
# -----------------------------------------------------------------------------
def _extract_metadata_with_exiftool(full_path: str) -> dict:
    """
    Runs the local exiftool to produce BOTH:
      - 'exiftool_text' : raw stdout (full human-readable dump)
      - 'exiftool_json' : parsed JSON object (all tags)
    Returns a dict with those keys; {} on failure.
    """
    meta: dict = {}
    try:
        # raw text (full dump)
        proc_txt = subprocess.run(
            [EXIFTOOL_PATH, full_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        if proc_txt.returncode == 0 and proc_txt.stdout:
            meta["exiftool_text"] = proc_txt.stdout
        else:
            meta["exiftool_text"] = proc_txt.stdout or proc_txt.stderr or ""

        # json (machine readable)
        proc_json = subprocess.run(
            [EXIFTOOL_PATH, "-json", "-n", full_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        if proc_json.returncode == 0 and proc_json.stdout:
            try:
                data = json.loads(proc_json.stdout)
                meta["exiftool_json"] = data[0] if isinstance(data, list) and data else {}
            except Exception:
                meta["exiftool_json"] = {}
        else:
            meta["exiftool_json"] = {}

    except FileNotFoundError:
        meta["exiftool_text"] = "exiftool not found at {}".format(EXIFTOOL_PATH)
        meta["exiftool_json"] = {}
    except Exception as e:
        meta["exiftool_text"] = f"exiftool error: {e}"
        meta["exiftool_json"] = {}

    return meta

# -----------------------------------------------------------------------------
# Pages
# -----------------------------------------------------------------------------
@app.route('/')
def home():
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

    # Validate file
    if 'image' not in request.files:
        return jsonify({'error': 'missing file field "image"'}), 400
    file = request.files['image']
    if not file or file.filename == '':
        return jsonify({'error': 'empty file'}), 400
    if not _is_image(file):
        return jsonify({'error': 'unsupported file type'}), 400

    # Form fields
    uid = (request.form.get('uid') or str(uuid.uuid4())).strip()
    alias = (request.form.get('alias') or 'guest').strip()
    category = (request.form.get('category') or 'general').strip()
    description = (request.form.get('description') or '').strip()
    points = CATEGORY_POINTS.get(category, 0)

    # Save original + thumbnail
    sub_id = str(uuid.uuid4())
    original_rel, thumb_rel = _save_original_and_thumb(file, sub_id)
    full_path = str((DATA_DIR / original_rel.lstrip('/')).resolve())

    # Extract metadata using local exiftool (raw text + json)
    meta = _extract_metadata_with_exiftool(full_path)

    # Persist
    now = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
    day_key = date.today().isoformat()

    db = get_db()
    db.execute(
        """
        INSERT INTO submissions
          (id, uid, alias, category, points, description,
           image, thumb, day_key, created_at, metadata, original)
        VALUES (?,  ?,   ?,     ?,        ?,      ?, 
                ?,     ?,     ?,       ?,        ?,        ?)
        """,
        (
            sub_id, uid, alias, category, points, description,
            original_rel.lstrip('/'),   # 'image' kept for compat (same as original)
            thumb_rel.lstrip('/'),
            day_key, now, json.dumps(meta, ensure_ascii=False),
            original_rel.lstrip('/'),
        )
    )
    db.commit()

    return jsonify({
        'id': sub_id, 'uid': uid, 'alias': alias,
        'category': category, 'points': points,
        'description': description,
        'image': original_rel,          # compat
        'original': original_rel,       # explicit
        'thumb': thumb_rel,
        'day_key': day_key, 'created': now,
        'metadata': meta,
    }), 201

@app.route('/api/leaderboard', methods=['GET'])
def leaderboard():
    init_db()
    backfill_points()
    db = get_db()

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

    up = db.execute(
        """
        SELECT id, uid, COALESCE(alias,'guest') AS alias, category, points, description,
               image, thumb, created_at, metadata, original
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
        'image': '/' + r['image'].lstrip('/'),                    # compat
        'original': '/' + (r['original'] or r['image']).lstrip('/'),
        'thumb': '/' + r['thumb'].lstrip('/'),
        'created': r['created_at'],
        'metadata': json.loads(r['metadata']) if r['metadata'] else {},
    } for r in up]

    return jsonify({'top3': top3, 'uploads': uploads})

@app.route('/uploads/<path:filename>')
def uploads(filename):
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
               image, thumb, created_at, metadata, original
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
            'image': '/' + r['image'].lstrip('/'),                    # compat
            'original': '/' + (r['original'] or r['image']).lstrip('/'),
            'thumb': '/' + r['thumb'].lstrip('/'),
            'created': r['created_at'],
            'metadata': json.loads(r['metadata']) if r['metadata'] else {},
        })
    return jsonify(out)

@app.route('/api/admin/update', methods=['POST'])
@admin_required
def admin_update():
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
    data = request.get_json(silent=True) or {}
    sub_id = (data.get('id') or '').strip()
    if not sub_id:
        return jsonify({'error': 'missing id'}), 400

    db = get_db()
    row = db.execute(
        "SELECT image, thumb, original FROM submissions WHERE id=?", (sub_id,)
    ).fetchone()
    if not row:
        return jsonify({'error': 'not found'}), 404

    def _rm(relpath: str):
        p = DATA_DIR / relpath.lstrip('/')
        try:
            if p.is_file():
                p.unlink()
        except Exception:
            pass

    _rm(row['image'] or '')
    _rm(row['thumb'] or '')
    _rm(row['original'] or '')
    db.execute("DELETE FROM submissions WHERE id=?", (sub_id,))
    db.commit()
    return jsonify({'ok': True})

# -----------------------------------------------------------------------------
# CLI helper (hash) & dev server
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
