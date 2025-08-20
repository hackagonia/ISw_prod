from __future__ import annotations

import os
import sys
import argparse
import sqlite3
import uuid
import json
import re
from datetime import datetime, date
from pathlib import Path

from flask import (
    Flask, request, jsonify, send_from_directory, g, send_file, session
)
from PIL import Image, ImageOps, UnidentifiedImageError, ExifTags
from werkzeug.security import check_password_hash, generate_password_hash

# Optional: better HEIC/HEIF support (safe to ignore if wheel unavailable)
try:
    import pillow_heif  # type: ignore
    pillow_heif.register_heif_opener()
except Exception:
    pass

# -----------------------------------------------------------------------------
# Flask app & config
# -----------------------------------------------------------------------------
app = Flask(__name__, static_folder='.', static_url_path='')
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25 MB upload cap
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE='Lax')

# -----------------------------------------------------------------------------
# Paths (Render-friendly)
# -----------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(ROOT)))
DATA_DIR.mkdir(parents=True, exist_ok=True)

UPLOAD_DIR = DATA_DIR / 'uploads'
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / 'app.db'

# -----------------------------------------------------------------------------
# Admin credentials (hash only; set ADMIN_PASSWORD_HASH in env)
# -----------------------------------------------------------------------------
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")

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
            image TEXT NOT NULL,     -- kept for backward compat (now mirrors 'original')
            thumb TEXT NOT NULL,
            day_key TEXT,
            created_at TEXT,
            metadata TEXT,
            original TEXT             -- new: untouched original file path
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
# Image & EXIF utilities
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

_TAGS = {v: k for k, v in ExifTags.TAGS.items()}
_GPS_TAGS = ExifTags.GPSTAGS

def _rational_to_float(x):
    try:
        return float(x[0]) / float(x[1]) if isinstance(x, tuple) else float(x)
    except Exception:
        try:
            return float(x)
        except Exception:
            return None

def _dms_to_deg(values, ref):
    try:
        d = _rational_to_float(values[0]) or 0.0
        m = _rational_to_float(values[1]) or 0.0
        s = _rational_to_float(values[2]) or 0.0
        deg = d + (m / 60.0) + (s / 3600.0)
        if ref in ('S', 'W'):
            deg = -deg
        return round(deg, 7)
    except Exception:
        return None

def _parse_exif(img: Image.Image) -> dict:
    out = {}
    try:
        exif = img.getexif()
        if not exif:
            return out
        tmp = {}
        for tag_id, value in exif.items():
            name = ExifTags.TAGS.get(tag_id, str(tag_id))
            tmp[name] = value

        out['make'] = tmp.get('Make')
        out['model'] = tmp.get('Model')
        out['software'] = tmp.get('Software')
        out['datetime_original'] = tmp.get('DateTimeOriginal') or tmp.get('DateTime')
        out['orientation'] = tmp.get('Orientation')
        out['lens_model'] = tmp.get('LensModel') or tmp.get('LensMake')
        out['f_number'] = tmp.get('FNumber')
        out['exposure_time'] = tmp.get('ExposureTime')
        out['iso_speed'] = tmp.get('ISOSpeedRatings') or tmp.get('PhotographicSensitivity')
        out['focal_length'] = tmp.get('FocalLength')

        gps_raw = tmp.get('GPSInfo')
        if gps_raw:
            gps = {}
            for k, v in gps_raw.items():
                name = _GPS_TAGS.get(k, str(k))
                gps[name] = v
            lat = lon = None
            if 'GPSLatitude' in gps and 'GPSLatitudeRef' in gps:
                lat = _dms_to_deg(gps['GPSLatitude'], gps.get('GPSLatitudeRef'))
            if 'GPSLongitude' in gps and 'GPSLongitudeRef' in gps:
                lon = _dms_to_deg(gps['GPSLongitude'], gps.get('GPSLongitudeRef'))
            if lat is not None and lon is not None:
                out['gps'] = {'lat': lat, 'lon': lon}

        # Best-effort IMEI hunt (rare)
        imei = None
        str_fields = []
        for k, v in tmp.items():
            if isinstance(v, (str, bytes)):
                try:
                    s = v.decode('utf-8', 'ignore') if isinstance(v, bytes) else v
                    str_fields.append(s)
                except Exception:
                    pass
        blob = " ".join(str_fields)
        m = re.search(r'\b(\d{14,16})\b', blob)
        if m:
            imei = m.group(1)
        out['imei'] = imei
    except Exception:
        pass
    return out

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
        # If we can't decode, use a 1x1 placeholder?
        thumb_rel = f"/uploads/{orig_name}"  # last resort: link to original

    return f"/uploads/{orig_name}", thumb_rel

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

    # Extract metadata from the original upload (before saving)
    meta = {}
    try:
        file.stream.seek(0)
        _orig_img = Image.open(file.stream)
        meta = _parse_exif(_orig_img) or {}
    except Exception:
        meta = {}
    finally:
        try: file.stream.seek(0)
        except Exception: pass

    # Save original + thumbnail
    sub_id = str(uuid.uuid4())
    original_rel, thumb_rel = _save_original_and_thumb(file, sub_id)

    now = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
    day_key = date.today().isoformat()

    db = get_db()
    db.execute(
        """
        INSERT INTO submissions
          (id, uid, alias, category, points, description, image, thumb, day_key, created_at, metadata, original)
        VALUES (?,  ?,   ?,     ?,        ?,      ?,           ?,     ?,     ?,       ?,        ?,        ?)
        """,
        (
            sub_id, uid, alias, category, points, description,
            original_rel.lstrip('/'),  # 'image' kept for compatibility; store original path
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
        'image': original_rel,        # compatibility (same as original)
        'original': original_rel,     # explicit original
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
        'image': '/' + r['image'].lstrip('/'),       # compat
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
    return jsonify({'is_admin': bool(session.get('is_admin')),
                    'user': ADMIN_USERNAME if session.get('is_admin') else None})

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
            'image': '/' + r['image'].lstrip('/'),           # compat
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
