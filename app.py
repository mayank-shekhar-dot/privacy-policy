"""Arpita & Mayank Love ♡ — run:  pip install flask flask-socketio simple-websocket pillow  then  python app.py  (for phone notifications also: pip install pywebpush)"""
import os
import json
import base64
import sqlite3
import secrets
import uuid
import time
from contextlib import closing
from datetime import datetime, timezone
from functools import wraps

from flask import (Flask, g, request, session, jsonify, send_from_directory,
                   redirect)
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from PIL import Image, ImageOps

# ----------------------------------------------------------------- config
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
DB_PATH = os.path.join(DATA_DIR, "love.db")
os.makedirs(UPLOAD_DIR, exist_ok=True)

USERS = ["Arpita", "Mayank"]
DEFAULT_PASSWORD = "2011"
OTHER = {"Arpita": "Mayank", "Mayank": "Arpita"}
PRODUCTION = os.environ.get("PRODUCTION") == "1"
ALLOWED_FORMATS = {"JPEG": "jpg", "PNG": "png", "WEBP": "webp", "GIF": "gif"}
REACTIONS = ["❤️", "😂", "😮", "😢", "👍", "🙏", "🔥", "🥰"]
IMG_MAX = 10 * 1024 * 1024
AUDIO_MAX = 10 * 1024 * 1024
VIDEO_MAX = 50 * 1024 * 1024


def load_secret_key():
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = os.path.join(DATA_DIR, "secret_key")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=PRODUCTION,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,
    MAX_CONTENT_LENGTH=64 * 1024 * 1024,
)
if PRODUCTION:  # running behind a hosting proxy that terminates HTTPS
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

origins = os.environ.get("ALLOWED_ORIGINS")
socketio = SocketIO(
    app,
    async_mode="threading",
    cors_allowed_origins=[o.strip() for o in origins.split(",")] if origins else None,
)

online = {u: set() for u in USERS}   # username -> socket ids (connected)
viewing = {u: set() for u in USERS}  # username -> socket ids whose page is visible right now

# ---- push notifications (Android Chrome etc.) ----
try:
    from pywebpush import webpush, WebPushException
    from py_vapid import Vapid
    from cryptography.hazmat.primitives import serialization
    PUSH_OK = True
except Exception:
    PUSH_OK = False
VAPID_SUB = os.environ.get("VAPID_EMAIL", "mailto:admin@example.com")
NOTIFY_USERS = {"Mayank"}  # only these people get phone notifications
SHOW_PREVIEW = False  # True = lock screen shows the message text; False = only "new message"


def load_vapid():
    env = os.environ.get("VAPID_PRIVATE_KEY")
    if env:
        return Vapid.from_string(env.strip())
    path = os.path.join(DATA_DIR, "vapid_private.pem")
    if os.path.exists(path):
        return Vapid.from_file(path)
    v = Vapid()
    v.generate_keys()
    v.save_key(path)
    raw = v.private_key.private_numbers().private_value.to_bytes(32, "big")
    print("\n  New notification key created. On Render, add this environment variable so it survives restarts:")
    print("  VAPID_PRIVATE_KEY=" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode() + "\n")
    return v


VAPID = load_vapid() if PUSH_OK else None
VAPID_PUBLIC = (base64.urlsafe_b64encode(VAPID.public_key.public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).rstrip(b"=").decode()
    if VAPID else None)


# --------------------------------------------------------------- database
def conn():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def query(sql, args=(), one=False):
    with closing(conn()) as c:
        rows = c.execute(sql, args).fetchall()
        c.commit()
    if one:
        return rows[0] if rows else None
    return rows


def execute(sql, args=()):
    with closing(conn()) as c:
        cur = c.execute(sql, args)
        c.commit()
        return cur.lastrowid


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def init_db():
    with closing(conn()) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            name TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            avatar TEXT,
            last_seen TEXT
        );
        CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            body TEXT NOT NULL DEFAULT '',
            image TEXT,
            created_at TEXT NOT NULL,
            delivered_at TEXT,
            read_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_msg_recipient ON messages(recipient, read_at);
        CREATE TABLE IF NOT EXISTS push_subs(
            endpoint TEXT PRIMARY KEY,
            user TEXT NOT NULL,
            data TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reactions(
            message_id INTEGER NOT NULL,
            user TEXT NOT NULL,
            emoji TEXT NOT NULL,
            PRIMARY KEY(message_id, user)
        );
        CREATE TABLE IF NOT EXISTS memories(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uploader TEXT NOT NULL,
            filename TEXT NOT NULL,
            caption TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        """)
        cols = [r[1] for r in c.execute("PRAGMA table_info(messages)")]
        if "attachments" not in cols:
            c.execute("ALTER TABLE messages ADD COLUMN attachments TEXT")
        if "edited_at" not in cols:
            c.execute("ALTER TABLE messages ADD COLUMN edited_at TEXT")
        c.commit()
    # Optional: create accounts from environment variables (handy for hosting)
    for name in USERS:
        pw = os.environ.get(f"{name.upper()}_PASSWORD")
        if pw and not query("SELECT 1 FROM users WHERE name=?", (name,), one=True):
            set_password(name, pw)


def set_password(name, password):
    h = generate_password_hash(password)
    with closing(conn()) as c:
        c.execute(
            "INSERT INTO users(name, password_hash) VALUES(?,?) "
            "ON CONFLICT(name) DO UPDATE SET password_hash=excluded.password_hash",
            (name, h),
        )
        c.commit()


init_db()


# ----------------------------------------------------------------- helpers
def current_user():
    u = session.get("user")
    return u if u in USERS else None


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not current_user():
            return jsonify(error="Please log in"), 401
        return fn(*a, **kw)
    return wrapper


def media_url(name):
    return f"/media/{name}" if name else None


def msg_files(r):
    files = []
    if r["attachments"]:
        try:
            for f in json.loads(r["attachments"]):
                files.append({"url": media_url(f["file"]), "kind": f["kind"]})
        except (ValueError, KeyError, TypeError):
            pass
    elif r["image"]:  # messages sent by older versions
        files.append({"url": media_url(r["image"]), "kind": "image"})
    return files


def msg_dict(r, reactions=None):
    return {
        "id": r["id"], "sender": r["sender"], "body": r["body"],
        "files": msg_files(r), "created_at": r["created_at"],
        "delivered_at": r["delivered_at"], "read_at": r["read_at"],
        "edited_at": r["edited_at"], "reactions": reactions or {},
    }


def get_reactions(mid):
    return {x["user"]: x["emoji"] for x in
            query("SELECT user, emoji FROM reactions WHERE message_id=?", (mid,))}


def rows_to_msgs(rows):
    rx = {}
    if rows:
        ids = tuple(r["id"] for r in rows)
        for x in query("SELECT message_id, user, emoji FROM reactions WHERE message_id IN (%s)"
                       % ",".join("?" * len(ids)), ids):
            rx.setdefault(x["message_id"], {})[x["user"]] = x["emoji"]
    return [msg_dict(r, rx.get(r["id"])) for r in rows]


def avatars():
    return {r["name"]: media_url(r["avatar"]) for r in query("SELECT name, avatar FROM users")}


def me_payload(user):
    return {"user": user, "other": OTHER[user], "csrf": session.get("csrf"), "avatars": avatars()}


def open_image(file_storage):
    """Return (PIL image, format) if the upload is a genuine allowed image, else None."""
    try:
        img = Image.open(file_storage.stream)
        fmt = img.format
        if fmt not in ALLOWED_FORMATS:
            return None
        if img.width * img.height > 60_000_000:
            return None
        img.verify()  # detects truncated / corrupt files
        file_storage.stream.seek(0)
        img = Image.open(file_storage.stream)
        img.load()
        return img, fmt
    except Exception:
        return None


def save_image(file_storage, max_dim=2200):
    """Validate, strip metadata (re-encode) and store with a random name."""
    opened = open_image(file_storage)
    if not opened:
        return None
    img, fmt = opened
    name = f"{uuid.uuid4().hex}.{ALLOWED_FORMATS[fmt]}"
    path = os.path.join(UPLOAD_DIR, name)
    if fmt == "GIF":
        file_storage.stream.seek(0)
        with open(path, "wb") as f:
            f.write(file_storage.stream.read())
        return name
    img = ImageOps.exif_transpose(img)
    img.thumbnail((max_dim, max_dim))
    if fmt == "JPEG" and img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    img.save(path, fmt, quality=88) if fmt in ("JPEG", "WEBP") else img.save(path, fmt)
    return name


def save_avatar(file_storage):
    opened = open_image(file_storage)
    if not opened:
        return None
    img, _ = opened
    img = ImageOps.exif_transpose(img).convert("RGB")
    img = ImageOps.fit(img, (400, 400), Image.LANCZOS)
    name = f"{uuid.uuid4().hex}.jpg"
    img.save(os.path.join(UPLOAD_DIR, name), "JPEG", quality=88)
    return name


def stream_size(fs):
    fs.stream.seek(0, 2)
    n = fs.stream.tell()
    fs.stream.seek(0)
    return n


def save_media(fs, voice=False):
    """Validate one uploaded photo / video / voice clip. Returns {"file", "kind"} or raises ValueError."""
    size = stream_size(fs)
    if size == 0:
        raise ValueError("Khali file hai.")
    head = fs.stream.read(16)
    fs.stream.seek(0)
    kind = ext = None
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in (b"heic", b"heix", b"hevc", b"mif1", b"msf1", b"avif", b"avis"):
            raise ValueError("Ye photo format support nahi hai, JPG/PNG bhejo.")
        if voice or brand in (b"M4A ", b"M4B "):
            kind, ext = "audio", ("m4a" if brand == b"M4A " else "mp4")
        else:
            kind, ext = "video", ("mov" if brand == b"qt  " else "mp4")
    elif head[:4] == b"\x1a\x45\xdf\xa3":
        kind, ext = ("audio" if voice else "video"), "webm"
    elif head[:4] == b"OggS":
        kind, ext = "audio", "ogg"
    if kind:
        if size > (AUDIO_MAX if kind == "audio" else VIDEO_MAX):
            raise ValueError("Video 50 MB se badi hai." if kind == "video" else "Voice message bahut badi hai.")
        name = f"{'a' if kind == 'audio' else 'v'}_{uuid.uuid4().hex}.{ext}"
        fs.save(os.path.join(UPLOAD_DIR, name))
        return {"file": name, "kind": kind}
    if size > IMG_MAX:
        raise ValueError("Photo 10 MB se badi hai.")
    name = save_image(fs)
    if not name:
        raise ValueError("Ye valid photo ya video nahi hai (JPG, PNG, GIF, WEBP, MP4, WEBM, MOV).")
    return {"file": name, "kind": "image"}


def delete_file(name):
    if not name:
        return
    try:
        os.remove(os.path.join(UPLOAD_DIR, secure_filename(name)))
    except OSError:
        pass


def create_message(sender, body, attachments=None):
    other = OTHER[sender]
    created = now_iso()
    delivered = created if online[other] else None
    mid = execute(
        "INSERT INTO messages(sender, recipient, body, attachments, created_at, delivered_at) "
        "VALUES(?,?,?,?,?,?)",
        (sender, other, body, json.dumps(attachments) if attachments else None, created, delivered))
    msg = msg_dict(query("SELECT * FROM messages WHERE id=?", (mid,), one=True))
    socketio.emit("new_message", msg, to=sender)
    socketio.emit("new_message", msg, to=other)
    notify(other, sender, body, attachments)
    return msg


def notify(recipient, sender, body, attachments):
    """Push a notification ONLY if the recipient is not looking at the site right now."""
    if not PUSH_OK or recipient not in NOTIFY_USERS or viewing[recipient]:
        return
    subs = query("SELECT endpoint, data FROM push_subs WHERE user=?", (recipient,))
    if not subs:
        return
    kinds = {x["kind"] for x in (attachments or [])}
    if SHOW_PREVIEW and body:
        text = body[:120]
    elif kinds == {"audio"}:
        text = "🎤 Voice message bheja ♡"
    elif "video" in kinds:
        text = "🎬 Video bheja ♡"
    elif kinds:
        text = "📷 Photo bheji ♡"
    else:
        text = "Naya message aaya ♡"
    payload = json.dumps({"title": f"💌 {sender}", "body": text, "tag": "chat"})

    def work():
        for s in subs:
            try:
                webpush(json.loads(s["data"]), payload, vapid_private_key=VAPID,
                        vapid_claims={"sub": VAPID_SUB}, ttl=86400)
            except WebPushException as e:
                code = getattr(getattr(e, "response", None), "status_code", None)
                if code in (404, 410):  # subscription expired
                    execute("DELETE FROM push_subs WHERE endpoint=?", (s["endpoint"],))
            except Exception:
                pass
    socketio.start_background_task(work)


# --------------------------------------------------------- security hooks
@app.before_request
def security_checks():
    g.nonce = secrets.token_urlsafe(16)
    if PRODUCTION and request.headers.get("X-Forwarded-Proto", "https") != "https":
        return redirect(request.url.replace("http://", "https://", 1), code=301)
    if (request.path.startswith("/api/") and request.method in ("POST", "PUT", "DELETE")
            and request.path != "/api/login"):
        token = request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf", "")
        if not expected or not secrets.compare_digest(token, expected):
            return jsonify(error="Session expired, please refresh"), 403


@app.after_request
def add_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        f"script-src 'self' https://cdnjs.cloudflare.com 'nonce-{getattr(g, 'nonce', '')}'; "
        "connect-src 'self' ws: wss:; frame-ancestors 'none'")
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    if PRODUCTION:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="File bahut badi hai (photo/voice 10 MB, video 50 MB tak)."), 413


# ------------------------------------------------------------------ routes
@app.get("/")
def index():
    with open(os.path.join(BASE_DIR, "index.html"), encoding="utf-8") as f:
        page = f.read().replace("__NONCE__", g.nonce)
    return page


SERVICE_WORKER = """
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('push', e => {
  let d = {};
  try { d = e.data.json(); } catch (_) {}
  e.waitUntil(self.registration.showNotification(d.title || 'Arpita & Mayank Love', {
    body: d.body || '', tag: d.tag || 'chat', renotify: true, vibrate: [120, 60, 120]
  }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const c of list) if ('focus' in c) return c.focus();
    return clients.openWindow('/');
  }));
});
"""


@app.get("/sw.js")
def service_worker():
    resp = app.response_class(SERVICE_WORKER, mimetype="application/javascript")
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.get("/api/push/key")
@login_required
def push_key():
    if not PUSH_OK:
        return jsonify(error="Server par 'pywebpush' install nahi hai (pip install pywebpush)."), 501
    return jsonify(key=VAPID_PUBLIC)


@app.post("/api/push/subscribe")
@login_required
def push_subscribe():
    sub = request.get_json(silent=True) or {}
    keys = sub.get("keys") or {}
    ep = sub.get("endpoint")
    if not (isinstance(ep, str) and ep.startswith("https://") and keys.get("p256dh") and keys.get("auth")):
        return jsonify(error="Invalid subscription"), 400
    clean = {"endpoint": ep, "keys": {"p256dh": keys["p256dh"], "auth": keys["auth"]}}
    with closing(conn()) as c:
        c.execute("INSERT INTO push_subs(endpoint, user, data) VALUES(?,?,?) "
                  "ON CONFLICT(endpoint) DO UPDATE SET user=excluded.user, data=excluded.data",
                  (ep, session["user"], json.dumps(clean)))
        c.commit()
    return jsonify(ok=True)


@app.post("/api/push/unsubscribe")
@login_required
def push_unsubscribe():
    ep = (request.get_json(silent=True) or {}).get("endpoint")
    if isinstance(ep, str):
        execute("DELETE FROM push_subs WHERE endpoint=? AND user=?", (ep, session["user"]))
    return jsonify(ok=True)


failed_logins = {}  # ip -> [timestamps]


@app.post("/api/login")
def login():
    ip = request.remote_addr or "?"
    recent = [t for t in failed_logins.get(ip, []) if time.time() - t < 300]
    failed_logins[ip] = recent
    if len(recent) >= 6:
        return jsonify(error="Too many tries. Please wait a few minutes. ♡"), 429
    data = request.get_json(silent=True) or {}
    name, pw = data.get("name"), data.get("password")
    row = query("SELECT * FROM users WHERE name=?", (name,), one=True) if name in USERS else None
    if not row or not isinstance(pw, str) or not check_password_hash(row["password_hash"], pw):
        failed_logins[ip].append(time.time())
        return jsonify(error="That password doesn't look right."), 401
    session.clear()
    session.permanent = True
    session["user"] = name
    session["csrf"] = secrets.token_hex(24)
    return jsonify(me_payload(name))


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    u = current_user()
    return jsonify(me_payload(u) if u else {"user": None})


@app.get("/api/messages")
@login_required
def messages():
    before = request.args.get("before", type=int)
    if before:
        rows = query("SELECT * FROM messages WHERE id < ? ORDER BY id DESC LIMIT 60", (before,))
    else:
        rows = query("SELECT * FROM messages ORDER BY id DESC LIMIT 60")
    return jsonify(messages=rows_to_msgs(list(reversed(rows))), has_more=len(rows) == 60)


@app.delete("/api/messages")
@login_required
def clear_chat():
    """Delete the whole conversation (photos, videos, voice clips, reactions) for both people."""
    files = []
    for r in query("SELECT image, attachments FROM messages"):
        if r["image"]:
            files.append(r["image"])
        if r["attachments"]:
            try:
                files += [f["file"] for f in json.loads(r["attachments"])]
            except (ValueError, KeyError, TypeError):
                pass
    execute("DELETE FROM messages")
    execute("DELETE FROM reactions")
    for name in files:
        delete_file(name)
    payload = {"by": session["user"]}
    socketio.emit("chat_cleared", payload, to="Arpita")
    socketio.emit("chat_cleared", payload, to="Mayank")
    return jsonify(ok=True)


@app.post("/api/messages/media")
@login_required
def send_media():
    files = [f for f in request.files.getlist("files") if f]
    if not files:
        return jsonify(error="Koi file nahi mili."), 400
    if len(files) > 10:
        return jsonify(error="Ek baar mein 10 files tak bhej sakte ho."), 400
    voice = request.form.get("voice") == "1" and len(files) == 1
    saved = []
    try:
        for f in files:
            saved.append(save_media(f, voice))
    except ValueError as e:
        for s in saved:
            delete_file(s["file"])
        return jsonify(error=str(e)), 400
    caption = (request.form.get("body") or "").strip()[:2000]
    return jsonify(create_message(session["user"], caption, saved))


MIMES = {"webm": ("video/webm", "audio/webm"), "mp4": ("video/mp4", "audio/mp4"),
         "m4a": ("audio/mp4", "audio/mp4"), "mov": ("video/quicktime", "video/quicktime"),
         "ogg": ("audio/ogg", "audio/ogg")}


@app.get("/media/<path:name>")
@login_required
def media(name):
    name = secure_filename(name)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    mime = MIMES[ext][1 if name.startswith("a_") else 0] if ext in MIMES else None
    resp = send_from_directory(UPLOAD_DIR, name, mimetype=mime)  # supports Range (video seeking)
    resp.headers["Cache-Control"] = "private, max-age=86400"
    return resp


@app.get("/api/memories")
@login_required
def list_memories():
    rows = query("SELECT * FROM memories ORDER BY id DESC")
    return jsonify(memories=[{
        "id": r["id"], "uploader": r["uploader"], "image": media_url(r["filename"]),
        "caption": r["caption"], "created_at": r["created_at"]} for r in rows])


@app.post("/api/memories")
@login_required
def add_memory():
    f = request.files.get("image")
    name = save_image(f) if f else None
    if not name:
        return jsonify(error="That doesn't look like a valid image (JPG, PNG, GIF or WEBP)."), 400
    caption = (request.form.get("caption") or "").strip()[:300]
    execute("INSERT INTO memories(uploader, filename, caption, created_at) VALUES(?,?,?,?)",
            (session["user"], name, caption, now_iso()))
    socketio.emit("memories_changed", {}, to="Arpita")
    socketio.emit("memories_changed", {}, to="Mayank")
    return jsonify(ok=True)


@app.delete("/api/memories/<int:mid>")
@login_required
def delete_memory(mid):
    row = query("SELECT * FROM memories WHERE id=?", (mid,), one=True)
    if not row:
        return jsonify(error="Not found"), 404
    if row["uploader"] != session["user"]:
        return jsonify(error="You can only remove memories you added."), 403
    execute("DELETE FROM memories WHERE id=?", (mid,))
    delete_file(row["filename"])
    socketio.emit("memories_changed", {}, to="Arpita")
    socketio.emit("memories_changed", {}, to="Mayank")
    return jsonify(ok=True)


@app.post("/api/avatar")
@login_required
def set_avatar():
    f = request.files.get("image")
    name = save_avatar(f) if f else None
    if not name:
        return jsonify(error="That doesn't look like a valid image."), 400
    user = session["user"]
    old = query("SELECT avatar FROM users WHERE name=?", (user,), one=True)
    execute("UPDATE users SET avatar=? WHERE name=?", (name, user))
    if old:
        delete_file(old["avatar"])
    payload = {"user": user, "avatar": media_url(name)}
    socketio.emit("avatar_changed", payload, to="Arpita")
    socketio.emit("avatar_changed", payload, to="Mayank")
    return jsonify(payload)


# ---------------------------------------------------------------- sockets
@socketio.on("connect")
def on_connect():
    user = current_user()
    if not user:
        return False  # reject unauthenticated sockets
    other = OTHER[user]
    join_room(user)
    first = not online[user]
    online[user].add(request.sid)
    if first:
        socketio.emit("presence", {"user": user, "online": True, "last_seen": None}, to=other)
    # tell this client whether the other person is here
    row = query("SELECT last_seen FROM users WHERE name=?", (other,), one=True)
    emit("presence", {"user": other, "online": bool(online[other]),
                      "last_seen": row["last_seen"] if row else None})
    # anything sent while I was away is now delivered
    pending = [r["id"] for r in query(
        "SELECT id FROM messages WHERE recipient=? AND delivered_at IS NULL", (user,))]
    if pending:
        at = now_iso()
        execute("UPDATE messages SET delivered_at=? WHERE recipient=? AND delivered_at IS NULL",
                (at, user))
        socketio.emit("delivered", {"ids": pending, "at": at}, to=other)


@socketio.on("disconnect")
def on_disconnect():
    user = session.get("user")
    if user not in USERS:
        return
    online[user].discard(request.sid)
    viewing[user].discard(request.sid)
    if not online[user]:
        seen = now_iso()
        execute("UPDATE users SET last_seen=? WHERE name=?", (seen, user))
        socketio.emit("presence", {"user": user, "online": False, "last_seen": seen},
                      to=OTHER[user])
        socketio.emit("typing", {"user": user, "typing": False}, to=OTHER[user])


@socketio.on("visible")
def on_visible(data):
    user = current_user()
    if not user:
        return
    if (data or {}).get("visible"):
        viewing[user].add(request.sid)
    else:
        viewing[user].discard(request.sid)


@socketio.on("send_message")
def on_send(data):
    user = current_user()
    if not user:
        return {"ok": False, "error": "Not logged in"}
    body = (data or {}).get("body")
    if not isinstance(body, str) or not body.strip():
        return {"ok": False, "error": "Empty message"}
    body = body.strip()
    if len(body) > 2000:
        return {"ok": False, "error": "Message is too long"}
    create_message(user, body, None)
    return {"ok": True}


@socketio.on("edit_message")
def on_edit(data):
    user = current_user()
    if not user:
        return {"ok": False, "error": "Not logged in"}
    try:
        mid = int((data or {}).get("id"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "Invalid message"}
    body = (data or {}).get("body")
    row = query("SELECT sender FROM messages WHERE id=?", (mid,), one=True)
    if not row or row["sender"] != user:
        return {"ok": False, "error": "Sirf apna message edit kar sakte ho."}
    if not isinstance(body, str) or not body.strip() or len(body.strip()) > 2000:
        return {"ok": False, "error": "Message khali ya bahut lamba hai."}
    at = now_iso()
    execute("UPDATE messages SET body=?, edited_at=? WHERE id=?", (body.strip(), at, mid))
    payload = {"id": mid, "body": body.strip(), "edited_at": at}
    for u in USERS:
        socketio.emit("message_edited", payload, to=u)
    return {"ok": True}


@socketio.on("react")
def on_react(data):
    user = current_user()
    if not user:
        return
    try:
        mid = int((data or {}).get("id"))
    except (TypeError, ValueError):
        return
    emoji = (data or {}).get("emoji")
    if not query("SELECT 1 FROM messages WHERE id=?", (mid,), one=True):
        return
    cur = query("SELECT emoji FROM reactions WHERE message_id=? AND user=?", (mid, user), one=True)
    if emoji is None or (cur and cur["emoji"] == emoji):
        execute("DELETE FROM reactions WHERE message_id=? AND user=?", (mid, user))
    elif emoji in REACTIONS:
        execute("INSERT INTO reactions(message_id, user, emoji) VALUES(?,?,?) "
                "ON CONFLICT(message_id, user) DO UPDATE SET emoji=excluded.emoji", (mid, user, emoji))
    else:
        return
    payload = {"id": mid, "reactions": get_reactions(mid)}
    for u in USERS:
        socketio.emit("reactions", payload, to=u)


@socketio.on("typing")
def on_typing(data):
    user = current_user()
    if user:
        socketio.emit("typing", {"user": user, "typing": bool((data or {}).get("typing"))},
                      to=OTHER[user])


@socketio.on("mark_read")
def on_read():
    user = current_user()
    if not user:
        return
    ids = [r["id"] for r in query(
        "SELECT id FROM messages WHERE recipient=? AND read_at IS NULL", (user,))]
    if ids:
        at = now_iso()
        execute("UPDATE messages SET read_at=?, delivered_at=COALESCE(delivered_at, ?) "
                "WHERE recipient=? AND read_at IS NULL", (at, at, user))
        socketio.emit("read", {"ids": ids, "at": at}, to=OTHER[user])


def setup_passwords(force=False):
    import getpass
    for name in USERS:
        exists = query("SELECT 1 FROM users WHERE name=?", (name,), one=True)
        if exists and not force:
            continue
        while True:
            pw = getpass.getpass(f"Choose a password for {name} (min 8 chars): ")
            if len(pw) < 8:
                print("  Too short, try again.")
            elif pw != getpass.getpass("  Confirm: "):
                print("  Did not match, try again.")
            else:
                set_password(name, pw)
                print(f"  {name} saved.")
                break


if __name__ == "__main__":
    import sys
    # first run: asks for the two passwords; "python app.py setpw" resets them
    if len(sys.argv) > 1 and sys.argv[1] == "setpw":
        setup_passwords(force=True)
    else:
        # ready-made password for both accounts: 2011  (change it before going online!)
        for _name in USERS:
            if not query("SELECT 1 FROM users WHERE name=?", (_name,), one=True):
                set_password(_name, DEFAULT_PASSWORD)
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  ♡ Open http://localhost:{port}  (phones on the same Wi-Fi: use this PC's IP)\n")
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True)
