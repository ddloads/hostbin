import base64
import hashlib
import hmac
import html
import os
import secrets
import sqlite3
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse


APP_NAME = os.getenv("APP_NAME", "Hostbin")
BASE_URL = os.getenv("BASE_URL", "").rstrip("/")
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "hostbin.sqlite3"
MAX_PASTE_BYTES = int(os.getenv("MAX_PASTE_BYTES", str(1024 * 1024)))
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))
COOKIE_NAME = "hostbin_flash"


LANGUAGES = [
    "Plain Text",
    "Bash",
    "C",
    "C++",
    "CSS",
    "Dockerfile",
    "Go",
    "HTML",
    "Java",
    "JavaScript",
    "JSON",
    "Markdown",
    "PHP",
    "Python",
    "Ruby",
    "Rust",
    "SQL",
    "TypeScript",
    "YAML",
]

EXPIRATIONS = {
    "never": None,
    "10m": 10 * 60,
    "1h": 60 * 60,
    "1d": 24 * 60 * 60,
    "1w": 7 * 24 * 60 * 60,
    "1mo": 30 * 24 * 60 * 60,
}


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS pastes (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                language TEXT NOT NULL,
                visibility TEXT NOT NULL,
                burn_after_read INTEGER NOT NULL DEFAULT 0,
                password_hash TEXT,
                delete_token_hash TEXT NOT NULL,
                views INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                expires_at INTEGER
            )
            """
        )
        db.execute("CREATE INDEX IF NOT EXISTS idx_pastes_created ON pastes(created_at DESC)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_pastes_expires ON pastes(expires_at)")


def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def make_id():
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    while True:
        paste_id = "".join(secrets.choice(alphabet) for _ in range(8))
        with get_db() as db:
            exists = db.execute("SELECT 1 FROM pastes WHERE id = ?", (paste_id,)).fetchone()
        if not exists:
            return paste_id


def hash_secret(secret):
    salt = secrets.token_hex(16)
    digest = hashlib.sha256(f"{salt}:{secret}".encode("utf-8")).hexdigest()
    return f"{salt}:{digest}"


def verify_secret(stored, secret):
    if not stored or not secret:
        return False
    try:
        salt, digest = stored.split(":", 1)
    except ValueError:
        return False
    candidate = hashlib.sha256(f"{salt}:{secret}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(digest, candidate)


def short_time(ts):
    if not ts:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))


def age(ts):
    delta = max(0, int(time.time()) - int(ts))
    units = [(86400, "d"), (3600, "h"), (60, "m")]
    for seconds, suffix in units:
        if delta >= seconds:
            return f"{delta // seconds}{suffix} ago"
    return "just now"


def escape(value):
    return html.escape(value or "", quote=True)


def flash_cookie(message):
    encoded = base64.urlsafe_b64encode(message.encode("utf-8")).decode("ascii")
    return f"{COOKIE_NAME}={encoded}; Path=/; HttpOnly; SameSite=Lax; Max-Age=5"


def clear_flash_cookie():
    return f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"


def absolute(path):
    return f"{BASE_URL}{path}" if BASE_URL else path


def layout(title, content, flash=None):
    safe_title = escape(f"{title} - {APP_NAME}" if title else APP_NAME)
    flash_html = f'<div class="flash">{escape(flash)}</div>' if flash else ""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{safe_title}</title>
  <link rel="stylesheet" href="/static/app.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/">{escape(APP_NAME)}</a>
    <nav>
      <a href="/new">New paste</a>
      <a href="/public">Public</a>
    </nav>
  </header>
  <main>
    {flash_html}
    {content}
  </main>
</body>
</html>"""


def css():
    return """
:root {
  color-scheme: light;
  --bg: #f7f5ef;
  --panel: #ffffff;
  --ink: #1e2528;
  --muted: #677176;
  --line: #d8ddd7;
  --accent: #0f766e;
  --accent-strong: #0b5f59;
  --danger: #b42318;
  --code-bg: #111827;
  --code-ink: #edf2f7;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 15px/1.5 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 14px clamp(16px, 4vw, 48px);
  border-bottom: 1px solid var(--line);
  background: rgba(255,255,255,.82);
  backdrop-filter: blur(10px);
  position: sticky;
  top: 0;
  z-index: 5;
}
.brand {
  color: var(--ink);
  font-weight: 800;
  font-size: 20px;
  letter-spacing: 0;
}
nav { display: flex; gap: 14px; flex-wrap: wrap; }
main {
  width: min(1120px, calc(100% - 32px));
  margin: 28px auto 48px;
}
.hero {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 340px;
  gap: 24px;
  align-items: start;
  margin-bottom: 24px;
}
h1, h2, h3 { line-height: 1.15; letter-spacing: 0; margin: 0 0 12px; }
h1 { font-size: clamp(30px, 4vw, 52px); max-width: 900px; }
h2 { font-size: 24px; }
p { margin: 0 0 16px; color: var(--muted); }
.panel, .paste-row {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
}
.panel { padding: 18px; }
.actions { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
.button, button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 40px;
  padding: 0 14px;
  border-radius: 6px;
  border: 1px solid var(--accent);
  background: var(--accent);
  color: #fff;
  font: inherit;
  font-weight: 700;
  cursor: pointer;
}
.button:hover, button:hover { background: var(--accent-strong); text-decoration: none; }
.button.secondary {
  background: transparent;
  color: var(--accent);
}
.button.secondary:hover { background: #e6f4f1; }
form { display: grid; gap: 14px; }
.grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}
label { display: grid; gap: 6px; font-weight: 700; color: var(--ink); }
input, select, textarea {
  width: 100%;
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 10px 12px;
  font: inherit;
  color: var(--ink);
  background: #fff;
}
textarea {
  min-height: 420px;
  resize: vertical;
  font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
  line-height: 1.45;
}
.checkline { display: flex; gap: 8px; align-items: center; font-weight: 600; }
.checkline input { width: auto; }
.hint { color: var(--muted); font-size: 13px; font-weight: 500; }
.paste-list { display: grid; gap: 10px; }
.paste-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 12px;
  padding: 14px;
}
.paste-row h3 { margin: 0 0 4px; font-size: 17px; overflow-wrap: anywhere; }
.meta {
  color: var(--muted);
  font-size: 13px;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.badge {
  display: inline-flex;
  align-items: center;
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: 2px 8px;
  background: #f8faf9;
  color: var(--muted);
  font-size: 12px;
}
.paste-head {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: start;
  margin-bottom: 12px;
}
.codebox {
  background: var(--code-bg);
  color: var(--code-ink);
  border-radius: 8px;
  overflow: auto;
  border: 1px solid #1f2937;
}
pre {
  margin: 0;
  padding: 18px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font: 14px/1.55 ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
}
.flash {
  background: #ecfdf3;
  border: 1px solid #abd7bd;
  color: #14532d;
  border-radius: 8px;
  padding: 12px 14px;
  margin-bottom: 16px;
}
.error {
  border-color: #f3b2aa;
  background: #fff5f4;
  color: var(--danger);
}
.empty { padding: 26px; text-align: center; color: var(--muted); }
@media (max-width: 760px) {
  .hero, .grid, .paste-row { grid-template-columns: 1fr; }
  .topbar { align-items: flex-start; }
  .paste-head { flex-direction: column; }
  textarea { min-height: 320px; }
}
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Hostbin/1.0"

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/static/app.css":
            self.send_text(css(), "text/css; charset=utf-8")
        elif path == "/":
            self.home()
        elif path == "/new":
            self.new_form()
        elif path == "/public":
            self.public_list()
        elif path.startswith("/p/"):
            self.view_paste(unquote(path.removeprefix("/p/")))
        elif path.startswith("/raw/"):
            self.raw_paste(unquote(path.removeprefix("/raw/")))
        elif path.startswith("/delete/"):
            self.delete_paste(unquote(path.removeprefix("/delete/")))
        else:
            self.not_found()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/create":
            self.create_paste()
        elif path.startswith("/p/"):
            self.view_paste(unquote(path.removeprefix("/p/")), posted=True)
        else:
            self.not_found()

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")

    def read_form(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_PASTE_BYTES + 8192:
            return None
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        return {key: values[-1] for key, values in parse_qs(body, keep_blank_values=True).items()}

    def get_flash(self):
        header = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie(header)
        morsel = jar.get(COOKIE_NAME)
        if not morsel:
            return None
        try:
            return base64.urlsafe_b64decode(morsel.value.encode("ascii")).decode("utf-8")
        except Exception:
            return None

    def send_html(self, title, content, status=200, flash=None, headers=None):
        body = layout(title, content, flash if flash is not None else self.get_flash()).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", clear_flash_cookie())
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, body, content_type="text/plain; charset=utf-8", status=200):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, flash=None):
        self.send_response(303)
        self.send_header("Location", location)
        if flash:
            self.send_header("Set-Cookie", flash_cookie(flash))
        self.end_headers()

    def home(self):
        content = f"""
<section class="hero">
  <div>
    <h1>Fast, private pastes you control.</h1>
    <p>{escape(APP_NAME)} is a compact self-hosted pastebin inspired by pastes.io: quick sharing, optional public listings, raw links, expiring pastes, passwords, and burn-after-read support.</p>
    <div class="actions">
      <a class="button" href="/new">Create a paste</a>
      <a class="button secondary" href="/public">Browse public pastes</a>
    </div>
  </div>
  <aside class="panel">
    <h2>Deployment</h2>
    <p>Run it behind your reverse proxy or expose the container directly. Data is stored in a SQLite database under <code>/data</code>.</p>
    <p class="hint">Set <code>BASE_URL</code>, <code>APP_NAME</code>, and <code>MAX_PASTE_BYTES</code> with environment variables.</p>
  </aside>
</section>
{self.recent_public(limit=8)}
"""
        self.send_html("", content)

    def new_form(self, error=None, values=None):
        values = values or {}
        lang_options = "".join(
            f'<option value="{escape(lang)}" {"selected" if values.get("language") == lang else ""}>{escape(lang)}</option>'
            for lang in LANGUAGES
        )
        exp_options = "".join(
            f'<option value="{key}" {"selected" if values.get("expires") == key else ""}>{label}</option>'
            for key, label in [
                ("never", "Never"),
                ("10m", "10 minutes"),
                ("1h", "1 hour"),
                ("1d", "1 day"),
                ("1w", "1 week"),
                ("1mo", "1 month"),
            ]
        )
        error_html = f'<div class="flash error">{escape(error)}</div>' if error else ""
        content = f"""
<h1>New paste</h1>
{error_html}
<form method="post" action="/create">
  <label>Paste content
    <textarea name="body" maxlength="{MAX_PASTE_BYTES}" required>{escape(values.get("body", ""))}</textarea>
    <span class="hint">Maximum size: {MAX_PASTE_BYTES:,} bytes.</span>
  </label>
  <div class="grid">
    <label>Title
      <input name="title" maxlength="120" value="{escape(values.get("title", ""))}" placeholder="Untitled paste">
    </label>
    <label>Language
      <select name="language">{lang_options}</select>
    </label>
    <label>Visibility
      <select name="visibility">
        <option value="unlisted" {"selected" if values.get("visibility") != "public" else ""}>Unlisted</option>
        <option value="public" {"selected" if values.get("visibility") == "public" else ""}>Public</option>
      </select>
    </label>
    <label>Expires
      <select name="expires">{exp_options}</select>
    </label>
    <label>Password
      <input name="password" type="password" maxlength="128" autocomplete="new-password" placeholder="Optional">
    </label>
    <label class="checkline">
      <input name="burn_after_read" type="checkbox" value="1" {"checked" if values.get("burn_after_read") == "1" else ""}>
      Burn after first successful read
    </label>
  </div>
  <div class="actions">
    <button type="submit">Create paste</button>
  </div>
</form>
"""
        self.send_html("New paste", content)

    def create_paste(self):
        form = self.read_form()
        if form is None:
            self.new_form("Paste is too large.")
            return
        body = form.get("body", "")
        if not body.strip():
            self.new_form("Paste content is required.", form)
            return
        if len(body.encode("utf-8")) > MAX_PASTE_BYTES:
            self.new_form("Paste exceeds the configured size limit.", form)
            return
        now = int(time.time())
        expires_key = form.get("expires", "never")
        expires_in = EXPIRATIONS.get(expires_key)
        expires_at = now + expires_in if expires_in else None
        delete_token = secrets.token_urlsafe(24)
        paste_id = make_id()
        title = (form.get("title") or "Untitled paste").strip()[:120]
        language = form.get("language") if form.get("language") in LANGUAGES else "Plain Text"
        visibility = "public" if form.get("visibility") == "public" else "unlisted"
        password = form.get("password", "")
        with get_db() as db:
            db.execute(
                """
                INSERT INTO pastes (
                    id, title, body, language, visibility, burn_after_read,
                    password_hash, delete_token_hash, views, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    paste_id,
                    title,
                    body,
                    language,
                    visibility,
                    1 if form.get("burn_after_read") == "1" else 0,
                    hash_secret(password) if password else None,
                    hash_secret(delete_token),
                    now,
                    expires_at,
                ),
            )
        self.redirect(
            f"/p/{quote(paste_id)}?delete={quote(delete_token)}",
            "Paste created. Save the delete link from this page if you want removal control.",
        )

    def load_paste(self, paste_id):
        with get_db() as db:
            paste = db.execute("SELECT * FROM pastes WHERE id = ?", (paste_id,)).fetchone()
            if paste and paste["expires_at"] and paste["expires_at"] <= int(time.time()):
                db.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))
                return None
            return paste

    def password_form(self, paste_id, error=None):
        error_html = f'<div class="flash error">{escape(error)}</div>' if error else ""
        content = f"""
<section class="panel">
  <h1>Protected paste</h1>
  <p>This paste requires a password before it can be viewed.</p>
  {error_html}
  <form method="post" action="/p/{quote(paste_id)}">
    <label>Password
      <input name="password" type="password" autofocus required>
    </label>
    <div class="actions"><button type="submit">Unlock</button></div>
  </form>
</section>
"""
        self.send_html("Protected paste", content, status=403 if error else 200, flash="")

    def view_paste(self, paste_id, posted=False):
        paste = self.load_paste(paste_id)
        if not paste:
            self.not_found()
            return
        if paste["password_hash"]:
            form = self.read_form() if posted else {}
            if not posted or not verify_secret(paste["password_hash"], form.get("password", "")):
                self.password_form(paste_id, "Invalid password." if posted else None)
                return
        with get_db() as db:
            db.execute("UPDATE pastes SET views = views + 1 WHERE id = ?", (paste_id,))
        delete_token = parse_qs(urlparse(self.path).query).get("delete", [""])[0]
        delete_link = ""
        if delete_token and verify_secret(paste["delete_token_hash"], delete_token):
            delete_link = f'<a class="button secondary" href="/delete/{quote(paste_id)}?token={quote(delete_token)}">Delete</a>'
        body = escape(paste["body"])
        raw_path = f"/raw/{quote(paste_id)}"
        content = f"""
<section class="paste-head">
  <div>
    <h1>{escape(paste["title"])}</h1>
    <div class="meta">
      <span class="badge">{escape(paste["language"])}</span>
      <span>{escape(paste["visibility"])}</span>
      <span>{age(paste["created_at"])}</span>
      <span>{paste["views"] + 1} views</span>
      <span>expires {short_time(paste["expires_at"])}</span>
    </div>
  </div>
  <div class="actions">
    <a class="button secondary" href="{raw_path}">Raw</a>
    <a class="button secondary" href="/new">New</a>
    {delete_link}
  </div>
</section>
<div class="codebox"><pre>{body}</pre></div>
"""
        self.send_html(paste["title"], content)
        if paste["burn_after_read"]:
            with get_db() as db:
                db.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))

    def raw_paste(self, paste_id):
        paste = self.load_paste(paste_id)
        if not paste:
            self.not_found(text=True)
            return
        if paste["password_hash"]:
            self.send_text("Password-protected pastes are only available through the web view.\n", status=403)
            return
        with get_db() as db:
            db.execute("UPDATE pastes SET views = views + 1 WHERE id = ?", (paste_id,))
        self.send_text(paste["body"])
        if paste["burn_after_read"]:
            with get_db() as db:
                db.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))

    def delete_paste(self, paste_id):
        token = parse_qs(urlparse(self.path).query).get("token", [""])[0]
        paste = self.load_paste(paste_id)
        if not paste or not verify_secret(paste["delete_token_hash"], token):
            self.not_found()
            return
        with get_db() as db:
            db.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))
        self.redirect("/", "Paste deleted.")

    def recent_public(self, limit=20):
        now = int(time.time())
        with get_db() as db:
            rows = db.execute(
                """
                SELECT id, title, language, views, created_at, expires_at
                FROM pastes
                WHERE visibility = 'public' AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (now, limit),
            ).fetchall()
        if not rows:
            return '<section class="panel empty">No public pastes yet.</section>'
        items = []
        for row in rows:
            items.append(
                f"""
<article class="paste-row">
  <div>
    <h3><a href="/p/{quote(row["id"])}">{escape(row["title"])}</a></h3>
    <div class="meta">
      <span class="badge">{escape(row["language"])}</span>
      <span>{age(row["created_at"])}</span>
      <span>{row["views"]} views</span>
      <span>expires {short_time(row["expires_at"])}</span>
    </div>
  </div>
  <a class="button secondary" href="/raw/{quote(row["id"])}">Raw</a>
</article>"""
            )
        return f'<section><h2>Recent public pastes</h2><div class="paste-list">{"".join(items)}</div></section>'

    def public_list(self):
        self.send_html("Public pastes", f"<h1>Public pastes</h1>{self.recent_public(limit=50)}")

    def not_found(self, text=False):
        if text:
            self.send_text("Not found\n", status=404)
            return
        self.send_html("Not found", '<section class="panel empty">Paste not found.</section>', status=404, flash="")


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"{APP_NAME} listening on http://{HOST}:{PORT}")
    server.serve_forever()
