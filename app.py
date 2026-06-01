import base64
import email.parser
import email.policy
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, quote, urlencode, unquote, urlparse
from urllib.request import Request, urlopen


APP_NAME = os.getenv("APP_NAME", "Hostbin")
BASE_URL = os.getenv("BASE_URL", "").rstrip("/")
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "hostbin.sqlite3"
MAX_PASTE_BYTES = int(os.getenv("MAX_PASTE_BYTES", str(1024 * 1024)))
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))
COOKIE_NAME = "hostbin_flash"
SESSION_COOKIE_NAME = "hostbin_session"
SESSION_TTL = 30 * 24 * 60 * 60
ASSET_VERSION = "2026-06-01-2"
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "").strip()
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
OAUTH_STATE_COOKIE_NAME = "hostbin_oauth_state"


LANGUAGES = [
    "Auto Detect",
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
    "Lua",
    "Markdown",
    "PHP",
    "Python",
    "Ruby",
    "Rust",
    "SQL",
    "TypeScript",
    "YAML",
]

STORED_LANGUAGES = [lang for lang in LANGUAGES if lang != "Auto Detect"]

EXTENSION_LANGUAGES = {
    ".bash": "Bash",
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".css": "CSS",
    ".dockerfile": "Dockerfile",
    ".go": "Go",
    ".h": "C",
    ".hpp": "C++",
    ".htm": "HTML",
    ".html": "HTML",
    ".java": "Java",
    ".js": "JavaScript",
    ".json": "JSON",
    ".lua": "Lua",
    ".md": "Markdown",
    ".php": "PHP",
    ".py": "Python",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".sh": "Bash",
    ".sql": "SQL",
    ".ts": "TypeScript",
    ".yaml": "YAML",
    ".yml": "YAML",
}

KEYWORDS = {
    "Bash": {"case", "do", "done", "elif", "else", "esac", "fi", "for", "function", "if", "in", "then", "while"},
    "C": {"auto", "break", "case", "char", "const", "continue", "default", "double", "else", "enum", "float", "for", "if", "int", "long", "return", "short", "sizeof", "static", "struct", "switch", "typedef", "void", "while"},
    "C++": {"auto", "bool", "break", "case", "class", "const", "constexpr", "continue", "default", "double", "else", "enum", "float", "for", "if", "int", "namespace", "new", "private", "protected", "public", "return", "static", "struct", "switch", "template", "typename", "using", "void", "while"},
    "CSS": {"align-items", "background", "border", "color", "display", "font", "grid", "height", "margin", "padding", "position", "width"},
    "Dockerfile": {"ADD", "ARG", "CMD", "COPY", "ENTRYPOINT", "ENV", "EXPOSE", "FROM", "LABEL", "RUN", "USER", "VOLUME", "WORKDIR"},
    "Go": {"break", "case", "chan", "const", "continue", "defer", "else", "fallthrough", "for", "func", "go", "if", "import", "interface", "map", "package", "range", "return", "select", "struct", "switch", "type", "var"},
    "Java": {"abstract", "boolean", "break", "case", "catch", "class", "const", "continue", "else", "enum", "extends", "final", "for", "if", "implements", "import", "interface", "new", "package", "private", "protected", "public", "return", "static", "throws", "try", "void", "while"},
    "JavaScript": {"async", "await", "break", "case", "catch", "class", "const", "continue", "default", "else", "export", "extends", "finally", "for", "function", "if", "import", "let", "new", "return", "switch", "throw", "try", "var", "while", "yield"},
    "JSON": {"true", "false", "null"},
    "Lua": {"and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while"},
    "PHP": {"class", "echo", "else", "elseif", "extends", "foreach", "function", "if", "namespace", "new", "private", "protected", "public", "return", "static", "use", "while"},
    "Python": {"and", "as", "assert", "async", "await", "break", "class", "continue", "def", "elif", "else", "except", "False", "finally", "for", "from", "if", "import", "in", "is", "lambda", "None", "not", "or", "pass", "return", "True", "try", "while", "with", "yield"},
    "Ruby": {"begin", "class", "def", "do", "else", "elsif", "end", "false", "if", "module", "nil", "return", "self", "then", "true", "unless", "while", "yield"},
    "Rust": {"as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "static", "struct", "trait", "true", "type", "unsafe", "use", "where", "while"},
    "SQL": {"ALTER", "AND", "AS", "CREATE", "DELETE", "DROP", "FROM", "GROUP", "INSERT", "INTO", "JOIN", "LIMIT", "NOT", "NULL", "OR", "ORDER", "SELECT", "SET", "TABLE", "UPDATE", "VALUES", "WHERE"},
    "TypeScript": {"any", "async", "await", "break", "case", "catch", "class", "const", "continue", "default", "else", "enum", "export", "extends", "finally", "for", "function", "if", "implements", "import", "interface", "let", "new", "private", "protected", "public", "return", "switch", "throw", "try", "type", "var", "while"},
    "YAML": {"false", "null", "true"},
}

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
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
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
        columns = {row[1] for row in db.execute("PRAGMA table_info(pastes)").fetchall()}
        if "owner_user_id" not in columns:
            db.execute("ALTER TABLE pastes ADD COLUMN owner_user_id INTEGER")
        user_columns = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        if "email" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if "google_sub" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")
        db.execute("CREATE INDEX IF NOT EXISTS idx_pastes_created ON pastes(created_at DESC)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_pastes_expires ON pastes(expires_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_pastes_owner ON pastes(owner_user_id, created_at DESC)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")


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


def detect_language(body, filename=None, selected=None):
    if selected and selected != "Auto Detect" and selected in STORED_LANGUAGES:
        return selected
    if filename:
        lowered = filename.lower()
        if lowered == "dockerfile" or lowered.endswith(".dockerfile"):
            return "Dockerfile"
        ext = Path(lowered).suffix
        if ext in EXTENSION_LANGUAGES:
            return EXTENSION_LANGUAGES[ext]
    stripped = (body or "").lstrip()
    sample = stripped[:2000]
    if not sample:
        return "Plain Text"
    if sample.startswith("<!doctype html") or sample.startswith("<html") or re.search(r"<[a-zA-Z][^>]*>", sample):
        return "HTML"
    if sample.startswith("{") or sample.startswith("["):
        try:
            json.loads(sample)
            return "JSON"
        except Exception:
            pass
    if re.search(r"\b(local\s+function|local\s+\w+\s*=|end\s*$|then\s*$)", sample, re.MULTILINE):
        return "Lua"
    if re.search(r"\b(def|import|from|class)\s+\w+", sample):
        return "Python"
    if re.search(r"\b(function|const|let|=>|console\.log)\b", sample):
        return "JavaScript"
    if re.search(r"\b(interface|type)\s+\w+\s*[={]", sample):
        return "TypeScript"
    if re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE TABLE)\b", sample, re.IGNORECASE):
        return "SQL"
    if re.search(r"^\s*FROM\s+\S+", sample, re.MULTILINE):
        return "Dockerfile"
    if re.search(r"^\s*[-\w]+\s*:\s+", sample, re.MULTILINE):
        return "YAML"
    if re.search(r"^\s*#include\s+<", sample, re.MULTILINE):
        return "C++" if "::" in sample or "std::" in sample else "C"
    if re.search(r"\bpackage\s+main\b|\bfunc\s+\w+\(", sample):
        return "Go"
    if re.search(r"\b(fn|let|impl|struct)\s+\w+", sample):
        return "Rust"
    if sample.startswith("#!") or re.search(r"\b(echo|fi|done|elif)\b", sample):
        return "Bash"
    return "Plain Text"


def line_comment_marker(language):
    return {
        "Bash": "#",
        "Dockerfile": "#",
        "Lua": "--",
        "Python": "#",
        "Ruby": "#",
        "SQL": "--",
        "YAML": "#",
    }.get(language, "//" if language in {"C", "C++", "Go", "Java", "JavaScript", "PHP", "Rust", "TypeScript"} else None)


def split_comment(line, marker):
    if not marker:
        return line, ""
    quote_char = None
    escaped = False
    for index, char in enumerate(line):
        if quote_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote_char:
                quote_char = None
            continue
        if char in {"'", '"', "`"}:
            quote_char = char
            continue
        if line.startswith(marker, index):
            return line[:index], line[index:]
    return line, ""


def highlight_non_comment(text, language):
    if not text:
        return ""
    keywords = KEYWORDS.get(language, set())
    string_pattern = re.compile(r"('(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`)")
    output = []
    cursor = 0
    for match in string_pattern.finditer(text):
        output.append(highlight_words(text[cursor:match.start()], keywords))
        output.append(f'<span class="tok-string">{escape(match.group(0))}</span>')
        cursor = match.end()
    output.append(highlight_words(text[cursor:], keywords))
    return "".join(output)


def highlight_words(text, keywords):
    escaped_text = escape(text)
    if keywords:
        keyword_pattern = re.compile(r"\b(" + "|".join(re.escape(word) for word in sorted(keywords, key=len, reverse=True)) + r")\b")
        escaped_text = keyword_pattern.sub(r'<span class="tok-keyword">\1</span>', escaped_text)
    escaped_text = re.sub(r"\b(\d+(?:\.\d+)?)\b", r'<span class="tok-number">\1</span>', escaped_text)
    return escaped_text


def highlight_code(body, language):
    if language == "Plain Text" or not body:
        return escape(body)
    marker = line_comment_marker(language)
    highlighted = []
    for line in body.splitlines(keepends=True):
        ending = ""
        if line.endswith("\r\n"):
            line, ending = line[:-2], "\r\n"
        elif line.endswith("\n"):
            line, ending = line[:-1], "\n"
        code_part, comment_part = split_comment(line, marker)
        rendered = highlight_non_comment(code_part, language)
        if comment_part:
            rendered += f'<span class="tok-comment">{escape(comment_part)}</span>'
        highlighted.append(rendered + ending)
    return "".join(highlighted)


def flash_cookie(message):
    encoded = base64.urlsafe_b64encode(message.encode("utf-8")).decode("ascii")
    return f"{COOKIE_NAME}={encoded}; Path=/; HttpOnly; SameSite=Lax; Max-Age=5"


def clear_flash_cookie():
    return f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"


def session_cookie(token):
    return f"{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"


def clear_session_cookie():
    return f"{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"


def oauth_state_cookie(state):
    return f"{OAUTH_STATE_COOKIE_NAME}={state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600"


def clear_oauth_state_cookie():
    return f"{OAUTH_STATE_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"


def session_token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def absolute(path):
    return f"{BASE_URL}{path}" if BASE_URL else path


def google_enabled():
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


def layout(title, content, flash=None, user=None):
    safe_title = escape(f"{title} - {APP_NAME}" if title else APP_NAME)
    flash_html = f'<div class="flash">{escape(flash)}</div>' if flash else ""
    account_links = (
        f'<a href="/my">My pastes</a><span class="nav-user">{escape(user["username"])}</span><a href="/logout">Log out</a>'
        if user
        else '<a href="/login">Log in</a><a href="/signup">Sign up</a>'
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{safe_title}</title>
  <script src="/static/app.js?v={ASSET_VERSION}"></script>
  <link rel="stylesheet" href="/static/app.css?v={ASSET_VERSION}">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/">{escape(APP_NAME)}</a>
    <nav>
      <a href="/new">New paste</a>
      <a href="/public">Public</a>
      {account_links}
      <button class="theme-toggle" type="button" id="theme-toggle" aria-label="Toggle dark mode" title="Toggle dark mode">Dark</button>
    </nav>
  </header>
  <main>
    {flash_html}
    {content}
  </main>
</body>
</html>"""


def js():
    return """(function () {
  try {
    var savedTheme = localStorage.getItem("hostbin-theme");
    if (savedTheme === "dark" || savedTheme === "light") {
      document.documentElement.setAttribute("data-theme", savedTheme);
    }
  } catch (e) {}
})();

document.addEventListener("DOMContentLoaded", function () {
  var root = document.documentElement;
  var toggle = document.getElementById("theme-toggle");
  if (!toggle) return;

  function currentTheme() {
    return root.getAttribute("data-theme") === "dark" ? "dark" : "light";
  }

  function setTheme(theme) {
    root.setAttribute("data-theme", theme);
    toggle.textContent = theme === "dark" ? "Light" : "Dark";
    toggle.setAttribute("aria-label", theme === "dark" ? "Switch to light mode" : "Switch to dark mode");
    try {
      localStorage.setItem("hostbin-theme", theme);
    } catch (e) {}
  }

  setTheme(currentTheme());
  toggle.addEventListener("click", function () {
    setTheme(currentTheme() === "dark" ? "light" : "dark");
  });
});
"""


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
  --input-bg: #ffffff;
  --button-soft: #e6f4f1;
  --topbar-bg: rgba(255,255,255,.82);
}
html[data-theme="dark"] {
  color-scheme: dark;
  --bg: #101214;
  --panel: #191d20;
  --ink: #eef2f3;
  --muted: #9aa6aa;
  --line: #30383d;
  --accent: #2dd4bf;
  --accent-strong: #5eead4;
  --danger: #f87171;
  --code-bg: #05070a;
  --code-ink: #e5eef5;
  --input-bg: #111518;
  --button-soft: #173633;
  --topbar-bg: rgba(16,18,20,.86);
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
  background: var(--topbar-bg);
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
nav { display: flex; gap: 14px; flex-wrap: wrap; align-items: center; }
.nav-user { color: var(--muted); font-size: 13px; }
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
.button.secondary:hover { background: var(--button-soft); }
.button.full { width: 100%; }
.theme-toggle {
  min-height: 32px;
  padding: 0 10px;
  border-color: var(--line);
  background: transparent;
  color: var(--ink);
  font-size: 13px;
}
.theme-toggle:hover { background: var(--button-soft); color: var(--ink); }
form { display: grid; gap: 14px; }
.auth-stack { display: grid; gap: 14px; }
.divider {
  color: var(--muted);
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 13px;
}
.divider::before, .divider::after {
  content: "";
  height: 1px;
  background: var(--line);
  flex: 1;
}
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
  background: var(--input-bg);
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
  background: var(--input-bg);
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
.tok-keyword { color: #93c5fd; font-weight: 700; }
.tok-string { color: #86efac; }
.tok-comment { color: #94a3b8; font-style: italic; }
.tok-number { color: #fbbf24; }
html[data-theme="dark"] .tok-keyword { color: #7dd3fc; }
html[data-theme="dark"] .tok-string { color: #bbf7d0; }
html[data-theme="dark"] .tok-comment { color: #718096; }
html[data-theme="dark"] .tok-number { color: #facc15; }
.flash {
  background: #ecfdf3;
  border: 1px solid #abd7bd;
  color: #14532d;
  border-radius: 8px;
  padding: 12px 14px;
  margin-bottom: 16px;
}
html[data-theme="dark"] .flash {
  background: #123325;
  border-color: #1d6b4b;
  color: #bbf7d0;
}
.error {
  border-color: #f3b2aa;
  background: #fff5f4;
  color: var(--danger);
}
html[data-theme="dark"] .error {
  border-color: #7f1d1d;
  background: #2b1214;
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
        if path == "/static/app.js":
            self.send_static(js(), "application/javascript; charset=utf-8")
        elif path == "/static/app.css":
            self.send_static(css(), "text/css; charset=utf-8")
        elif path == "/":
            self.home()
        elif path == "/new":
            self.new_form()
        elif path == "/my":
            self.my_pastes()
        elif path == "/public":
            self.public_list()
        elif path == "/signup":
            self.signup_form()
        elif path == "/login":
            self.login_form()
        elif path == "/logout":
            self.logout()
        elif path == "/auth/google":
            self.google_start()
        elif path == "/auth/google/callback":
            self.google_callback()
        elif path.startswith("/edit/"):
            self.edit_paste_form(unquote(path.removeprefix("/edit/")))
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
        elif path == "/signup":
            self.signup()
        elif path == "/login":
            self.login()
        elif path.startswith("/edit/"):
            self.update_paste(unquote(path.removeprefix("/edit/")))
        elif path.startswith("/p/"):
            self.view_paste(unquote(path.removeprefix("/p/")), posted=True)
        else:
            self.not_found()

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")

    def read_form(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_PASTE_BYTES + 65536:
            return None
        body = self.rfile.read(length)
        content_type = self.headers.get("Content-Type", "")
        if content_type.startswith("multipart/form-data"):
            return self.read_multipart_form(content_type, body)
        text = body.decode("utf-8", errors="replace")
        return {key: values[-1] for key, values in parse_qs(text, keep_blank_values=True).items()}

    def read_multipart_form(self, content_type, body):
        message = email.parser.BytesParser(policy=email.policy.default).parsebytes(
            b"Content-Type: " + content_type.encode("utf-8") + b"\r\n\r\n" + body
        )
        form = {}
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if not name:
                continue
            filename = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            if filename:
                form[name] = SimpleNamespace(
                    filename=filename,
                    content=payload,
                    text=payload.decode("utf-8-sig", errors="replace"),
                )
            else:
                charset = part.get_content_charset() or "utf-8"
                form[name] = payload.decode(charset, errors="replace")
        upload = form.get("file")
        if upload and upload.content:
            form["uploaded_filename"] = upload.filename
            form["body"] = upload.text
        return form

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

    def current_user(self):
        header = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie(header)
        morsel = jar.get(SESSION_COOKIE_NAME)
        if not morsel:
            return None
        now = int(time.time())
        token_hash = session_token_hash(morsel.value)
        with get_db() as db:
            row = db.execute(
                """
                SELECT users.id, users.username
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                """,
                (token_hash, now),
            ).fetchone()
            db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        return row

    def send_html(self, title, content, status=200, flash=None, headers=None, extra_cookies=None):
        user = self.current_user()
        body = layout(title, content, flash if flash is not None else self.get_flash(), user=user).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", clear_flash_cookie())
        for cookie in extra_cookies or []:
            self.send_header("Set-Cookie", cookie)
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

    def send_static(self, body, content_type):
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, flash=None, extra_cookies=None):
        self.send_response(303)
        self.send_header("Location", location)
        if flash:
            self.send_header("Set-Cookie", flash_cookie(flash))
        for cookie in extra_cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def home(self):
        user = self.current_user()
        user_action = (
            '<a class="button secondary" href="/my">View my pastes</a>'
            if user
            else '<a class="button secondary" href="/signup">Create an account</a>'
        )
        content = f"""
<section class="hero">
  <div>
    <h1>Fast, private pastes you control.</h1>
    <p>{escape(APP_NAME)} is a compact self-hosted pastebin inspired by pastes.io: quick sharing, optional public listings, raw links, expiring pastes, passwords, user accounts, and burn-after-read support.</p>
    <div class="actions">
      <a class="button" href="/new">Create a paste</a>
      <a class="button secondary" href="/public">Browse public pastes</a>
      {user_action}
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

    def account_form(self, mode, error=None, values=None):
        values = values or {}
        is_signup = mode == "signup"
        title = "Sign up" if is_signup else "Log in"
        action = "/signup" if is_signup else "/login"
        button = "Create account" if is_signup else "Log in"
        switch = (
            'Already have an account? <a href="/login">Log in</a>.'
            if is_signup
            else 'Need an account? <a href="/signup">Sign up</a>.'
        )
        error_html = f'<div class="flash error">{escape(error)}</div>' if error else ""
        google_button = (
            f"""
  <a class="button secondary full" href="/auth/google">Continue with Google</a>
  <div class="divider">or</div>
"""
            if google_enabled()
            else ""
        )
        content = f"""
<section class="panel">
  <h1>{title}</h1>
  <p>{switch}</p>
  {error_html}
  <div class="auth-stack">
    {google_button}
    <form method="post" action="{action}">
      <label>Username
        <input name="username" value="{escape(values.get("username", ""))}" maxlength="40" autocomplete="username" required>
        <span class="hint">Use 3-40 letters, numbers, underscores, or hyphens.</span>
      </label>
      <label>Password
        <input name="password" type="password" minlength="8" maxlength="128" autocomplete="{"new-password" if is_signup else "current-password"}" required>
      </label>
      <div class="actions"><button type="submit">{button}</button></div>
    </form>
  </div>
</section>
"""
        self.send_html(title, content, status=400 if error else 200)

    def signup_form(self, error=None, values=None):
        self.account_form("signup", error, values)

    def login_form(self, error=None, values=None):
        self.account_form("login", error, values)

    def clean_username(self, username):
        username = (username or "").strip()
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
        if len(username) < 3 or len(username) > 40 or any(ch not in allowed for ch in username):
            return None
        return username

    def username_from_email(self, email):
        base = (email.split("@", 1)[0] if email else "google_user").lower()
        cleaned = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in base).strip("_-")
        if len(cleaned) < 3:
            cleaned = "google_user"
        cleaned = cleaned[:32]
        with get_db() as db:
            username = cleaned
            suffix = 1
            while db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                tail = f"_{suffix}"
                username = f"{cleaned[:40 - len(tail)]}{tail}"
                suffix += 1
            return username

    def create_session(self, user_id):
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        with get_db() as db:
            db.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (session_token_hash(token), user_id, now, now + SESSION_TTL),
            )
        return token

    def google_redirect_uri(self):
        return GOOGLE_REDIRECT_URI or absolute("/auth/google/callback")

    def google_start(self):
        if not google_enabled():
            self.redirect("/login", "Google sign-in is not configured.")
            return
        redirect_uri = self.google_redirect_uri()
        if not redirect_uri.startswith("http"):
            self.redirect("/login", "Set BASE_URL or GOOGLE_REDIRECT_URI before using Google sign-in.")
            return
        state = secrets.token_urlsafe(32)
        query = urlencode(
            {
                "client_id": GOOGLE_CLIENT_ID,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": "openid email profile",
                "state": state,
                "prompt": "select_account",
            }
        )
        self.redirect(f"{GOOGLE_AUTH_URL}?{query}", extra_cookies=[oauth_state_cookie(state)])

    def google_callback(self):
        if not google_enabled():
            self.redirect("/login", "Google sign-in is not configured.")
            return
        query = parse_qs(urlparse(self.path).query)
        code = query.get("code", [""])[0]
        state = query.get("state", [""])[0]
        error = query.get("error", [""])[0]
        header = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie(header)
        expected_state = jar.get(OAUTH_STATE_COOKIE_NAME).value if jar.get(OAUTH_STATE_COOKIE_NAME) else ""
        if error:
            self.redirect("/login", f"Google sign-in failed: {error}", extra_cookies=[clear_oauth_state_cookie()])
            return
        if not code or not state or not expected_state or not hmac.compare_digest(state, expected_state):
            self.redirect("/login", "Google sign-in state was invalid.", extra_cookies=[clear_oauth_state_cookie()])
            return
        try:
            userinfo = self.fetch_google_userinfo(code)
            user_id = self.find_or_create_google_user(userinfo)
        except Exception:
            self.redirect("/login", "Google sign-in could not be completed.", extra_cookies=[clear_oauth_state_cookie()])
            return
        token = self.create_session(user_id)
        self.redirect(
            "/my",
            "Logged in with Google.",
            extra_cookies=[session_cookie(token), clear_oauth_state_cookie()],
        )

    def fetch_google_userinfo(self, code):
        token_body = urlencode(
            {
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": self.google_redirect_uri(),
                "grant_type": "authorization_code",
            }
        ).encode("utf-8")
        token_request = Request(
            GOOGLE_TOKEN_URL,
            data=token_body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            method="POST",
        )
        with urlopen(token_request, timeout=10) as response:
            token_payload = json.loads(response.read().decode("utf-8"))
        access_token = token_payload.get("access_token")
        if not access_token:
            raise ValueError("missing access token")
        user_request = Request(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        )
        with urlopen(user_request, timeout=10) as response:
            userinfo = json.loads(response.read().decode("utf-8"))
        if not userinfo.get("sub") or not userinfo.get("email") or not userinfo.get("email_verified"):
            raise ValueError("unverified google account")
        return userinfo

    def find_or_create_google_user(self, userinfo):
        google_sub = userinfo["sub"]
        email = userinfo["email"].lower()
        now = int(time.time())
        with get_db() as db:
            user = db.execute("SELECT id FROM users WHERE google_sub = ?", (google_sub,)).fetchone()
            if user:
                db.execute("UPDATE users SET email = ? WHERE id = ?", (email, user["id"]))
                return user["id"]
            username = self.username_from_email(email)
            cursor = db.execute(
                """
                INSERT INTO users (username, password_hash, email, google_sub, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, hash_secret(secrets.token_urlsafe(32)), email, google_sub, now),
            )
            return cursor.lastrowid

    def signup(self):
        form = self.read_form() or {}
        username = self.clean_username(form.get("username"))
        password = form.get("password", "")
        if not username:
            self.signup_form("Choose a valid username.", form)
            return
        if len(password) < 8:
            self.signup_form("Password must be at least 8 characters.", form)
            return
        now = int(time.time())
        try:
            with get_db() as db:
                cursor = db.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, hash_secret(password), now),
                )
                user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            self.signup_form("That username is already taken.", form)
            return
        token = self.create_session(user_id)
        self.redirect("/my", "Account created.", extra_cookies=[session_cookie(token)])

    def login(self):
        form = self.read_form() or {}
        username = (form.get("username") or "").strip()
        password = form.get("password", "")
        with get_db() as db:
            user = db.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        if not user or not verify_secret(user["password_hash"], password):
            self.login_form("Invalid username or password.", form)
            return
        token = self.create_session(user["id"])
        self.redirect("/my", "Logged in.", extra_cookies=[session_cookie(token)])

    def logout(self):
        header = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie(header)
        morsel = jar.get(SESSION_COOKIE_NAME)
        if morsel:
            with get_db() as db:
                db.execute("DELETE FROM sessions WHERE token_hash = ?", (session_token_hash(morsel.value),))
        self.redirect("/", "Logged out.", extra_cookies=[clear_session_cookie()])

    def new_form(self, error=None, values=None):
        values = values or {}
        self.paste_form("New paste", "/create", "Create paste", values, error)

    def paste_form(self, title, action, button, values=None, error=None):
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
        show_password = action == "/create"
        password_html = (
            """
    <label>Password
      <input name="password" type="password" maxlength="128" autocomplete="new-password" placeholder="Optional">
    </label>
"""
            if show_password
            else '<p class="hint">Password and burn-after-read settings cannot be changed after creation.</p>'
        )
        burn_html = (
            f"""
    <label class="checkline">
      <input name="burn_after_read" type="checkbox" value="1" {"checked" if values.get("burn_after_read") == "1" else ""}>
      Burn after first successful read
    </label>
"""
            if show_password
            else ""
        )
        content = f"""
<h1>{escape(title)}</h1>
{error_html}
<form method="post" action="{escape(action)}" enctype="multipart/form-data">
  <label>Paste content
    <textarea name="body" maxlength="{MAX_PASTE_BYTES}">{escape(values.get("body", ""))}</textarea>
    <span class="hint">Maximum size: {MAX_PASTE_BYTES:,} bytes.</span>
  </label>
  <label>Create from file
    <input name="file" type="file" accept=".txt,.log,.md,.json,.js,.ts,.py,.lua,.html,.css,.sql,.yaml,.yml,.sh,.php,.rb,.rs,.go,.java,.c,.cpp,text/*">
    <span class="hint">Choose a text file to use as the paste content. Uploaded file content replaces the text area when submitted.</span>
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
    {password_html}
    {burn_html}
  </div>
  <div class="actions">
    <button type="submit">{escape(button)}</button>
  </div>
</form>
"""
        self.send_html(title, content)

    def paste_to_form_values(self, paste):
        expires_key = "never"
        if paste["expires_at"]:
            remaining = max(0, paste["expires_at"] - int(time.time()))
            if remaining <= EXPIRATIONS["10m"]:
                expires_key = "10m"
            elif remaining <= EXPIRATIONS["1h"]:
                expires_key = "1h"
            elif remaining <= EXPIRATIONS["1d"]:
                expires_key = "1d"
            elif remaining <= EXPIRATIONS["1w"]:
                expires_key = "1w"
            else:
                expires_key = "1mo"
        return {
            "title": paste["title"],
            "body": paste["body"],
            "language": paste["language"],
            "visibility": paste["visibility"],
            "expires": expires_key,
        }

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
        default_title = form.get("uploaded_filename") or "Untitled paste"
        title = (form.get("title") or default_title).strip()[:120]
        language = detect_language(body, form.get("uploaded_filename"), form.get("language"))
        visibility = "public" if form.get("visibility") == "public" else "unlisted"
        password = form.get("password", "")
        user = self.current_user()
        with get_db() as db:
            db.execute(
                """
                INSERT INTO pastes (
                    id, title, body, language, visibility, burn_after_read,
                    password_hash, delete_token_hash, views, created_at, expires_at, owner_user_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
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
                    user["id"] if user else None,
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

    def require_owned_paste(self, paste_id):
        user = self.current_user()
        if not user:
            self.redirect("/login", "Log in to edit your pastes.")
            return None, None
        paste = self.load_paste(paste_id)
        if not paste or paste["owner_user_id"] != user["id"]:
            self.not_found()
            return None, None
        return user, paste

    def edit_paste_form(self, paste_id, error=None, values=None):
        _, paste = self.require_owned_paste(paste_id)
        if not paste:
            return
        form_values = values or self.paste_to_form_values(paste)
        self.paste_form("Edit paste", f"/edit/{quote(paste_id)}", "Save changes", form_values, error)

    def update_paste(self, paste_id):
        _, paste = self.require_owned_paste(paste_id)
        if not paste:
            return
        form = self.read_form()
        if form is None:
            self.edit_paste_form(paste_id, "Paste is too large.")
            return
        body = form.get("body", "")
        if not body.strip():
            self.edit_paste_form(paste_id, "Paste content is required.", form)
            return
        if len(body.encode("utf-8")) > MAX_PASTE_BYTES:
            self.edit_paste_form(paste_id, "Paste exceeds the configured size limit.", form)
            return
        expires_key = form.get("expires", "never")
        expires_in = EXPIRATIONS.get(expires_key)
        expires_at = int(time.time()) + expires_in if expires_in else None
        default_title = form.get("uploaded_filename") or "Untitled paste"
        title = (form.get("title") or default_title).strip()[:120]
        language = detect_language(body, form.get("uploaded_filename"), form.get("language"))
        visibility = "public" if form.get("visibility") == "public" else "unlisted"
        with get_db() as db:
            db.execute(
                """
                UPDATE pastes
                SET title = ?, body = ?, language = ?, visibility = ?, expires_at = ?
                WHERE id = ?
                """,
                (title, body, language, visibility, expires_at, paste_id),
            )
        self.redirect(f"/p/{quote(paste_id)}", "Paste updated.")

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
        user = self.current_user()
        owns_paste = user and paste["owner_user_id"] == user["id"]
        if delete_token and verify_secret(paste["delete_token_hash"], delete_token):
            delete_link = f'<a class="button secondary" href="/delete/{quote(paste_id)}?token={quote(delete_token)}">Delete</a>'
        elif owns_paste:
            delete_link = f'<a class="button secondary" href="/delete/{quote(paste_id)}?owner=1">Delete</a>'
        edit_link = f'<a class="button secondary" href="/edit/{quote(paste_id)}">Edit</a>' if owns_paste else ""
        body = highlight_code(paste["body"], paste["language"])
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
    {edit_link}
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
        owner_delete = parse_qs(urlparse(self.path).query).get("owner", [""])[0] == "1"
        paste = self.load_paste(paste_id)
        user = self.current_user()
        owns_paste = user and paste and paste["owner_user_id"] == user["id"]
        if not paste or not (verify_secret(paste["delete_token_hash"], token) or (owner_delete and owns_paste)):
            self.not_found()
            return
        with get_db() as db:
            db.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))
        self.redirect("/my" if owns_paste else "/", "Paste deleted.")

    def recent_public(self, limit=20):
        now = int(time.time())
        with get_db() as db:
            rows = db.execute(
                """
                SELECT pastes.id, pastes.title, pastes.language, pastes.views,
                       pastes.created_at, pastes.expires_at, users.username
                FROM pastes
                LEFT JOIN users ON users.id = pastes.owner_user_id
                WHERE visibility = 'public' AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY pastes.created_at DESC
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
      <span>{escape(row["username"]) if row["username"] else "anonymous"}</span>
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

    def my_pastes(self):
        user = self.current_user()
        if not user:
            self.redirect("/login", "Log in to see your pastes.")
            return
        now = int(time.time())
        with get_db() as db:
            rows = db.execute(
                """
                SELECT id, title, language, visibility, views, created_at, expires_at
                FROM pastes
                WHERE owner_user_id = ? AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at DESC
                LIMIT 100
                """,
                (user["id"], now),
            ).fetchall()
        if not rows:
            listing = '<section class="panel empty">You have not created any pastes yet.</section>'
        else:
            items = []
            for row in rows:
                items.append(
                    f"""
<article class="paste-row">
  <div>
    <h3><a href="/p/{quote(row["id"])}">{escape(row["title"])}</a></h3>
    <div class="meta">
      <span class="badge">{escape(row["language"])}</span>
      <span>{escape(row["visibility"])}</span>
      <span>{age(row["created_at"])}</span>
      <span>{row["views"]} views</span>
      <span>expires {short_time(row["expires_at"])}</span>
    </div>
  </div>
  <div class="actions">
    <a class="button secondary" href="/edit/{quote(row["id"])}">Edit</a>
    <a class="button secondary" href="/raw/{quote(row["id"])}">Raw</a>
    <a class="button secondary" href="/delete/{quote(row["id"])}?owner=1">Delete</a>
  </div>
</article>"""
                )
            listing = f'<section><div class="paste-list">{"".join(items)}</div></section>'
        content = f"""
<section class="paste-head">
  <div>
    <h1>My pastes</h1>
    <p>Signed in as {escape(user["username"])}.</p>
  </div>
  <div class="actions"><a class="button" href="/new">Create paste</a></div>
</section>
{listing}
"""
        self.send_html("My pastes", content)

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
