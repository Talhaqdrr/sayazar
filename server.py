#!/usr/bin/env python3
"""Sayazar Masjid website server. Uses only the Python standard library.

  python3 server.py                  start the website
  python3 server.py --set-password   choose the admin password

Website: http://localhost:8000      Admin: http://localhost:8000/admin
Optional environment variables: PORT, HOST, DATA_DIR.
"""
import datetime as dt
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "data"))
EVENTS_FILE = DATA_DIR / "events.json"
ADMIN_FILE = DATA_DIR / "admin.json"

# Only these files are ever served, so data/ and anything else here stays private
PAGES = {"/": "index.html", "/index.html": "index.html", "/admin": "admin.html"}
ICONS = {
    "/favicon.ico": ("favicon.ico", "image/x-icon"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
    "/apple-touch-icon.png": ("apple-touch-icon.png", "image/png"),
    "/favicon-512.png": ("favicon-512.png", "image/png"),
}

MAX_BODY = 16 * 1024
SESSION_HOURS = 12
PBKDF2_ROUNDS = 300_000
MAX_LOGIN_FAILURES = 5
LOCKOUT_SECONDS = 60
FIELD_LIMITS = {"title": 120, "titleUr": 120, "location": 120, "details": 1000}

lock = threading.Lock()
sessions = {}  # token -> expiry time
login_failures = 0
locked_until = 0.0


def write_json(path, value):
    """Replace the file in one step so a crash can't leave it half written."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def read_events():
    if not EVENTS_FILE.exists():
        return []
    return json.loads(EVENTS_FILE.read_text(encoding="utf-8"))


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ROUNDS).hex()


def save_password(password):
    salt = secrets.token_hex(16)
    write_json(ADMIN_FILE, {"salt": salt, "hash": hash_password(password, salt)})
    os.chmod(ADMIN_FILE, 0o600)


def check_password(password):
    admin = json.loads(ADMIN_FILE.read_text(encoding="utf-8"))
    return hmac.compare_digest(hash_password(password, admin["salt"]), admin["hash"])


def clean_event(body):
    """Return (event, None) when valid, otherwise (None, message)."""
    if not isinstance(body, dict):
        return None, "Invalid event."
    event = {}
    for field, limit in FIELD_LIMITS.items():
        value = body.get(field, "")
        if not isinstance(value, str):
            return None, "Invalid %s." % field
        value = value.strip()
        if len(value) > limit:
            return None, "%s is too long (limit %d characters)." % (field, limit)
        event[field] = value
    if not event["title"]:
        return None, "Please enter a title."
    date, time_ = body.get("date", ""), body.get("time", "")
    try:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
            raise ValueError
        dt.date.fromisoformat(date)
    except (TypeError, ValueError):
        return None, "Please choose a valid date."
    if time_ and not (isinstance(time_, str) and re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", time_)):
        return None, "Please choose a valid time."
    event["date"], event["time"] = date, time_
    event["showInBanner"] = bool(body.get("showInBanner", True))
    return event, None


class Handler(BaseHTTPRequestHandler):
    server_version = "Sayazar"
    sys_version = ""

    def send_bytes(self, status, data, content_type, headers=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def send_api(self, status, value, headers=()):
        data = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_bytes(status, data, "application/json; charset=utf-8",
                        [("Cache-Control", "no-store"), *headers])

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return None
        if not 0 < length <= MAX_BODY or "application/json" not in self.headers.get("Content-Type", ""):
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None

    def session_token(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        return cookie["sayazar_admin"].value if "sayazar_admin" in cookie else ""

    def signed_in(self):
        token = self.session_token()
        with lock:
            expiry = sessions.get(token)
            if expiry is None:
                return False
            if expiry < time.time():
                del sessions[token]
                return False
        return True

    def cookie_header(self, token, max_age):
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
        return ("Set-Cookie", "sayazar_admin=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict%s"
                % (token, max_age, secure))

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/events":
            with lock:
                events = read_events()
            self.send_api(200, sorted(events, key=lambda e: (e["date"], e["time"])))
        elif path == "/api/session":
            self.send_api(200, {"signedIn": self.signed_in()})
        elif path in PAGES:
            data = (ROOT / PAGES[path]).read_bytes()
            self.send_bytes(200, data, "text/html; charset=utf-8", [("Cache-Control", "no-cache")])
        elif path in ICONS:
            name, content_type = ICONS[path]
            self.send_bytes(200, (ROOT / name).read_bytes(), content_type, [("Cache-Control", "max-age=86400")])
        else:
            self.send_bytes(404, b"Not found", "text/plain; charset=utf-8")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/login":
            self.login()
        elif path == "/api/logout":
            with lock:
                sessions.pop(self.session_token(), None)
            self.send_api(200, {"ok": True}, [self.cookie_header("", 0)])
        elif path == "/api/events":
            self.save_event(None)
        else:
            self.send_api(404, {"error": "Not found."})

    def do_PUT(self):
        match = re.fullmatch(r"/api/events/([a-f0-9]{16})", self.path)
        if match:
            self.save_event(match.group(1))
        else:
            self.send_api(404, {"error": "Not found."})

    def do_DELETE(self):
        match = re.fullmatch(r"/api/events/([a-f0-9]{16})", self.path)
        if not match:
            self.send_api(404, {"error": "Not found."})
        elif not self.signed_in():
            self.send_api(401, {"error": "Please sign in."})
        else:
            with lock:
                events = read_events()
                kept = [e for e in events if e["id"] != match.group(1)]
                write_json(EVENTS_FILE, kept)
            if len(kept) == len(events):
                self.send_api(404, {"error": "That event no longer exists."})
            else:
                self.send_api(200, {"ok": True})

    def login(self):
        global login_failures, locked_until
        body = self.read_body()
        password = body.get("password") if isinstance(body, dict) else None
        if not isinstance(password, str):
            self.send_api(400, {"error": "Please enter the password."})
            return
        with lock:
            if time.time() < locked_until:
                self.send_api(429, {"error": "Too many attempts. Please wait a minute and try again."})
                return
        if not check_password(password):
            with lock:
                login_failures += 1
                if login_failures >= MAX_LOGIN_FAILURES:
                    login_failures, locked_until = 0, time.time() + LOCKOUT_SECONDS
            self.send_api(401, {"error": "Incorrect password."})
            return
        token = secrets.token_urlsafe(32)
        with lock:
            login_failures = 0
            now = time.time()
            for key in [k for k, expiry in sessions.items() if expiry < now]:
                del sessions[key]
            sessions[token] = now + SESSION_HOURS * 3600
        self.send_api(200, {"ok": True}, [self.cookie_header(token, SESSION_HOURS * 3600)])

    def save_event(self, event_id):
        if not self.signed_in():
            self.send_api(401, {"error": "Please sign in."})
            return
        event, error = clean_event(self.read_body())
        if error:
            self.send_api(400, {"error": error})
            return
        with lock:
            events = read_events()
            if event_id is None:
                event["id"] = secrets.token_hex(8)
                events.append(event)
            else:
                event["id"] = event_id
                index = next((i for i, e in enumerate(events) if e["id"] == event_id), None)
                if index is None:
                    self.send_api(404, {"error": "That event no longer exists."})
                    return
                events[index] = event
            write_json(EVENTS_FILE, events)
        self.send_api(200, event)

    def log_message(self, fmt, *args):
        pass


def set_password():
    first = getpass.getpass("New admin password (at least 10 characters): ")
    if len(first) < 10:
        sys.exit("Password is too short. Nothing was changed.")
    if getpass.getpass("Type it again: ") != first:
        sys.exit("The passwords did not match. Nothing was changed.")
    save_password(first)
    print("Admin password saved. Restart the server if it is running.")


def main():
    if "--set-password" in sys.argv:
        set_password()
        return
    if not ADMIN_FILE.exists():
        password = secrets.token_urlsafe(12)
        save_password(password)
        print("\nFirst run: your admin password is  %s" % password)
        print("It is shown only once. Change it any time with: python3 server.py --set-password\n")
    if not EVENTS_FILE.exists():
        write_json(EVENTS_FILE, [])
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 8000))
    server = ThreadingHTTPServer((host, port), Handler)
    print("Website: http://localhost:%d" % port)
    print("Admin:   http://localhost:%d/admin" % port)
    print("Press Ctrl + C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
