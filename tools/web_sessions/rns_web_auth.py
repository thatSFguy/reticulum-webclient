#!/usr/bin/python3
"""Private Unix-socket session service. Nginx alone performs Basic login."""
import hashlib
from contextlib import contextmanager
import http.cookies
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import socketserver
import socket as sockets
import sqlite3
import time

COOKIE = '__Host-rns_session'
TTL = 7 * 24 * 60 * 60
ORIGIN = os.environ.get('RNS_WEB_ORIGIN')


class Sessions:
    def __init__(self, database, users):
        self.database = str(database)
        self.users = users
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, credential TEXT NOT NULL, expires INTEGER NOT NULL)')
        os.chmod(self.database, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def credential(self, username):
        value = self.users.get(username)
        return hashlib.sha256(value.encode()).hexdigest() if value else None

    def issue(self, username, old_token=None, now=None):
        credential = self.credential(username)
        if credential is None:
            raise ValueError('Unknown authenticated user')
        now = int(time.time() if now is None else now)
        token = secrets.token_urlsafe(32)
        expires = now + TTL
        with self.connect() as db:
            db.execute('DELETE FROM sessions WHERE expires <= ?', (now,))
            if old_token:
                db.execute('DELETE FROM sessions WHERE token_hash = ?', (self.digest(old_token),))
            db.execute('INSERT INTO sessions VALUES (?, ?, ?, ?)', (self.digest(token), username, credential, expires))
        return token, expires

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def verify(self, token, now=None):
        if not token or not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            return None
        with self.connect() as db:
            row = db.execute('SELECT username, credential, expires FROM sessions WHERE token_hash = ?', (self.digest(token),)).fetchone()
        if not row or row[2] <= (time.time() if now is None else now) or row[1] != self.credential(row[0]):
            return None
        return {'username': row[0], 'expiresAt': row[2]}

    def revoke(self, token):
        if token:
            with self.connect() as db:
                db.execute('DELETE FROM sessions WHERE token_hash = ?', (self.digest(token),))


def read_cookie(header):
    if not header or len(header) > 8192:
        return None
    try:
        cookies = http.cookies.SimpleCookie()
        cookies.load(header)
        return cookies[COOKIE].value if COOKIE in cookies else None
    except http.cookies.CookieError:
        return None


def cookie_header(token='', max_age=TTL):
    return f'{COOKIE}={token}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Strict'


class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *args):
        pass  # Never log cookies, credentials, headers or request URLs.

    def reply(self, status, data=None, headers=None):
        body = json.dumps(data).encode() if data is not None else b''
        self.send_response(status)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        if data is not None:
            self.send_header('Content-Type', 'application/json')
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path not in ['/verify', '/status']:
            self.reply(404)
            return
        session = self.server.sessions.verify(read_cookie(self.headers.get('Cookie')))
        if self.path == '/verify':
            self.reply(204 if session else 401)
        else:
            self.reply(200 if session else 401, {'authenticated': bool(session), 'expiresAt': session['expiresAt'] if session else None})

    def do_POST(self):
        if not ORIGIN or self.headers.get('Origin') != ORIGIN:
            self.reply(403)
            return
        token = read_cookie(self.headers.get('Cookie'))
        if self.path == '/issue':
            # The socket is restricted to Nginx's group. Nginx overwrites this
            # header with $remote_user only after successful Basic Auth.
            username = self.headers.get('X-Authenticated-User', '')
            try:
                token, _ = self.server.sessions.issue(username, old_token=token)
            except ValueError:
                self.reply(403)
                return
            self.reply(303, headers={'Set-Cookie': cookie_header(token), 'Location': '/'})
        elif self.path == '/logout':
            self.server.sessions.revoke(token)
            self.reply(303, headers={'Set-Cookie': cookie_header(max_age=0), 'Location': '/'})
        else:
            self.reply(404)


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    # A browser requests many ES modules concurrently on first load.
    request_queue_size = 256


def main():
    os.umask(0o077)
    credentials = Path(os.environ['CREDENTIALS_DIRECTORY']) / 'users'
    users = dict(line.split(':', 1) for line in credentials.read_text().splitlines() if ':' in line)
    sessions = Sessions(Path(os.environ.get('STATE_DIRECTORY', '/var/lib/rns-web-auth')) / 'sessions.sqlite3', users)
    socket = Path(os.environ.get('RUNTIME_DIRECTORY', '/run/rns-web-auth')) / 'auth.sock'
    socket.unlink(missing_ok=True)
    with Server(str(socket), Handler) as server:
        server.sessions = sessions
        os.chmod(socket, 0o660)
        notify = os.environ.get('NOTIFY_SOCKET')
        if notify:
            address = '\0' + notify[1:] if notify.startswith('@') else notify
            with sockets.socket(sockets.AF_UNIX, sockets.SOCK_DGRAM) as notifier:
                notifier.sendto(b'READY=1', address)
        server.serve_forever()


if __name__ == '__main__':
    main()
