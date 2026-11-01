# Optional remembered login for a private WebSocket bridge

This is an **opt-in, self-hosted Linux/Nginx example**, not a requirement for the
GitHub Pages app. It solves a mobile-browser problem: iOS suspends WebSockets
while locked, and some browsers discard their HTTP Basic authentication cache.
Repeated WebSocket handshakes can then repeatedly prompt for credentials.

Nginx performs Basic Auth **only at sign-in**. The Python standard-library
service issues a seven-day opaque session cookie, and Nginx `auth_request`
checks it for both the app and WebSocket upgrades. No username/password is
stored in JavaScript, localStorage, URLs or the cookie. This does not keep iOS
running in the background or implement WebSocket reconnection itself.

## Security properties

- A `__Host-` cookie with `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`,
  `Max-Age=604800`, and **no Domain attribute**.
- Random 256-bit tokens. SQLite stores only their SHA-256 digests, username,
  credential fingerprint and expiry; never plaintext session tokens.
- Expiry is fixed at seven days from login, not extended on each request.
- Logout revokes the server-side session and deletes the browser cookie.
  Logging in again rotates any supplied old session.
- Sign-in/logout require same-origin POSTs. Missing or foreign Origin is rejected.
- The auth helper listens only on a private Unix socket, not a public TCP port.
  Only Nginx and the service account must be able to access that socket.
- Nginx sets `X-Authenticated-User` from its verified `$remote_user`, overwriting
  client input. Never expose the helper directly or forward a client-supplied
  authenticated username.
- Authorization and cookies are removed before proxying to the bridge. The
  access-log example excludes request headers and query strings.
- Failure of the auth helper fails closed. The bridge remains loopback-only.

## Deployment outline

1. Confirm Nginx has `--with-http_auth_request_module`. Obtain a valid TLS
   certificate for **your own hostname** using your existing certificate setup.
   Preserve unrelated virtual hosts and HTTP/ACME configuration.
2. Set up the bridge separately with listener `127.0.0.1:7878` and a fixed,
   operator-configured local RNS destination. For the bundled Python bridge,
   use `--ws-host 127.0.0.1 --rnsd-host 127.0.0.1 --rnsd-port 4242`.
   Never expose port 7878 publicly or enable client-selected TCP destinations.
   Enforce WebSocket message-size limits in the bridge itself; Nginx's
   `client_max_body_size` does not limit frames after an upgrade.
3. Reuse an existing protected htpasswd file, or run `htpasswd -cB
   /etc/nginx/.rns-users YOUR_USERNAME` interactively. The example assumes
   `root:www-data` ownership and mode `0640`. Do not pass passwords as CLI
   arguments or include them in logs.
4. Install `rns_web_auth.py` as `/usr/local/libexec/rns_web_auth.py`, owned by
   root and not writable by the service account. It needs Python 3 and SQLite
   from the standard library, not the Reticulum virtual environment.
5. Adapt `rns-web-auth.service.example` before installing it. Choose an existing
   unprivileged account (`reticulum` in the example) and Nginx's actual group
   (`www-data` on Debian). Set `RNS_WEB_ORIGIN` to the exact HTTPS origin, without
   a trailing slash, matching the Nginx Origin checks. `LoadCredential` requires
   a systemd version that supports it (tested with systemd 252).
6. Copy `login.html` into the webclient's static root. Adapt every hostname,
   TLS path and web root in `nginx.conf.example`. The file belongs in Nginx's
   HTTP context; do not replace the main nginx.conf or unrelated sites.
7. Start the auth service and confirm `/run/rns-web-auth/auth.sock` is
   `reticulum:www-data`, mode `0660`, under a `0750` directory. The service uses
   a private `0700` state directory and `0600` SQLite database. Then run
   `nginx -t` and reload Nginx **only if validation succeeds**.

The service intentionally has a larger accept backlog for the concurrent
module requests made on initial app load. State survives service restarts.
`ProtectHome=true` prevents it from accessing Reticulum identities/messages.

## Client behavior and logout

The ordinary HTTPS page initially shows a Sign in button. That same-origin
form invokes Nginx's existing Basic login prompt and returns to the app with
the persistent cookie. Browser WebSockets send the cookie automatically;
there are no credentials in the WebSocket URL. Clearing cookies, private
browsing, expiry or explicit logout can still require another login.

Add this form to your deployment's settings page if you want a sign-out button:

```html
<form action="/auth/logout" method="post"><button>Sign out</button></form>
```

A client with auto-reconnect should also clear its remembered connection
intent when this form is submitted. To detect expiry without triggering any
Basic dialog, GET `/auth/status` with same-origin credentials: it returns JSON
and status `200` or `401`, **without WWW-Authenticate**. Pause reconnect attempts
on `401` and offer an explicit form POST to `/auth/login`.

Signing out revokes the session, not a password saved by the browser or its
password manager. Existing upgraded WebSockets should be closed by the client
on logout; authentication is checked at the next handshake, not every frame.

## Operations and verification

- Restart the auth service after changing the htpasswd file: systemd credentials
  are snapshotted at service start. The loaded credential fingerprint then
  invalidates sessions created with an older password, or for removed users.
- To invalidate every session, stop the service, remove **only its session
  database**, then restart it. This never affects RNS/LXMF identities/messages.
- Protect session-database backups like authentication data, even though stored
  tokens are hashed. Never print cookies or Authorization headers in diagnostics.
- Test initial login and a fresh browser context carrying only the cookie:
  both HTTPS and WSS should work without Basic credentials in that context.
- Verify unauthenticated status/upgrade requests are denied, malformed cookies
  fail, foreign-origin POSTs/upgrades are rejected, logout prevents token replay,
  and a normal page reload retains the session.

Run the eight dependency-free tests with:

```sh
python3 -m unittest discover -s tools/web_sessions -p 'test_*.py' -v
```

The implementation was exercised with Nginx 1.22, Python 3.11, systemd 252 and
Chromium, including a browser context without an HTTP Basic credential cache.
Real iPhone Brave/Safari lock-screen behavior still requires device testing.
