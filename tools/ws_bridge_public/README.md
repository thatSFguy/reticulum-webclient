# ws_bridge_public — hardened public WebSocket→TCP bridge

A locked-down variant of `tools/ws_bridge.go` meant to be hosted on a
public server (e.g. michmesh.net) so browser clients that can't run a
local bridge (Safari/iOS/Firefox users, or anyone without a local rnsd)
can reach a Reticulum network.

It is a **separate program** from `ws_bridge.go`. The plain bridge dials
whatever host:port the client asks for — convenient on localhost, but an
open TCP proxy / SSRF relay if exposed. This one never does that.

## Why it's safe to expose

- **No open-proxy / SSRF.** It refuses to start unless you either pin one
  rnsd (`-target`) or whitelist a fixed set (`-allow`). Clients can never
  make it dial an arbitrary host, so it can't be abused to reach your
  server's localhost services, cloud metadata (`169.254.169.254`), or the
  rest of the internet.
- **Concurrency caps** — global (`-max-conns`) and per-IP
  (`-max-conns-per-ip`).
- **Per-connection byte cap** (`-max-bytes`) and **idle timeout**
  (`-idle-timeout`).
- **IP/CIDR blocklist** (`-blocklist`), hot-reloadable with `SIGHUP`.
- **Origin allow-list** (`-allowed-origins`, defaults to the official web
  client) and an optional **shared-secret token** (`-token`).
- **Frame-size limit** (`-max-frame`) + HTTP header read timeout
  (slowloris mitigation).
- Binds to **127.0.0.1 by default** — run it behind a TLS reverse proxy.

Message content is always end-to-end encrypted in the browser; this
bridge only copies bytes. These controls protect the **host**, not
message confidentiality (which never depended on the bridge).

## Build

```bash
cd tools
go build -trimpath -ldflags="-s -w" -o ws_bridge_public ./ws_bridge_public
```

No cgo, no extra modules (reuses `tools/go.mod`'s `gorilla/websocket`).
Cross-compiles like the other bridge (`GOOS=linux/darwin/windows`).

## Recommended deployment (michmesh.net)

rnsd running locally with a `TCPServerInterface` on `127.0.0.1:4242`, the
bridge bound to localhost, and Caddy terminating TLS in front:

```bash
ws_bridge_public \
  -target 127.0.0.1:4242 \
  -trust-proxy \
  -max-conns 512 \
  -max-conns-per-ip 8 \
  -max-bytes 209715200 \
  -idle-timeout 15m \
  -blocklist /etc/ws_bridge/blocklist.txt
```

Only the proxy is internet-facing; the bridge port (7878) stays on
localhost. Open **443 only** in the firewall.

### Caddy (automatic TLS → wss://)

```caddy
bridge.michmesh.net {
    reverse_proxy 127.0.0.1:7878
}
```

Caddy provisions a certificate automatically and forwards the WebSocket
upgrade. It also sets `X-Forwarded-For`, which is why the bridge is run
with `-trust-proxy` (so per-IP caps and the blocklist see the real client
IP, not `127.0.0.1`). Web client users then put
`wss://bridge.michmesh.net` in the **WebSocket bridge URL** field. Because
the target is pinned, the **Reticulum daemon (host:port)** field is
ignored — any value (e.g. the prefilled public hub) is fine.

### systemd unit (with sandboxing)

```ini
[Unit]
Description=Reticulum public WebSocket bridge
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ws_bridge_public -target 127.0.0.1:4242 -trust-proxy -max-bytes 209715200 -idle-timeout 15m -blocklist /etc/ws_bridge/blocklist.txt
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_INET6
ReadOnlyPaths=/etc/ws_bridge

[Install]
WantedBy=multi-user.target
```

`systemctl reload ws_bridge_public` re-reads the blocklist without
dropping connections.

## Blocklist file

One entry per line; IPs or CIDRs; `#` comments and blank lines ignored:

```
# abusive ranges
203.0.113.0/24
198.51.100.7
2001:db8::/32
```

Edit it, then `kill -HUP <pid>` (or `systemctl reload`).

## Monitoring

`GET /healthz` returns `ok active=… total_conns=… total_bytes=…` for
uptime checks and dashboards.

## Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `-target host:port` | (none) | Pin the rnsd; client host/port ignored. **Set this.** |
| `-allow a:1,b:2` | (none) | Allowlist mode (only if `-target` is empty). |
| `-bind` | `127.0.0.1` | Bind address. Keep localhost; expose via the proxy. |
| `-port` | `7878` | Listen port. |
| `-max-conns` | `512` | Global concurrent-connection cap (0 = off). |
| `-max-conns-per-ip` | `8` | Per-IP concurrent cap (0 = off). |
| `-max-bytes` | `0` | Per-connection total byte cap (0 = off). |
| `-idle-timeout` | `0` | Close idle connections, e.g. `15m` (0 = off). |
| `-max-frame` | `1048576` | Max inbound WebSocket frame bytes (0 = off). |
| `-allowed-origins` | official web client | Comma-separated Origins, or `*`. |
| `-token` | (none) | Require `?token=…` on each connection. |
| `-trust-proxy` | `false` | Use `X-Forwarded-For` (set ONLY behind a trusted proxy). |
| `-blocklist FILE` | (none) | IP/CIDR blocklist, reload on SIGHUP. |

## Notes / further hardening you might layer on

- Origin checks stop casual cross-site browser abuse but can be spoofed by
  non-browser clients — pair with `-token` for a private bridge.
- Add **fail2ban** on the log (the `rejected:` / `closing:` lines) to ban
  noisy IPs into the blocklist automatically.
- Caddy/nginx can add **request rate limiting** in front for new-connection
  throttling beyond the concurrent caps here.
- Keep the pinned rnsd's own interface locked down (IFAC) if you don't want
  anonymous clients injecting into your mesh.
