# TCP (WebSocket) connection — full setup guide

The "Connect (WebSocket)" option lets the web client join a Reticulum network through an existing `rnsd` instead of talking to a local LoRa radio. This is how you use the client from **Safari, Firefox, or iOS** (none of which have Web Bluetooth or Web Serial), how you use it from a machine that has no RNode attached, and how you reach a wider Reticulum mesh that spans TCP, I2P, or another backbone configured on the daemon side.

## Architecture

Browsers cannot open raw TCP sockets — the security model only exposes HTTP, WebSocket, and WebTransport. So the web client's "TCP" option really speaks WebSocket to a small bridge script which sits in front of your `rnsd`'s TCP interface and copies bytes in both directions:

```
┌──────────────┐   WebSocket    ┌──────────────┐   TCP    ┌─────────┐   LoRa / I2P / TCP
│  Browser     │ ◄────────────► │ ws_bridge.py │ ◄──────► │  rnsd   │ ◄─────────────────►  Reticulum network
│  web client  │  (HDLC frames) │              │          │         │
└──────────────┘                └──────────────┘          └─────────┘
```

- The web client builds raw Reticulum packets the same way it does for the LoRa path, but frames them in **HDLC** (`0x7E` flag, `0x7D` escape) instead of KISS before handing them to the transport.
- The bridge process — either the **Go binary** (`ws_bridge.exe` on Windows, `ws_bridge` on Linux/macOS, prebuilt and attached to each `bridge-v*` GitHub release) or the **Python script** (`tools/ws_bridge.py`) — accepts WebSocket connections, opens a TCP connection to an `rnsd` running a `TCPServerInterface`, and forwards raw bytes in both directions without parsing any frames.
- `rnsd` receives HDLC frames from the bridge exactly the way it does from any other TCP peer — the bridge is indistinguishable on the wire from a local TCP client.

The Go binary is the default suggestion: ~3-4 MB, no runtime dependency, no `pip install`, instant start. The Python script is there as a no-build fallback if you already have Python and prefer not to download a binary.

Identity and all protocol work stays in the browser. `rnsd` is only acting as a transport — it does not own your Reticulum identity, does not see your private keys, and does not decrypt your messages. From `rnsd`'s point of view, the browser is a peer node on its TCP interface.

## Step-by-step setup

**1. Install and configure `rnsd`** on the machine that will run the bridge (can be the same machine as the browser, or a server on your network).

```bash
pip install rns
```

Edit `~/.reticulum/config` (create it if it does not exist) and add a TCP server interface:

```
[[RNS TCP Server Interface]]
    type = TCPServerInterface
    interface_enabled = True
    listen_ip = 0.0.0.0
    listen_port = 4242
```

Along with whatever other interfaces you want to use as your network backbone — another `TCPClientInterface` pointing at a public RNS node, an `I2PInterface`, an `AutoInterface` for LAN discovery, a `RNodeInterface` if you have an RNode plugged in directly, etc. See [upstream Reticulum documentation](https://markqvist.github.io/Reticulum/manual/interfaces.html) for options.

Start `rnsd`:

```bash
rnsd
```

Leave it running. You should see a line like `Listening for TCP connections on 0.0.0.0:4242`.

**2. Get the bridge.** Pick one of the two paths.

**2a. Prebuilt Go binary (recommended).** Easiest is the in-app **Connect via TCP → Download the bridge** button, which links to a fixed, version-independent URL on this site. You can also grab those directly:

- `https://thatsfguy.github.io/reticulum-webclient/bridge/ws_bridge-windows-amd64.exe` — Windows 10/11 64-bit
- `https://thatsfguy.github.io/reticulum-webclient/bridge/ws_bridge-linux-amd64` — Linux 64-bit
- `https://thatsfguy.github.io/reticulum-webclient/bridge/ws_bridge-darwin-arm64` — macOS Apple Silicon

These are mirrored on every deploy from the [bridge releases page](https://github.com/thatSFguy/reticulum-webclient/releases?q=bridge-v) (which also has the per-version filenames and `SHA256SUMS.txt`). The stable Pages URLs exist specifically so the download link doesn't change across versions — GitHub's own release-asset URLs rotate a signed token on every request, which breaks Windows SmartScreen "report as safe" (it can't attach to a URL that never recurs). If you report the Windows binary to <https://www.microsoft.com/wdsi/filesubmission>, use the fixed `…/bridge/ws_bridge-windows-amd64.exe` URL above, not the `release-assets.githubusercontent.com/…?sig=…` URL the browser redirects to. (The durable fix for the unsigned-binary warning is code signing; the stable URL just makes the report and per-URL reputation actually stick.)

Then verify the download against the published `SHA256SUMS.txt`:

```bash
sha256sum -c SHA256SUMS.txt          # Linux / macOS / Git Bash
certutil -hashfile ws_bridge-*.exe SHA256   # PowerShell on Windows
```

On Linux / macOS, `chmod +x ws_bridge-*` once after downloading.

**2b. Python script (alternative).** If you'd rather not download a binary:

```bash
pip install websockets
```

The Python bridge depends only on `websockets` (stdlib `asyncio` does the rest). `rns` is already installed from step 1.

**3. Start the bridge.** It listens on `ws://localhost:7878` by default. The Reticulum daemon target (`host:port`) is supplied by the webapp at connect time — the bridge itself takes no rnsd flags (Go bridge) or uses defaults (`localhost:4242`, Python bridge).

```bash
# Go binary (Windows)
ws_bridge.exe                          # listen on localhost:7878
ws_bridge.exe -bind 0.0.0.0 -port 7878 # LAN-visible, custom port

# Go binary (Linux / macOS)
./ws_bridge-*-linux-amd64              # same defaults

# Python script
python tools/ws_bridge.py
python tools/ws_bridge.py --ws-host 0.0.0.0 --ws-port 7878 --rnsd-host 10.0.0.5 --rnsd-port 4242
```

The **Go bridge** clears the terminal and shows a live status screen — version, listen address, each connected client (browser, rnsd target, bytes up/down), total throughput, and links to the webapp/source. Run it with `-plain` to keep the old scrolling log instead (for running as a service or when output is redirected). The **Python bridge** prints a two-line banner. Either way, a running bridge is the signal you can connect.

**Per-connection rnsd target — the practical difference between the two bridges:** the Go bridge accepts the rnsd `host:port` from the webapp via query parameters on every connection, so one running bridge can serve any number of webapp instances pointed at any number of different `rnsd`s without restart. The Python bridge ignores those query parameters and always uses its own `--rnsd-host`/`--rnsd-port` flags from startup; the same webapp UI works against either bridge.

**4. Open the web client** — either the live GitHub Pages URL or a local `python -m http.server 8000` copy — and hit **Connect (WebSocket)**. Two fields in the connect card:

- **WebSocket bridge URL** — defaults to `ws://localhost:7878`. Change only if your bridge runs elsewhere.
- **Reticulum daemon (host:port)** — the rnsd you want to reach. On a fresh install this is **prefilled with a public Reticulum hub picked at random** (the ↻ button rerolls to another, spreading new-user load across hubs instead of concentrating it on one), so you can just click Connect. Override it with your own daemon (e.g. `localhost:4242`) any time — a custom value sticks. Required by the Go bridge; ignored by the Python bridge but harmless to fill in.

Both fields persist across reloads (localStorage). The log panel will print `WebSocket connected` and `Connected to Reticulum network via WebSocket`; the messaging panel appears without any radio-config step.

**5. Announce yourself.** Enter a display name and click `Send Announce`. Within a second or two your announce should show up in any other Reticulum client connected to the same network — including Sideband and MeshChat if they are on the same backbone.

## Mixed-content caveat

If you load the web client from `https://thatsfguy.github.io/reticulum-webclient/` and try to connect to `ws://localhost:7878`, the browser will refuse. Modern browsers block plain `ws://` connections from HTTPS pages as a mixed-content policy. Three ways around it:

1. **Load the web client locally, not from GitHub Pages.** `python -m http.server 8000` from the repo root and open `http://localhost:8000/`. Now `ws://localhost:7878` is same-origin in terms of scheme compatibility and the browser allows it. This is the fastest way to try the TCP path.

2. **Serve the bridge as `wss://` with a certificate the browser trusts.** With the Python bridge, edit `tools/ws_bridge.py` to wrap the `websockets.serve` call in an `ssl_context`. The Go binary doesn't currently have a built-in TLS flag — option 3 below is the right path for that. Either way, any cert works as long as the browser trusts it — letsencrypt, a self-signed cert you imported into the OS trust store, or a development cert from `mkcert`. Then update the URL field in the web client to `wss://your.domain:7878`.

3. **Use a reverse proxy.** Run nginx or caddy in front of the bridge with a TLS cert, terminating TLS and forwarding `wss://` to the plain bridge. This is the production story for anything exposed to the internet, and the recommended way to put TLS in front of the Go binary.

Option 1 is fine for one-machine testing. Option 3 is the right answer for anything you want to keep running.

## Security

**The browser owns your Reticulum identity.** Your Ed25519 and X25519 private keys live in IndexedDB in the browser where you are running the web client. The bridge and the `rnsd` never see them. If you expose the WebSocket bridge to the open internet without TLS, an attacker between you and the bridge can observe every encrypted Reticulum packet you send and receive, but cannot impersonate you or read your LXMF messages (both ends of the ECDH are protected inside the Reticulum protocol). That said, running plaintext WebSocket to a bridge is still a bad idea for general use; use `wss://` for anything beyond localhost.

**Public-facing `rnsd` instances** that accept TCP connections should probably require IFAC (interface access codes) or be tunneled through something with authentication. The bridge is a dumb forwarder — it will happily connect any WebSocket client to the `rnsd` it is configured to talk to. If you expose the bridge publicly without locking down the `rnsd`, anyone who can reach the WebSocket port can inject packets into your Reticulum network.

## Troubleshooting

- **"WebSocket error before open" immediately after clicking Connect.** The bridge is not running, or is listening on a different port, or the URL in the field is wrong. Verify with `curl -v http://localhost:7878/` — a running bridge will respond with an HTTP 400 (`WebSocket Upgrade Required`), which is good.
- **Connection opens then immediately closes, bridge logs `cannot reach rnsd`.** `rnsd` is not running, or its TCP interface is on a different port, or is bound to a different address than the bridge is trying to connect to. Check the `rnsd` logs for `Listening for TCP connections on …`.
- **Connected but no announces appear.** `rnsd` has no upstream network interface configured (only the TCP server interface, which is how the bridge reached it). Edit `~/.reticulum/config` to add a backbone interface that actually touches other nodes.
- **Announces appear but nobody can reach you.** Check that you have clicked `Send Announce` at least once, and that the log is showing `Periodic announce skipped` every 5 minutes without error. Relay identity caches do expire; that is why the periodic re-announce is mandatory.
- **Works on Chrome but not Safari.** You are probably loading the live GitHub Pages URL and running into the mixed-content block. Serve the static files locally (`python -m http.server 8000`) and try again.
