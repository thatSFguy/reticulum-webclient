# reticulum-lora-webclient

A browser-based Reticulum messaging client. Connects either directly to an [RNode](https://unsigned.io/rnode) LoRa modem over Web Bluetooth or Web Serial, or to any running Reticulum daemon (`rnsd`) over a WebSocket bridge, and exchanges encrypted LXMF messages with Sideband, NomadNet, MeshChat, and other Reticulum nodes anywhere on the network.

**Live app:** <https://thatsfguy.github.io/reticulum-lora-webclient/>

No build step, no framework, no bundler. Plain ES modules, loaded directly in the browser. The LoRa path runs entirely in the browser with no server. The TCP-via-WebSocket path needs a small bridge process to sit between the browser and an existing `rnsd` — pick either the prebuilt Go binary (no runtime to install) or the Python script (`tools/ws_bridge.py`, 130 lines).

## What it does

- Connects over any of three transports:
  - **Web Bluetooth** to an RNode (primary, Chrome/Edge/Brave on desktop and Android).
  - **Web Serial** to an RNode (desktop fallback).
  - **WebSocket** to a local or remote `rnsd` via a small bridge script (any modern browser, including Safari and Firefox).
- Configures the radio (frequency, bandwidth, spreading factor, coding rate, TX power) and turns it on — when talking to an RNode. When talking to `rnsd` over WebSocket there is no radio to configure; the network config lives on the daemon side.
- Generates and persists an Ed25519 / X25519 Reticulum identity in IndexedDB.
- Sends and receives Reticulum announces, auto-announces once at connect and every five minutes thereafter so relay identity caches stay warm.
- Encrypts and decrypts LXMF messages for **opportunistic single-packet delivery** using the standard Reticulum ECDH + HKDF + AES-256-CBC + HMAC-SHA256 scheme.
- Accepts incoming **Reticulum Link** handshakes and receives link-delivered LXMF messages. We act as link responder only — we validate LINKREQUESTs, emit LRPROOFs signed with our long-term Ed25519 key, receive LRRTT acknowledgements, decrypt inbound link traffic, and send per-packet PROOF receipts back so the sender does not retry forever. Sideband and MeshChat both round-trip cleanly this way.
- Filters the contact list by LXMF `name_hash` so announces from telemetry beacons, heartbeats, or other non-LXMF destinations do not pollute it. Contacts get an unread-count badge and a small delete button in the sidebar.
- Stores identity, contacts, and message history locally in IndexedDB. Messages are sorted in the conversation view by their IndexedDB insertion order, which keeps the timeline correct even when a clockless LoRa sender reports a nonsense timestamp. Nothing leaves your browser except over the radio link.

## What it does not do (yet)

- **Link initiation** — we are responder only. Messages we originate are always delivered opportunistically, which caps them at roughly 250–300 bytes of content.
- **Resources** — multi-packet transfers over an established link (needed for messages larger than a single packet). So no file or image attachments.
- **Ratchet emission on outbound announces** — we parse ratchet fields on inbound announces so the signature still validates, but we do not yet emit our own ratchet.
- **Outbound retry queue** — a send that fails has no "pending" or "failed" state in the UI yet.
- No propagation node / store-and-forward support. Both parties must be on the air at the same time.
- No multi-hop transport routing tables. Single-hop LoRa only.
- No IFAC, no LXMF stamps (we handle them on inbound, but do not emit them), no GROUP destinations.

See `CLAUDE.md` for the scope rules and implementation plan, and `docs/PROTOCOL_NOTES.md` for the detailed Reticulum / LXMF interop findings accumulated while building this client.

## Platform support

| Platform            | Web Bluetooth | Web Serial | WebSocket (TCP via bridge) | Works? |
|---------------------|---------------|------------|----------------------------|--------|
| Chrome Android      | Yes           | No         | Yes                        | Primary target |
| Chrome/Edge desktop | Yes           | Yes        | Yes                        | Dev and daily use |
| Brave desktop       | Yes           | Yes        | Yes                        | Works |
| Safari (iOS/macOS)  | No            | No         | Yes                        | WebSocket only |
| Firefox             | No            | No         | Yes                        | WebSocket only |

WebSocket works everywhere, which is the practical way to use the client from Safari, Firefox, or iOS. The LoRa-over-RNode paths require a browser that implements Web Bluetooth or Web Serial.

Web Bluetooth requires HTTPS (or `http://localhost`). GitHub Pages and any other HTTPS host are fine. WebSocket from an HTTPS page must be `wss://` (see the TCP section below for the mixed-content caveat).

## Running it

Because it is all static files with ES module imports, any HTTPS static host works. Locally:

```bash
# from the project root
python -m http.server 8000
```

Then open `http://localhost:8000/` in Chrome, Edge, or Brave. `localhost` is treated as a secure origin, so Web Bluetooth and Web Serial are both available without a certificate.

For a public deploy, push to `gh-pages` (or any static bucket) and visit the HTTPS URL directly. No build step.

## Using it

1. **Connect.** Click `Connect (BLE)` and pick your RNode from the Bluetooth chooser, or click `Connect (Serial)` and select the USB serial port, or click `Connect (WebSocket)` with a bridge URL to reach a remote `rnsd` (see the TCP section below). The webapp will detect the modem, read firmware version and battery, and auto-start the radio with the values in the collapsible Radio Configuration panel — or, on the WebSocket path, skip all radio config and go straight to the messaging UI.
2. **Set your display name** and click `Send Announce`. This broadcasts your identity and destination to the network so other Reticulum nodes can learn how to reach you. Your LXMF address is shown under `Your Identity`.
3. **Wait for announces.** When another node announces, it shows up in the contact list on the left.
4. **Open a conversation.** Click a contact to open the conversation view, type a message, and hit Enter. Incoming messages from that contact land in the same view.

Identity persists across reloads. `Export Identity` writes a JSON file containing your private keys; `New Identity` generates a fresh keypair (and will change your LXMF address).

## TCP (WebSocket) connection

The "Connect (WebSocket)" option lets the web client join a Reticulum network through an existing `rnsd` instead of talking to a local LoRa radio. This is how you use the client from **Safari, Firefox, or iOS** (none of which have Web Bluetooth or Web Serial), how you use it from a machine that has no RNode attached, and how you reach a wider Reticulum mesh that spans TCP, I2P, or another backbone configured on the daemon side.

### Architecture

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

### Step-by-step setup

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

**2a. Prebuilt Go binary (recommended).** Grab the latest from the [bridge releases page](https://github.com/thatSFguy/reticulum-lora-webclient/releases?q=bridge-v) and save it next to your other tools. Pick by platform:

- `ws_bridge-*-windows-amd64.exe` — Windows 10/11 64-bit
- `ws_bridge-*-linux-amd64` — Linux 64-bit
- `ws_bridge-*-darwin-arm64` — macOS Apple Silicon

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

You'll see `ws_bridge listening on ws://localhost:7878` (Go) or the equivalent two-line Python banner. That's the signal the bridge is up.

**Per-connection rnsd target — the practical difference between the two bridges:** the Go bridge accepts the rnsd `host:port` from the webapp via query parameters on every connection, so one running bridge can serve any number of webapp instances pointed at any number of different `rnsd`s without restart. The Python bridge ignores those query parameters and always uses its own `--rnsd-host`/`--rnsd-port` flags from startup; the same webapp UI works against either bridge.

**4. Open the web client** — either the live GitHub Pages URL or a local `python -m http.server 8000` copy — and hit **Connect (WebSocket)**. Two fields in the connect card:

- **WebSocket bridge URL** — defaults to `ws://localhost:7878`. Change only if your bridge runs elsewhere.
- **Reticulum daemon (host:port)** — the rnsd you want to reach. On a fresh install this is **prefilled with a public Reticulum hub picked at random** (the ↻ button rerolls to another, spreading new-user load across hubs instead of concentrating it on one), so you can just click Connect. Override it with your own daemon (e.g. `localhost:4242`) any time — a custom value sticks. Required by the Go bridge; ignored by the Python bridge but harmless to fill in.

Both fields persist across reloads (localStorage). The log panel will print `WebSocket connected` and `Connected to Reticulum network via WebSocket`; the messaging panel appears without any radio-config step.

**5. Announce yourself.** Enter a display name and click `Send Announce`. Within a second or two your announce should show up in any other Reticulum client connected to the same network — including Sideband and MeshChat if they are on the same backbone.

### Mixed-content caveat

If you load the web client from `https://thatsfguy.github.io/reticulum-lora-webclient/` and try to connect to `ws://localhost:7878`, the browser will refuse. Modern browsers block plain `ws://` connections from HTTPS pages as a mixed-content policy. Three ways around it:

1. **Load the web client locally, not from GitHub Pages.** `python -m http.server 8000` from the repo root and open `http://localhost:8000/`. Now `ws://localhost:7878` is same-origin in terms of scheme compatibility and the browser allows it. This is the fastest way to try the TCP path.

2. **Serve the bridge as `wss://` with a certificate the browser trusts.** With the Python bridge, edit `tools/ws_bridge.py` to wrap the `websockets.serve` call in an `ssl_context`. The Go binary doesn't currently have a built-in TLS flag — option 3 below is the right path for that. Either way, any cert works as long as the browser trusts it — letsencrypt, a self-signed cert you imported into the OS trust store, or a development cert from `mkcert`. Then update the URL field in the web client to `wss://your.domain:7878`.

3. **Use a reverse proxy.** Run nginx or caddy in front of the bridge with a TLS cert, terminating TLS and forwarding `wss://` to the plain bridge. This is the production story for anything exposed to the internet, and the recommended way to put TLS in front of the Go binary.

Option 1 is fine for one-machine testing. Option 3 is the right answer for anything you want to keep running.

### Security

**The browser owns your Reticulum identity.** Your Ed25519 and X25519 private keys live in IndexedDB in the browser where you are running the web client. The bridge and the `rnsd` never see them. If you expose the WebSocket bridge to the open internet without TLS, an attacker between you and the bridge can observe every encrypted Reticulum packet you send and receive, but cannot impersonate you or read your LXMF messages (both ends of the ECDH are protected inside the Reticulum protocol). That said, running plaintext WebSocket to a bridge is still a bad idea for general use; use `wss://` for anything beyond localhost.

**Public-facing `rnsd` instances** that accept TCP connections should probably require IFAC (interface access codes) or be tunneled through something with authentication. The bridge is a dumb forwarder — it will happily connect any WebSocket client to the `rnsd` it is configured to talk to. If you expose the bridge publicly without locking down the `rnsd`, anyone who can reach the WebSocket port can inject packets into your Reticulum network.

### Troubleshooting

- **"WebSocket error before open" immediately after clicking Connect.** The bridge is not running, or is listening on a different port, or the URL in the field is wrong. Verify with `curl -v http://localhost:7878/` — a running bridge will respond with an HTTP 400 (`WebSocket Upgrade Required`), which is good.
- **Connection opens then immediately closes, bridge logs `cannot reach rnsd`.** `rnsd` is not running, or its TCP interface is on a different port, or is bound to a different address than the bridge is trying to connect to. Check the `rnsd` logs for `Listening for TCP connections on …`.
- **Connected but no announces appear.** `rnsd` has no upstream network interface configured (only the TCP server interface, which is how the bridge reached it). Edit `~/.reticulum/config` to add a backbone interface that actually touches other nodes.
- **Announces appear but nobody can reach you.** Check that you have clicked `Send Announce` at least once, and that the log is showing `Periodic announce skipped` every 5 minutes without error. Relay identity caches do expire; that is why the periodic re-announce is mandatory.
- **Works on Chrome but not Safari.** You are probably loading the live GitHub Pages URL and running into the mixed-content block. Serve the static files locally (`python -m http.server 8000`) and try again.

## Architecture

All Reticulum protocol logic runs in the browser — identity, announce, encrypt/decrypt, LXMF, link handshake, retry queue, packet receipts. What changes between transports is only how the finished raw Reticulum packet gets from our browser out onto the network.

```
                                 ┌──► KISS ──► RNode fw ──► SX126x ──► LoRa RF   (BLE / Serial path)
                                 │
Browser (all protocol logic) ────┤
                                 │
                                 └──► HDLC ──► WebSocket ──► ws_bridge ──► rnsd ──► network  (WebSocket path)
```

The BLE / Serial path needs an RNode and gives you direct-to-LoRa messaging with no server. The WebSocket path needs `rnsd` and a small bridge script, but runs everywhere (including Safari, Firefox, iOS) and can reach any Reticulum network `rnsd` is connected to — LoRa via a local RNode, TCP backbones to public nodes, I2P, `AutoInterface` LAN discovery, whatever you configure on the daemon side.

## Module layout

```
reticulum-lora-webclient/
  index.html              Single-page app shell
  css/style.css           Dark theme

  js/
    ble-transport.js       Web Bluetooth NUS byte stream
    serial-transport.js    Web Serial byte stream
    websocket-transport.js WebSocket byte stream (for the TCP-via-bridge path)
    kiss.js                KISS frame encode/decode for the RNode path
    hdlc.js                HDLC frame encode/decode for the rnsd path
    rnode.js               RNode command layer (detect, configure, send/recv over KISS)
    rnsd-interface.js      Reticulum-direct interface over HDLC+WebSocket
                           (exposes the same shape as rnode.js so app.js doesn't branch)
    reticulum.js           Reticulum packet header encode/decode + constants
    identity.js            Ed25519 + X25519 keypair, identity hash, destination hash
    crypto.js              ECDH + HKDF + Token (AES-256-CBC + HMAC-SHA256)
    announce.js            Build, parse, and validate Reticulum announces
    link.js                Reticulum Link: responder validation, initiator handshake,
                           LRPROOF build/verify, link_id derivation, signalling encoding,
                           Token encrypt/decrypt over the derived link key
    lxmf.js                LXMF message pack/unpack + signature
    store.js               IndexedDB for identity, contacts, messages
    app.js                 UI controller and state management

  tools/                   Python RNS-based offline verifiers + ws_bridge.py
  tests/                   Level-2 round-trip harness against RNS reference
  docs/PROTOCOL_NOTES.md   Reticulum / LXMF interop findings reference
```

Libraries (`@noble/curves` for Ed25519/X25519 and `@msgpack/msgpack` for LXMF payload serialization) are loaded from a CDN via an import map in `index.html`. Web Crypto handles AES-CBC, HMAC, HKDF, and SHA-256 natively.

## Diagnostic tools and bridge

The `tools/` directory contains Python scripts that validate the web client's wire output against the Python RNS reference, plus the WebSocket bridge used by the TCP connection option.

- `tools/ws_bridge.py` — WebSocket↔TCP forwarder used by the "Connect (WebSocket)" option to reach a local or remote `rnsd`. Requires `pip install websockets`. See the **TCP (WebSocket) connection** section above for setup.
- `tools/identity_info.py` — dumps every derivable public piece of an exported identity (enc/sig/ratchet private and public bytes, identity hash, LXMF destination hash). Read-only, never touches network.
- `tools/verify_lrproof.py` — runs a self-test of RNS's Ed25519, X25519, and HKDF primitives, then verifies a real LRPROOF hex string (lifted from the web client log) against `Identity.validate` to prove our link-proof signatures are byte-compatible with upstream.
- `tools/verify_announce.py` — builds an `lxmf.delivery` announce with RNS using the web client's identity and runs it through `Identity.validate_announce`, proving our announce format is acceptable to the upstream reference.
- `tools/rns_responder.py` — runs Python RNS as a link responder against a supplied LINKREQUEST data field, captures the LRPROOF bytes RNS would emit, and prints them field by field for a byte-for-byte diff against the web client's own output.

All depend only on `rns`, `umsgpack`, and (for the bridge) `websockets` from pip.

## Development notes

- Open the browser DevTools console to see stack traces. The in-page log shows a terse one-line error, but the full trace only lives in the console.
- The webapp listens for `error` and `unhandledrejection` on `window` and mirrors the message into the log, so uncaught errors from async handlers still show up.
- `store.js` uses a single IndexedDB database named `reticulum-webclient` with object stores for `identity`, `contacts`, and `messages`. To wipe local state, open DevTools then Application then Storage then Clear site data.
- The KISS parser accumulates bytes across BLE notifications and emits complete frames on FEND boundaries. BLE splits frames at arbitrary points, so any per-notification framing assumption will break.
- Reticulum destination hashes are computed with the identity hexhash **outside** the name hash input, matching upstream `Destination.hash(identity, app_name, *aspects)`. The hexhash appears only in the human-readable `Destination.name`, never in on-wire hashes.
- LRPROOF packets have a special framing exception in upstream `Packet::pack`: the 16-byte destination slot of the header carries the link_id instead of the SINGLE destination's hash, and the flag byte's destination-type bits are hardcoded to `LINK` regardless of the destination the packet was constructed with. Our `buildPacket` matches this by accepting `destType` and `destHash` as explicit parameters rather than deriving them from a destination object.
- Every accepted CONTEXT_NONE data packet on an established link gets an immediate PROOF packet sent back, carrying the 32-byte SHA-256 of the received packet's hashable part plus an Ed25519 signature of that hash. Without this packet receipt, the sender's delivery-receipt timeout fires and it retries on a fresh link, producing a "same message keeps arriving" loop.
- Periodic re-announcement is mandatory for inbound link delivery, not cosmetic. Relays validate inbound LRPROOFs by looking up the responder's identity in their own `Identity.known_destinations` cache, and that cache gets GC'd — without a periodic refresh the LRPROOF is dropped at the relay before ever reaching the initiator. See `docs/PROTOCOL_NOTES.md` §14 for detail.
- See `docs/PROTOCOL_NOTES.md` for the full set of protocol-layer findings, including the destination hash formula, Web Crypto AES-CBC auto-padding gotcha, LXMF wire format differences between opportunistic and link delivery, stamp handling for signature verification, and the clockless-sender timestamp workaround.

## Security and trust model

All Reticulum protocol work — identity generation, ECDH key exchange, AES-256-CBC encryption, HMAC authentication, Ed25519 signing, LXMF message packing — runs inside your browser (or the Android WebView). The radio or daemon on the other end of the transport only sees fully encrypted packets.

**What is protected:**

- **Message content** is end-to-end encrypted. Each LXMF message uses a fresh ephemeral X25519 key exchange, HKDF-SHA256 key derivation, and AES-256-CBC + HMAC-SHA256 (Reticulum's Token / modified Fernet construction). Neither the transport layer, relay nodes, nor the rnsd daemon can read your messages.
- **Delivery receipts** on link-delivered messages include an Ed25519 signature that is computationally unforgeable without the responder's private key.
- **Announce signatures** are Ed25519-signed over the full announce body including the destination hash, public key, name hash, random hash, ratchet (if present), and app data. Forging an announce for a destination you do not own the private key for is infeasible.

**What is NOT protected (known limitations):**

- **Private keys at rest** are stored unencrypted in the browser's IndexedDB. Anyone with access to your browser profile — browser extensions with matching host permissions, device backup tools, physical access to an unlocked device, or root access on Android — can extract them. The Export Identity file is likewise unencrypted JSON containing the complete signing and encryption private keys. Treat it like a password.
- **No forward secrecy.** The ratchet key is generated once at identity creation and is never rotated. If an attacker obtains your private key, they can decrypt previously captured messages. Full ratchet rotation is deferred to a future release.
- **BLE transport is cleartext at L2.** Web Bluetooth does not request BLE bonding, so the NUS link between your device and the RNode modem is not encrypted at the Bluetooth radio layer. An observer within Bluetooth range (~10 m) can see the encrypted Reticulum packets and their headers (destination hashes, packet types, sizes, timing) but cannot decrypt message content.
- **WebSocket `ws://` to remote hosts exposes packet headers.** When using the WebSocket transport to a non-localhost destination over `ws://` (not `wss://`), Reticulum packet headers are visible to network observers on the path. Message content remains end-to-end encrypted, but destination hashes, packet types, and timing metadata leak. The app shows a visible warning banner when a non-localhost `ws://` connection is active. Use `wss://` for remote connections if your bridge supports TLS.
- **Metadata.** Reticulum packet headers contain 16-byte destination hashes in cleartext by design. Any observer on the radio channel or transport path can correlate who is communicating with whom by watching destination hashes, even though they cannot read message content. Periodic announces broadcast your full 64-byte public key, display name, and destination hash to the mesh every five minutes. This is inherent to the Reticulum protocol, not specific to this client.
- **Map tiles.** The Nodes view loads map tiles from OpenStreetMap (`tile.openstreetmap.org`). The tile server sees your IP address and the geographic region you are viewing, though it does not see your Reticulum identity or messages.

**Recommendations for alpha testers:**

1. Do not run this on a device where untrusted browser extensions have access to your browsing data.
2. Use `wss://` (not `ws://`) for any WebSocket connection to a remote host.
3. Keep your Export Identity JSON file in a secure location (password manager, encrypted drive). Anyone who obtains it can impersonate you and decrypt your messages.
4. Understand that your display name and destination hash are broadcast to the mesh every five minutes. Do not use a display name that reveals information you want to keep private.

## Related projects

- [reticulum-rnode](https://github.com/thatSFguy/reticulum-rnode) — the RNode firmware this client talks to.
- [reticulum-lora-repeater](https://github.com/thatSFguy/reticulum-lora-repeater) — a repeater node built on the same LoRa stack. Its `docs/RATCHET_PROTOCOL.md` is the canonical reference for how Reticulum 0.7+ announces are laid out on the wire.
- [markqvist/Reticulum](https://github.com/markqvist/Reticulum) — upstream Python Reticulum.
- [markqvist/LXMF](https://github.com/markqvist/LXMF) — upstream LXMF message format.
