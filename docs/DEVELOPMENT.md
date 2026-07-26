# Development guide

For end-user setup, see the [README](../README.md). This file covers running the app from source, the architecture, the module layout, the diagnostic tooling, and the hard-won implementation notes.

## Running from source

Because it is all static files with ES module imports, any HTTPS static host works. Locally:

```bash
# from the project root
python -m http.server 8000
```

Then open `http://localhost:8000/` in Chrome, Edge, or Brave. `localhost` is treated as a secure origin, so Web Bluetooth and Web Serial are both available without a certificate.

For a public deploy, push to `gh-pages` (or any static bucket) and visit the HTTPS URL directly. No build step.

## Architecture

All Reticulum protocol logic runs in the browser — identity, announce, encrypt/decrypt, LXMF, link handshake, retry queue, packet receipts. What changes between transports is only how the finished raw Reticulum packet gets from our browser out onto the network.

```
                                 ┌──► KISS ──► RNode fw ──► SX126x ──► LoRa RF   (BLE / Serial path)
                                 │
Browser (all protocol logic) ────┤
                                 │
                                 └──► HDLC ──► WebSocket ──► ws_bridge ──► rnsd ──► network  (WebSocket path)
```

The BLE / Serial path needs an RNode and gives you direct-to-LoRa messaging with no server. The WebSocket path needs `rnsd` and a small bridge script (see [TCP-BRIDGE.md](TCP-BRIDGE.md)), but runs everywhere (including Safari, Firefox, iOS) and can reach any Reticulum network `rnsd` is connected to — LoRa via a local RNode, TCP backbones to public nodes, I2P, `AutoInterface` LAN discovery, whatever you configure on the daemon side.

## Module layout

```
reticulum-webclient/
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
    aln-interface.js       Agnostic-LoRa-Net BLE mesh bearer (with aln-router.js,
                           aln-tunnel.js, nus-demux.js — ports of the mobile app's Kotlin)
    reticulum.js           Reticulum packet header encode/decode + constants
    identity.js            Ed25519 + X25519 keypair, identity hash, destination hash, ratchet
    crypto.js              ECDH + HKDF + Token (AES-256-CBC + HMAC-SHA256)
    announce.js            Build, parse, and validate Reticulum announces (incl. ratchet)
    link.js                Reticulum Link: responder validation, initiator handshake,
                           LRPROOF build/verify, link_id derivation, signalling encoding,
                           Token encrypt/decrypt over the derived link key
    resource.js            Resource transfer (multi-packet): send + receive, proofs
                           (attachments, large messages, NomadNet pages/files)
    lxmf.js                LXMF message pack/unpack + signature
    nomadnet.js            NomadNet REQUEST/RESPONSE protocol + link-target parsing
    micron.js              Micron markup → HTML (headings, styling, links, fields, tables)
    known-destinations.js  Well-known destination hash labels
    store.js               IndexedDB for identity, contacts, messages, nodes, bookmarks
    app.js                 UI controller and state management
    (transport-config.js, transport-flasher-app.js, dfu.js power the repeater flasher page)

  lib/                     Vendored libraries (@noble/curves, @msgpack/msgpack, bz2,
                           Leaflet, qrcode-generator) — no CDN at runtime
  hubs.json                Curated public RNS hubs prefilled into the TCP connect field
  tools/                   Go + Python WS bridges, Python RNS-based offline verifiers
  test/, tests/            In-browser self-test page + round-trip harness vs RNS reference
  docs/PROTOCOL_NOTES.md   Reticulum / LXMF interop findings reference
```

Web Crypto handles AES-CBC, HMAC, HKDF, and SHA-256 natively.

## Diagnostic tools and bridge

The `tools/` directory contains Python scripts that validate the web client's wire output against the Python RNS reference, plus the WebSocket bridge used by the TCP connection option.

- `tools/ws_bridge.go` — the WebSocket↔TCP forwarder for the "Connect (WebSocket)" option, shipped as prebuilt binaries on each `bridge-v*` release. Single CGO-free binary; shows a live status screen (`-plain` for plain logging). Per-connection rnsd target via query params, so one bridge serves many webapp instances. See [TCP-BRIDGE.md](TCP-BRIDGE.md).
- `tools/ws_bridge.py` — the same forwarder as a no-binary Python fallback. Requires `pip install websockets`; rnsd target via `--rnsd-host`/`--rnsd-port` flags.
- `tools/identity_info.py` — dumps every derivable public piece of an exported identity (enc/sig/ratchet private and public bytes, identity hash, LXMF destination hash). Read-only, never touches network.
- `tools/verify_lrproof.py` — runs a self-test of RNS's Ed25519, X25519, and HKDF primitives, then verifies a real LRPROOF hex string (lifted from the web client log) against `Identity.validate` to prove our link-proof signatures are byte-compatible with upstream.
- `tools/verify_announce.py` — builds an `lxmf.delivery` announce with RNS using the web client's identity and runs it through `Identity.validate_announce`, proving our announce format is acceptable to the upstream reference.
- `tools/rns_responder.py` — runs Python RNS as a link responder against a supplied LINKREQUEST data field, captures the LRPROOF bytes RNS would emit, and prints them field by field for a byte-for-byte diff against the web client's own output.

The Python verifiers and the Python bridge depend only on `rns`, `umsgpack`, and `websockets` from pip. The Go bridge has no runtime dependencies.

## Development notes

- Open the browser DevTools console to see stack traces. The in-page log shows a terse one-line error, but the full trace only lives in the console.
- The webapp listens for `error` and `unhandledrejection` on `window` and mirrors the message into the log, so uncaught errors from async handlers still show up.
- `store.js` uses a single IndexedDB database named `reticulum-webclient` with object stores for `identity`, `contacts`, `messages`, `nodes`, `bookmarks`, and `history`. To wipe local state, open DevTools then Application then Storage then Clear site data.
- The KISS parser accumulates bytes across BLE notifications and emits complete frames on FEND boundaries. BLE splits frames at arbitrary points, so any per-notification framing assumption will break.
- Reticulum destination hashes are computed with the identity hexhash **outside** the name hash input, matching upstream `Destination.hash(identity, app_name, *aspects)`. The hexhash appears only in the human-readable `Destination.name`, never in on-wire hashes.
- LRPROOF packets have a special framing exception in upstream `Packet::pack`: the 16-byte destination slot of the header carries the link_id instead of the SINGLE destination's hash, and the flag byte's destination-type bits are hardcoded to `LINK` regardless of the destination the packet was constructed with. Our `buildPacket` matches this by accepting `destType` and `destHash` as explicit parameters rather than deriving them from a destination object.
- Every accepted CONTEXT_NONE data packet on an established link gets an immediate PROOF packet sent back, carrying the 32-byte SHA-256 of the received packet's hashable part plus an Ed25519 signature of that hash. Without this packet receipt, the sender's delivery-receipt timeout fires and it retries on a fresh link, producing a "same message keeps arriving" loop.
- Periodic re-announcement is mandatory for inbound link delivery, not cosmetic. Relays validate inbound LRPROOFs by looking up the responder's identity in their own `Identity.known_destinations` cache, and that cache gets GC'd — without a periodic refresh the LRPROOF is dropped at the relay before ever reaching the initiator. See `docs/PROTOCOL_NOTES.md` §14 for detail.
- See `docs/PROTOCOL_NOTES.md` for the full set of protocol-layer findings, including the destination hash formula, Web Crypto AES-CBC auto-padding gotcha, LXMF wire format differences between opportunistic and link delivery, stamp handling for signature verification, and the clockless-sender timestamp workaround.
- `CLAUDE.md` holds the agent-facing scope rules, the version-bump rule, and the implemented-protocol-surface summary.
