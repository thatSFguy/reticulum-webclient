# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Scope Rule

**Never create, modify, or delete files outside this project directory (`reticulum-webclient/`).** Exception: may read files from the sibling `reticulum-*` projects for reference (see Sibling Projects below).

## Open-PR Check Rule

**Before starting any work of our own, check for open pull requests** (`gh pr list --state open`). Outside contributors open PRs against `master`; reviewing and integrating them first avoids building on a base that is about to change and avoids version-bump collisions.

- Review every PR line by line for security before merging — this app holds users' private keys. Look for exfiltration (new network destinations, `fetch`/`WebSocket`/`sendBeacon` targets), unsafe DOM sinks (`innerHTML` with peer- or file-supplied data), credential or key handling, and changes to CI workflows.
- Fork PRs from first-time contributors don't run CI until a maintainer approves them, so their "tests passed" claims are unverified. Integrate on a branch, open a PR so `verify.yml` runs, and merge with a merge commit (not squash) so GitHub records the original PRs as merged.
- Resolve their version bumps into a single bump per the Version Bump Rule.

## Version Bump Rule

**Every commit that ships user-facing changes (JS, HTML, CSS, or any file copied into `_site/` by the deploy workflow) must bump the patch version in `package.json`.** Bug fixes = patch bump (0.3.1 → 0.3.2). New features = minor bump (0.3.2 → 0.4.0). Breaking changes = major bump (0.4.x → 1.0.0). Docs-only, CI-only, tooling-only, and test-only commits do NOT require a bump.

CI (`.github/workflows/deploy.yml`) syncs the version badge in `index.html` from `package.json` on every deploy, so only `package.json` needs editing — don't hand-edit the `v?.?.?` tokens in HTML.

## Project Overview

Browser-based Reticulum messaging client — a static JavaScript web app that exchanges encrypted LXMF messages (including attachments) with Sideband/NomadNet/MeshChat users, and browses NomadNet pages (micron markup). Several bearers:

- **RNode LoRa modem** over Web Bluetooth or Web Serial (KISS framing)
- **rnsd daemon** over a WebSocket bridge (`tools/ws_bridge.go` / `.py`) to TCP transport nodes
- **Agnostic-LoRa-Net (ALN) mesh** over BLE (port of the mobile app's Kotlin stack)

No build step, no server, no framework — plain ES modules hosted on GitHub Pages. All protocol logic (identity, crypto, announces, Links, Resources) runs in the browser; the radio/daemon on the far side only sees encrypted packets.

The authoritative protocol reference is the sibling `reticulum-specifications/SPEC.md` — code comments cite it as `SPEC §…`.

## Architecture

### Module Layout

```
reticulum-webclient/
  index.html                — Single-page app UI
  flasher.html              — Repeater-firmware flasher + config console
  privacy.html              — Privacy notes for the live app
  hubs.json                 — Curated public TCP transport entrypoints
  css/style.css             — Dark theme
  js/
    app.js                  — UI controller + state management (the big one)
    — transports —
    ble-transport.js        — Web Bluetooth NUS connection + byte stream
    serial-transport.js     — Web Serial byte stream
    websocket-transport.js  — WS bridge byte stream (to rnsd TCP)
    rnsd-interface.js       — rnsd-over-WS interface wiring
    aln-interface.js/-router.js/-tunnel.js, nus-demux.js
                            — Agnostic-LoRa-Net BLE mesh (ports of the
                              mobile app's Kotlin, kept byte-for-byte)
    kiss.js, hdlc.js        — Frame encode/decode
    rnode.js                — RNode command layer (detect, config, CMD_DATA)
    dfu.js                  — Web-Serial DFU flasher
    — protocol —
    reticulum.js            — Packet header encode/decode, constants
    identity.js             — Ed25519/X25519 keypair, identity/dest hashes
    crypto.js               — ECDH + HKDF + Token encrypt/decrypt
    announce.js             — Build/parse/validate announces (+ §4.7 stamp trailer)
    stamps.js, stamp-worker.js
                            — Proof-of-work stamps (RNS/Stamps.py port: fractional
                              cost targets, LXMF workblocks, Web Worker search)
    sha256.js               — Sync SHA-256/HMAC/HKDF with resumable midstate
    lxmf.js                 — LXMF message pack/unpack + signature
    link.js                 — Links: handshake, session crypto, keepalive
    resource.js             — Resource transfers over Links (send + receive)
    nomadnet.js, micron.js  — NomadNet page requests + micron renderer
    propagation.js          — propagation-node /get wire-shape helpers (§5.8)
    known-destinations.js   — Well-known destination table
    transport-config.js     — Repeater config protocol (BLE GATT / Serial)
    transport-flasher-app.js— flasher.html controller
    store.js                — IndexedDB for identity, contacts, messages
    identity-backup.js      — Identity export/import JSON (+ display name)
    location-share.js       — One-shot, user-reviewed location into the draft
    reconnect.js            — WebSocket auto-reconnect (resume/network/refresh)
  lib/                      — Vendored libraries (see Dependencies)
  tools/                    — ws_bridge (Go + Python), RNS verify scripts,
                              web_sessions/ (optional nginx cookie-login example)
  tests/                    — roundtrip harness (Node) validated against
                              the Python RNS reference by run_tests.py
```

### Dependencies

All vendored into `lib/` (no CDN at runtime, no npm install needed):

| Library | Purpose |
|---------|---------|
| @noble/curves (`noble-curves-ed25519.js`) | Ed25519, X25519 |
| @msgpack/msgpack (`msgpack.js`) | LXMF payload serialization |
| `bz2.js` | Resource decompression |
| Leaflet (`leaflet.js`) | Node map view |
| qrcode-generator (`qrcode.js`) | Contact-card QR export |
| Web Crypto API | AES-CBC, HMAC-SHA256, HKDF, SHA-256 (browser native) |

### Platform Support

| Platform | Web Bluetooth | Web Serial | WebSocket | Works? |
|----------|--------------|------------|-----------|--------|
| Chrome/Edge/Brave Android | Yes | No | Yes | Primary target |
| Chrome/Edge Desktop | Yes | Yes | Yes | Works |
| Safari iOS | No | No | Yes | WS-bridge only (Apple blocks BLE/Serial) |
| Firefox | No | No | Yes | WS-bridge only |

## Implemented Protocol Surface

Everything from the original phased plan shipped long ago, plus a lot the plan deferred. In scope and working today:

- Announces (send/receive/validate, ratchet field, display names, path responses)
- **Announce stamps** (§4.7, RNS 1.6) — validate/strip the trailer and record the
  peer's link-request cost; generate our own destination stamp once (persisted)
- **Link-request stamps** (§6.1.1) — stamped ephemeral X25519 key when the destination
  announced a cost (falls back to unstamped on timeout); **stamped path requests**
  (§7.1, 64-byte form with ephemeral transport_id); inbound path? lengths per §7.2.1
- **LXMF stamps** (§5.7) — proof-of-work stamp on outbound messages/reactions to peers
  that announce a stamp cost; 16-byte ticket stamps when a peer gave us a ticket
  (fields[0x0C]); stamped-message message_id taken from the wire prefix (§5.6.1)
- Opportunistic LXMF send/receive with delivery proofs and retries
- **Ratchets** — encrypt to the peer's announced ratchet key; rotate our own
- **Links** — handshake, session crypto, LXMF-over-Link; link MTU negotiated per bearer
  (228 on LoRa-class, 500 otherwise); keepalive pings + stale watchdog (§6.7);
  verified link delivery proofs (§6.5)
- **Resources** — send and receive over Links (attachments, NomadNet pages, oversized
  REQUESTs); part size follows the link MTU (§10.2); ADV retransmit, re-advertisement
  tolerance, empty-hashmap (RNS 1.6) and HMU boundary handling
- NomadNet page browsing (micron renderer, forms, file downloads)
- Reactions (SPEC §5.9.8) and reply-to threading (SPEC §5.9.9), group-chat-relay compliant
- Path requests (§7.1/§7.2.6 leaf duties) and HEADER_2 originator conversion (§2.3)
- Contact cards (JSON, QR export/scan — byte-compatible with the mobile app)
- **Propagation-node retrieval** (§5.8.3) — sync offline messages via `/get` over an identified Link (LINKIDENTIFY §6.7.6); auto-sync on connect + every 15 min

## Deferred (Not In Scope)

- **Propagation-node submission** — the outbound `PROPAGATED` method (handing our own sends to a node for offline recipients); we only retrieve
- **Multi-hop transport** — full routing table (we are a leaf; the §2.3 HEADER_2 conversion + upstream transport_id is sufficient)
- **Inbound LXMF stamp enforcement / issuing tickets** — we announce no inbound
  stamp cost, so we neither validate peers' stamps nor hand out tickets
- **IFAC** — interface authentication (IFAC-flagged packets are rejected at parse)
- **GROUP destinations** — only SINGLE needed for point-to-point messaging
- **Multi-segment Resources** (> 1 MiB per segment)
- **Blackhole lists** (§12.7) — a transport-node feature (`publish_blackhole` /
  `blackhole_sources`); we only label `rnstransport.info.blackhole` announces
- **NomadNet partials and RRC rooms** — `p:` and `rrc` links are recognised (§11.6.3)
  and reported as unsupported instead of failing as malformed hashes

## Reticulum Protocol Quick Reference

### Packet Header (2 + 16 + 1 = 19 bytes minimum)
```
Byte 0 (flags):
  bits 7-6: header_type (0=HEADER_1, 1=HEADER_2)
  bit 5:    context_flag
  bit 4:    transport_type (0=broadcast, 1=transport)
  bits 3-2: destination_type (0=SINGLE, 1=GROUP, 2=PLAIN, 3=LINK)
  bits 1-0: packet_type (0=DATA, 1=ANNOUNCE, 2=LINKREQUEST, 3=PROOF)
Byte 1: hop count
Bytes 2-17: destination_hash (16 bytes)
Byte 18: context
Bytes 19+: data
```

### Constants
```
HEADER_1 = 0x00, HEADER_2 = 0x01
PACKET_DATA = 0x00, PACKET_ANNOUNCE = 0x01
DEST_SINGLE = 0x00, DEST_PLAIN = 0x02
TRUNCATED_HASHLENGTH = 16 bytes (128 bits)
NAME_HASH_LENGTH = 10 bytes (80 bits)
MTU = 500 bytes
```

## Sibling Projects

All siblings live under `/home/robw/projects/` (WSL):

- `reticulum-specifications/` — **`SPEC.md`, the authoritative protocol reference** cited throughout the code as `SPEC §…`. Runtime verifiers in its `tools/` lock claims against the Python RNS/LXMF reference.
- `reticulum-mobile-app/` — Kotlin app; the webclient mirrors its patterns (reaction palette, contact cards, ALN stack, group-chat relay routing).
- `reticulum-rnode/` — RNode firmware. `src/Ble.cpp` (BLE NUS), `src/Kiss.cpp` (KISS framing), `docs/dfu.js` (Web Serial DFU reference).
- `reticulum-lora-repeater/` — repeater/transport firmware (formerly `reticulum-lora-transport`) that `flasher.html` flashes and configures; protocol docs in its `docs/CONFIG_FORMAT.md` / `SERIAL_PROTOCOL.md`.
- `reticulum-group-chat/` — Go relay that re-originates group messages.
- `reticulum-client-interoperability/` — cross-client interop test notes.

Note: this WSL environment has **no Node.js** — `tests/*.mjs` can't run locally; rely on CI (`.github/workflows/verify.yml`). Python 3 is available.
