# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Scope Rule

**Never create, modify, or delete files outside this project directory (`reticulum-webclient/`).** Exception: may read files from the sibling `reticulum-rnode/` project for reference.

## Version Bump Rule

**Every commit that ships user-facing changes (JS, HTML, CSS, or any file copied into `_site/` by the deploy workflow) must bump the patch version in `package.json`.** Bug fixes = patch bump (0.3.1 → 0.3.2). New features = minor bump (0.3.2 → 0.4.0). Breaking changes = major bump (0.4.x → 1.0.0). Docs-only, CI-only, tooling-only, and test-only commits do NOT require a bump.

CI (`.github/workflows/deploy.yml`) syncs the version badge in `index.html` from `package.json` on every deploy, so only `package.json` needs editing — don't hand-edit the `v?.?.?` tokens in HTML.

## Project Overview

Reticulum-lite web client — a static JavaScript web app that connects to an RNode LoRa modem over Web Bluetooth and exchanges encrypted messages with Sideband/NomadNet users on a Reticulum LoRa network.

No build step, no server, no framework — plain ES modules hosted on GitHub Pages.

## Architecture

### Transport Chain

```
Browser (Web Bluetooth) → BLE NUS → RNode firmware (KISS) → SX1262 → LoRa RF
                                                                        ↕
Sideband (phone) ← BLE/USB → RNode firmware (KISS) ← SX1262 ← LoRa RF
```

The webapp implements enough of the Reticulum protocol to interoperate with the existing network. The RNode is a dumb radio modem — all protocol logic runs in the browser.

### Module Layout

```
reticulum-webclient/
  index.html              — Single-page app UI
  css/style.css           — Dark theme (matches rnode flasher aesthetic)
  js/
    ble-transport.js      — Web Bluetooth NUS connection + byte stream
    kiss.js               — KISS frame encode/decode
    rnode.js              — RNode command layer (detect, config, CMD_DATA)
    reticulum.js          — Packet header encode/decode, constants
    identity.js           — Ed25519/X25519 keypair, identity hash, dest hash
    crypto.js             — ECDH + HKDF + Token (Fernet-variant) encrypt/decrypt
    announce.js           — Build and parse Reticulum announces
    destination.js        — Destination hash computation
    lxmf.js               — LXMF message pack/unpack + signature
    store.js              — IndexedDB for identity, contacts, messages
    app.js                — UI controller + state management
  lib/
    noble-curves.min.js   — @noble/curves (Ed25519, X25519) ~50KB
    msgpack.min.js        — MessagePack encoder/decoder
```

### Dependencies

| Library | Purpose | Size | Source |
|---------|---------|------|--------|
| @noble/curves | Ed25519, X25519 | ~50KB | CDN (esm.sh or unpkg) |
| @msgpack/msgpack | LXMF payload serialization | ~15KB | CDN |
| Web Crypto API | AES-CBC, HMAC-SHA256, HKDF, SHA-256 | 0 (browser native) | — |
| Web Bluetooth API | BLE NUS connection | 0 (browser native) | — |

No npm, no bundler, no build step. Libraries loaded via `<script>` or ESM import from CDN.

### Platform Support

| Platform | Web Bluetooth | Works? |
|----------|--------------|--------|
| Chrome Android | Yes | Primary target |
| Chrome Desktop | Yes | Dev/testing |
| Edge Desktop | Yes | Works |
| Safari iOS | No | Blocked (Apple) |
| Firefox | No | Blocked |

## Implementation Plan

### Phase 1: BLE Transport + Raw Packet Sniffer
**Goal**: Connect to RNode via Web Bluetooth, configure radio, display raw LoRa packets.

Build: `ble-transport.js`, `kiss.js`, `rnode.js`, basic `app.js` + `index.html`

Key detail: Web Bluetooth uses GATT characteristics, not a Stream. KISS frames may arrive split across multiple BLE notifications — the parser must accumulate bytes and emit complete frames on FEND boundaries.

NUS UUIDs:
- Service: `6e400001-b5a3-f393-e0a9-e50e24dcca9e`
- TX (write): `6e400002-b5a3-f393-e0a9-e50e24dcca9e`
- RX (notify): `6e400003-b5a3-f393-e0a9-e50e24dcca9e`

**Verify**: See hex dumps of Reticulum announces from a nearby Sideband node.

### Phase 2: Reticulum Packet Parser + Identity
**Goal**: Parse packet headers, generate persistent Ed25519/X25519 identity.

Build: `identity.js`, `destination.js`, `reticulum.js`, `store.js`

Identity structure:
- encryption_public_key (32 bytes, X25519) + signing_public_key (32 bytes, Ed25519) = 64 bytes
- identity_hash = SHA-256(public_key)[0:16]
- destination_hash = SHA-256(name_hash + identity_hash)[0:16]
- name_hash = SHA-256("lxmf.delivery")[0:10]

**Verify**: Parse announces from Sideband, display sender identity hash.

### Phase 3: Announce Send/Receive
**Goal**: Validate incoming announces, send our own so Sideband can discover us.

Build: `announce.js`

Announce packet structure:
- public_key(64) + name_hash(10) + random_hash(10) + signature(64) + [app_data]
- Signature over: dest_hash + public_key + name_hash + random_hash + app_data

**Verify**: Our announce shows up in Sideband's discovered list.

### Phase 4: Receive LXMF Messages
**Goal**: Decrypt and display messages sent from Sideband.

Build: `crypto.js`, `lxmf.js`

Decryption flow:
1. Extract ephemeral X25519 pubkey (32 bytes) from ciphertext
2. ECDH: shared_secret = X25519(our_private, ephemeral_public)
3. HKDF(shared_secret, salt=recipient_identity_hash) → signing_key(32) + encryption_key(32)
4. Verify HMAC-SHA256, decrypt AES-256-CBC, remove PKCS7 padding
5. Parse LXMF: source_hash(16) + signature(64) + msgpack([timestamp, title, content, fields])

**Verify**: Message from Sideband decrypts and displays correctly. This is the critical interop milestone.

### Phase 5: Send LXMF Messages
**Goal**: Compose and send encrypted messages to known contacts.

Extend: `crypto.js` (encrypt), `lxmf.js` (pack outbound)

Encryption is the reverse of decryption. Max single-packet message ~250-300 bytes after all overhead.

**Verify**: Message sent from webclient appears correctly in Sideband.

### Phase 6: UI Polish
**Goal**: Usable messaging app with conversation view.

Build out: `app.js`, `index.html`, `css/style.css`
- Contact list from discovered announces
- Conversation threads
- Identity management (show our hash, set display name, export/import keys)
- Radio config UI

## Deferred (Not In Scope)

- **Ratchets** — forward secrecy key rotation (parse the field to avoid byte misalignment, but don't implement rotation)
- **Links** — bidirectional encrypted tunnels (needed for messages > single-packet)
- **Resources** — large file/data transfers over Links
- **Propagation nodes** — store-and-forward relay for offline recipients
- **Multi-hop transport** — full routing table (single-hop LoRa is sufficient)
- **LXMF stamps** — proof-of-work (skip unless target network requires it)
- **IFAC** — interface authentication (skip unless network uses it)
- **GROUP destinations** — only SINGLE needed for point-to-point messaging

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

## Sibling Project

The RNode firmware lives at `C:\Users\rob\PlatformIO\reticulum-rnode\`. Key files:
- `src/Ble.cpp` — BLE NUS implementation (MTU, buffering, flush behavior)
- `src/Kiss.cpp` — KISS protocol + transport abstraction
- `docs/js/rnode.js` — JavaScript KISS implementation (reuse framing helpers)
- `docs/dfu.js` — DFU flasher (reference for Web Serial patterns)
