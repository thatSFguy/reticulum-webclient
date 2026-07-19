# MeshCore ↔ Reticulum Tunnel — Interface Spec (SPIKE)

Status: **spike / exploratory**, but the wire-level details below are now
**verified against the MeshCore companion protocol docs and firmware
references** (fetched June 2026 — see §16). Byte layouts that were guesses in
the first draft have been replaced with confirmed values; the few items that
remain genuinely unverifiable from docs are called out explicitly in §13.

Target client: this repo (`reticulum-webclient`), baseline `v0.24.2`.

---

## 1. Goal

Add a new **interface** to the web client that uses a MeshCore companion
radio as the bearer for Reticulum traffic, instead of an RNode speaking
KISS. From the app's point of view nothing changes: it still builds raw
Reticulum packets and hands them to an interface object; the interface still
emits received raw Reticulum packets back. Only the bearer changes — RF
frames on the air are MeshCore frames, and the RNS packet is opaque payload
inside them.

This is **tunnelling**, not bridging: MeshCore nodes do not understand
Reticulum. A MeshCore node sees our traffic as opaque application datagrams
and floods/forwards them by MeshCore's own rules. Two or more web clients
(or a web client and a Python RNS node fronted by the same kind of MeshCore
companion) form a Reticulum overlay that *rides on* the MeshCore mesh.

```
RNS overlay:   web client  ── raw RNS packet ──  web client / rnsd
                   │                                   │
encapsulation:  MeshCore channel datagram (opaque)  MeshCore channel datagram
                   │                                   │
bearer:        MeshCore companion ── LoRa RF ── MeshCore repeaters ── MeshCore companion
```

---

## 2. Where it fits in the existing architecture

The repo already separates two layers, and a MeshCore tunnel slots into both:

**Transport layer** (raw bytes): `ble-transport.js`, `serial-transport.js`,
`websocket-transport.js`.

**Interface layer** (packets ↔ app.js), exposing a common contract that
`rnode.js` (KISS + radio) and `rnsd-interface.js` (HDLC-direct, no radio)
both implement:

```js
{
  connect(), disconnect(),
  sendPacket(rawReticulumBytes),
  _onPacket(packet, rssi, snr),   // interface → app
  _onLog(msg), _onDisconnect(),
  get connected,
  get capabilities,               // { rnodeControl, radioConfig }
  // RNode command stubs (detect/getFirmwareVersion/setFrequency/…)
}
```

The MeshCore tunnel is a **new interface module** (`meshcore-interface.js`)
fulfilling this exact contract, plus a **companion-protocol codec**
(`meshcore-companion.js`) for the command/response/push framing, the tunnel
envelope, and fragmentation/reassembly. The BLE transport is reusable for the
byte stream, with one framing caveat (§8).

```
app.js
  └── meshcore-interface.js     ← new: fulfils the rnode.js/rnsd-interface.js contract
        ├── meshcore-companion.js  ← new: CMD/RESP/PUSH framing + tunnel envelope + reassembly
        └── ble-transport.js       ← reused (with a single-write fix, §8)
```

---

## 3. MeshCore background (verified)

The companion radio runs *companion* firmware exposing a binary command
protocol to a host over BLE or USB. The host drives the radio; the radio
owns all MeshCore RF, routing, and crypto.

### 3.1 Companion BLE transport

MeshCore companion BLE uses the **same UUIDs as Nordic UART Service** —
identical to RNode:

| Role | UUID |
|------|------|
| Service | `6e400001-b5a3-f393-e0a9-e50e24dcca9e` |
| RX (app → device, write) | `6e400002-b5a3-f393-e0a9-e50e24dcca9e` |
| TX (device → app, notify) | `6e400003-b5a3-f393-e0a9-e50e24dcca9e` |

**Consequence:** the browser chooser (filtered on the NUS service) lists both
RNodes and MeshCore companions and cannot tell them apart by UUID.
Disambiguation is by the `APP_START` handshake (§9.1).

**Framing over BLE:** one BLE characteristic value = one complete companion
frame. BLE's link layer guarantees integrity and boundaries, so there is **no
inter-frame delimiter and no KISS/HDLC escaping**. Each frame is
`[code:1][data:…]`, little-endian ints, UTF-8 strings.
(USB serial instead wraps frames as `'>'`/`'<'` + 2-byte LE length — not used
here, but relevant if a serial transport is added later.)

**MTU:** default BLE MTU 23 (20-byte payload). The host MUST request a larger
MTU (the protocol guidance is `requestMtu(512)`). A companion frame must fit
in one characteristic write.

**Frame size:** firmware constant `MAX_FRAME_SIZE = 172` bytes; the binary
channel-data payload the host may send is `MAX_CHANNEL_DATA_LENGTH =
MAX_FRAME_SIZE − 9 = 163` bytes (oversize ⇒ `PACKET_ERROR /
ERR_CODE_ILLEGAL_ARG`).

### 3.2 MeshCore on-air packet wire format

```
[header:1][transport_codes:4?][path_len:1][path:0..64][payload:0..184]
```
Max total packet = **255 bytes** (`MAX_TRANS_UNIT`). Header `VVPPPPRR`:
version (bits 6-7), payload type (bits 2-5, mask 0x0F), route type (bits 0-1).
Route types: `TRANSPORT_FLOOD 0x00`, `FLOOD 0x01`, `DIRECT 0x02`,
`TRANSPORT_DIRECT 0x03`. Payload types we touch: `GRP_DATA 0x06` (binary
group datagram — what we emit), `MULTIPART 0x0A` (radio-internal frag),
`RAW_CUSTOM 0x0F` (raw app bytes, custom encryption — not host-reachable).

---

## 4. The carrier decision (verified)

The session chose a **"raw / custom" encapsulation**. Verification confirmed
the load-bearing constraint:

> `PAYLOAD_TYPE_RAW_CUSTOM` (0x0F) exists on the air, but **the companion
> command protocol exposes no command to emit it, and none to inject an
> arbitrary mesh packet.** The only host-reachable binary path is
> `CMD_SEND_CHANNEL_DATA` (0x3E) → `PAYLOAD_TYPE_GRP_DATA` (0x06), received as
> `RESP_CODE_CHANNEL_DATA_RECV` (0x1B). `MULTIPART` is **not** host-exposed.

Three paths; the spike takes B (A is the firmware north-star):

- **A — true `RAW_CUSTOM`, requires firmware change.** Add `CMD_SEND_RAW_CUSTOM`
  + an inbound push. Cleanest (no channel crypto, no namespace sharing, and we
  could leave the payload unencrypted since RNS already encrypts end-to-end).
  Requires patching/flashing every companion radio → out of scope for a
  browser-only spike.
- **B — channel binary datagram (recommended, works on stock firmware).**
  `CMD_SEND_CHANNEL_DATA` (0x3E) on a dedicated channel, `data_type` set to a
  fixed value in the developer range (§9.4). On the air it is an
  AES-128-encrypted `GRP_DATA` datagram (§10). Cost: the RNS payload is double-
  encrypted and every participant shares one channel secret.
- **C — `MULTIPART` for big packets.** Verified **not exposed** to the host —
  unavailable. We fragment ourselves (§7).

**Decision: Option B.** It is the only path that runs on unmodified MeshCore
firmware. Keep the tunnel envelope (§5) carrier-agnostic so a later move to A
is just a change in how a frame is handed to the radio.

---

## 5. Tunnel envelope (our framing inside the channel payload)

Two verified facts shape this:
1. We share the developer `data_type` namespace, so we must self-identify.
2. **The inbound `0x1B` frame contains no sender identity** — MeshCore does
   not forward the sender's public key or path to the host. So reassembly
   cannot key on a MeshCore-provided sender. We must carry our **own sender
   tag** inside the envelope.

```
RNS-over-MeshCore envelope (8 bytes):
  [0]    magic        0x52 ('R')    — cheap sanity filter on top of data_type
  [1]    version      0x01
  [2]    flags        bit0 = fragmented, bit1 = first, bit2 = last, bits3-7 reserved
  [3..4] sender_tag   2 bytes = last 2 bytes of sender's RNS identity hash
  [5]    msg_id       per-sender rolling id (mod 256)
  [6]    frag_index   0-based
  [7]    frag_count   total fragments (1 if not fragmented)
  [8..]  payload      raw Reticulum packet bytes (or this fragment's slice)
```

- Reassembly key = `(sender_tag, msg_id)`. `sender_tag` is a 2-byte hint only
  (collisions possible on a large mesh; widen to 3 bytes if needed) — the
  authoritative validation is still the RNS layer after reassembly.
- One byte each for index/count caps a tunnelled packet at 255 fragments —
  far beyond what the RNS MTU needs (§7).
- Envelope overhead is **8 bytes**; tunable. `data_type` (§9.4) is the coarse
  protocol discriminator, the magic byte is belt-and-suspenders.

---

## 6. Addressing model

RNS addressing lives **inside** the RNS packet (16-byte dest hash, announces)
and is already implemented. MeshCore addressing is a separate lower layer the
tunnel only uses to move bytes between companions.

For the spike: **broadcast/flood.** Send tunnelled packets as channel
datagrams with `path_len = 0xFF` (flood). Every participant on the tunnel
channel receives every RNS packet — exactly what Reticulum's broadcast-on-a-
shared-medium model already assumes for single-hop LoRa. RNS drops packets
whose destination isn't ours via existing app.js logic. The tunnel does **not**
map RNS dest hashes onto MeshCore direct addressing — deferred (§14).

---

## 7. MTU and fragmentation

| Layer | Limit |
|-------|-------|
| Reticulum MTU | 500 bytes |
| MeshCore total packet (on air) | 255 bytes (`MAX_TRANS_UNIT`) |
| **Host-sendable channel payload** | **163 bytes** (`MAX_CHANNEL_DATA_LENGTH`) |
| Our tunnel envelope | 8 bytes |
| **Usable RNS bytes per fragment** | **163 − 8 = 155 bytes** |

The 163-byte host limit already accounts for on-air channel-crypto expansion
(the firmware adds the channel hash, MAC, timestamp, and AES padding under the
hood — §10), so we size purely against 163. Consequences:

- A Reticulum **announce** (≈19-byte header + ~167-byte payload ≈ 186 bytes)
  → **2 fragments.** Fragmentation is a day-one path, not an edge case.
- A full **500-byte RNS packet** → `ceil(500/155) = 4 fragments`. Comfortably
  within the 255-fragment cap.
- Many single-packet LXMF messages fit in 1–2 fragments.

Sender: if `len ≤ 155` send one frame (`frag_count=1`); else split into
`ceil(len/155)` slices with a fresh `msg_id` and correct flags/index/count.

Receiver: buffer by `(sender_tag, msg_id)`; concatenate in index order once
all `frag_count` present; hand the packet to `_onPacket`. **Bound and time out**
partial messages (e.g. ≤N concurrent reassemblies, 30 s TTL) — LoRa loss is
normal and an unbounded buffer is a memory-exhaustion vector (§11). No
retransmission: a lost fragment loses the RNS packet, and Reticulum's upper
layers (LXMF proofs, Links) own reliability, as they must over any lossy RF.

---

## 8. BLE transport reuse and the single-write caveat

`ble-transport.js` connects to a companion radio unmodified (same NUS UUIDs),
but its `write()` **chunks** output into `this.mtu`-sized pieces (default 20).
That is correct for KISS (a reassembled byte stream) but **wrong for MeshCore**,
where *one characteristic write must equal one whole frame*. Fix by either (a)
giving the MeshCore interface its own frame-atomic `write()` after negotiating
a 512-byte MTU, or (b) adding a "no-chunk" mode to `ble-transport.js`. Inbound,
treat each notification as one complete frame (the inverse of KISS — no
accumulation).

---

## 9. Verified companion frames

All codes/layouts below are from the companion protocol doc (§16). Byte
offsets are within the frame (BLE: the whole characteristic value).

### 9.1 Handshake / disambiguation — `APP_START` (0x01) → `SELF_INFO` (0x05)
Request: `[0]=0x01`, `[1..7]` reserved (ignored), `[8..]` optional app name
(UTF-8). Response `SELF_INFO` (0x05) returns advert type, TX power, **32-byte
public key** (bytes 4–35), advert lat/lon, and **radio params** — frequency
(bytes 48–51 ÷1000), bandwidth (52–55 ÷1000), spreading factor (56), coding
rate (57), device name (58+). Receiving `SELF_INFO` confirms a MeshCore
companion (an RNode would not answer), and lets us **display** the radio
config read-only even though we can't set it (§12).

### 9.2 Provision the tunnel channel — `SET_CHANNEL` (0x20)
`[0]=0x20`, `[1]`=channel index (0–7), `[2..33]`=channel name (32 B, UTF-8,
null-padded), `[34..49]`=**secret (16 bytes)**. Total 50 B. **The 32-byte
secret variant is rejected with `PACKET_ERROR`** — MeshCore channel keys are
16 bytes (AES-128). Read back with `GET_CHANNEL` (0x1F) `[0]=0x1F,[1]=index`
→ `CHANNEL_INFO` (0x12) `[0]=0x12,[1]=index,[2..33]=name,[34..49]=secret`.
Only **8 channel slots exist**; the tunnel consumes one.

### 9.3 Send — `CMD_SEND_CHANNEL_DATA` (0x3E)
```
[0]      0x3E
[1]      channel index (0-7)
[2]      path length (0xFF = flood; else actual length)
[3..2+pl] path bytes (omitted when path_len == 0xFF)
[next 2] data_type (uint16 LE)
[rest]   binary payload (≤ 163 bytes)   ← our 8-byte envelope + RNS slice
```
Oversize payload ⇒ `PACKET_ERROR / ERR_CODE_ILLEGAL_ARG`.

### 9.4 Receive — `RESP_CODE_CHANNEL_DATA_RECV` (0x1B)
```
[0]      0x1B
[1]      SNR (int8, ×4 — divide by 4.0 for dB)
[2..3]   reserved (ignore)
[4]      channel index (0-7)
[5]      path length (path bytes NOT forwarded to host)
[6..7]   data_type (uint16 LE)   ← pre-filter: must equal our value
[8]      data length
[9..]    payload                  ← our envelope starts here
```
**No sender identity in this frame** → drives the §5 `sender_tag`. SNR maps to
`_onPacket(packet, rssi, snr)`; **RSSI is not provided** → pass 0 (as
`rnsd-interface.js` already does).

### 9.5 `data_type`
`0x0000` reserved/invalid-on-send; `0x0001–0x00FF` internal; `0x0100–0xFEFF`
registered app namespaces; `0xFF00–0xFFFE` **testing/dev, no registration**;
`0xFFFF` `DATA_TYPE_DEV`. Use a **fixed value in `0xFF00–0xFFFE`** (e.g.
`0xFF52`) as our protocol discriminator so the host can pre-filter inbound
`0x1B` frames by bytes 6–7 before parsing; the §5 magic byte guards residual
collisions.

---

## 10. Cryptography & the double-encryption question

This was the explicit concern. Short answer: **double encryption is fine — it
cannot weaken Reticulum, and over Option B it is mandatory rather than a
choice. The only real costs are airtime overhead and a shared low-value
channel secret that is a DoS/injection surface, not a confidentiality one.**

### 10.1 The two layers

| | Inner — Reticulum (the real security) | Outer — MeshCore channel (bearer) |
|--|--|--|
| Endpoints | the two RNS identities | everyone holding the channel secret |
| Key exchange | X25519 ECDH, per-message ephemeral key | pre-shared 16-byte channel secret |
| Cipher | AES-256-CBC | **AES-128-ECB** |
| Integrity | HMAC-SHA256 (truncated 16 B) | **HMAC-SHA256 truncated to 2 bytes** |
| Sender auth | Ed25519 signatures (announce/LXMF) | **none** — anyone with the secret can forge |
| Replay | RNS packet-hash dedup / link seq | 4-byte timestamp only (uniqueness, not anti-replay) |
| Forward secrecy | optional ratchets | none |

### 10.2 Why it is not a security concern
- **No weakening is possible.** Wrapping already-ciphertext in a second cipher
  never degrades the inner cipher. Message confidentiality/integrity/
  authenticity rest entirely on the inner Reticulum layer and are unaffected
  by anything the outer layer does.
- **The outer crypto is weak, but harmlessly so here.** AES-128-**ECB** would
  normally leak repeated 16-byte plaintext blocks — but our outer plaintext
  *is* the inner RNS ciphertext, i.e. high-entropy with no repeated blocks, so
  ECB's structural flaw is never exposed. The **2-byte outer MAC** (1/65536
  forgery odds) is weak, but a frame that forges past it still has to carry a
  payload that passes full inner RNS validation — which it cannot. Outer
  replay is likewise moot because RNS dedups.
- **The channel secret is low-value.** All participants share one 16-byte
  secret. If it leaks, an attacker can see that *opaque* traffic flows, and can
  inject/replay/flood datagrams onto the channel. They **cannot** read RNS
  contents, forge an RNS identity, or impersonate an RNS sender. So a leak is
  an **availability/spam** problem, not a confidentiality breach — treat the
  channel secret as a shared membership token, not a real key.

### 10.3 What the outer layer actually costs
- **You can't opt out of it.** A MeshCore channel *is* its encryption — there
  is no plaintext channel. Under Option B, double encryption is intrinsic, not
  a design choice. (Only Option A's firmware `RAW_CUSTOM` path could be
  single-layer.)
- **Airtime/overhead.** Outer framing eats ~3–18 bytes (1-byte hash + 2-byte
  MAC + 0–15 padding) plus the 4-byte timestamp; this is already baked into the
  163-byte host limit, which is *why* usable per-fragment payload is only ~155
  B and announces need 2 fragments. More fragments = more airtime = more
  duty-cycle pressure (§11).
- **No outer sender auth** means anyone with the secret can inject arbitrary
  tunnel envelopes / fragment floods. Defenses: `data_type` + magic pre-filter,
  **bounded + TTL'd reassembly buffers**, and RNS-layer validation discards the
  rest. It is a spam/memory vector to engineer against, not a break.
- **Two key systems to provision** — RNS identity *and* the MeshCore channel
  secret, shared out-of-band — is added onboarding friction.

---

## 11. Negative impacts / risks (consolidated)

| # | Impact | Severity | Mitigation / note |
|---|--------|----------|-------------------|
| 1 | **Flood amplification & duty cycle** — periodic RNS announces become channel datagrams flooded by every MeshCore repeater; on a shared community mesh this is heavy and impolite. | **High** | Long announce intervals (repo already defaults TCP to 60 min); duty-cycle-aware send pacing; consider a dedicated/low-traffic channel. |
| 2 | **Mandatory fragmentation** — ~155 usable bytes/fragment; announces ≈2, full packets ≈4 frags; losing any fragment loses the whole packet. | **Med** | Day-one reassembly with TTL; rely on RNS upper-layer reliability. |
| 3 | **Double-encryption overhead** (§10.3) — outer crypto shrinks payload and adds airtime. | **Med** | Intrinsic to Option B; minimized by tight envelope. |
| 4 | **Channel-secret = shared DoS/injection surface** (no outer sender auth). | **Med** | Bounded/TTL'd reassembly; pre-filter; RNS validation; treat secret as non-confidential. |
| 5 | **Only 8 channel slots** — tunnel consumes one. | Low | Document; make the slot index configurable. |
| 6 | **Self-echo unknown** — sender may receive its own `0x1B` back (docs silent). | Low | Drop frames whose `sender_tag` is ours; confirm empirically (§13). |
| 7 | **Low throughput / high latency** — LoRa + flood + fragmentation. RNS **Links/Resources** (timely round-trips, large transfers) may be impractical; single-packet LXMF is the sweet spot. | Med | Links/Resources already deferred in CLAUDE.md; scope to messaging. |
| 8 | **RNode/MeshCore indistinguishable by BLE UUID.** | Low | `APP_START` handshake (§9.1); UI bearer selector. |
| 9 | **Shared `data_type` namespace** (unregistered range). | Low | Fixed `0xFF52` + magic byte. |

---

## 12. app.js integration and capabilities

```js
get capabilities() {
  return { rnodeControl: false, radioConfig: false };
}
```
MeshCore owns its radio; we don't set freq/SF/BW/power (though §9.1 lets us
*display* them read-only). Provide benign RNode-command stubs like
`rnsd-interface.js` so un-gated app.js callers keep working. `transport-config.js`
needs a "MeshCore companion" bearer option; because UUIDs collide with RNode,
the user picks the bearer type in the UI, then the device.

---

## 13. Remaining open questions (genuinely unverified by docs)

Most first-draft unknowns are now resolved inline above. These still require a
real companion radio:

1. **Self-echo** — does a sender receive its own channel datagram back as
   `0x1B`? (Docs silent — §11 #6.) Determines whether the self-`sender_tag`
   drop is required or just defensive.
2. **Real per-fragment headroom** — confirm 163 host bytes hold after the
   firmware's on-air crypto expansion in practice; tune `MAX_FRAG_PAYLOAD`
   (currently 155) against measurement.
3. **512-byte MTU over Web Bluetooth specifically** — some browser/OS BLE
   stacks cap below 512; verify the negotiated value and cap frame size to it.
4. **Duty-cycle headroom** — measure announce-storm airtime against regional
   limits to set a safe minimum announce interval for the MeshCore bearer.

---

## 14. Out of scope

Firmware changes (Option A `RAW_CUSTOM`); MeshCore radio configuration from the
client; MeshCore direct addressing (broadcast/flood only, §6); tunnel-layer
ARQ/retransmission; a MeshCore chat/contacts UI; and everything already
deferred in CLAUDE.md (ratchets, multi-hop RNS transport, propagation nodes,
Links/Resources beyond single-packet messaging).

---

## 15. Proposed implementation order

1. `meshcore-companion.js` — CMD/RESP/PUSH codec, tunnel-envelope encode/decode,
   fragmentation + TTL'd reassembler. Pure functions + a small stateful
   reassembler → **unit-testable with no BLE**, like `kiss.js`/`lxmf.js` under
   `tests/`.
2. BLE single-write/MTU fix (§8).
3. `meshcore-interface.js` — the contract object: `connect()` handshake
   (`APP_START` → `SELF_INFO`, ensure channel via `SET_CHANNEL`),
   `sendPacket()` → fragment → `0x3E`, `0x1B` push → reassemble → `_onPacket`.
4. `transport-config.js` + UI bearer option.
5. Interop bring-up on real companion radios; close §13; tune `MAX_FRAG_PAYLOAD`.

First milestone (repo's "verify" style): **two web clients, each on a MeshCore
companion, exchange one LXMF message end-to-end over the MeshCore mesh.**

---

## 16. References

MeshCore (read against firmware source before implementing; wiki/docs lag code):
- Companion protocol — <https://github.com/meshcore-dev/MeshCore/blob/main/docs/companion_protocol.md>
- Companion Radio Protocol (wiki) — <https://github.com/meshcore-dev/MeshCore/wiki/Companion-Radio-Protocol>
- Companion firmware source — `examples/companion_radio/` in <https://github.com/meshcore-dev/MeshCore>
- Packet Structure and Types — <https://deepwiki.com/meshcore-dev/MeshCore/7.1-packet-structure-and-types>
- Payload Format — <https://docs.meshcore.io/payloads/>
- Channel/group cryptography — <https://deepwiki.com/ripplebiz/MeshCore/9.2-message-encryption> and <https://jacksbrain.com/2026/01/a-hitchhiker-s-guide-to-meshcore-cryptography/>

Reticulum side: this repo's `docs/PROTOCOL_NOTES.md`, `CLAUDE.md`, and the
`rnode.js` / `rnsd-interface.js` interface contract.
