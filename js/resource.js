// js/resource.js — receiver side of the Reticulum Resource protocol (SPEC §10).
//
// A Resource carries a payload too large for one Link packet (~360 bytes) —
// i.e. essentially every NomadNet page. We only implement the RECEIVE half:
// advertisement → request part windows → collect parts → reassemble →
// decrypt → decompress → verify → emit proof.
//
// Wire contexts (all on an active Link):
//   RESOURCE_ADV 0x02  in   msgpack dict (§10.4), link-encrypted
//   RESOURCE     0x01  in   one raw slice of the encrypted whole — NOT
//                           individually encrypted (§10.6 gotcha)
//   RESOURCE_REQ 0x03  out  request a window of parts (§10.5)
//   RESOURCE_HMU 0x04  in   hashmap continuation (§10.7), link-encrypted
//   RESOURCE_PRF 0x05  out  PROOF, resource_hash(32)||full_proof(32) (§10.8)
//   RESOURCE_ICL 0x06  in   initiator cancel (resource_hash)
//   RESOURCE_RCL 0x07  out  receiver reject/cancel (resource_hash)

'use strict';

import { decode as msgpackDecode, encode as msgpackEncode } from '@msgpack/msgpack';
import { sha256 } from './identity.js';
import { concatBytes, arraysEqual } from './announce.js';
import { bunzip2 } from '../lib/bz2.js';

export const CTX_RESOURCE     = 0x01;
export const CTX_RESOURCE_ADV = 0x02;
export const CTX_RESOURCE_REQ = 0x03;
export const CTX_RESOURCE_HMU = 0x04;
export const CTX_RESOURCE_PRF = 0x05;
export const CTX_RESOURCE_ICL = 0x06;
export const CTX_RESOURCE_RCL = 0x07;

const MAPHASH_LEN = 4;
const RANDOM_HASH_SIZE = 4;
const HASHMAP_IS_NOT_EXHAUSTED = 0x00;
const HASHMAP_IS_EXHAUSTED = 0xFF;
const INITIAL_WINDOW = 4;

// Default per-resource cap. NomadNet pages and /get blobs are small; this
// bounds both buffer allocation and bz2 expansion (SPEC §10.4 callout).
export const DEFAULT_MAX_SIZE = 4 * 1024 * 1024;

// Flag bits in the advertisement `f` byte (§10.4).
const FLAG_ENCRYPTED   = 0x01;  // e
const FLAG_COMPRESSED  = 0x02;  // c
const FLAG_SPLIT       = 0x04;  // s (multi-segment)
const FLAG_IS_REQUEST  = 0x08;  // u
const FLAG_IS_RESPONSE = 0x10;  // p
const FLAG_HAS_META    = 0x20;  // x

// Parse a decrypted RESOURCE_ADV body (msgpack dict) into a normalized object.
export function parseAdvertisement(plaintext) {
  const d = msgpackDecode(plaintext);
  if (typeof d !== 'object' || d === null) throw new Error('resource: bad advertisement');
  const f = d.f | 0;
  return {
    transferSize: d.t | 0,        // encrypted wire length
    dataSize: d.d | 0,            // uncompressed plaintext length
    parts: d.n | 0,               // parts in this segment
    hash: u8(d.h),                // 32-byte resource hash
    randomHash: u8(d.r),          // 4-byte integrity/hashmap salt
    originalHash: u8(d.o),        // first-segment hash
    segmentIndex: d.i | 0,
    totalSegments: d.l | 0,
    requestId: d.q == null ? null : u8(d.q),
    flags: f,
    encrypted: !!(f & FLAG_ENCRYPTED),
    compressed: !!(f & FLAG_COMPRESSED),
    split: !!(f & FLAG_SPLIT),
    isRequest: !!(f & FLAG_IS_REQUEST),
    isResponse: !!(f & FLAG_IS_RESPONSE),
    hasMetadata: !!(f & FLAG_HAS_META),
    hashmapFragment: u8(d.m),     // concatenated 4-byte map hashes
  };
}

function u8(v) {
  if (v == null) return new Uint8Array(0);
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v)) return new Uint8Array(v);
  return new Uint8Array(0);
}

// Receives a single Resource over an active link.
//
//   link    — the active Link (used only for the single assemble-time decrypt)
//   adv     — parsed advertisement (parseAdvertisement output)
//   opts.send(context, payload, isProof) — emit a link packet. For DATA
//             contexts the caller link-encrypts payload; for PROOF it does not.
//   opts.onComplete({ data, metadata, requestId }) — assembled payload
//   opts.onError(reason)
//   opts.onProgress(fraction)
//   opts.maxSize — override DEFAULT_MAX_SIZE
export class ResourceReceiver {
  constructor(link, adv, opts) {
    this.link = link;
    this.adv = adv;
    this.send = opts.send;
    this.onComplete = opts.onComplete || (() => {});
    this.onError = opts.onError || (() => {});
    this.onProgress = opts.onProgress || (() => {});
    this.maxSize = opts.maxSize || DEFAULT_MAX_SIZE;
    // Slow-transport knobs (set by the caller for lora-class transports):
    // maxWindow caps §10.10 window growth — the ALN node's tunnel/tx queues
    // are shallow, and a burst larger than they hold guarantees a dropped
    // part. stallMs arms a re-request watchdog: without one, a single lost
    // part left `outstanding` non-empty FOREVER (the next window is only
    // requested when all outstanding parts arrive) — the observed image-
    // transfer hang. 0 disables.
    this.maxWindow = opts.maxWindow || 16;
    this.stallMs = opts.stallMs || 0;
    this.stallRetriesLeft = opts.stallRetries ?? 5;
    this._stallTimer = null;

    this.totalParts = adv.parts;
    this.parts = new Array(this.totalParts).fill(null);
    this.receivedCount = 0;
    this.knownHashmap = [];        // array of 4-byte Uint8Array map hashes
    this.outstanding = new Set();  // map-hash hex currently requested
    this.window = INITIAL_WINDOW;
    this.done = false;
    this.waitingHMU = false;

    // Seed the hashmap from the advertisement fragment.
    this._ingestHashmap(adv.hashmapFragment);
  }

  _armStall() {
    if (!this.stallMs || this.done) return;
    clearTimeout(this._stallTimer);
    this._stallTimer = setTimeout(() => this._onStall(), this.stallMs);
  }

  _onStall() {
    if (this.done) return;
    if (this.stallRetriesLeft-- <= 0) {
      this._fail(`stalled: ${this.outstanding.size} part(s) outstanding, retries exhausted`);
      return;
    }
    // Shrink back to the initial window (loss = the burst was too big for
    // the path) and re-request everything still missing. A lost HMU is
    // recovered the same way — waitingHMU is cleared so _requestNext can
    // re-issue the exhausted REQ.
    this.window = INITIAL_WINDOW;
    this.outstanding.clear();
    this.waitingHMU = false;
    this._requestNext();
  }

  // Kick off the transfer (caps check + first request).
  start() {
    if (this.adv.transferSize > this.maxSize || this.adv.dataSize > this.maxSize) {
      this._fail(`resource too large (t=${this.adv.transferSize}, d=${this.adv.dataSize}, cap=${this.maxSize})`);
      return;
    }
    if (this.adv.split && this.adv.totalSegments > 1) {
      // Multi-segment (>1 MiB) is out of scope — NomadNet pages never hit it.
      this._fail('multi-segment resources not supported');
      return;
    }
    if (this.totalParts <= 0) { this._fail('resource has no parts'); return; }
    this._requestNext();
  }

  _ingestHashmap(bytes) {
    if (!bytes || bytes.length === 0) return;
    for (let off = 0; off + MAPHASH_LEN <= bytes.length; off += MAPHASH_LEN) {
      if (this.knownHashmap.length >= this.totalParts) break;
      this.knownHashmap.push(bytes.subarray(off, off + MAPHASH_LEN));
    }
  }

  // Receiver requests the next window of parts it doesn't yet have (§10.5).
  _requestNext() {
    if (this.done) return;

    const requested = [];
    for (let i = 0; i < this.knownHashmap.length && requested.length < this.window; i++) {
      if (this.parts[i] === null) requested.push(this.knownHashmap[i]);
    }

    if (requested.length > 0) {
      this.outstanding.clear();
      for (const mh of requested) this.outstanding.add(hex(mh));
      const body = concatBytes([
        new Uint8Array([HASHMAP_IS_NOT_EXHAUSTED]),
        this.adv.hash,
        ...requested,
      ]);
      this.send(CTX_RESOURCE_REQ, body, false);
      this._armStall();
      return;
    }

    // No known parts left to request. If the hashmap is incomplete, pull the
    // next segment with a part-less exhausted REQ (§10.7 — receivers MAY do
    // this, and it interoperates with every conformant sender).
    if (this.knownHashmap.length < this.totalParts) {
      const last = this.knownHashmap[this.knownHashmap.length - 1];
      const body = concatBytes([
        new Uint8Array([HASHMAP_IS_EXHAUSTED]),
        last,
        this.adv.hash,
      ]);
      this.waitingHMU = true;
      this.send(CTX_RESOURCE_REQ, body, false);
      this._armStall();
    }
    // else: everything known and requested — completion is driven by handlePart.
  }

  // An inbound RESOURCE (0x01) part: a raw slice, matched by SHA256(slice||r)[:4].
  async handlePart(sliceBytes) {
    if (this.done) return;
    this._armStall();              // any part activity = the sender is alive
    const mh = (await sha256(concatBytes([sliceBytes, this.adv.randomHash]))).subarray(0, MAPHASH_LEN);
    const mhHex = hex(mh);
    if (!this.outstanding.has(mhHex)) return;  // unrequested / duplicate

    // Place into the first matching empty slot within the known hashmap.
    for (let i = 0; i < this.knownHashmap.length; i++) {
      if (this.parts[i] === null && arraysEqual(this.knownHashmap[i], mh)) {
        this.parts[i] = sliceBytes;
        this.receivedCount++;
        break;
      }
    }
    this.outstanding.delete(mhHex);
    this.onProgress(this.receivedCount / this.totalParts);

    if (this.receivedCount >= this.totalParts) {
      await this._assemble();
    } else if (this.outstanding.size === 0) {
      // Grow the window each completed round (§10.10), then ask for more.
      if (this.window < this.maxWindow) this.window++;
      this._requestNext();
    }
  }

  // RESOURCE_HMU (0x04): resource_hash(32) || msgpack([segIdx, hashmapBytes]).
  handleHashmapUpdate(plaintext) {
    if (this.done) return;
    const rh = plaintext.subarray(0, 32);
    if (!arraysEqual(rh, this.adv.hash)) return;  // not ours
    // §10.7 HMU hardening (RNS >= 1.3.9): ignore HMUs we didn't ask for.
    if (!this.waitingHMU) return;
    const [, hashmapBytes] = msgpackDecode(plaintext.subarray(32));
    const seg = u8(hashmapBytes);
    // §10.7: an HMU carrying zero map hashes cancels the transfer. Without
    // this we'd re-send the exhausted REQ and loop forever against a sender
    // that answers it with another empty HMU.
    if (seg.length < MAPHASH_LEN) {
      this._fail('empty hashmap update — cancelling (SPEC §10.7)');
      return;
    }
    this._ingestHashmap(seg);
    this.waitingHMU = false;
    this._requestNext();
  }

  // RESOURCE_ICL (0x06): initiator cancelled. No RCL echo — the sender
  // already knows the transfer is dead.
  cancel(reason = 'cancelled by sender') {
    if (this.done) return;
    this.done = true;
    clearTimeout(this._stallTimer);
    this.onError(reason);
  }

  // Local receiver-side abort (e.g. superseded by a newer advertisement).
  // Unlike cancel(), this puts RESOURCE_RCL on the wire (§10.9).
  abort(reason = 'aborted') {
    this._fail(reason);
  }

  async _assemble() {
    try {
      // Concatenate all parts and decrypt the whole once (§10.8 / §10.12).
      const whole = concatBytes(this.parts);
      let blob;
      if (this.adv.encrypted) {
        blob = await this.link.decrypt(whole);
      } else {
        blob = whole;
      }

      // Strip the leading 4 random bytes (discard — NOT adv.r) (§10.8 step 3).
      let plaintext = blob.subarray(RANDOM_HASH_SIZE);

      if (this.adv.compressed) {
        plaintext = bunzip2(plaintext, this.maxSize);
      }

      // Integrity and proof are both over this `plaintext` — which still
      // includes any metadata prefix (metadata is stripped AFTER, §10.8 step 6).
      const check = await sha256(concatBytes([plaintext, this.adv.randomHash]));
      if (!arraysEqual(check, this.adv.hash)) {
        this._fail('resource integrity check failed (CORRUPT)');
        return;
      }

      this.done = true;
      clearTimeout(this._stallTimer);

      // Emit the proof: resource_hash(32) || SHA256(plaintext || resource_hash) (§10.8).
      const fullProof = await sha256(concatBytes([plaintext, this.adv.hash]));
      this.send(CTX_RESOURCE_PRF, concatBytes([this.adv.hash, fullProof]), true);

      // Strip 3-byte-uint24-length-prefixed msgpack metadata if present (§10.2/§10.8).
      let data = plaintext;
      let metadata = null;
      if (this.adv.hasMetadata) {
        const mlen = (data[0] << 16) | (data[1] << 8) | data[2];
        metadata = msgpackDecode(data.subarray(3, 3 + mlen));
        data = data.subarray(3 + mlen);
      }

      this.onComplete({ data, metadata, requestId: this.adv.requestId });
    } catch (e) {
      this._fail(`resource assembly failed: ${e.message}`);
    }
  }

  _fail(reason) {
    if (this.done) return;
    this.done = true;
    clearTimeout(this._stallTimer);
    // §10.9: RESOURCE_RCL on ANY receiver-side abort, not just advertisement
    // reject (matches RNS >= 1.3.9) — otherwise the sender keeps
    // retransmitting until its watchdog gives up. Inbound ICL takes the
    // cancel() path instead, which correctly does not echo an RCL back.
    try { this.send(CTX_RESOURCE_RCL, this.adv.hash, false); } catch { /* best effort */ }
    this.onError(reason);
  }
}

function hex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

// Part slice size: must fit a HEADER_1 link DATA packet (19B header) within
// MTU 500. RNS uses mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE; 464 is the same
// conservative bound and is sender-internal (the receiver reassembles by
// hashmap order regardless).
const SDU = 464;
// Map hashes that fit in the first advertisement (rest via RESOURCE_HMU).
const HASHMAP_MAX_LEN = 74;

// Sender side of the Resource protocol (SPEC §10.2–10.8). We send
// UNCOMPRESSED (flag c=0) so no bz2 *compressor* is needed. The payload is
// link-encrypted once as a whole, then sliced into raw parts.
//
//   link    — active Link (its session key encrypts the whole blob)
//   data    — Uint8Array plaintext to deliver
//   opts.send(context, payload, isProof) — emit a link packet. The caller
//     link-encrypts ADV/HMU, sends RESOURCE parts RAW, PROOF unencrypted.
//   opts.requestId / opts.isResponse / opts.isRequest — for REQUEST/RESPONSE
//   opts.onComplete() — peer returned a valid proof
//   opts.onError(reason)
export class ResourceSender {
  constructor(link, data, opts) {
    this.link = link;
    this.data = data;
    this.send = opts.send;
    this.requestId = opts.requestId || null;
    this.isResponse = !!opts.isResponse;
    this.isRequest = !!opts.isRequest;
    this.onComplete = opts.onComplete || (() => {});
    this.onError = opts.onError || (() => {});
    // Slow-transport knobs (caller sets these for lora-class transports):
    // sdu — part slice size. The default 464 (RNS MTU maths) makes each part
    // a ~484B packet that the ALN node must SAR-fragment; 192 keeps the whole
    // link DATA packet (19B header + slice) inside the mesh's 214B single-
    // frame cutoff — the same change that made texts fast. Sender-internal:
    // the receiver reassembles by hashmap order whatever the slice size.
    // pacingMs — inter-part gap when serving a window. Firing a window
    // back-to-back overran the node's shallow queues (guaranteed drop);
    // pacing to ~channel rate keeps every part inside per-hop ARQ cover.
    this.sdu = opts.sdu || SDU;
    this.pacingMs = opts.pacingMs || 0;
    this.done = false;
  }

  async start() {
    const data = this.data;
    this.randomHash = randomBytes(RANDOM_HASH_SIZE);  // adv.r — integrity/hashmap salt

    // §10.2: a fresh 4-byte throwaway prefix travels inside the encrypted
    // blob (distinct from randomHash); receiver strips & discards it.
    const blob = concatBytes([randomBytes(RANDOM_HASH_SIZE), data]);
    const encrypted = await this.link.encrypt(blob);

    // Hash/proof are over the ORIGINAL plaintext + randomHash (not the prefix,
    // not the encrypted form) so both sides agree (§10.2 step 5 / §10.8).
    this.hash = await sha256(concatBytes([data, this.randomHash]));
    this.expectedProof = await sha256(concatBytes([data, this.hash]));

    // Slice the encrypted whole into parts; fingerprint each to a 4-byte map hash.
    this.parts = [];
    for (let off = 0; off < encrypted.length; off += this.sdu) {
      this.parts.push(encrypted.subarray(off, off + this.sdu));
    }
    if (this.parts.length === 0) this.parts.push(new Uint8Array(0));
    this.totalParts = this.parts.length;

    this.mapHashes = [];
    this.partByMapHash = new Map();
    for (let i = 0; i < this.totalParts; i++) {
      const mh = (await sha256(concatBytes([this.parts[i], this.randomHash]))).subarray(0, MAPHASH_LEN);
      this.mapHashes.push(mh);
      this.partByMapHash.set(hex(mh), this.parts[i]);
    }

    let f = FLAG_ENCRYPTED;
    if (this.isRequest) f |= FLAG_IS_REQUEST;
    if (this.isResponse) f |= FLAG_IS_RESPONSE;

    const firstCount = Math.min(this.totalParts, HASHMAP_MAX_LEN);
    const adv = {
      t: encrypted.length, d: data.length, n: this.totalParts,
      h: this.hash, r: this.randomHash, o: this.hash, i: 1, l: 1,
      q: this.requestId, f, m: concatBytes(this.mapHashes.slice(0, firstCount)),
    };
    await this.send(CTX_RESOURCE_ADV, new Uint8Array(msgpackEncode(adv)), false);
  }

  // RESOURCE_REQ (0x03): serve the requested parts, and the next hashmap
  // segment if the receiver exhausted what it knows (§10.5/§10.7).
  async handleRequest(plaintext) {
    if (this.done) return;
    let off = 0;
    const exhausted = plaintext[off]; off += 1;
    let lastMapHash = null;
    if (exhausted === HASHMAP_IS_EXHAUSTED) { lastMapHash = plaintext.subarray(off, off + MAPHASH_LEN); off += MAPHASH_LEN; }
    const resHash = plaintext.subarray(off, off + 32); off += 32;
    if (!arraysEqual(resHash, this.hash)) return;  // not ours

    for (; off + MAPHASH_LEN <= plaintext.length; off += MAPHASH_LEN) {
      const part = this.partByMapHash.get(hex(plaintext.subarray(off, off + MAPHASH_LEN)));
      if (!part) continue;
      await this.send(CTX_RESOURCE, part, false);  // raw slice
      if (this.pacingMs && !this.done) {
        await new Promise((r) => setTimeout(r, this.pacingMs));
      }
    }

    if (exhausted === HASHMAP_IS_EXHAUSTED && lastMapHash) {
      const idx = this.mapHashes.findIndex((m) => arraysEqual(m, lastMapHash));
      if (idx >= 0) {
        const segStart = idx + 1;
        const seg = this.mapHashes.slice(segStart, segStart + HASHMAP_MAX_LEN);
        if (seg.length) {
          const body = concatBytes([this.hash, new Uint8Array(msgpackEncode([Math.floor(segStart / HASHMAP_MAX_LEN), concatBytes(seg)]))]);
          await this.send(CTX_RESOURCE_HMU, body, false);
        } else {
          // §10.7 (RNS >= 1.3.9): no hashmap left to continue with means the
          // receiver's request sequencing is broken — cancel instead of
          // emitting an empty HMU (or, pre-fix, silently stalling the peer).
          this.done = true;
          try { await this.send(CTX_RESOURCE_ICL, this.hash, false); } catch { /* best effort */ }
          this.onError('exhausted REQ past end of hashmap — cancelling (SPEC §10.7)');
        }
      }
    }
  }

  // RESOURCE_PRF (0x05): resource_hash(32) || full_proof(32).
  handleProof(proofData) {
    if (this.done) return;
    if (!arraysEqual(proofData.subarray(0, 32), this.hash)) return;  // not ours
    if (arraysEqual(proofData.subarray(32, 64), this.expectedProof)) {
      this.done = true;
      this.onComplete();
    } else {
      this.done = true;
      this.onError('resource proof mismatch');
    }
  }

  cancel(reason = 'cancelled') {
    if (this.done) return;
    this.done = true;
    this.onError(reason);
  }
}
