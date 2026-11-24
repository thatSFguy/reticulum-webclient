// js/sha256.js — synchronous SHA-256 with resumable midstate.
//
// Web Crypto's digest() is async and opaque, which is fine for one-off
// hashes but useless for proof-of-work: a stamp search hashes the same
// long prefix millions of times with only the last few bytes changing.
// This module exposes the compression function so the search can hash
// the fixed prefix ONCE, keep the intermediate state, and then pay a
// single 64-byte block per candidate (js/stamps.js). It is also used for
// the small synchronous HMAC/HKDF needed to build LXMF stamp workblocks.
//
// Plain FIPS 180-4; no dependencies; works in Window, Worker and Node.

'use strict';

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

// One SHA-256 compression: folds the 64-byte block at buf[off..off+64)
// into `state` (Uint32Array(8)) in place. `W` is a caller-owned
// Uint32Array(64) scratch so hot loops allocate nothing.
export function compress(state, buf, off, W) {
  for (let i = 0; i < 16; i++) {
    const j = off + (i << 2);
    W[i] = (buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3];
  }
  for (let i = 16; i < 64; i++) {
    const w15 = W[i - 15], w2 = W[i - 2];
    const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
    const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
  }
  let a = state[0], b = state[1], c = state[2], d = state[3];
  let e = state[4], f = state[5], g = state[6], h = state[7];
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const ch = (e & f) ^ (~e & g);
    const t1 = (h + S1 + ch + K[i] + W[i]) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const mj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (S0 + mj) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0;
    d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  state[0] = (state[0] + a) | 0; state[1] = (state[1] + b) | 0;
  state[2] = (state[2] + c) | 0; state[3] = (state[3] + d) | 0;
  state[4] = (state[4] + e) | 0; state[5] = (state[5] + f) | 0;
  state[6] = (state[6] + g) | 0; state[7] = (state[7] + h) | 0;
}

// Streaming hasher. clone() snapshots the midstate so a fixed prefix can
// be absorbed once and finished many times with different suffixes.
export class Sha256 {
  constructor() {
    this.state = new Uint32Array(IV);
    this.buf = new Uint8Array(64);
    this.bufLen = 0;
    this.total = 0;          // bytes absorbed (Number: fine up to 2^53)
    this.W = new Uint32Array(64);
  }

  update(data) {
    let i = 0;
    const n = data.length;
    this.total += n;
    if (this.bufLen > 0) {
      while (i < n && this.bufLen < 64) this.buf[this.bufLen++] = data[i++];
      if (this.bufLen < 64) return this;
      compress(this.state, this.buf, 0, this.W);
      this.bufLen = 0;
    }
    for (; i + 64 <= n; i += 64) compress(this.state, data, i, this.W);
    while (i < n) this.buf[this.bufLen++] = data[i++];
    return this;
  }

  digest() {
    const bits = this.total * 8;
    const pad = new Uint8Array(this.bufLen < 56 ? 64 : 128);
    pad.set(this.buf.subarray(0, this.bufLen));
    pad[this.bufLen] = 0x80;
    writeLen64(pad, pad.length - 8, bits);
    const st = new Uint32Array(this.state);
    for (let off = 0; off < pad.length; off += 64) compress(st, pad, off, this.W);
    return stateToBytes(st);
  }

  clone() {
    const c = new Sha256();
    c.state.set(this.state);
    c.buf.set(this.buf);
    c.bufLen = this.bufLen;
    c.total = this.total;
    return c;
  }
}

export function sha256Sync(data) {
  return new Sha256().update(data).digest();
}

export function hmacSha256Sync(key, data) {
  let k = key.length > 64 ? sha256Sync(key) : key;
  const ipad = new Uint8Array(64), opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    const b = i < k.length ? k[i] : 0;
    ipad[i] = b ^ 0x36;
    opad[i] = b ^ 0x5c;
  }
  const inner = new Sha256().update(ipad).update(data).digest();
  return new Sha256().update(opad).update(inner).digest();
}

// RFC 5869 HKDF-SHA256, matching RNS.Cryptography.hkdf (empty/None salt
// → 32 zero bytes, None context → empty).
export function hkdfSha256Sync(length, ikm, salt, info = new Uint8Array(0)) {
  if (!salt || salt.length === 0) salt = new Uint8Array(32);
  const prk = hmacSha256Sync(salt, ikm);
  const out = new Uint8Array(length);
  let prev = new Uint8Array(0);
  let off = 0;
  for (let i = 1; off < length; i++) {
    const msg = new Uint8Array(prev.length + info.length + 1);
    msg.set(prev, 0);
    msg.set(info, prev.length);
    msg[msg.length - 1] = i & 0xff;
    prev = hmacSha256Sync(prk, msg);
    out.set(prev.subarray(0, Math.min(32, length - off)), off);
    off += 32;
  }
  return out;
}

export function stateToBytes(st) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i * 4]     = st[i] >>> 24;
    out[i * 4 + 1] = (st[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (st[i] >>> 8) & 0xff;
    out[i * 4 + 3] = st[i] & 0xff;
  }
  return out;
}

export function writeLen64(buf, off, bits) {
  const hi = Math.floor(bits / 0x100000000);
  const lo = bits >>> 0;
  buf[off]     = hi >>> 24; buf[off + 1] = (hi >>> 16) & 0xff;
  buf[off + 2] = (hi >>> 8) & 0xff; buf[off + 3] = hi & 0xff;
  buf[off + 4] = lo >>> 24; buf[off + 5] = (lo >>> 16) & 0xff;
  buf[off + 6] = (lo >>> 8) & 0xff; buf[off + 7] = lo & 0xff;
}
