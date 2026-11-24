// js/stamps.js — Reticulum / LXMF proof-of-work stamps (SPEC §5.7.2, §4.7,
// §6.1.1, §7.1). A port of RNS/Stamps.py (RNS 1.6.1).
//
// One primitive covers every stamp kind upstream uses:
//
//   valid  ⇔  int(SHA-256(workblock || stamp), big-endian) <= target(cost)
//
//   kind                 workblock                         stamp  cost
//   -------------------  --------------------------------  -----  -----------------
//   announce  (§4.7)     dest_hash||public_key||name_hash   14 B  gen 25.0 / req 23.5
//   path req  (§7.1)     dest_hash||tag                     14 B  15.8
//   link req  (§6.1.1)   dest_hash||ed25519_pub             the X25519 pub itself
//   LXMF msg  (§5.7.2)   HKDF-expanded message_id (768 kB)  32 B  peer's stamp_cost
//
// Costs are fractional: an 8.8 fixed-point value whose target comes from
// the upstream mantissa table (TAB) — NOT from floating-point 2**x, which
// lands off-by-one at the boundaries (SPEC §5.7.2).
//
// The search hashes the fixed workblock prefix once and keeps the SHA-256
// midstate, so each candidate costs one compression (two for an 80-byte
// key-stamp tail). In the browser the search fans out over Web Workers
// (js/stamp-worker.js); in Node (tests) it runs inline.
//
// This module must stay free of bare-specifier imports: module workers do
// not see the page's import map.

'use strict';

import { Sha256, compress, sha256Sync, hkdfSha256Sync, writeLen64 } from './sha256.js';
import { x25519 } from '../lib/noble-curves-ed25519.js';

// ---- Constants (RNS/Transport.py, RNS/Identity.py, LXMF/LXStamper.py) ----

export const STAMP_COST_CAP      = 100;
export const DESTINATION_COST    = 23.5;   // required on receive (interface default)
export const DESTINATION_VALUE   = 25.0;   // what upstream generates its own to
export const LR_COST             = 12.5;   // default announced link-request cost
export const LINK_COST_CAP       = 40;
export const PR_COST             = 15.8;   // path-request stamp required
export const PR_VALUE            = 15.8;   // path-request stamp generated
export const STAMPLENGTH         = 14;     // announce / path-request stamp bytes
export const LXMF_STAMP_SIZE     = 32;
export const EXTPAYLOADMARKER    = 0xC1;
export const EXTPAYLOADLENGTH    = 18;     // marker + flags + stamp(14) + cost(2)
export const WORKBLOCK_EXPAND_ROUNDS    = 3000;
export const WORKBLOCK_EXPAND_ROUNDS_PN = 1000;
export const COST_TICKET         = 0x100;

const MANTISSA_BITS = 33n;
const COST_FP_BITS  = 8;
const COST_FP       = 1 << COST_FP_BITS;

// Authoritative upstream table, copied verbatim from RNS/Stamps.py (1.6.1).
// tests/stamps.mjs + tests/run_stamps.py cross-check targets against RNS.
const TAB = [
  0x200000000, 0x201635f4b, 0x202c7b53f, 0x2042d0287, 0x2059347ce, 0x206fa85c2,
  0x20862bd0d, 0x209cbee5e, 0x20b361a62, 0x20ca141c7, 0x20e0d653b, 0x20f7a856e,
  0x210e8a30e, 0x21257becc, 0x213c7d958, 0x21538f363, 0x216ab0d9f, 0x2181e28bc,
  0x21992456e, 0x21b076467, 0x21c7d865a, 0x21df4abfb, 0x21f6cd5ff, 0x220e6051a,
  0x222603a02, 0x223db756b, 0x22557b80d, 0x226d5029e, 0x2285355d5, 0x229d2b269,
  0x22b531914, 0x22cd48a8e, 0x22e57078f, 0x22fda90d2, 0x2315f2711, 0x232e4cb06,
  0x2346b7d6d, 0x235f33f02, 0x2377c1080, 0x23905f2a5, 0x23a90e62d, 0x23c1cebd6,
  0x23daa045f, 0x23f383087, 0x240c7710c, 0x24257c6af, 0x243e9322f, 0x2457bb44f,
  0x2470f4dce, 0x248a3ff70, 0x24a39c9f6, 0x24bd0ae23, 0x24d68acbc, 0x24f01c683,
  0x2509bfc3e, 0x252374eb2, 0x253d3bea3, 0x255714cda, 0x2570ffa1b, 0x258afc72e,
  0x25a50b4dc, 0x25bf2c3ec, 0x25d95f527, 0x25f3a4957, 0x260dfc146, 0x262865dbd,
  0x2642e1f89, 0x265d70775, 0x26781164c, 0x2692c4cdc, 0x26ad8abf2, 0x26c86345b,
  0x26e34e6e7, 0x26fe4c463, 0x27195cda0, 0x27348036e, 0x274fb669c, 0x276aff7fd,
  0x27865b862, 0x27a1ca89d, 0x27bd4c982, 0x27d8e1be3, 0x27f48a095, 0x28104586c,
  0x282c1443e, 0x2847f64e1, 0x2863ebb2a, 0x287ff47f0, 0x289c10c0c, 0x28b840854,
  0x28d483da3, 0x28f0dacd1, 0x290d456b8, 0x2929c3c32, 0x294655e1a, 0x2962fbd4d,
  0x297fb5aa6, 0x299c83702, 0x29b96533f, 0x29d65b03b, 0x29f364ed3, 0x2a1082fe8,
  0x2a2db5459, 0x2a4afbd07, 0x2a6856ad3, 0x2a85c5e9e, 0x2aa34994b, 0x2ac0e1bbd,
  0x2ade8e6d6, 0x2afc4fb7c, 0x2b1a25a92, 0x2b38104ff, 0x2b560fba9, 0x2b7423f75,
  0x2b924d14b, 0x2bb08b213, 0x2bcede2b5, 0x2bed4641b, 0x2c0bc372e, 0x2c2a55cd9,
  0x2c48fd607, 0x2c67ba3a3, 0x2c868c699, 0x2ca573fd7, 0x2cc47104a, 0x2ce3838e1,
  0x2d02aba89, 0x2d21e9633, 0x2d413cccf, 0x2d60a5f4e, 0x2d8024ea1, 0x2d9fb9bba,
  0x2dbf6478c, 0x2ddf2530b, 0x2dfefbf2a, 0x2e1ee8cde, 0x2e3eebd1d, 0x2e5f050dd,
  0x2e7f34914, 0x2e9f7a6ba, 0x2ebfd6ac8, 0x2ee049635, 0x2f00d29fb, 0x2f2172715,
  0x2f4228e7d, 0x2f62f612e, 0x2f83da026, 0x2fa4d4c5f, 0x2fc5e66d9, 0x2fe70f092,
  0x30084ea87, 0x3029a55ba, 0x304b13329, 0x306c983d7, 0x308e348c4, 0x30afe82f3,
  0x30d1b3368, 0x30f395b26, 0x31158fb31, 0x3137a148f, 0x3159ca845, 0x317c0b75a,
  0x319e642d6, 0x31c0d4bc1, 0x31e35d322, 0x3205fda05, 0x3228b6172, 0x324b86a75,
  0x326e6f619, 0x32917056b, 0x32b489979, 0x32d7bb34e, 0x32fb053fb, 0x331e67c8f,
  0x3341e2e19, 0x3365769aa, 0x338923054, 0x33ace8329, 0x33d0c633c, 0x33f4bd1a0,
  0x3418ccf6b, 0x343cf5db1, 0x346137d89, 0x348593008, 0x34aa07647, 0x34ce9515e,
  0x34f33c266, 0x3517fca78, 0x353cd6aaf, 0x3561ca426, 0x3586d77fa, 0x35abfe747,
  0x35d13f32b, 0x35f699cc4, 0x361c0e531, 0x36419cd93, 0x366745709, 0x368d082b6,
  0x36b2e51bc, 0x36d8dc53e, 0x36feede5f, 0x372519e44, 0x374b60614, 0x3771c16f3,
  0x37983d209, 0x37bed387e, 0x37e584b7a, 0x380c50c28, 0x383337bb0, 0x385a39b3f,
  0x388156bff, 0x38a88ef1f, 0x38cfe25ca, 0x38f751131, 0x391edb280, 0x394680aea,
  0x396e41b9d, 0x39961e5cd, 0x39be16aab, 0x39e62ab6b, 0x3a0e5a940, 0x3a36a6561,
  0x3a5f0e101, 0x3a8791d59, 0x3ab031b9f, 0x3ad8edd0c, 0x3b01c62d9, 0x3b2abae3f,
  0x3b53cc07b, 0x3b7cf9ac7, 0x3ba643e60, 0x3bcfaac83, 0x3bf92e66f, 0x3c22ced63,
  0x3c4c8c29e, 0x3c7666762, 0x3ca05dcf1, 0x3cca7248c, 0x3cf4a3f78, 0x3d1ef2ef9,
  0x3d495f454, 0x3d73e90cf, 0x3d9e905b1, 0x3dc955443, 0x3df437dcc, 0x3e1f38396,
  0x3e4a566ed, 0x3e759291b, 0x3ea0ecb6d, 0x3ecc64f31, 0x3ef7fb5b3, 0x3f23b0044,
  0x3f4f83033, 0x3f7b746d2, 0x3fa784571, 0x3fd3b2d65,
];
if (TAB.length !== COST_FP) throw new Error('stamps: TAB length');

// Upstream asserts sha256(",".join(str(v) for v in TAB)) == TAB_DIGEST at
// import; do the same so a corrupted copy fails loudly, not silently.
const TAB_DIGEST = '55ba3ce1df224895b0dfdc102eb4359fc2f5a7efefee68df0cc90c8a8ac24f48';
if (toHex(sha256Sync(new TextEncoder().encode(TAB.join(',')))) !== TAB_DIGEST) {
  throw new Error('stamps: TAB digest mismatch');
}

const TAB_BIG = TAB.map(BigInt);
const TWO_256 = 1n << 256n;

// ---- Cost arithmetic -------------------------------------------------------

export function costToFp(cost) {
  const v = Math.floor(Number(cost) * COST_FP + 0.5);
  return Math.max(0, Math.min(v, STAMP_COST_CAP * COST_FP));
}

export function costFromFp(fp) { return fp / COST_FP; }

export function quantizeCost(cost) { return costFromFp(costToFp(cost)); }

// RNS cost_to_bytes order: (integer, fraction).
export function costToBytes(cost) {
  const fp = costToFp(cost);
  return [(fp >> COST_FP_BITS) & 0xff, fp & 0xff];
}

export function targetFromFp(fp) {
  if (fp < 0 || fp > STAMP_COST_CAP * COST_FP) throw new RangeError('stamp cost out of range');
  const r = 256 * COST_FP - fp;
  const i = Math.floor(r / COST_FP), f = r % COST_FP;
  return (TAB_BIG[f] << BigInt(i)) >> MANTISSA_BITS;
}

export function targetFromCost(cost) { return targetFromFp(costToFp(cost)); }

// Target as 8 big-endian uint32 words, directly comparable with the
// SHA-256 state words. A target >= 2^256 accepts every digest.
export function targetWords(target) {
  if (target >= TWO_256) return new Array(8).fill(0xffffffff);
  const w = new Array(8);
  for (let i = 7; i >= 0; i--) { w[i] = Number(target & 0xffffffffn); target >>= 32n; }
  return w;
}

function bytesToBig(b) {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

function bitLength(v) { return v === 0n ? 0 : v.toString(2).length; }

// ---- Validation ------------------------------------------------------------

function concat(a, b) {
  const o = new Uint8Array(a.length + b.length);
  o.set(a, 0); o.set(b, a.length);
  return o;
}

export function stampValid(stamp, cost, workblock) {
  const wb = workblock || new Uint8Array(0);
  return bytesToBig(sha256Sync(concat(wb, stamp))) <= targetFromCost(cost);
}

// Work actually done, as a float on the 1/256 grid (RNS 1.6 stamp_value).
export function stampValue(workblock, stamp) {
  const hn = bytesToBig(sha256Sync(concat(workblock || new Uint8Array(0), stamp)));
  if (hn === 0n) return 256;
  const nb = Number(MANTISSA_BITS) + 1;
  const bl = bitLength(hn);
  const lz = 256 - bl;
  const mn = bl > nb ? hn >> BigInt(bl - nb) : hn << BigInt(nb - bl);
  // bisect_right(TAB, mn): count of entries <= mn.
  let lo = 0, hi = TAB_BIG.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (mn < TAB_BIG[mid]) hi = mid; else lo = mid + 1; }
  return costFromFp(((lz + 1) << COST_FP_BITS) - lo);
}

export function stampValueLegacy(workblock, stamp) {
  return 256 - bitLength(bytesToBig(sha256Sync(concat(workblock || new Uint8Array(0), stamp))));
}

// ---- LXMF workblock (SPEC §5.7.2 step 1) -----------------------------------

function packbUint(n) {
  if (n < 128) return Uint8Array.of(n);
  if (n < 256) return Uint8Array.of(0xcc, n);
  return Uint8Array.of(0xcd, n >> 8, n & 0xff);
}

export function stampWorkblock(material, expandRounds = WORKBLOCK_EXPAND_ROUNDS) {
  if (!expandRounds) return material;
  const out = new Uint8Array(expandRounds * 256);
  for (let n = 0; n < expandRounds; n++) {
    const salt = sha256Sync(concat(material, packbUint(n)));
    out.set(hkdfSha256Sync(256, material, salt), n * 256);
  }
  return out;
}

// ---- Search primitives (sync; shared by inline mode and the worker) ------

// Absorb the whole-block part of `prefix` once; return the midstate plus a
// pre-padded final buffer with a `size`-byte hole for the candidate.
export function makeSearcher(prefix, size) {
  const nFull = Math.floor(prefix.length / 64) * 64;
  const h = new Sha256();
  if (nFull) h.update(prefix.subarray(0, nFull));
  const tail = prefix.subarray(nFull);
  const finalLen = tail.length + size < 56 ? 64 : 128;
  const fb = new Uint8Array(finalLen);
  fb.set(tail, 0);
  fb[tail.length + size] = 0x80;
  writeLen64(fb, finalLen - 8, (prefix.length + size) * 8);
  return { mid: new Uint32Array(h.state), fb, holeOff: tail.length, size, st: new Uint32Array(8), W: new Uint32Array(64) };
}

function hashHole(s) {
  s.st.set(s.mid);
  compress(s.st, s.fb, 0, s.W);
  if (s.fb.length === 128) compress(s.st, s.fb, 64, s.W);
  return s.st;
}

function leq(st, T) {
  for (let i = 0; i < 8; i++) {
    const h = st[i] >>> 0;
    if (h < T[i]) return true;
    if (h > T[i]) return false;
  }
  return true;
}

// Try up to `maxRounds` detached stamps. The candidate is random, then
// counts up in its first four bytes (any bytes are a valid candidate; a
// random start keeps parallel workers disjoint).
export function searchHash(searcher, T, maxRounds) {
  const { fb, holeOff, size } = searcher;
  crypto.getRandomValues(fb.subarray(holeOff, holeOff + size));
  for (let r = 1; r <= maxRounds; r++) {
    if (leq(hashHole(searcher), T)) return { stamp: fb.slice(holeOff, holeOff + size), rounds: r };
    for (let j = holeOff; j < holeOff + Math.min(4, size); j++) {
      fb[j] = (fb[j] + 1) & 0xff;
      if (fb[j] !== 0) break;          // no carry
    }
  }
  return { stamp: null, rounds: maxRounds };
}

// Try up to `maxRounds` fresh X25519 keypairs whose public key, used as the
// stamp over `material`, meets the target (RNS _loop_key).
export function searchKey(searcher, T, maxRounds) {
  const { fb, holeOff } = searcher;
  for (let r = 1; r <= maxRounds; r++) {
    const priv = x25519.utils.randomPrivateKey();
    const pub = x25519.getPublicKey(priv);
    fb.set(pub, holeOff);
    if (leq(hashHole(searcher), T)) return { priv, pub, rounds: r };
  }
  return { priv: null, pub: null, rounds: maxRounds };
}

// ---- Async drivers ---------------------------------------------------------

const hasWorkers = typeof Worker !== 'undefined' && typeof window !== 'undefined';

function workerCount() {
  const hc = (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) || 2;
  return Math.max(1, Math.min(8, hc - 1));
}

const yieldTick = () => new Promise(r => setTimeout(r, 0));

// Runs a search job until found or timed out. job = { kind: 'hash'|'key',
// prefix, size, T }. Resolves { stamp } / { priv, pub } or null.
async function runSearch(job, { timeoutMs = 0, onProgress } = {}) {
  if (hasWorkers) {
    try { return await runInWorkers(job, timeoutMs, onProgress); }
    catch (e) { console.warn('stamps: worker search failed, running inline:', e); }
  }
  const searcher = makeSearcher(job.prefix, job.size);
  const deadline = timeoutMs ? Date.now() + timeoutMs : Infinity;
  const chunk = job.kind === 'key' ? 64 : 20000;
  let total = 0;
  while (Date.now() < deadline) {
    const res = job.kind === 'key' ? searchKey(searcher, job.T, chunk) : searchHash(searcher, job.T, chunk);
    total += res.rounds;
    if (res.stamp || res.priv) return { ...res, rounds: total };
    if (onProgress) onProgress(total);
    await yieldTick();
  }
  return null;
}

function runInWorkers(job, timeoutMs, onProgress) {
  return new Promise((resolve, reject) => {
    const n = workerCount();
    const workers = [];
    const counts = new Array(n).fill(0);
    let done = false, started = 0, failed = 0;
    const finish = (val) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      for (const w of workers) w.terminate();
      resolve(val);
    };
    const timer = timeoutMs ? setTimeout(() => finish(null), timeoutMs) : null;
    for (let i = 0; i < n; i++) {
      let w;
      try { w = new Worker(new URL('./stamp-worker.js', import.meta.url), { type: 'module' }); }
      catch (e) { if (!started) { clearTimeout(timer); return reject(e); } break; }
      started++;
      workers.push(w);
      w.onmessage = (ev) => {
        const m = ev.data;
        if (m.type === 'found') {
          counts[i] = m.rounds;
          finish({ stamp: m.stamp, priv: m.priv, pub: m.pub, rounds: counts.reduce((a, b) => a + b, 0) });
        } else if (m.type === 'progress') {
          counts[i] = m.rounds;
          if (onProgress) onProgress(counts.reduce((a, b) => a + b, 0));
        }
      };
      w.onerror = (e) => {
        e.preventDefault?.();
        if (++failed === started && !done) {
          done = true; clearTimeout(timer);
          for (const x of workers) x.terminate();
          reject(new Error(e.message || 'stamp worker error'));
        }
      };
      w.postMessage(job);
    }
  });
}

function checkCost(cost, cap = STAMP_COST_CAP) {
  if (!(Number(cost) >= 0) || Number(cost) > cap) throw new RangeError(`invalid stamp cost ${cost}`);
}

// Detached stamp of `size` bytes over `workblock` meeting `cost`.
// Resolves { stamp, value, rounds } or null on timeout.
export async function generateStamp(workblock, cost, { size = LXMF_STAMP_SIZE, timeoutMs = 0, onProgress } = {}) {
  checkCost(cost);
  const T = targetWords(targetFromCost(cost));
  const res = await runSearch({ kind: 'hash', prefix: workblock, size, T }, { timeoutMs, onProgress });
  if (!res || !res.stamp) return null;
  return { stamp: res.stamp, value: stampValue(workblock, res.stamp), rounds: res.rounds };
}

// Stamped X25519 keypair over `material` meeting `cost` (SPEC §6.1.1).
// Resolves { priv, pub, value, rounds } or null on timeout.
export async function generateStampedKey(material, cost, { timeoutMs = 0 } = {}) {
  checkCost(cost);
  const T = targetWords(targetFromCost(cost));
  const res = await runSearch({ kind: 'key', prefix: material, size: 32, T }, { timeoutMs });
  if (!res || !res.priv) return null;
  return { priv: res.priv, pub: res.pub, value: stampValue(material, res.pub), rounds: res.rounds };
}

// ---- Announce extension payload (SPEC §4.7) --------------------------------

export function destinationStampMaterial(destHash, publicKey, nameHash) {
  const m = new Uint8Array(destHash.length + publicKey.length + nameHash.length);
  m.set(destHash, 0); m.set(publicKey, destHash.length); m.set(nameHash, destHash.length + publicKey.length);
  return m;
}

// 0xC1 || ext_flags(0) || stamp(14) || lr_cost fraction byte || lr_cost integer byte
export function buildAnnounceExt(stamp, lrCost = LR_COST) {
  if (!stamp || stamp.length !== STAMPLENGTH) throw new Error('announce stamp must be 14 bytes');
  const [ci, cf] = costToBytes(Math.min(Number(lrCost), LINK_COST_CAP));
  const ext = new Uint8Array(EXTPAYLOADLENGTH);
  ext[0] = EXTPAYLOADMARKER;
  ext[1] = 0x00;
  ext.set(stamp, 2);
  ext[16] = cf;
  ext[17] = ci & 0x7f;
  return ext;
}

// Receive-side trailer handling, mirroring Identity.validate_announce:
// the trailer is stripped (and lr_cost recorded) ONLY when the stamp
// validates at `requiredValue`; otherwise app_data is returned verbatim.
// Returns { appData, stamped, valid, value, lrCost }.
export function parseAnnounceExt(appData, destHash, publicKey, nameHash, requiredValue = DESTINATION_COST) {
  const out = { appData, stamped: false, valid: false, value: null, lrCost: null };
  if (!appData || appData.length < EXTPAYLOADLENGTH) return out;
  const ext = appData.subarray(appData.length - EXTPAYLOADLENGTH);
  const anchor = ext[EXTPAYLOADLENGTH - 1];
  const extended = (anchor & 0x80) !== 0;
  const lrCost = costFromFp(((anchor & 0x7f) << COST_FP_BITS) | ext[EXTPAYLOADLENGTH - 2]);
  if (ext[0] !== EXTPAYLOADMARKER || extended || lrCost > STAMP_COST_CAP) return out;
  out.stamped = true;
  const stamp = ext.subarray(2, 2 + STAMPLENGTH);
  const wb = destinationStampMaterial(destHash, publicKey, nameHash);
  out.value = stampValue(wb, stamp);
  if (stampValid(stamp, requiredValue, wb)) {
    out.valid = true;
    out.lrCost = lrCost;
    out.appData = appData.subarray(0, appData.length - EXTPAYLOADLENGTH);
  }
  return out;
}

// ---- Path-request stamp (SPEC §7.1) ----------------------------------------

export function pathRequestStampMaterial(destHash, tag) {
  return concat(destHash, tag);
}

// ---- Misc -------------------------------------------------------------------

function toHex(b) {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}
