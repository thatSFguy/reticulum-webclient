// js/announce.js — Reticulum announce build/parse/validate.
//
// Announce data layout (after Reticulum header):
//   public_key(64) + name_hash(10) + random_hash(10) +
//   [ratchet(32) if context_flag] + signature(64) + [app_data]
//
// Signed data = dest_hash + public_key + name_hash + random_hash + [ratchet] + app_data

'use strict';

import { ed25519 } from '@noble/curves/ed25519';
import { decodeMulti as msgpackDecodeMulti } from '@msgpack/msgpack';
import { Identity, computeDestinationHash, computeNameHash, sha256, truncatedHash } from './identity.js';
import { KEYSIZE, SIGLENGTH, NAME_HASH_LENGTH, TRUNCATED_HASHLENGTH } from './reticulum.js';
import { toHex } from './kiss.js';
import { parseAnnounceExt, buildAnnounceExt, DESTINATION_COST } from './stamps.js';

// Parse an announce packet's payload (data after Reticulum header).
// Returns { publicKey, nameHash, randomHash, ratchet, signature, appData,
//           signedAppData, stamp, identityHash, destHash }
//
// `signedAppData` is app_data exactly as it rode the wire (what the §4.2
// signature covers). `appData` is the application part: since RNS 1.6
// app_data ends with an 18-byte stamp trailer (SPEC §4.7), and — like
// upstream Identity.validate_announce — we strip it only when the stamp
// validates at DESTINATION_COST. `stamp` = { stamped, valid, value, lrCost };
// lrCost is the link-request cost the destination wants (§6.1.1), or null.
export async function parseAnnounce(payload, contextFlag, destHashFromHeader) {
  if (payload.length < KEYSIZE + NAME_HASH_LENGTH + NAME_HASH_LENGTH + SIGLENGTH) {
    return null;  // too short
  }

  let offset = 0;
  const publicKey = payload.subarray(offset, offset + KEYSIZE); offset += KEYSIZE;
  const nameHash  = payload.subarray(offset, offset + NAME_HASH_LENGTH); offset += NAME_HASH_LENGTH;
  const randomHash = payload.subarray(offset, offset + NAME_HASH_LENGTH); offset += NAME_HASH_LENGTH;

  let ratchet = null;
  if (contextFlag) {
    ratchet = payload.subarray(offset, offset + 32); offset += 32;
  }

  const signature = payload.subarray(offset, offset + SIGLENGTH); offset += SIGLENGTH;
  const appData   = payload.subarray(offset);

  // Compute identity hash from public key
  const identityHash = await truncatedHash(publicKey);

  // Recompute the destination hash from name_hash + identity_hash and
  // verify it matches the header value (SPEC §4.5 step 3). This is the
  // core anti-spoofing check: the signature only proves the announcer
  // holds the private key for `public_key` — it does NOT prove that key
  // is bound to the dest_hash the packet claims. Without this check a
  // valid signature paired with a victim's dest_hash would be accepted,
  // letting an attacker hijack a known destination. dest_hash =
  // SHA256(name_hash + identity_hash)[:16].
  const expectedDestHash = await truncatedHash(concatBytes([nameHash, identityHash]));
  if (destHashFromHeader && !arraysEqual(expectedDestHash, destHashFromHeader)) {
    return null;  // dest_hash does not derive from this key — reject
  }
  const destHash = destHashFromHeader || expectedDestHash;

  const ext = parseAnnounceExt(appData, destHash, publicKey, nameHash, DESTINATION_COST);

  return {
    publicKey, nameHash, randomHash, ratchet, signature,
    appData: ext.appData, signedAppData: appData,
    stamp: { stamped: ext.stamped, valid: ext.valid, value: ext.value, lrCost: ext.lrCost },
    identityHash, destHash, appName: 'lxmf.delivery',
  };
}

// Validate an announce's Ed25519 signature
export function validateAnnounce(announce, destHashFromHeader) {
  const { publicKey, nameHash, randomHash, ratchet, signature } = announce;
  const appData = announce.signedAppData ?? announce.appData;

  // Build signed_data = dest_hash + public_key + name_hash + random_hash + [ratchet] + app_data
  const parts = [destHashFromHeader, publicKey, nameHash, randomHash];
  if (ratchet) parts.push(ratchet);
  parts.push(appData);

  const signedData = concatBytes(parts);
  const sigPubKey = publicKey.subarray(32, 64);  // Ed25519 public key

  try {
    return ed25519.verify(signature, signedData, sigPubKey);
  } catch {
    return false;
  }
}

// Build an announce for our identity.
//
// If `ratchetPub` is supplied, the announce carries the ratchet in
// the Reticulum 0.7+ layout: the 32-byte ratchet public key is
// inserted between `random_hash` and `signature` in the on-wire
// payload, and also included in `signed_data` (in the same
// position) so the initiator-side signature check matches.
//
// Callers that emit a ratchet announce MUST also set the packet
// header's `contextFlag` bit to 1 so receivers know to parse the
// extra 32 bytes. The returned `hasRatchet` flag is a convenience
// for the caller that drives `buildPacket`.
//
// If `destStamp` (14 bytes, SPEC §4.7) is supplied, the RNS 1.6 extension
// trailer `0xC1 00 || stamp || lr_cost` is appended to app_data before
// signing, advertising `lrCost` as our inbound link-request cost.
export async function buildAnnounce(identity, appName = 'lxmf.delivery', appData = new Uint8Array(0), ratchetPub = null, destStamp = null, lrCost = undefined) {
  const nameHash = await computeNameHash(appName);
  const destHash = await computeDestinationHash(appName, identity.hash);
  if (destStamp) appData = concatBytes([appData, buildAnnounceExt(destStamp, lrCost)]);

  // random_hash is 5 random bytes + 5-byte big-endian uint40 of the
  // emission Unix timestamp. Upstream RNS reads the trailing 5 bytes
  // via Transport.timebase_from_random_blob to make path-table merge
  // decisions when an inbound announce carries a higher hop count
  // (RNS/Transport.py:1700-1745, 3100-3101). Emitting 10 random bytes
  // there gives upstream a uniformly-random "timestamp" that's almost
  // always far-future (median ≈ year 19403), so legitimate later
  // announces lose against the stale-but-future-timestamped ghost
  // and our destination becomes unreachable until the path TTL
  // expires. See reticulum-specifications SPEC.md §4.1.
  const randomHash = new Uint8Array(10);
  crypto.getRandomValues(randomHash.subarray(0, 5));
  const ts = Math.floor(Date.now() / 1000);
  randomHash[5] = Math.floor(ts / 0x100000000) & 0xFF;
  randomHash[6] = (ts >>> 24) & 0xFF;
  randomHash[7] = (ts >>> 16) & 0xFF;
  randomHash[8] = (ts >>> 8)  & 0xFF;
  randomHash[9] =  ts         & 0xFF;

  // signed_data = dest_hash + public_key + name_hash + random_hash + [ratchet] + app_data
  const signedParts = [destHash, identity.publicKey, nameHash, randomHash];
  if (ratchetPub) signedParts.push(ratchetPub);
  signedParts.push(appData);
  const signedData = concatBytes(signedParts);
  const signature = identity.sign(signedData);

  // Wire payload = public_key(64) + name_hash(10) + random_hash(10) + [ratchet(32)] + signature(64) + app_data
  const payloadParts = [identity.publicKey, nameHash, randomHash];
  if (ratchetPub) payloadParts.push(ratchetPub);
  payloadParts.push(signature);
  payloadParts.push(appData);
  const payload = concatBytes(payloadParts);

  return { destHash, payload, hasRatchet: !!ratchetPub };
}

// Decode the FIRST msgpack object in `bytes`, ignoring anything after it
// (umsgpack semantics). SPEC §4.3: a parser MUST NOT require the value to
// end the buffer — an RNS 1.6 stamp trailer we couldn't validate (§4.7)
// is still attached. Throws if the buffer doesn't start with msgpack.
export function decodeFirstMsgpack(bytes) {
  for (const v of msgpackDecodeMulti(bytes)) return v;
  throw new Error('empty msgpack buffer');
}

// Return app_data with a trailing §4.7 extension removed if one is
// structurally present (marker byte in the right place), regardless of
// whether its stamp validated. Display-only helper: upstream keeps an
// unvalidated trailer, but no application field ever ends in one.
export function withoutAnnounceExt(appData) {
  if (appData && appData.length >= 18 && appData[appData.length - 18] === 0xC1
      && (appData[appData.length - 1] & 0x80) === 0) {
    return appData.subarray(0, appData.length - 18);
  }
  return appData;
}

// Parse the LXMF delivery announce app_data (SPEC §4.3):
//   [display_name(bin), stamp_cost_int|nil, [SF_*]?, stamp_cost_frac|nil]
// Returns { name, stampCost } — stampCost is the cost a sender must pay
// to message this destination (§5.7.4), validated to 1 <= c < 100, else
// null. Element [3] (exact fractional cost, LXMF 1.3) wins over [1].
export function parseLxmfAppData(appData) {
  const out = { name: extractDisplayName(appData), stampCost: null };
  try {
    const d = decodeFirstMsgpack(appData);
    if (Array.isArray(d)) {
      let c = null;
      if (d.length > 3 && typeof d[3] === 'number') c = d[3];
      else if (d.length > 1 && typeof d[1] === 'number') c = d[1];
      if (c !== null && Number.isFinite(c) && c >= 1 && c < 100) out.stampCost = c;
    }
  } catch { /* not msgpack — no cost */ }
  return out;
}

// Parse an interface-discovery announce's app_data (SPEC §4.8.1/§4.8.2):
//   flags(1) || msgpack(info) || stamp(32)        (flags & 0x02 → encrypted)
// `info` is keyed by small integers. Returns { encrypted } or
// { name, type, transport, reachableOn, port, lat, lon } — display only;
// we don't auto-connect to discovered interfaces, so the discovery stamp
// (§4.8.3) is not validated. Null if it doesn't parse.
export function parseDiscoveryAppData(appData) {
  if (!appData || appData.length < 2) return null;
  const flags = appData[0];
  if (flags & 0x02) return { encrypted: true };
  let info;
  try { info = decodeFirstMsgpack(appData.subarray(1)); } catch { return null; }
  if (!info || typeof info !== 'object') return null;
  const get = (k) => (info instanceof Map ? info.get(k) : (info[k] ?? info[String(k)]));
  const str = (v) => (typeof v === 'string' ? v : v instanceof Uint8Array ? new TextDecoder().decode(v) : null);
  const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
  return {
    encrypted: false,
    name: str(get(0xFF)),
    type: str(get(0x00)),
    transport: get(0x01) === true,
    reachableOn: str(get(0x02)),
    port: num(get(0x06)),
    lat: num(get(0x03)),
    lon: num(get(0x04)),
  };
}

// Extract display name from announce app_data.
// LXMF/Sideband announces app_data as msgpack, typically:
//   [display_name_bytes, stamp_cost, ...]
// or sometimes a raw UTF-8 string. Try msgpack first, fall back to UTF-8.
export function extractDisplayName(appData) {
  if (!appData || appData.length === 0) return null;

  // Try msgpack decode (first object only; trailing bytes tolerated)
  try {
    const decoded = decodeFirstMsgpack(appData);
    if (Array.isArray(decoded) && decoded.length > 0) {
      // First element is the display name (bytes or string)
      const name = decoded[0];
      if (name instanceof Uint8Array) {
        return new TextDecoder('utf-8', { fatal: false }).decode(name);
      }
      if (typeof name === 'string') return name;
    }
    if (typeof decoded === 'string') return decoded;
    if (decoded instanceof Uint8Array) {
      return new TextDecoder('utf-8', { fatal: false }).decode(decoded);
    }
  } catch {
    // Not valid msgpack — fall through to raw UTF-8
  }

  // Fall back: try raw UTF-8 (strict, returns null on invalid bytes),
  // minus any unvalidated §4.7 trailer (0xC1 is never valid UTF-8).
  try {
    const body = withoutAnnounceExt(appData);
    if (!body.length) return null;
    return new TextDecoder('utf-8', { fatal: true }).decode(body);
  } catch {
    return null;
  }
}

// ---- Helpers --------------------------------------------------------

function concatBytes(arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function arraysEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export { concatBytes, arraysEqual };
