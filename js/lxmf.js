// js/lxmf.js — LXMF message pack/unpack.
//
// LXMF packed format (before encryption):
//   destination_hash(16) + source_hash(16) + signature(64) + msgpack(payload)
//
// For single-packet opportunistic delivery, destination_hash is stripped
// (inferred from the RNS packet header). So on-wire LXMF payload is:
//   source_hash(16) + signature(64) + msgpack(payload)
//
// Payload msgpack array: [timestamp, title_bytes, content_bytes, fields_dict]
// Optional 5th element: stamp (proof-of-work, ignored for now)

'use strict';

import { encode as msgpackEncode, decode as msgpackDecode } from '@msgpack/msgpack';
import { Identity, sha256 } from './identity.js';
import { concatBytes } from './announce.js';
import { TRUNCATED_HASHLENGTH, SIGLENGTH } from './reticulum.js';

const DESTINATION_LENGTH = 16;
const SIGNATURE_LENGTH   = 64;

// ---- Unpack an LXMF message (after decryption) -----------------------

// Unpack from the on-wire format (destination_hash already known from RNS header):
//   source_hash(16) + signature(64) + msgpack(payload)
export async function unpackMessage(data, destHash) {
  if (data.length < TRUNCATED_HASHLENGTH + SIGNATURE_LENGTH + 1) {
    throw new Error('LXMF message too short');
  }

  const sourceHash = data.subarray(0, TRUNCATED_HASHLENGTH);
  const signature  = data.subarray(TRUNCATED_HASHLENGTH, TRUNCATED_HASHLENGTH + SIGNATURE_LENGTH);
  const msgpackData = data.subarray(TRUNCATED_HASHLENGTH + SIGNATURE_LENGTH);

  // Decode msgpack payload
  const payload = msgpackDecode(msgpackData);

  if (!Array.isArray(payload) || payload.length < 4) {
    throw new Error('Invalid LXMF payload structure');
  }

  const timestamp = payload[0];
  const title     = decodeField(payload[1]);
  const content   = decodeField(payload[2]);
  const fields    = payload[3] || {};
  const stamp     = payload.length > 4 ? payload[4] : null;

  // Upstream LXMF signs over msgpack.packb([timestamp, title, content,
  // fields]) — the 4-element payload WITHOUT the stamp — using Python's
  // u-msgpack-python. Re-encoding those 4 elements in JS via
  // @msgpack/msgpack rarely produces byte-identical output: Python
  // preserves dict insertion order, picks bin/str types based on
  // sender-side encoding decisions, and may widen ints/floats
  // differently than our JS encoder. So we compute the "canonical"
  // 4-element msgpack by PATCHING the on-wire 5-element bytes: flip
  // the fixarray header from 0x95 to 0x94, and strip the trailing
  // stamp bytes. That preserves the sender's exact byte encoding of
  // the first four elements — which is what was actually signed.
  let hashedPrefix = null;
  let hashPrefix   = null;
  if (payload.length === 5 && msgpackData.length > 1 && msgpackData[0] === 0x95) {
    const stampEncoded = new Uint8Array(msgpackEncode(payload[4]));
    const prefixLen = msgpackData.length - stampEncoded.length;
    if (prefixLen > 1 && prefixLen <= msgpackData.length) {
      const prefix = new Uint8Array(prefixLen);
      prefix.set(msgpackData.subarray(0, prefixLen));
      prefix[0] = 0x94;  // fixarray-4
      hashedPrefix = concatBytes([destHash, sourceHash, prefix]);
      hashPrefix   = await sha256(hashedPrefix);
    }
  }

  // Fallback: re-encode the 4-element payload in JS. Works when the
  // sender's msgpack encoding happens to match ours (typically simple
  // payloads with no fields dict).
  const strippedMsgpack = new Uint8Array(msgpackEncode([timestamp, payload[1], payload[2], fields]));
  const hashedStripped = concatBytes([destHash, sourceHash, strippedMsgpack]);
  const hashStripped   = await sha256(hashedStripped);

  // Fallback: sign over the raw on-wire msgpack. Handles unusual
  // sender builds where the stamp was appended as a separate blob
  // after a 4-element array rather than being packed as element 5.
  const hashedOriginal = concatBytes([destHash, sourceHash, msgpackData]);
  const hashOriginal   = await sha256(hashedOriginal);

  return {
    sourceHash,
    signature,
    timestamp,
    title,
    content,
    fields,
    stamp,
    destHash,
    msgpackData,
    // Primary = wire-prefix-patched 4-element msgpack (if available, else
    // re-encoded). verifyMessageSignature tries prefix first when set.
    hashedPart: hashedStripped,
    messageHash: hashStripped,
    msgpackForHash: strippedMsgpack,
    // Preferred view: byte-identical 4-element prefix extracted from wire.
    hashedPartPrefix: hashedPrefix,
    messageHashPrefix: hashPrefix,
    // Fallback view for the "no stamp stripping" variant.
    hashedPartOriginal: hashedOriginal,
    messageHashOriginal: hashOriginal,
    payloadElementCount: payload.length,
  };
}

// Unpack an LXMF message received over an established Link.
//
// Unlike opportunistic delivery (which strips the destination hash because
// it is inferred from the RNS packet header), link-delivered LXMF includes
// the full container:
//   destination_hash(16) + source_hash(16) + signature(64) + msgpack(payload)
// The leading destination hash comes from inside the link ciphertext, not
// from the outer packet header (which carries the link_id instead).
export async function unpackLinkMessage(data) {
  if (data.length < 2 * TRUNCATED_HASHLENGTH + SIGNATURE_LENGTH + 1) {
    throw new Error('LXMF link message too short');
  }
  const destHash = data.subarray(0, TRUNCATED_HASHLENGTH);
  const inner = data.subarray(TRUNCATED_HASHLENGTH);
  return unpackMessage(inner, destHash);
}

// Verify LXMF message signature using the sender's public key.
// Tries the stamp-stripped-and-re-encoded view first (upstream LXMF
// spec behavior), and if that fails falls back to signing over the
// raw on-wire msgpack bytes. Returns an object describing which
// variant matched, or {ok: false} if neither did.
export function verifyMessageSignature(message, senderIdentity) {
  // Try the wire-prefix-patched view first — this is what upstream LXMF
  // signs and it preserves byte-for-byte compatibility with the sender's
  // msgpack encoding (no re-encoding drift).
  if (message.hashedPartPrefix && message.messageHashPrefix) {
    const prefixSigned = concatBytes([message.hashedPartPrefix, message.messageHashPrefix]);
    if (senderIdentity.verify(message.signature, prefixSigned)) {
      return { ok: true, variant: 'prefix' };
    }
  }
  const strippedSigned = concatBytes([message.hashedPart, message.messageHash]);
  if (senderIdentity.verify(message.signature, strippedSigned)) {
    return { ok: true, variant: 'stripped' };
  }
  if (message.hashedPartOriginal && message.messageHashOriginal) {
    const originalSigned = concatBytes([message.hashedPartOriginal, message.messageHashOriginal]);
    if (senderIdentity.verify(message.signature, originalSigned)) {
      return { ok: true, variant: 'original' };
    }
  }
  return { ok: false };
}

// ---- Pack an outbound LXMF message -----------------------------------

// Encode a number as a msgpack float64 (0xcb + 8 bytes big-endian),
// regardless of whether the value is integer-valued.
function encodeFloat64(value) {
  const buf = new Uint8Array(9);
  buf[0] = 0xcb;
  new DataView(buf.buffer).setFloat64(1, value, false);  // big-endian
  return buf;
}

// Encode an LXMF field key as a msgpack INTEGER (§5.9 — field keys are
// 1-byte ints, e.g. 0x06 FIELD_IMAGE). The bundled encoder can't do this:
// its encodeMap calls Object.keys() (empty for a Map) and writes keys as
// strings, so it would silently drop fields or use string keys. Hence we
// hand-build the fields map.
function encodeIntKey(k) {
  if (k >= 0 && k <= 127) return new Uint8Array([k]);          // positive fixint
  if (k >= 128 && k <= 255) return new Uint8Array([0xcc, k]);  // uint8
  throw new Error(`LXMF field key out of range: ${k}`);
}

// Hand-encode the fields map with integer keys. Accepts a Map or a plain
// object; values are msgpack-encoded normally (arrays/bytes/strings work).
function encodeFieldsMap(fields) {
  const entries = fields instanceof Map
    ? [...fields.entries()]
    : Object.entries(fields || {}).map(([k, v]) => [Number(k), v]);
  if (entries.length === 0) return new Uint8Array([0x80]);     // empty fixmap
  if (entries.length > 15) throw new Error('too many LXMF fields');
  const parts = [new Uint8Array([0x80 | entries.length])];     // fixmap header
  for (const [k, v] of entries) {
    parts.push(encodeIntKey(k));
    parts.push(new Uint8Array(msgpackEncode(v)));
  }
  return concatBytes(parts);
}

export async function packMessage(sourceIdentity, destHash, sourceHash, title, content, fields = {}) {
  const titleBytes   = new TextEncoder().encode(title || '');
  const contentBytes = new TextEncoder().encode(content || '');
  const timestamp    = Date.now() / 1000;  // float seconds

  // Msgpack encode payload. The timestamp MUST be a float64 (0xcb) even when
  // it lands on a whole second — the default encoder routes integer-valued
  // numbers to a msgpack integer, which breaks the signed bytes against
  // upstream LXMF/umsgpack (RNS LXMF emits float64 unconditionally). We can't
  // force-float the whole array because the fields map uses integer keys, so
  // assemble the 4-element fixarray by hand with a hand-encoded float64 stamp.
  const msgpackData = concatBytes([
    new Uint8Array([0x94]),                       // fixarray, 4 elements
    encodeFloat64(timestamp),                     // [0] timestamp (float64)
    new Uint8Array(msgpackEncode(titleBytes)),    // [1] title (bin)
    new Uint8Array(msgpackEncode(contentBytes)),  // [2] content (bin)
    encodeFieldsMap(fields),                       // [3] fields (map, integer keys)
  ]);

  // Compute message hash
  const hashedPart = concatBytes([destHash, sourceHash, msgpackData]);
  const messageHash = await sha256(hashedPart);

  // Sign: signed_data = hashed_part + message_hash
  const signedData = concatBytes([hashedPart, messageHash]);
  const signature = sourceIdentity.sign(signedData);

  // On-wire format (destination stripped for opportunistic single-packet):
  //   source_hash(16) + signature(64) + msgpack(payload)
  return concatBytes([sourceHash, signature, msgpackData]);
}

// ---- Helpers ---------------------------------------------------------

function decodeField(val) {
  if (val instanceof Uint8Array || val instanceof ArrayBuffer) {
    return new TextDecoder().decode(val);
  }
  if (typeof val === 'string') return val;
  if (val === null || val === undefined) return '';
  return String(val);
}
