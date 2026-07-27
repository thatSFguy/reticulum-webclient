// js/propagation.js — LXMF propagation-node protocol helpers (SPEC §5.8).
//
// A propagation node stores messages for recipients who were offline and
// hands them over on request. Retrieval (§5.8.3) rides the generic §11
// REQUEST/RESPONSE protocol over an identify()-d Link:
//
//   /get [null, null]                  → [transient_id, ...] listing
//   /get [wanted, have, limit_kb]      → [timebase, [lxmf_data, ...]] bundle,
//                                        and the node purges `have` ids
//
// Each lxmf_data blob is dest_hash(16) || ciphertext — the same encrypted
// body the sender produced; the propagation node never decrypts it. These
// are pure wire-shape helpers; the sync orchestration lives in app.js.

'use strict';

import { decode as msgpackDecode } from '@msgpack/msgpack';

export const PN_NAME     = 'lxmf.propagation';
export const PN_GET_PATH = '/get';

// LXMPeer error codes returned as a bare integer RESPONSE (SPEC §5.8.2).
const PN_ERROR_NAMES = {
  0xf0: 'not identified on link (ERROR_NO_IDENTITY)',
  0xf1: 'access denied (ERROR_NO_ACCESS)',
  0xf2: 'rate-limited, retry later (ERROR_THROTTLED)',
  0xf3: 'invalid key (ERROR_INVALID_KEY)',
  0xf4: 'malformed request (ERROR_INVALID_DATA)',
  0xf5: 'not found (ERROR_NOT_FOUND)',
};

export function pnErrorName(code) {
  return PN_ERROR_NAMES[code] || `unknown error 0x${Number(code).toString(16)}`;
}

// A numeric RESPONSE to a /get is always an error code, never data.
export function pnResponseIsError(response) {
  return typeof response === 'number' || typeof response === 'bigint';
}

// Parse the 7-element lxmf.propagation announce app_data (SPEC §5.8.5).
// Element [5] MUST be a 3-element list — misparsing it as an int is the
// classic interop break the spec warns about. Returns null on any
// shape violation; callers treat that as "node config unknown".
export function parsePnAppData(bytes) {
  try {
    const d = msgpackDecode(bytes);
    if (!Array.isArray(d) || d.length < 7) return null;
    const costs = d[5];
    if (!Array.isArray(costs) || costs.length < 3) return null;
    return {
      timebase:             Number(d[1]) || 0,
      active:               !!d[2],
      perTransferLimitKb:   Number(d[3]) || 0,
      perSyncLimitKb:       Number(d[4]) || 0,
      stampCost:            Number(costs[0]) || 0,
      stampCostFlexibility: Number(costs[1]) || 0,
      peeringCost:          Number(costs[2]) || 0,
      metadata:             d[6] ?? null,
    };
  } catch {
    return null;
  }
}

// Normalize a /get [null, null] listing RESPONSE to an array of transient
// ids. Servers return plain ids; be lenient about [id, size] pairs (the
// node's internal shape, SPEC flow step 4) and about id length — upstream
// uses full 32-byte hashes, the spec text says 16. Empty/absent → [].
export function normalizeIdList(response) {
  if (!Array.isArray(response)) return [];
  const out = [];
  for (const entry of response) {
    const id = Array.isArray(entry) ? entry[0] : entry;
    if (id instanceof Uint8Array && (id.length === 16 || id.length === 32)) {
      out.push(id);
    }
  }
  return out;
}

// Normalize a /get message-fetch RESPONSE to { timebase, messages }.
// Canonical shape is [timebase, [lxmf_data, ...]] (SPEC §5.8.3); accept a
// still-packed msgpack blob and a bare blob list defensively.
export function normalizeMessageBundle(response) {
  let v = response;
  if (v instanceof Uint8Array) {
    try { v = msgpackDecode(v); } catch { throw new Error('malformed message bundle'); }
  }
  if (v == null) return { timebase: null, messages: [] };
  if (!Array.isArray(v)) throw new Error('unexpected message bundle shape');
  if (v.length === 2 &&
      (typeof v[0] === 'number' || typeof v[0] === 'bigint') &&
      Array.isArray(v[1])) {
    return { timebase: Number(v[0]), messages: v[1].filter(b => b instanceof Uint8Array) };
  }
  return { timebase: null, messages: v.filter(b => b instanceof Uint8Array) };
}
