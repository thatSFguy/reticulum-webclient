// js/nomadnet.js — NomadNet REQUEST/RESPONSE protocol helpers (SPEC §11).
//
// NomadNet pages ride the generic over-Link request/response RPC: the
// client sends a REQUEST (context 0x09) carrying msgpack
// [timestamp, sha256(path)[:16], data]; the server replies inline
// (context 0x0A, msgpack [request_id, response]) or, for anything over
// ~360 bytes, as a Resource (§10) whose advertisement `q` field is the
// same request_id.
//
// These are pure helpers — the link orchestration / dispatch lives in
// app.js alongside the existing initiator-link code path.

'use strict';

import { encode as msgpackEncode, decode as msgpackDecode } from '@msgpack/msgpack';
import { sha256 } from './identity.js';

export const CTX_REQUEST  = 0x09;
export const CTX_RESPONSE = 0x0A;

// nomadnetwork.node aspect → name_hash 213e6311bcec54ab4fde (SPEC §11.6.1).
export const NN_NODE_ASPECT = 'nomadnetwork.node';
export const NN_DEFAULT_PATH = '/page/index.mu';

// SHA-256(path)[:16] — the path hash that goes on the wire (the path string
// itself never does).
export async function requestPathHash(path) {
  return (await sha256(new TextEncoder().encode(path))).subarray(0, 16);
}

// Build the REQUEST body: msgpack([timestamp, request_path_hash, data]).
// `data` is encoded directly into the list (NOT pre-packed) — null for a
// plain GET, a dict for form posts (SPEC §11.1 gotcha).
export async function buildRequest(path, data = null) {
  const pathHash = await requestPathHash(path);
  const envelope = [Date.now() / 1000, pathHash, data];
  return new Uint8Array(msgpackEncode(envelope));
}

// Parse a decrypted RESPONSE body (msgpack [request_id, response]).
// Returns { requestId: Uint8Array, response }. Throws on malformed.
export function parseResponse(plaintext) {
  const decoded = msgpackDecode(plaintext);
  if (!Array.isArray(decoded) || decoded.length < 2) {
    throw new Error('nomadnet: malformed response envelope');
  }
  const requestId = decoded[0] instanceof Uint8Array
    ? decoded[0]
    : new Uint8Array(decoded[0] || []);
  return { requestId, response: decoded[1] };
}

// The page bytes for a /page response may be bytes or a string (servers
// vary). Normalize to a UTF-8 string.
export function responseToText(response) {
  if (response == null) return '';
  if (typeof response === 'string') return response;
  if (response instanceof Uint8Array) {
    return new TextDecoder('utf-8', { fatal: false }).decode(response);
  }
  // /file/ responses come back as [filename_bytes, file_bytes] — not text.
  return '';
}

// Strip leading `#!` page headers (SPEC §11.6.4). Returns { headers, body }.
// headers: { cache, bg, fg } where any may be undefined.
export function stripPageHeaders(text) {
  const headers = {};
  const lines = text.split('\n');
  let i = 0;
  for (; i < lines.length; i++) {
    const line = lines[i];
    if (!line.startsWith('#!')) break;
    const directive = line.slice(2).trim();
    const eq = directive.indexOf('=');
    if (eq > 0) {
      const key = directive.slice(0, eq).trim();
      const val = directive.slice(eq + 1).trim();
      if (key === 'c') headers.cache = parseInt(val, 10);
      else if (key === 'bg') headers.bg = val;
      else if (key === 'fg') headers.fg = val;
    }
  }
  return { headers, body: lines.slice(i).join('\n') };
}

const HASH_RE = /^[0-9a-f]{32}$/;

// Parse a micron link target (SPEC §11.6.3). Returns one of:
//   { kind: 'page', path }                 same-node navigation
//   { kind: 'node', hash, path }           cross-node page fetch
//   { kind: 'lxmf', hash }                 open a conversation (not a page)
//   { kind: 'unknown', raw }
// Hashes are normalized to lowercase and strictly validated (no embedded
// separators) to avoid cache-poisoning aliases.
export function parseLinkTarget(target) {
  if (!target) return { kind: 'unknown', raw: target };
  let t = target.trim();

  // Shorthand `type@hash[:path]` (nnn → node, lxmf → conversation).
  const at = t.indexOf('@');
  if (at >= 0) {
    const type = t.slice(0, at);
    const rest = t.slice(at + 1);
    if (type === 'lxmf' || type === 'lxmf.delivery') {
      const hash = rest.split(':')[0].toLowerCase();
      return HASH_RE.test(hash) ? { kind: 'lxmf', hash } : { kind: 'unknown', raw: target };
    }
    if (type === 'nnn' || type === 'nomadnetwork.node') {
      return parseNodeTarget(rest);
    }
    return { kind: 'unknown', raw: target };
  }

  // Same-node path.
  if (t.startsWith('/')) return { kind: 'page', path: t };

  // Bare cross-node hash, optionally with `:/path`.
  return parseNodeTarget(t);
}

function parseNodeTarget(s) {
  const colon = s.indexOf(':');
  const hash = (colon >= 0 ? s.slice(0, colon) : s).toLowerCase();
  if (!HASH_RE.test(hash)) return { kind: 'unknown', raw: s };
  const path = colon >= 0 ? s.slice(colon + 1) : NN_DEFAULT_PATH;
  return { kind: 'node', hash, path: path.startsWith('/') ? path : NN_DEFAULT_PATH };
}
