// js/aln-tunnel.js — agnostic-LoRa-Net tunnel envelope helpers.
//
// JS port of the mobile app's AgnosticLoraTunnel (Kotlin), kept byte-for-byte
// faithful to the node firmware (src/main.cpp tunnel_emit/tunnel_rx_frame) and
// the reference AgnosticLoraInterface.py. Inside each HDLC frame is a typed,
// length-prefixed address followed by the opaque Reticulum packet:
//
//   frame body := [u8 addr_type][u8 addr_len][addr bytes…][payload…]
//     outbound (host → node): addr = dst node id  → mesh routes there
//     inbound  (node → host): addr = src node id  ← arrived from there
//
// addr_type 0x01 = LOCATOR (a node id) is the only live type; 0x02 = IDENTITY
// is reserved and rejected by current firmware — we never emit it and ignore it
// inbound. As of firmware v2 the node id is a 16-byte blake2b hash in canonical
// byte order (no endianness): display hex maps straight to wire bytes, byte[0]
// first (matches the firmware's nid_write/nid_read memcpy).

'use strict';

export const NODE_ID_BYTES        = 16;
export const ADDR_TYPE_LOCATOR    = 0x01;
export const ADDR_TYPE_IDENTITY   = 0x02;   // reserved — never emitted, ignored inbound
export const ADVERTISED_NAME_PREFIX        = 'ALN-';
export const LEGACY_ADVERTISED_NAME_PREFIX = 'AgnLoRa-';

const HEX = '0123456789ABCDEF';

// Wrap a raw Reticulum `payload` in a LOCATOR envelope addressed to `locator`
// (wire-form node id). Returns the HDLC frame *body*; the caller HDLC-frames it.
export function encodeLocatorFrame(locator, payload) {
  const out = new Uint8Array(2 + locator.length + payload.length);
  out[0] = ADDR_TYPE_LOCATOR;
  out[1] = locator.length;
  out.set(locator, 2);
  out.set(payload, 2 + locator.length);
  return out;
}

// Strip the envelope from a de-HDLC'd frame body and return the raw Reticulum
// packet, or null when it's not a LOCATOR frame we can use (too short, truncated
// against its own addr_len, or a non-LOCATOR type — matching tunnel_rx_frame).
// A bare envelope with no payload decodes to an empty array, not null.
export function decodeFrame(frame) {
  if (frame.length < 2) return null;
  const addrType = frame[0];
  const addrLen  = frame[1];
  if (addrType !== ADDR_TYPE_LOCATOR) return null;
  if (frame.length < 2 + addrLen) return null;
  return frame.slice(2 + addrLen);
}

// The source node id (display/directory hex, uppercase) of a de-HDLC'd inbound
// frame, or null for frames decodeFrame would reject. The router uses it for
// reverse-path learning. addr_len-driven, so any locator width round-trips.
export function sourceFromFrame(frame) {
  if (frame.length < 2) return null;
  const addrType = frame[0];
  const addrLen  = frame[1];
  if (addrType !== ADDR_TYPE_LOCATOR) return null;
  if (addrLen === 0 || frame.length < 2 + addrLen) return null;
  let s = '';
  for (let i = 2; i < 2 + addrLen; i++) {
    s += HEX[frame[i] >>> 4] + HEX[frame[i] & 0x0F];
  }
  return s;
}

// Parse a node-id hex string into its NODE_ID_BYTES wire form (canonical order,
// no endianness — byte[0] is the first hex pair). Case-insensitive, optional 0x.
// Returns null unless the string is exactly NODE_ID_BYTES*2 hex digits.
export function locatorFromHex(hex) {
  const clean = (hex || '').trim().replace(/^0x/i, '');
  if (clean.length !== NODE_ID_BYTES * 2) return null;
  const out = new Uint8Array(NODE_ID_BYTES);
  for (let i = 0; i < NODE_ID_BYTES; i++) {
    const hi = parseInt(clean[2 * i], 16);
    const lo = parseInt(clean[2 * i + 1], 16);
    if (Number.isNaN(hi) || Number.isNaN(lo)) return null;
    out[i] = (hi << 4) | lo;
  }
  return out;
}

// True if `hex` is a syntactically valid uplink node id.
export function isValidNodeIdHex(hex) {
  return locatorFromHex(hex) !== null;
}

// True if `name` is one of our nodes' advertised names (current ALN- or legacy
// AgnLoRa-). For a BLE scan filter only; the matched name is never a node-id
// source (a friendly name carries no id; the default carries only 8 of 32 hex).
export function isAdvertisedName(name) {
  if (!name) return false;
  const n = name.toLowerCase();
  return n.startsWith(ADVERTISED_NAME_PREFIX.toLowerCase()) ||
         n.startsWith(LEGACY_ADVERTISED_NAME_PREFIX.toLowerCase());
}

// The display label after the advertised-name prefix (ALN-kitchen → "kitchen"),
// or null if the name is absent / lacks a known prefix. DISPLAY ONLY — never a
// node-id source.
export function labelFromAdvertisedName(name) {
  if (!name) return null;
  for (const prefix of [ADVERTISED_NAME_PREFIX, LEGACY_ADVERTISED_NAME_PREFIX]) {
    if (name.toLowerCase().startsWith(prefix.toLowerCase())) {
      const label = name.substring(prefix.length).trim();
      return label.length ? label : null;
    }
  }
  return null;
}

// Uppercase hex of a byte array (shared with the router).
export function toHexUpper(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += HEX[bytes[i] >>> 4] + HEX[bytes[i] & 0x0F];
  }
  return s;
}
