// js/identity.js — Reticulum identity: Ed25519 signing + X25519 encryption.

'use strict';

import { ed25519, x25519 } from '@noble/curves/ed25519';
import { TRUNCATED_HASHLENGTH, NAME_HASH_LENGTH } from './reticulum.js';

// Retired-ratchet ring depth. 16 rotations × the 30-min rotation gate ≈ an
// 8-hour decryptable window for senders on stale announces (upstream RNS
// keeps 512, but its announces are rarer; 16 bounds the export blob size).
export const RATCHET_RING_DEPTH = 16;

// SHA-256 helper (returns Uint8Array)
export async function sha256(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

// Truncated hash (SHA-256 truncated to `length` bytes)
export async function truncatedHash(data, length = TRUNCATED_HASHLENGTH) {
  const full = await sha256(data);
  return full.subarray(0, length);
}

export class Identity {
  constructor() {
    this.encPrivKey = null;       // X25519 private key (32 bytes) — long-term identity
    this.encPubKey = null;        // X25519 public key  (32 bytes)
    this.sigPrivKey = null;       // Ed25519 private key (32 bytes)
    this.sigPubKey = null;        // Ed25519 public key  (32 bytes)
    this.ratchetPrivKey = null;         // X25519 private key (32 bytes) — current ratchet
    this.ratchetPubKey = null;          // X25519 public key  (32 bytes)
    this.prevRatchets = [];             // Retired ratchet privkeys, newest first, capped at
                                        // RATCHET_RING_DEPTH and PERSISTED via exportPrivateKeys.
                                        // The old 1-deep in-memory slot made the decryptable
                                        // window ≈ 2 announces — and ONE after any reload —
                                        // so senders holding a slightly stale announce (the
                                        // normal case on a slow LoRa mesh) encrypted to keys
                                        // we had already discarded: silent drop, no proof,
                                        // sender retries forever. Upstream RNS keeps 512.
    this.publicKey = null;        // Combined: encPub(32) + sigPub(32) = 64 bytes
    this.hash = null;             // Identity hash: SHA-256(publicKey)[0:16]
  }

  async generate() {
    this.encPrivKey = x25519.utils.randomPrivateKey();
    this.encPubKey = x25519.getPublicKey(this.encPrivKey);

    this.sigPrivKey = ed25519.utils.randomPrivateKey();
    this.sigPubKey = ed25519.getPublicKey(this.sigPrivKey);

    // Fresh ratchet keypair — included in every outbound announce so
    // other nodes encrypt to it instead of the long-term identity key.
    this.ratchetPrivKey = x25519.utils.randomPrivateKey();
    this.ratchetPubKey = x25519.getPublicKey(this.ratchetPrivKey);

    this.publicKey = new Uint8Array(64);
    this.publicKey.set(this.encPubKey, 0);
    this.publicKey.set(this.sigPubKey, 32);

    this.hash = await truncatedHash(this.publicKey);
  }

  async loadFromPrivateKeys(encPriv, sigPriv, ratchetPriv = null, prevRatchets = []) {
    this.encPrivKey = new Uint8Array(encPriv);
    this.sigPrivKey = new Uint8Array(sigPriv);
    this.encPubKey = x25519.getPublicKey(this.encPrivKey);
    this.sigPubKey = ed25519.getPublicKey(this.sigPrivKey);

    if (ratchetPriv) {
      this.ratchetPrivKey = new Uint8Array(ratchetPriv);
      this.ratchetPubKey = x25519.getPublicKey(this.ratchetPrivKey);
    }
    this.prevRatchets = (prevRatchets || [])
      .slice(0, RATCHET_RING_DEPTH)
      .map(k => new Uint8Array(k));

    this.publicKey = new Uint8Array(64);
    this.publicKey.set(this.encPubKey, 0);
    this.publicKey.set(this.sigPubKey, 32);

    this.hash = await truncatedHash(this.publicKey);
  }

  // Generate a fresh ratchet keypair without touching the long-term
  // identity keys. Used by the one-time migration that upgrades an
  // existing identity on first load under a ratchet-aware client.
  generateRatchet() {
    this.ratchetPrivKey = x25519.utils.randomPrivateKey();
    this.ratchetPubKey = x25519.getPublicKey(this.ratchetPrivKey);
  }

  // Rotate the ratchet: push the current ratchet privkey onto the retired
  // ring (kept for decrypting in-flight traffic from senders that haven't
  // seen the new announce yet), then generate a fresh ratchet. Long-term
  // enc/sig keys, identity_hash and destination_hash are untouched so
  // peers don't have to re-add us. Callers decide WHEN to rotate — see
  // sendAnnounce's RATCHET_ROTATE_MS gate (rotating on every announce
  // churned through the ring faster than peers could refresh their cache).
  rotateRatchet() {
    if (this.ratchetPrivKey) {
      this.prevRatchets.unshift(this.ratchetPrivKey);
      if (this.prevRatchets.length > RATCHET_RING_DEPTH) {
        this.prevRatchets.length = RATCHET_RING_DEPTH;
      }
    }
    this.ratchetPrivKey = x25519.utils.randomPrivateKey();
    this.ratchetPubKey = x25519.getPublicKey(this.ratchetPrivKey);
  }

  async loadFromPublicKey(pubKey) {
    this.publicKey = new Uint8Array(pubKey);
    this.encPubKey = this.publicKey.subarray(0, 32);
    this.sigPubKey = this.publicKey.subarray(32, 64);
    this.hash = await truncatedHash(this.publicKey);
  }

  sign(data) {
    return ed25519.sign(data, this.sigPrivKey);
  }

  verify(signature, data) {
    try {
      return ed25519.verify(signature, data, this.sigPubKey);
    } catch {
      return false;
    }
  }

  exportPrivateKeys() {
    const out = {
      encPrivKey: Array.from(this.encPrivKey),
      sigPrivKey: Array.from(this.sigPrivKey),
    };
    if (this.ratchetPrivKey) {
      out.ratchetPrivKey = Array.from(this.ratchetPrivKey);
    }
    if (this.prevRatchets.length) {
      out.prevRatchets = this.prevRatchets.map(k => Array.from(k));
    }
    return out;
  }
}

// Compute the destination hash for a SINGLE destination owned by `identityHash`.
//
// Matches upstream Reticulum's Destination.hash(identity, app_name, *aspects):
//   name_hash = SHA256(expand_name(None, app_name, *aspects))[:10]
//   dest_hash = SHA256(name_hash + identity.hash)[:16]
//
// Note: expand_name is called with identity=None, so the identity's hexhash
// is NOT part of the string fed to the name hash. The hexhash only appears
// in the human-readable Destination.name, never in on-wire hashes.
//
// fullName: e.g. "lxmf.delivery"
export async function computeDestinationHash(fullName, identityHash) {
  const nameHash = await truncatedHash(
    new TextEncoder().encode(fullName),
    NAME_HASH_LENGTH
  );
  const material = new Uint8Array(NAME_HASH_LENGTH + TRUNCATED_HASHLENGTH);
  material.set(nameHash, 0);
  material.set(identityHash, NAME_HASH_LENGTH);
  return truncatedHash(material);
}

// Compute the name_hash field used in announces. Same rule as above:
// identity hexhash is NOT part of the hashed string.
export async function computeNameHash(fullName) {
  return truncatedHash(
    new TextEncoder().encode(fullName),
    NAME_HASH_LENGTH
  );
}
