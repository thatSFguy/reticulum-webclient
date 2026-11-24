// js/identity-backup.js — Backward-compatible identity backup metadata.

'use strict';

export function exportIdentityBackup(identity, displayName) {
  return { ...identity.exportPrivateKeys(), displayName };
}

// Required keys retain their existing flat layout. Display-name metadata is
// optional so backups produced before it was included remain importable.
// Returns null when valid, else a human-readable reason.
export function validateIdentityImport(obj) {
  const is32 = (a) => Array.isArray(a) && a.length === 32 &&
    a.every(n => Number.isInteger(n) && n >= 0 && n <= 255);
  if (!obj || typeof obj !== 'object') return 'not a JSON object';
  if (!is32(obj.encPrivKey)) return 'missing or invalid encPrivKey (need 32 bytes)';
  if (!is32(obj.sigPrivKey)) return 'missing or invalid sigPrivKey (need 32 bytes)';
  if (obj.ratchetPrivKey != null && !is32(obj.ratchetPrivKey)) return 'invalid ratchetPrivKey';
  if (obj.displayName !== undefined &&
      (typeof obj.displayName !== 'string' || obj.displayName.length > 31)) {
    return 'invalid displayName (need text of at most 31 characters)';
  }
  return null;
}
