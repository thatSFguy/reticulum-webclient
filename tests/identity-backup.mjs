// Run with node tests/identity-backup.mjs; no browser or dependencies required.
import assert from 'node:assert/strict';
import test from 'node:test';
import { exportIdentityBackup, validateIdentityImport } from '../js/identity-backup.js';

// Fixed test data only, never a user's identity or generated private keys.
const keys = {
  encPrivKey: Array(32).fill(1),
  sigPrivKey: Array(32).fill(2),
  ratchetPrivKey: Array(32).fill(3),
  prevRatchets: [Array(32).fill(4)],
};
const identity = { exportPrivateKeys: () => keys };

for (const displayName of ['WebClient', 'Jiří 🦊', '', 'x'.repeat(31)]) {
  test(`display name round-trips through JSON (${JSON.stringify(displayName)})`, () => {
    const backup = exportIdentityBackup(identity, displayName);
    const imported = JSON.parse(JSON.stringify(backup));
    assert.equal(validateIdentityImport(imported), null);
    assert.equal(imported.displayName, displayName);
    for (const key of Object.keys(keys)) assert.deepEqual(imported[key], keys[key]);
    assert.equal(Object.hasOwn(keys, 'displayName'), false, 'export does not mutate identity data');
  });
}

test('legacy key-only and ratchet-bearing backups remain importable', () => {
  assert.equal(validateIdentityImport({ encPrivKey: keys.encPrivKey, sigPrivKey: keys.sigPrivKey }), null);
  assert.equal(validateIdentityImport(keys), null);
  assert.equal(Object.hasOwn(keys, 'displayName'), false);
});

for (const displayName of [null, 42, {}, [], 'x'.repeat(32)]) {
  test(`invalid display-name metadata is rejected (${JSON.stringify(displayName)})`, () => {
    assert.match(validateIdentityImport({ ...keys, displayName }), /invalid displayName/);
  });
}

test('existing private-key validation is preserved', () => {
  assert.match(validateIdentityImport(null), /not a JSON object/);
  assert.match(validateIdentityImport({ ...keys, encPrivKey: [] }), /invalid encPrivKey/);
  assert.match(validateIdentityImport({ ...keys, sigPrivKey: Array(32).fill(256) }), /invalid sigPrivKey/);
  assert.match(validateIdentityImport({ ...keys, ratchetPrivKey: Array(32).fill(1.5) }), /invalid ratchetPrivKey/);
});
