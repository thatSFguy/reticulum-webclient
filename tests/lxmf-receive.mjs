// tests/lxmf-receive.mjs
//
// LXMF receive/retry helpers (SPEC §5.9.3, §5.5, flows/lxmf-outbound-retry):
//  - FIELD_AUDIO mode byte → presentation (Opus plays, Codec2 downloads)
//  - retry re-encryption: encrypting the same packed LXMF twice yields
//    different ciphertexts (so relays don't drop the retry as a duplicate)
//    that both decrypt to the same payload with the same message_id.
// Run with `node tests/lxmf-receive.mjs`.

import { Identity, computeDestinationHash } from "../js/identity.js";
import { encrypt, decrypt } from "../js/crypto.js";
import { packMessage, unpackMessage, audioDescriptor } from "../js/lxmf.js";

let pass = 0, fail = 0;
const errs = [];
const ok = (c, m) => { if (c) pass++; else { fail++; errs.push(m); } };
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

async function main() {
  // ---- §5.9.3 audio modes ----
  const ogg = new Uint8Array([0x4f, 0x67, 0x67, 0x53, 1, 2, 3]);
  ok(audioDescriptor(0x10, ogg).kind === "audio" && audioDescriptor(0x10, ogg).mime === "audio/ogg", "AM_OPUS_OGG should play");
  ok(audioDescriptor(0x19, ogg).kind === "audio", "AM_OPUS_LOSSLESS should play");
  ok(audioDescriptor(0x03, new Uint8Array(8)).kind === "file", "Codec2 must not be fed to <audio>");
  ok(/codec2/i.test(audioDescriptor(0x09, new Uint8Array(8)).name), "Codec2 download name");
  ok(audioDescriptor(0xff, ogg).kind === "audio", "AM_CUSTOM with an OGG header should play");
  ok(audioDescriptor(0xff, new Uint8Array(8)).kind === "file", "AM_CUSTOM without OGG header → download");

  // ---- retry re-encryption ----
  const alice = new Identity(); await alice.generate();
  const bob = new Identity(); await bob.generate();
  const aliceDest = await computeDestinationHash("lxmf.delivery", alice.hash);
  const bobDest = await computeDestinationHash("lxmf.delivery", bob.hash);
  const { payload, messageId } = await packMessage(alice, bobDest, aliceDest, "", "retry me", new Map());
  const c1 = await encrypt(payload, bob.ratchetPubKey, bob.hash);
  const c2 = await encrypt(payload, bob.ratchetPubKey, bob.hash);
  ok(toHex(c1) !== toHex(c2), "two encryptions of one LXMF must differ (fresh ephemeral key)");
  for (const [i, c] of [c1, c2].entries()) {
    const plain = await decrypt(c, [bob.ratchetPrivKey, bob.encPrivKey], bob.hash);
    const m = await unpackMessage(plain, bobDest);
    ok(m.content === "retry me" && toHex(m.messageId) === toHex(messageId), `attempt ${i + 1} decrypts to the same message_id`);
  }

  if (fail) {
    console.error(`lxmf-receive.mjs: ${fail} failed, ${pass} passed:\n  - ${errs.join("\n  - ")}`);
    process.exit(1);
  }
  console.log(`lxmf-receive.mjs: ${pass} checks passed`);
}

main().catch((e) => { console.error(`lxmf-receive.mjs crashed: ${e.stack || e}`); process.exit(1); });
