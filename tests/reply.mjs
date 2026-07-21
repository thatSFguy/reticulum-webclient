// tests/reply.mjs
//
// Unit tests for reply-to threading (SPEC §5.9.9): FIELD_REPLY_TO (0x30)
// + optional FIELD_REPLY_QUOTE (0x31) must round-trip through the LXMF
// pack/unpack layer byte-exact — the 0x30 value is the raw 32-byte
// canonical message_id (NOT hex), and the signature must still verify
// with the fields present (int-keyed fields map, hand-encoded by
// lxmf.js's encodeFieldsMap).
//
// Run with `node tests/reply.mjs` (exits non-zero on any failure).

import { Identity, computeDestinationHash } from "../js/identity.js";
import { packMessage, unpackMessage, verifyMessageSignature } from "../js/lxmf.js";

let pass = 0, fail = 0; const errs = [];
const ok = (c, m) => { if (c) pass++; else { fail++; errs.push(m); } };

// Read either a Map- or object-shaped msgpack field map (mirrors app.js
// getField — @msgpack/msgpack surfaces int keys as numeric-string object
// keys).
const getField = (fields, key) =>
  fields instanceof Map ? fields.get(key) : (fields[key] ?? fields[String(key)]);

const bytesEqual = (a, b) =>
  a instanceof Uint8Array && b instanceof Uint8Array &&
  a.length === b.length && a.every((x, i) => x === b[i]);

async function main() {
  const alice = new Identity();
  await alice.generate();
  const aliceDest = await computeDestinationHash("lxmf.delivery", alice.hash);
  const bob = new Identity();
  await bob.generate();
  const bobDest = await computeDestinationHash("lxmf.delivery", bob.hash);

  // ---- The message being replied to -----------------------------------
  const { payload: origPayload, messageId: origId } = await packMessage(
    alice, bobDest, aliceDest, "", "original message", new Map()
  );
  ok(origId.length === 32, "canonical message_id is 32 bytes");
  const origUnpacked = await unpackMessage(origPayload, bobDest);
  ok(bytesEqual(new Uint8Array(origUnpacked.messageId), new Uint8Array(origId)),
    "receiver-computed message_id matches sender's (reply target key)");

  // ---- A reply carrying FIELD_REPLY_TO (0x30) -------------------------
  const replyFields = new Map([[0x30, new Uint8Array(origId)]]);
  const { payload: replyPayload } = await packMessage(
    bob, aliceDest, bobDest, "", "the reply text", replyFields
  );
  const reply = await unpackMessage(replyPayload, aliceDest);
  ok(reply.content === "the reply text", "reply content survives");
  const replyTo = getField(reply.fields, 0x30);
  ok(replyTo instanceof Uint8Array, "fields[0x30] decodes as raw bytes (not hex string)");
  ok(bytesEqual(replyTo, new Uint8Array(origId)),
    "fields[0x30] is byte-exact the target's canonical message_id");
  ok(verifyMessageSignature(reply, bob).ok,
    "reply signature verifies with the 0x30 field present");

  // ---- Reply with the optional FIELD_REPLY_QUOTE (0x31) ---------------
  const quoted = new TextEncoder().encode("original message");
  const quoteFields = new Map([
    [0x30, new Uint8Array(origId)],
    [0x31, quoted],
  ]);
  const { payload: qPayload } = await packMessage(
    bob, aliceDest, bobDest, "", "reply with quote", quoteFields
  );
  const q = await unpackMessage(qPayload, aliceDest);
  ok(bytesEqual(getField(q.fields, 0x30), new Uint8Array(origId)),
    "0x30 survives alongside 0x31");
  const qv = getField(q.fields, 0x31);
  ok(qv != null && new TextDecoder().decode(qv) === "original message",
    "fields[0x31] quote round-trips as UTF-8");
  ok(verifyMessageSignature(q, bob).ok,
    "signature verifies with both reply fields present");

  console.error(`reply.mjs: ${pass} passed, ${fail} failed`);
  for (const e of errs) console.error(`  FAIL: ${e}`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
