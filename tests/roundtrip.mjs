// tests/roundtrip.mjs
//
// Level 2 test harness. Runs the web client's actual JavaScript modules
// under Node, generates a set of test vectors (two fresh identities, an
// announce, an encrypted LXMF message, a link request / LRPROOF pair),
// and prints them to stdout as a JSON document. The Python runner
// tests/run_tests.py captures that JSON and validates each vector
// against RNS's reference implementation.
//
// Run directly with `node tests/roundtrip.mjs` to see the vectors;
// run via `python tests/run_tests.py` to run the validation step too.

import { Identity, computeDestinationHash } from "../js/identity.js";
import { buildAnnounce, parseAnnounce } from "../js/announce.js";
import { encrypt } from "../js/crypto.js";
import { packMessage } from "../js/lxmf.js";
import { Link, computePacketFullHash } from "../js/link.js";
import {
  buildPacket,
  parsePacket,
  HEADER_1,
  DEST_SINGLE,
  DEST_LINK,
  PACKET_ANNOUNCE,
  PACKET_DATA,
  PACKET_LINKREQ,
  PACKET_PROOF,
} from "../js/reticulum.js";
import { encode as msgpackEncode } from "@msgpack/msgpack";

const toHex = (b) =>
  Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (s) =>
  new Uint8Array(s.match(/.{1,2}/g).map((h) => parseInt(h, 16)));

function exportIdentity(id, destHash) {
  return {
    encPriv: toHex(id.encPrivKey),
    sigPriv: toHex(id.sigPrivKey),
    ratchetPriv: toHex(id.ratchetPrivKey),
    encPub: toHex(id.encPubKey),
    sigPub: toHex(id.sigPubKey),
    ratchetPub: toHex(id.ratchetPubKey),
    publicKey: toHex(id.publicKey),
    identityHash: toHex(id.hash),
    destHash: toHex(destHash),
  };
}

async function main() {
  // ---- Two fresh identities ------------------------------------------------
  const alice = new Identity();
  await alice.generate();
  const aliceDestHash = await computeDestinationHash("lxmf.delivery", alice.hash);

  const bob = new Identity();
  await bob.generate();
  const bobDestHash = await computeDestinationHash("lxmf.delivery", bob.hash);

  // ---- Scenario A: Alice emits an announce with a ratchet ------------------
  const aliceName = "AliceTest";
  const appData = new Uint8Array(
    msgpackEncode([new TextEncoder().encode(aliceName), 0])
  );
  const {
    destHash: announceDestHash,
    payload: announcePayload,
    hasRatchet,
  } = await buildAnnounce(alice, "lxmf.delivery", appData, alice.ratchetPubKey);

  const announcePacket = buildPacket({
    headerType: HEADER_1,
    contextFlag: hasRatchet ? 1 : 0,
    destType: DEST_SINGLE,
    packetType: PACKET_ANNOUNCE,
    destHash: announceDestHash,
    context: 0x00,
    payload: announcePayload,
  });

  // Parse our own announce bytes back through parseAnnounce so the
  // self-consistency of our encode/decode pair is checked locally
  // before Python touches it. If this throws we never get to Python.
  const pktForParse = parsePacket(announcePacket);
  if (!pktForParse) throw new Error("self-parse: parsePacket returned null for our own announce");
  const parsed = await parseAnnounce(pktForParse.payload, pktForParse.contextFlag, pktForParse.destHash);
  if (!parsed || !parsed.ratchet) {
    throw new Error("self-parse: parseAnnounce did not recover a ratchet from our own announce");
  }
  if (toHex(parsed.ratchet) !== toHex(alice.ratchetPubKey)) {
    throw new Error("self-parse: ratchet round-trip mismatch");
  }

  // SPEC §2.4 hop-count bound: hops 0..127 parse, hops >= 128 are
  // dropped as malformed (mirrors RNS >= 1.3.8 Packet.unpack).
  const hopProbe = Uint8Array.from(announcePacket);
  hopProbe[1] = 127;
  if (!parsePacket(hopProbe)) throw new Error("hop bound: parsePacket rejected valid hops=127");
  hopProbe[1] = 128;
  if (parsePacket(hopProbe)) throw new Error("hop bound: parsePacket accepted malformed hops=128");
  hopProbe[1] = 255;
  if (parsePacket(hopProbe)) throw new Error("hop bound: parsePacket accepted malformed hops=255");

  // ---- Scenario B: Alice sends an opportunistic LXMF message to Bob --------
  const content = "hello from tests/roundtrip.mjs";
  const { payload: lxmfPayload } = await packMessage(
    alice,
    bobDestHash,
    aliceDestHash,
    "",
    content,
    {}
  );
  // Encrypt to Bob's ratchet pub (what sendMessage would do if Bob's
  // most recent announce carried a ratchet, which it does in this
  // harness). Bob's decrypt path will try ratchet-priv first, which
  // is what the web client now does.
  const encrypted = await encrypt(lxmfPayload, bob.ratchetPubKey, bob.hash);
  const dataPacket = buildPacket({
    headerType: HEADER_1,
    destType: DEST_SINGLE,
    packetType: PACKET_DATA,
    destHash: bobDestHash,
    context: 0x00,
    payload: encrypted,
  });

  // ---- Scenario C: Alice is a link responder; Python (or a caller supplied
  // LINKREQUEST on argv) drives the initiator side. For self-contained
  // testing in CI we construct a plausible LINKREQUEST body here with a
  // mock initiator ephemeral pair, run it through Link.validateRequest,
  // and emit the resulting LRPROOF packet. The signature can be verified
  // against Alice's long-term sig pub alone, so Python can check this
  // without ever holding the initiator's private keys.
  //
  // The LINKREQUEST body needs to look byte-identical to what a real
  // Reticulum initiator would emit: a 32-byte X25519 pubkey, a 32-byte
  // Ed25519 pubkey, and 3 bytes of signalling for mtu=500 mode=1.
  const peerX = fromHex(
    "4a4b4c4d4e4f5051525354555657585960616263646566676869707172737475"
  );
  const peerSig = fromHex(
    "8081828384858687888990919293949596979899aabbccddeeff000102030405"
  );
  const lrSignalling = new Uint8Array([0x20, 0x01, 0xf4]); // mtu=500 mode=1
  const lrData = new Uint8Array(32 + 32 + 3);
  lrData.set(peerX, 0);
  lrData.set(peerSig, 32);
  lrData.set(lrSignalling, 64);
  const lrPacket = buildPacket({
    headerType: HEADER_1,
    destType: DEST_SINGLE,
    packetType: PACKET_LINKREQ,
    destHash: aliceDestHash,
    context: 0x00,
    payload: lrData,
  });

  const pktForLink = parsePacket(lrPacket);
  const { link } = await Link.validateRequest(pktForLink, alice);
  const lrProofPacket = buildPacket({
    headerType: HEADER_1,
    destType: DEST_LINK,
    packetType: PACKET_PROOF,
    destHash: link.linkId,
    context: 0xff,
    payload: link.cachedProofData,
  });

  // ---- Scenario D: full Alice-initiates-link-to-Bob 4-way handshake -------
  // Alice is the initiator. She creates a Link targeting Bob's destination
  // using Bob's long-term Ed25519 sig pub (which she would have learned from
  // his earlier announce) and his destination hash. She packs a LINKREQUEST,
  // Bob runs it through Link.validateRequest (responder path, already tested),
  // Alice runs the resulting LRPROOF through link.validateProof, both sides
  // go ACTIVE, Alice encrypts a test payload with the link session key, and
  // Bob decrypts it with the same key. If any byte of the handshake drifts
  // this scenario fails.
  const { link: aliceInitiator, requestData: aliceLrData } = Link.createInitiator(
    bob.sigPubKey,
    bobDestHash,
  );
  const aliceLrPacket = buildPacket({
    headerType: HEADER_1,
    destType:   DEST_SINGLE,
    packetType: PACKET_LINKREQ,
    destHash:   bobDestHash,
    context:    0x00,
    payload:    aliceLrData,
  });
  const aliceLrParsed = parsePacket(aliceLrPacket);
  await aliceInitiator.setLinkIdFromPacket(aliceLrParsed);

  // Bob (responder) validates Alice's LINKREQUEST.
  const { link: bobResponder, proofData: bobProofData } =
    await Link.validateRequest(aliceLrParsed, bob);

  // link_id must match on both sides or the whole handshake is wrong.
  if (toHex(bobResponder.linkId) !== toHex(aliceInitiator.linkId)) {
    throw new Error(
      `initiator/responder link_id mismatch: alice=${toHex(aliceInitiator.linkId)} bob=${toHex(bobResponder.linkId)}`
    );
  }

  // Bob packs the LRPROOF packet the same way the web client does.
  const bobLrProofPacket = buildPacket({
    headerType: HEADER_1,
    destType:   DEST_LINK,
    packetType: PACKET_PROOF,
    destHash:   bobResponder.linkId,
    context:    0xff,
    payload:    bobProofData,
  });

  // Alice validates the LRPROOF on her pending initiator link.
  const aliceProofParsed = parsePacket(bobLrProofPacket);
  const lrProofResult = await aliceInitiator.validateProof(aliceProofParsed);
  if (!lrProofResult.ok) {
    throw new Error(`initiator validateProof failed: ${lrProofResult.reason}`);
  }

  // Alice and Bob must now agree on the derived key. If they don't, the
  // decrypt step below will fail the HMAC verify.
  if (toHex(aliceInitiator.derivedKey) !== toHex(bobResponder.derivedKey)) {
    throw new Error(
      `derivedKey mismatch after handshake: alice[:16]=${toHex(aliceInitiator.derivedKey.subarray(0, 16))} bob[:16]=${toHex(bobResponder.derivedKey.subarray(0, 16))}`
    );
  }

  // Alice encrypts a small payload and Bob decrypts it.
  const linkTestPlaintext = new TextEncoder().encode("hi over link from alice");
  const linkCiphertext = await aliceInitiator.encrypt(linkTestPlaintext);
  const linkDecrypted = await bobResponder.decrypt(linkCiphertext);
  const linkDecryptedStr = new TextDecoder().decode(linkDecrypted);
  if (linkDecryptedStr !== "hi over link from alice") {
    throw new Error(
      `link encrypt/decrypt round-trip failed: got ${JSON.stringify(linkDecryptedStr)}`
    );
  }

  // ---- Emit a JSON document describing everything the Python runner needs -
  const out = {
    version: 1,
    alice: exportIdentity(alice, aliceDestHash),
    bob: exportIdentity(bob, bobDestHash),
    announce: {
      displayName: aliceName,
      hasRatchet,
      packet: toHex(announcePacket),
    },
    lxmf_send: {
      from: "alice",
      to: "bob",
      content,
      packet: toHex(dataPacket),
    },
    link: {
      linkRequestPacket: toHex(lrPacket),
      linkId: toHex(link.linkId),
      lrProofPacket: toHex(lrProofPacket),
      signedData: toHex(link.signedData),
    },
    link_handshake: {
      linkIdInitiator: toHex(aliceInitiator.linkId),
      linkIdResponder: toHex(bobResponder.linkId),
      derivedKey: toHex(aliceInitiator.derivedKey),
      rttSeconds: aliceInitiator.rtt,
      linkReqPacket: toHex(aliceLrPacket),
      lrProofPacket: toHex(bobLrProofPacket),
      testCiphertext: toHex(linkCiphertext),
      testPlaintext: "hi over link from alice",
    },
  };

  process.stdout.write(JSON.stringify(out, null, 2));
}

main().catch((e) => {
  console.error("harness failure:", e.message);
  console.error(e.stack);
  process.exit(1);
});
