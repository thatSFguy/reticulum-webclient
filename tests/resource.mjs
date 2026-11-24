// tests/resource.mjs
//
// Resource + Link robustness tests (SPEC §6.6, §6.7, §10). Runs a real
// ResourceSender against a real ResourceReceiver over an in-memory "wire"
// that can drop chosen packets, using a real Link session key, plus Link
// unit checks. Run with `node tests/resource.mjs` (non-zero exit on failure).

import { ed25519, x25519 } from "@noble/curves/ed25519";
import { Link, keepaliveSeconds, resourceSdu, encodeSignalling, BASE_MTU } from "../js/link.js";
import {
  ResourceSender, ResourceReceiver, parseAdvertisement,
  CTX_RESOURCE, CTX_RESOURCE_ADV, CTX_RESOURCE_REQ, CTX_RESOURCE_HMU,
  CTX_RESOURCE_PRF, CTX_RESOURCE_ICL, CTX_RESOURCE_RCL,
} from "../js/resource.js";
import { encode as msgpackEncode, decode as msgpackDecode } from "@msgpack/msgpack";
import { buildPacket, parsePacket, HEADER_1, DEST_SINGLE, PACKET_LINKREQ } from "../js/reticulum.js";

let pass = 0, fail = 0;
const errs = [];
const ok = (c, m) => { if (c) pass++; else { fail++; errs.push(m); } };
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

function makeLink(mtu) {
  const link = new Link();
  link.derivedKey = rnd(64);
  link.mtu = mtu;
  return link;
}

// Wire a sender and receiver together. `drop(ctx, n)` returns true to lose
// the n-th packet (1-based, per context). `mutateAdv` may rewrite the
// decoded advertisement dict before the receiver sees it.
async function transfer({ mtu, size, drop = () => false, mutateAdv = null, senderOpts = {}, receiverOpts = {} }) {
  const link = makeLink(mtu);
  const data = rnd(size);
  const counts = {};
  let receiver = null, sender = null;
  const result = { done: false, error: null, data: null, advCount: 0, reqCount: 0, rcl: 0, icl: 0 };

  const deliver = async (to, ctx, payload) => {
    counts[ctx] = (counts[ctx] || 0) + 1;
    if (drop(ctx, counts[ctx])) return;
    await sleep(0);
    if (to === "rx") {
      if (ctx === CTX_RESOURCE_ADV) {
        result.advCount++;
        let plain = await link.decrypt(payload);
        if (mutateAdv) plain = new Uint8Array(msgpackEncode(mutateAdv(msgpackDecode(plain))));
        const adv = parseAdvertisement(plain);
        if (receiver && !receiver.done && eq(receiver.adv.hash, adv.hash)) { receiver.handleReadvertisement(); return; }
        receiver = new ResourceReceiver(link, adv, {
          // Proofs travel unencrypted; REQ / RCL are link-encrypted.
          send: async (c, p, isProof) => deliver("tx", c, isProof ? p : await link.encrypt(p)),
          onComplete: ({ data: d }) => { result.done = true; result.data = d; },
          onError: (r) => { result.error = r; },
          ...receiverOpts,
        });
        receiver.start();
      } else if (ctx === CTX_RESOURCE) await receiver?.handlePart(payload);
      else if (ctx === CTX_RESOURCE_HMU) receiver?.handleHashmapUpdate(await link.decrypt(payload));
      else if (ctx === CTX_RESOURCE_ICL) { result.icl++; receiver?.cancel("icl"); }
    } else {
      if (ctx === CTX_RESOURCE_REQ) { result.reqCount++; await sender.handleRequest(await link.decrypt(payload)); }
      else if (ctx === CTX_RESOURCE_PRF) sender.handleProof(payload);
      else if (ctx === CTX_RESOURCE_RCL) { result.rcl++; sender.cancel("rcl"); }
    }
  };

  await new Promise((resolve) => {
    sender = new ResourceSender(link, data, {
      send: async (c, p) => deliver("rx", c, c === CTX_RESOURCE ? p : await link.encrypt(p)),
      onComplete: () => { result.senderDone = true; resolve(); },
      onError: (r) => { result.senderError = r; resolve(); },
      ...senderOpts,
    });
    sender.start();
    setTimeout(resolve, 20000);
  });
  result.sender = sender;
  result.receiver = receiver;
  result.match = result.data && eq(result.data, data);
  return result;
}

async function main() {
  // ---- §10.2 step 6: part count follows the link MTU, like upstream ----
  for (const mtu of [228, 500]) {
    const r = await transfer({ mtu, size: 3000 });
    const sdu = resourceSdu(mtu);
    ok(r.sender.sdu === sdu, `sdu at mtu ${mtu} is ${r.sender.sdu}, want ${sdu}`);
    ok(r.sender.totalParts === Math.ceil(r.sender.transferSize / sdu),
      `parts ${r.sender.totalParts} != ceil(t/sdu) at mtu ${mtu} (upstream receiver would disagree)`);
    ok(r.sender.parts.every((p) => 19 + p.length <= mtu), `a part packet exceeds mtu ${mtu}`);
    ok(r.match && r.senderDone, `transfer at mtu ${mtu} failed: ${r.error || r.senderError}`);
  }
  ok(resourceSdu(500) === 464 && resourceSdu(228) === 192, "resourceSdu constants");

  // ---- > 74 parts: hashmap update (HMU) path ----
  {
    const r = await transfer({ mtu: 228, size: 20000 });
    ok(r.sender.totalParts > 74, "test transfer should need an HMU");
    ok(r.match && r.senderDone, `HMU transfer failed: ${r.error || r.senderError}`);
  }

  // ---- RNS 1.6 empty-hashmap advertisement → HASHMAP_IS_EMPTY request ----
  {
    const r = await transfer({ mtu: 500, size: 4000, mutateAdv: (d) => ({ ...d, m: new Uint8Array(0) }) });
    ok(r.match && r.senderDone, `empty-hashmap advertisement transfer failed: ${r.error || r.senderError}`);
  }

  // ---- lost first REQ: sender re-advertises; receiver must NOT abort ----
  {
    const r = await transfer({
      mtu: 500, size: 2000,
      drop: (ctx, n) => ctx === CTX_RESOURCE_REQ && n === 1,
      senderOpts: { advTimeoutMs: 50 },
    });
    ok(r.advCount >= 2, "sender did not re-send the advertisement after a lost REQ");
    ok(r.rcl === 0, "receiver put RCL on the wire for a re-advertisement");
    ok(r.match && r.senderDone, `re-advertised transfer failed: ${r.error || r.senderError}`);
  }

  // ---- silent receiver: sender gives up instead of hanging forever ----
  {
    const r = await transfer({
      mtu: 500, size: 2000,
      drop: (ctx) => ctx === CTX_RESOURCE_REQ,
      senderOpts: { advTimeoutMs: 20 },
    });
    ok(r.senderError && /advertisement/.test(r.senderError), `sender should fail after ADV retries, got ${r.senderError}`);
  }

  // ---- hostile part count is rejected before allocation ----
  {
    const link = makeLink(500);
    let err = null;
    const rx = new ResourceReceiver(link, {
      transferSize: 1000, dataSize: 900, parts: 50_000_000, hash: rnd(32), randomHash: rnd(4),
      hashmapFragment: new Uint8Array(0), split: false, totalSegments: 1,
    }, { send: () => {}, onError: (e) => { err = e; } });
    rx.start();
    ok(err && /implausible/.test(err) && rx.parts === null, `hostile n not rejected cleanly: ${err}`);
  }

  // ---- link close cancels an in-flight send (promise settles) ----
  {
    const link = makeLink(500);
    let settled = null;
    const s = new ResourceSender(link, rnd(5000), {
      send: async () => {}, onComplete: () => { settled = "done"; }, onError: (r) => { settled = r; },
    });
    await s.start();
    s.cancel("link closed");
    ok(settled === "link closed" && s.done, "cancel() did not settle the sender");
  }

  // ---- §6.6.5: 96-byte LRPROOF (no signalling) must verify, at base MTU ----
  {
    const respSigPriv = ed25519.utils.randomPrivateKey();
    const respSigPub = ed25519.getPublicKey(respSigPriv);
    const dest = rnd(16);
    const { link } = Link.createInitiator(respSigPub, dest, null, 228);
    link.linkId = rnd(16);
    const respX = x25519.getPublicKey(x25519.utils.randomPrivateKey());
    const signed = new Uint8Array([...link.linkId, ...respX, ...respSigPub]);   // NO signalling
    const proof = new Uint8Array([...ed25519.sign(signed, respSigPriv), ...respX]);
    const res = await link.validateProof({ payload: proof });
    ok(res.ok, `96-byte LRPROOF rejected: ${res.reason}`);
    ok(link.mtu === BASE_MTU, `link MTU after 96-byte proof is ${link.mtu}, want ${BASE_MTU}`);

    // 99-byte proof confirming less than we asked for.
    const { link: l2 } = Link.createInitiator(respSigPub, dest, null, 500);
    l2.linkId = rnd(16);
    const sig228 = encodeSignalling(228, 1);
    const signed2 = new Uint8Array([...l2.linkId, ...respX, ...respSigPub, ...sig228]);
    const proof2 = new Uint8Array([...ed25519.sign(signed2, respSigPriv), ...respX, ...sig228]);
    const res2 = await l2.validateProof({ payload: proof2 });
    ok(res2.ok && l2.mtu === 228, `99-byte proof with mtu 228: ok=${res2.ok} mtu=${l2.mtu}`);
    ok(l2.rtt >= 0 && l2.rtt < 60, `RTT from monotonic clock looks wrong: ${l2.rtt}`);
  }

  // ---- responder clamps a requested MTU to its own bearer ----
  {
    const ours = { sigPrivKey: ed25519.utils.randomPrivateKey() };
    ours.sigPubKey = ed25519.getPublicKey(ours.sigPrivKey);
    const req = new Uint8Array([...rnd(32), ...rnd(32), ...encodeSignalling(1064, 1)]);
    const pkt = parsePacket(buildPacket({ headerType: HEADER_1, destType: DEST_SINGLE, packetType: PACKET_LINKREQ, destHash: rnd(16), context: 0, payload: req }));
    try {
      const { link } = await Link.validateRequest(pkt, ours, 228);
      ok(link.mtu === 228, `responder accepted mtu ${link.mtu}, want clamp to 228`);
      ok(link.createdAt > 0, "responder link has no createdAt (watchdog cannot age it)");
    } catch (e) {
      ok(false, `validateRequest threw: ${e.message}`);
    }
  }

  // ---- §6.7.1 keepalive interval ----
  ok(keepaliveSeconds(0) === 360 && keepaliveSeconds(0.01) === 5 && keepaliveSeconds(10) === 360,
    "keepalive clamp to [5, 360]");
  ok(Math.abs(keepaliveSeconds(0.5) - 0.5 * (360 / 1.75)) < 1e-9, "keepalive = rtt × 360/1.75");

  if (fail) {
    console.error(`resource.mjs: ${fail} failed, ${pass} passed:\n  - ${errs.join("\n  - ")}`);
    process.exit(1);
  }
  console.log(`resource.mjs: ${pass} checks passed`);
  process.exit(0);
}

main().catch((e) => { console.error(`resource.mjs crashed: ${e.stack || e}`); process.exit(1); });
