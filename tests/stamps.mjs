// tests/stamps.mjs
//
// Proof-of-work stamp tests (SPEC §4.7, §5.7.2, §6.1.1, §7.1).
//
// Two halves:
//  1. Self-checks run here under Node: the synchronous SHA-256 / HMAC /
//     HKDF in js/sha256.js against node:crypto, and parsing of REAL RNS
//     1.6.1 stamped announces (tests/fixtures/rns-1.6.1-announces.json,
//     copied from reticulum-specifications/test-vectors) — the trailer must
//     validate, be stripped, and yield lr_cost 12.5.
//  2. Vectors printed as JSON on stdout for tests/run_stamps.py, which
//     checks every one against RNS's own RNS.Stamps / validate_announce:
//     cost targets, stamp values, LXMF workblocks, generated LXMF stamps,
//     stamped link keys, path-request stamps and a full stamped announce.
//
// Self-check failures go to stderr and exit non-zero.

import { createHash, hkdfSync, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { encode as msgpackEncode } from "@msgpack/msgpack";

import { Sha256, sha256Sync, hkdfSha256Sync } from "../js/sha256.js";
import {
  targetFromCost, stampValue, stampValueLegacy, stampValid, stampWorkblock,
  generateStamp, generateStampedKey, destinationStampMaterial, pathRequestStampMaterial,
  DESTINATION_VALUE, DESTINATION_COST, LR_COST, PR_VALUE, STAMPLENGTH,
} from "../js/stamps.js";
import { Identity, computeDestinationHash, computeNameHash } from "../js/identity.js";
import { buildAnnounce, parseAnnounce, validateAnnounce, extractDisplayName, parseLxmfAppData } from "../js/announce.js";
import { parsePnAppData } from "../js/propagation.js";
import { buildPacket, parsePacket, HEADER_1, DEST_SINGLE, PACKET_ANNOUNCE } from "../js/reticulum.js";

let pass = 0, fail = 0;
const errs = [];
const ok = (c, m) => { if (c) pass++; else { fail++; errs.push(m); } };
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (s) => new Uint8Array(s.match(/.{1,2}/g).map((h) => parseInt(h, 16)));
const rnd = (n) => new Uint8Array(randomBytes(n));
const nodeSha = (b) => toHex(createHash("sha256").update(b).digest());

async function selfChecks() {
  // ---- SHA-256 against node:crypto, across block boundaries ----
  for (const n of [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 1000]) {
    const b = rnd(n);
    ok(toHex(sha256Sync(b)) === nodeSha(b), `sha256Sync mismatch at length ${n}`);
  }
  {
    const b = rnd(300);
    const h = new Sha256().update(b.subarray(0, 70));
    const c = h.clone();
    h.update(b.subarray(70));
    c.update(b.subarray(70, 200)).update(b.subarray(200));
    ok(toHex(h.digest()) === nodeSha(b) && toHex(c.digest()) === nodeSha(b), "Sha256 streaming/clone mismatch");
  }
  // ---- HKDF against node:crypto ----
  {
    const ikm = rnd(32), salt = rnd(32);
    const want = toHex(new Uint8Array(hkdfSync("sha256", ikm, salt, new Uint8Array(0), 256)));
    ok(toHex(hkdfSha256Sync(256, ikm, salt)) === want, "hkdfSha256Sync mismatch");
  }
  // ---- Cost targets: whole-number costs are exactly 1 << (256 - c) ----
  for (const c of [1, 8, 16, 25]) {
    ok(targetFromCost(c) === 1n << BigInt(256 - c), `target(${c}) is not 2^(256-${c})`);
  }

  // ---- Real RNS 1.6.1 stamped announces (§4.7) ----
  const fx = JSON.parse(readFileSync(new URL("./fixtures/rns-1.6.1-announces.json", import.meta.url)));
  for (const v of fx.vectors) {
    const pkt = parsePacket(fromHex(v.expected.wire_bytes_hex));
    const a = await parseAnnounce(pkt.payload, pkt.contextFlag, pkt.destHash);
    ok(!!a, `${v.label}: parseAnnounce rejected`);
    if (!a) continue;
    ok(validateAnnounce(a, pkt.destHash), `${v.label}: signature over trailer-bearing app_data failed`);
    ok(a.stamp.stamped && a.stamp.valid, `${v.label}: stamp not recognised as valid (value ${a.stamp.value})`);
    ok(a.stamp.lrCost === 12.5, `${v.label}: lr_cost ${a.stamp.lrCost}, want 12.5`);
    ok(toHex(a.appData) === v.inputs.app_data_msgpack_hex, `${v.label}: trailer not stripped`);
    ok(extractDisplayName(a.appData) === "AliceTest", `${v.label}: display name lost`);

    // Tamper with the stamp: upstream keeps app_data verbatim (trailer and
    // all). Display-name parsing must still work (§4.3 trailing-bytes rule).
    const raw = fromHex(v.expected.wire_bytes_hex);
    raw[raw.length - 10] ^= 0xff;
    const p2 = parsePacket(raw);
    const b = await parseAnnounce(p2.payload, p2.contextFlag, p2.destHash);
    ok(b && !b.stamp.valid && b.stamp.lrCost === null, `${v.label}: tampered stamp accepted`);
    ok(b && b.appData.length === a.appData.length + 18, `${v.label}: invalid trailer was stripped`);
    ok(b && extractDisplayName(b.appData) === "AliceTest", `${v.label}: name lost behind unvalidated trailer`);
  }

  // ---- §4.3 4-element LXMF app_data, cost parsing ----
  {
    const name = new TextEncoder().encode("Reticulum5");
    ok(toHex(msgpackEncode([name, null, [0], null])) === "94c40a5265746963756c756d35c09100c0",
      "4-element app_data bytes differ from SPEC §4.3 example");
    const withTrailer = new Uint8Array([...msgpackEncode([name, 9, [0], 8.5]), 0xc1, 0, ...new Uint8Array(14), 0x80, 0x0c]);
    const p = parseLxmfAppData(withTrailer);
    ok(p.name === "Reticulum5" && p.stampCost === 8.5, `parseLxmfAppData: ${JSON.stringify(p)}`);
    ok(parseLxmfAppData(msgpackEncode([name, 255])).stampCost === null, "out-of-range cost not rejected");
    ok(parseLxmfAppData(msgpackEncode([name, 0])).stampCost === null, "cost 0 must mean no stamp");
  }

  // ---- PN announce behind an unvalidated trailer (§5.8.5) ----
  {
    const pn = msgpackEncode([false, 1750000000, true, 256, 10240, [16, 3, 18], {}, [16.0, 3, 18]]);
    const withTrailer = new Uint8Array([...pn, 0xc1, 0, ...new Uint8Array(14), 0x40, 0x03]);
    const parsed = parsePnAppData(withTrailer);
    ok(parsed && parsed.active === true && parsed.timebase === 1750000000, "parsePnAppData failed behind trailer");
  }
}

async function vectors() {
  const out = {};

  out.targets = [0, 0.5, 1, 3.25, 8, 8.5, 12.5, 15.8, 17.8, 23.5, 25, 40, 99.99, 100]
    .map((c) => ({ cost: c, target: targetFromCost(c).toString(16) }));

  out.values = [];
  for (let i = 0; i < 24; i++) {
    const wb = rnd(i % 3 === 0 ? 0 : 90), st = rnd(14);
    out.values.push({ wb: toHex(wb), stamp: toHex(st), value: stampValue(wb, st), legacy: stampValueLegacy(wb, st) });
  }

  out.workblocks = [];
  for (const rounds of [25, 3000]) {
    const material = rnd(32);
    out.workblocks.push({ material: toHex(material), rounds, sha256: toHex(sha256Sync(stampWorkblock(material, rounds))) });
  }

  // LXMF stamps: expanded workblock over a message_id, integer + fractional cost.
  out.lxmf = [];
  for (const cost of [10, 9.5]) {
    const messageId = rnd(32);
    const wb = stampWorkblock(messageId);
    const res = await generateStamp(wb, cost, { size: 32 });
    if (!res) throw new Error(`LXMF stamp generation failed at cost ${cost}`);
    ok(stampValid(res.stamp, cost, wb), `own LXMF stamp invalid at cost ${cost}`);
    out.lxmf.push({ messageId: toHex(messageId), cost, stamp: toHex(res.stamp), value: res.value });
  }

  // Stamped link-request key (§6.1.1): material = dest_hash || ed25519_pub.
  {
    const material = rnd(48);
    const res = await generateStampedKey(material, 8);
    if (!res) throw new Error("stamped key generation failed");
    out.keystamp = { material: toHex(material), cost: 8, priv: toHex(res.priv), pub: toHex(res.pub), value: res.value };
  }

  // Path-request stamp (§7.1): over dest_hash || tag at PR_VALUE.
  {
    const dest = rnd(16), tag = rnd(16);
    const res = await generateStamp(pathRequestStampMaterial(dest, tag), PR_VALUE, { size: STAMPLENGTH });
    if (!res) throw new Error("path-request stamp generation failed");
    out.prstamp = { dest: toHex(dest), tag: toHex(tag), stamp: toHex(res.stamp) };
  }

  // Full stamped announce at the upstream generation value (§4.7).
  {
    const alice = new Identity();
    await alice.generate();
    const destHash = await computeDestinationHash("lxmf.delivery", alice.hash);
    const nameHash = await computeNameHash("lxmf.delivery");
    const t0 = Date.now();
    const res = await generateStamp(destinationStampMaterial(destHash, alice.publicKey, nameHash), DESTINATION_VALUE, { size: STAMPLENGTH });
    if (!res) throw new Error("destination stamp generation failed");
    const appData = new Uint8Array(msgpackEncode([new TextEncoder().encode("StampTest"), null, [0], null]));
    const { payload, hasRatchet } = await buildAnnounce(alice, "lxmf.delivery", appData, alice.ratchetPubKey, res.stamp, LR_COST);
    const packet = buildPacket({
      headerType: HEADER_1, contextFlag: hasRatchet ? 1 : 0, destType: DEST_SINGLE,
      packetType: PACKET_ANNOUNCE, destHash, context: 0x00, payload,
    });
    // Our own parser must accept it too.
    const pkt = parsePacket(packet);
    const a = await parseAnnounce(pkt.payload, pkt.contextFlag, pkt.destHash);
    ok(a && a.stamp.valid && a.stamp.lrCost === LR_COST && toHex(a.appData) === toHex(appData) && validateAnnounce(a, pkt.destHash),
      "own stamped announce does not round-trip through parseAnnounce");
    ok(res.value >= DESTINATION_COST, `destination stamp value ${res.value} below ${DESTINATION_COST}`);
    out.announce = {
      packet: toHex(packet), destHash: toHex(destHash), appData: toHex(appData),
      lrCost: LR_COST, value: res.value, rounds: res.rounds, ms: Date.now() - t0,
    };
  }
  return out;
}

async function main() {
  await selfChecks();
  const out = await vectors();
  if (fail) {
    process.stderr.write(`stamps.mjs: ${fail} self-check(s) failed (${pass} passed):\n  - ${errs.join("\n  - ")}\n`);
    process.exit(1);
  }
  process.stderr.write(`stamps.mjs: ${pass} self-checks passed\n`);
  process.stdout.write(JSON.stringify(out, null, 2));
}

main().catch((e) => { process.stderr.write(`stamps.mjs crashed: ${e.stack || e}\n`); process.exit(1); });
