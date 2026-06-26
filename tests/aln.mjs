// tests/aln.mjs
//
// Unit tests for the agnostic-LoRa-Net (ALN) tunnel: the envelope helpers
// (aln-tunnel.js), the NUS frame/text demux (nus-demux.js), and the
// identity router (aln-router.js). These are JS ports of the mobile app's
// AgnosticLoraTunnel / NusDemux / AgnosticLoraRouter (Kotlin), and the
// assertions here mirror that project's byte-for-byte tests — pinned to the
// node firmware contract, not to a self-consistent round-trip.
//
// Run with `node tests/aln.mjs` (exits non-zero on any failure). The router's
// link/proof cases use Web Crypto (crypto.subtle), available under Node 20+.

import { NusDemux } from "../js/nus-demux.js";
import { encodeFrame } from "../js/hdlc.js";
import * as T from "../js/aln-tunnel.js";
import { AlnRouter } from "../js/aln-router.js";
import { computeLinkId, computePacketFullHash } from "../js/link.js";
import {
  buildPacket, parsePacket,
  PACKET_ANNOUNCE, PACKET_DATA, PACKET_LINKREQ, PACKET_PROOF,
  DEST_SINGLE, DEST_PLAIN, DEST_LINK,
} from "../js/reticulum.js";

let pass = 0, fail = 0; const errs = [];
const ok = (c, m) => { if (c) pass++; else { fail++; errs.push(m); } };
const eqBytes = (a, b) => { if (!a || !b || a.length !== b.length) return false; for (let i = 0; i < a.length; i++) if ((a[i] & 0xff) !== (b[i] & 0xff)) return false; return true; };
const arrEq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const setEq = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
const enc = (s) => { const o = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i) & 0xff; return o; };
const cat = (...as) => { let n = 0; for (const a of as) n += a.length; const o = new Uint8Array(n); let k = 0; for (const a of as) { o.set(a, k); k += a.length; } return o; };
const B = (...v) => new Uint8Array(v);

// ───────────────────────── NusDemux ─────────────────────────
function sink() { const frames = [], lines = []; return { frames, lines, d: new NusDemux((f) => frames.push(f), (l) => lines.push(l)) }; }
{ const s = sink(); s.d.feed(enc("loc AABB 9828F51B\r\nregistered ok\n")); ok(arrEq(s.lines, ["loc AABB 9828F51B", "registered ok"]) && s.frames.length === 0, "demux: text lines on LF"); }
{ const s = sink(); const body = B(0x01, 0x04, 0x1B, 0xF5, 0x28, 0x98, 0x42); s.d.feed(encodeFrame(body)); ok(s.frames.length === 1 && eqBytes(s.frames[0], body), "demux: frame decodes"); }
{ const s = sink(); const body = B(0x01, 0x04, 0x7E, 0x7D, 0x00, 0x00, 0x55); s.d.feed(encodeFrame(body)); ok(eqBytes(s.frames[0], body), "demux: escaped bytes unescape"); }
{ const s = sink(); const body = B(0x01, 0x04, 1, 2, 3, 4, 9); s.d.feed(cat(enc("[dir] 1 binding(s):\n"), encodeFrame(body), enc("  AABB -> D97EEC3A  ttl=595s\n"))); ok(arrEq(s.lines, ["[dir] 1 binding(s):", "  AABB -> D97EEC3A  ttl=595s"]) && eqBytes(s.frames[0], body), "demux: text/frame/text interleave"); }
{ const s = sink(); s.d.feed(cat(enc("partial"), encodeFrame(B(0x01, 0x00, 7)), enc("whole line\n"))); ok(arrEq(s.lines, ["whole line"]), "demux: frame boundary clears partial line"); }
{ const s = sink(); const body = new Uint8Array(60); for (let i = 0; i < 60; i++) body[i] = i; const wire = cat(enc("loc X 11223344\n"), encodeFrame(body)); for (const b of wire) s.d.feed(B(b)); ok(arrEq(s.lines, ["loc X 11223344"]) && eqBytes(s.frames[0], body), "demux: byte-at-a-time chunking"); }
{ const s = sink(); s.d.feed(B(0x7E, 0x7E)); ok(s.frames.length === 0, "demux: empty frame is keepalive"); s.d.feed(enc("hb\n")); ok(arrEq(s.lines, ["hb"]), "demux: text after keepalive"); }
{ const s = sink(); s.d.feed(enc("\n\r\n  \nreal\n")); ok(arrEq(s.lines, ["real"]), "demux: blank lines dropped"); }

// ───────────────────────── AgnosticLoraTunnel ─────────────────────────
const ID_HEX = "b0459c8072face9964867b39d8ed4e3e";
const ID = B(0xB0, 0x45, 0x9C, 0x80, 0x72, 0xFA, 0xCE, 0x99, 0x64, 0x86, 0x7B, 0x39, 0xD8, 0xED, 0x4E, 0x3E);
ok(eqBytes(T.locatorFromHex(ID_HEX), ID), "tunnel: locatorFromHex natural order");
ok(eqBytes(T.locatorFromHex("0x" + ID_HEX), T.locatorFromHex(ID_HEX.toUpperCase())), "tunnel: locator prefix/case");
ok(T.locatorFromHex(ID_HEX.slice(0, -2)) === null && T.locatorFromHex(ID_HEX + "00") === null && T.locatorFromHex("Z".repeat(32)) === null && T.locatorFromHex("9828F51B") === null && T.locatorFromHex("") === null, "tunnel: locatorFromHex rejects wrong width");
ok(eqBytes(T.encodeLocatorFrame(T.locatorFromHex(ID_HEX), B(0x00, 0x11, 0x22)), cat(B(0x01, 0x10), ID, B(0x00, 0x11, 0x22))), "tunnel: encode typed frame");
ok(eqBytes(T.decodeFrame(cat(B(0x01, 0x10), ID, B(0xDE, 0xAD, 0xBE, 0xEF))), B(0xDE, 0xAD, 0xBE, 0xEF)), "tunnel: decode strips envelope");
{ const loc = T.locatorFromHex("deadbeefdeadbeefdeadbeefdeadbeef"); const p = new Uint8Array(200); for (let i = 0; i < 200; i++) p[i] = (i * 7) & 0xff; ok(eqBytes(T.decodeFrame(T.encodeLocatorFrame(loc, p)), p), "tunnel: encode/decode round-trips 200B"); }
ok(T.decodeFrame(cat(B(0x02, 0x10), ID, B(9, 9))) === null && T.decodeFrame(B(0x7F, 0x01, 1, 2)) === null, "tunnel: decode ignores IDENTITY/unknown");
ok(T.decodeFrame(B()) === null && T.decodeFrame(B(0x01)) === null && T.decodeFrame(B(0x01, 0x10, 1, 2)) === null, "tunnel: decode rejects truncated");
ok(eqBytes(T.decodeFrame(cat(B(0x01, 0x10), ID)), B()), "tunnel: decode allows zero-length payload");
ok(T.sourceFromFrame(cat(B(0x01, 0x10), ID, B(0x42))) === ID_HEX.toUpperCase() && T.sourceFromFrame(cat(B(0x02, 0x10), ID)) === null && T.sourceFromFrame(B(0x01, 0x10, 1, 2)) === null, "tunnel: sourceFromFrame natural order + rejects");
ok(T.isValidNodeIdHex(ID_HEX) && !T.isValidNodeIdHex("9828F51B") && !T.isValidNodeIdHex("nope"), "tunnel: isValidNodeIdHex");
ok(T.labelFromAdvertisedName("ALN-kitchen") === "kitchen" && T.labelFromAdvertisedName("AgnLoRa-b0459c80") === "b0459c80" && T.labelFromAdvertisedName("ALN-") === null && T.labelFromAdvertisedName("RNode 1234") === null, "tunnel: labelFromAdvertisedName");
ok(T.isAdvertisedName("ALN-kitchen") && T.isAdvertisedName("aln-x") && T.isAdvertisedName("AgnLoRa-b0") && !T.isAdvertisedName("RNode") && !T.isAdvertisedName(null), "tunnel: isAdvertisedName");

// ───────────────────────── AgnosticLoraRouter ─────────────────────────
const selfId = "A".repeat(32), peerId = "B".repeat(32);
const selfHash = new Uint8Array(16).fill(0xAA), peerHash = new Uint8Array(16).fill(0xBB);
const N1 = "D97EEC3AD97EEC3AD97EEC3AD97EEC3A", N2 = "B51EEC13B51EEC13B51EEC13B51EEC13", N3 = "11223344112233441122334411223344", FB = "9828F51B9828F51B9828F51B9828F51B";
const router = (fb = null) => new AlnRouter(selfId, fb);
const announce = (dest = selfHash) => buildPacket({ packetType: PACKET_ANNOUNCE, destType: DEST_SINGLE, destHash: dest, payload: new Uint8Array(140) });
const data = (dest = peerHash) => buildPacket({ packetType: PACKET_DATA, destType: DEST_SINGLE, destHash: dest, payload: new Uint8Array(32) });
const linkRequest = (dest = peerHash) => buildPacket({ packetType: PACKET_LINKREQ, destType: DEST_SINGLE, destHash: dest, payload: new Uint8Array(67) });

async function routerTests() {
  { const r = router(); ok((await r.routeOutbound(announce(), 0)).kind === "deferred", "router: announce no peers deferred"); const ev = await r.onInbound(N1, announce(peerHash), 1); ok(ev && arrEq(ev.newPeerNodes, [N1]), "router: inbound announce new peer"); ok(r.cachedAnnounceFor(N1) != null && r.cachedAnnounceFor(N1) == null, "router: cached announce once"); }
  { const r = router(); await r.onInbound(N1, announce(peerHash), 0); await r.onInbound(N2, announce(new Uint8Array(16).fill(0xCC)), 0); await r.onInbound(N3, announce(new Uint8Array(16).fill(0xDD)), 0); const d = await r.routeOutbound(announce(), 1); ok(d.kind === "send" && setEq(d.targets, [N1, N2, N3]) && d.targets.length === 3, "router: fresh announce fans out deduped"); }
  { const r = router(); r.onTextLine(`loc ${peerId} ${N1}`, 0); const d = await r.routeOutbound(data(), 1); ok(d.kind === "send" && arrEq(d.targets, [N1]), "router: data to resolved peer"); }
  { const r = router(); const raw = data(); ok((await r.routeOutbound(raw, 0)).kind === "buffered" && arrEq(r.resolveWanted(), [peerId]), "router: data unknown buffers"); r.onTextLine(`loc ${peerId} ${N2}`, 1); const fl = await r.drainRoutable(2); ok(fl.length === 1 && eqBytes(fl[0][0], raw) && fl[0][1] === N2 && !r.hasPending(), "router: flush on loc"); }
  { const r = router(FB); const d = await r.routeOutbound(data(), 0); ok(d.kind === "send" && arrEq(d.targets, [FB]), "router: unknown peer falls back to uplink"); }
  { const r = router("9828F51B"); ok(r.fallbackUplinkHex === null && (await r.routeOutbound(data(), 0)).kind === "buffered", "router: invalid-width fallback ignored"); }
  { const r = router(); const ev = await r.onInbound(N1, announce(peerHash), 0); ok(ev && arrEq(ev.newPeerNodes, [N1]), "router: inbound announce learns reverse-path"); const d = await r.routeOutbound(data(), 1); ok(d.kind === "send" && arrEq(d.targets, [N1]), "router: reverse-path data routes"); }
  { const r = router(); ok(r.onTextLine(`loc ${selfId} ${FB}`, 0) === null && r.onTextLine(`  ${selfId} -> ${FB}  ttl=600s`, 0) === null && r.knownPeerNodes().length === 0, "router: own registration echo ignored"); }
  { const r = router(); const ev = r.onTextLine(`registered 16-byte id at ${N1}`, 0); ok(ev && !ev.routesChanged && ev.newPeerNodes.length === 0, "router: registered ack reported, no route change"); }
  { const r = router(); r.onTextLine(`loc ${peerId} ${N1}`, 0); ok((await r.routeOutbound(data(), 1)).kind === "send" && (await r.routeOutbound(data(), 11 * 60000)).kind === "buffered", "router: stale bindings prune"); }
  { const r = router(); const pathReq = buildPacket({ packetType: PACKET_DATA, destType: DEST_PLAIN, destHash: new Uint8Array(16).fill(0x11), payload: new Uint8Array(8) }); ok((await r.routeOutbound(pathReq, 0)).kind === "deferred" && !r.hasPending(), "router: PLAIN no peers deferred, not buffered"); r.onTextLine(`loc ${peerId} ${N1}`, 1); const d = await r.routeOutbound(pathReq, 2); ok(d.kind === "send" && arrEq(d.targets, [N1]) && r.resolveWanted().length === 0, "router: PLAIN fans out, no resolve spam"); }
  { const r = router(FB); const ev = r.onTextLine(`registered 16-byte id at ${FB}`, 0); ok(ev && ev.summary.includes(`attached node ${FB}`) && r.attachedNodeHex === FB && (await r.routeOutbound(data(), 1)).kind === "buffered", "router: register ack learns attached node + neutralizes matching fallback"); }
  { const r = router(FB); ok(r.onTextLine(`[hb] up=1616s  node=${FB}  nbrs=1 routes=2 txq=0 stk=1223`, 0) === null && r.attachedNodeHex === FB && (await r.routeOutbound(data(), 1)).kind === "buffered", "router: heartbeat learns attached node silently"); }
  { const r = router(); ok(r.onTextLine(`  ${selfId} -> ${FB}  ttl=600s`, 0) === null && r.attachedNodeHex === FB, "router: own binding row bootstraps attached node"); }
  { const r = router(); r.onTextLine(`loc ${peerId} ${FB}`, 0); r.onTextLine(`registered 16-byte id at ${FB}`, 1); ok((await r.routeOutbound(data(), 2)).kind === "buffered" && r.onTextLine(`loc ${peerId} ${FB}`, 3) === null && r.knownPeerNodes().length === 0, "router: binding at attached node purged + rejected"); }
  { const r = router(); const proof = buildPacket({ packetType: PACKET_PROOF, destType: DEST_SINGLE, destHash: new Uint8Array(16).fill(0x42), payload: new Uint8Array(64) }); ok((await r.routeOutbound(proof, 0)).kind === "deferred" && !r.hasPending() && r.resolveWanted().length === 0, "router: proof with no reverse route dropped"); }
  { const r = router(); ok(r.onTextLine(`[hb] up=1 node=${FB} x`, 0) === null && r.onTextLine(`[ble] adv=1 connected=1 rx=902`, 0) === null && r.onTextLine(`[dir] 2 binding(s):`, 0) === null && r.knownPeerNodes().length === 0, "router: heartbeat/noise lines ignored"); }

  // ── crypto-dependent (link routes + reverse proof) ──
  { const r = router(); r.onTextLine(`loc ${peerId} ${N1}`, 0); const lr = linkRequest(); ok((await r.routeOutbound(lr, 1)).kind === "send", "router: outbound LINKREQ sends"); const linkId = await computeLinkId(parsePacket(lr)); const linkPacket = buildPacket({ packetType: PACKET_DATA, destType: DEST_LINK, destHash: linkId, payload: new Uint8Array(16) }); const d = await r.routeOutbound(linkPacket, 2); ok(d.kind === "send" && arrEq(d.targets, [N1]), "router: outbound LINKREQ pins link traffic"); }
  { const r = router(); const lr = linkRequest(selfHash); await r.onInbound(N2, lr, 0); const linkId = await computeLinkId(parsePacket(lr)); const proof = buildPacket({ packetType: PACKET_DATA, destType: DEST_LINK, destHash: linkId, payload: new Uint8Array(99) }); const d = await r.routeOutbound(proof, 1); ok(d.kind === "send" && arrEq(d.targets, [N2]), "router: inbound LINKREQ routes our replies back"); }
  { const r = router(); r.onTextLine(`registered 16-byte id at ${N1}`, 0); const lr = linkRequest(selfHash); ok(await r.onInbound(N1, lr, 1) === null, "router: loopback inbound learns nothing"); const linkId = await computeLinkId(parsePacket(lr)); const onLink = buildPacket({ packetType: PACKET_DATA, destType: DEST_LINK, destHash: linkId, payload: new Uint8Array(16) }); ok((await r.routeOutbound(onLink, 2)).kind === "buffered", "router: loopback LINKREQ not pinned"); }
  { const r = router(); const lr = linkRequest(selfHash); const linkId = await computeLinkId(parsePacket(lr)); const lrproof = buildPacket({ packetType: PACKET_PROOF, destType: DEST_LINK, destHash: linkId, payload: new Uint8Array(99) }); ok((await r.routeOutbound(lrproof, 0)).kind === "buffered", "router: LRPROOF buffered before pin"); const ev = await r.onInbound(N2, lr, 1); ok(ev && ev.routesChanged, "router: inbound LINKREQ flags route change"); const fl = await r.drainRoutable(2); ok(fl.length === 1 && fl[0][1] === N2, "router: buffered link packet flushes on pin"); }
  { const r = router(); const inboundData = data(selfHash); await r.onInbound(N1, inboundData, 0); const trunc = (await computePacketFullHash(parsePacket(inboundData))).slice(0, 16); const proof = buildPacket({ packetType: PACKET_PROOF, destType: DEST_SINGLE, destHash: trunc, payload: new Uint8Array(64) }); const d = await r.routeOutbound(proof, 1); ok(d.kind === "send" && arrEq(d.targets, [N1]), "router: inbound DATA pins reverse route for delivery proof"); }
}

await routerTests();

console.log(`\naln: ${pass} passed, ${fail} failed`);
if (fail) { console.log("FAILURES:\n  " + errs.join("\n  ")); process.exit(1); }
