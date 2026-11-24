// tests/misc.mjs
//
// Small conformance checks: §2.2 zero-length data, §4.8 discovery app_data,
// §5.9.5 propagation-node name, §11.6.3 NomadNet local-action link targets,
// and micron anchor-id namespacing. Run with `node tests/misc.mjs`.

import { encode as msgpackEncode } from "@msgpack/msgpack";
import { parsePacket, buildPacket, HEADER_1, HEADER_2, DEST_SINGLE, PACKET_DATA } from "../js/reticulum.js";
import { parseDiscoveryAppData } from "../js/announce.js";
import { parsePnAppData } from "../js/propagation.js";
import { parseLinkTarget } from "../js/nomadnet.js";
import { renderMicron } from "../js/micron.js";
import { lookupDestination } from "../js/known-destinations.js";

let pass = 0, fail = 0;
const errs = [];
const ok = (c, m) => { if (c) pass++; else { fail++; errs.push(m); } };
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));

// Hand-encode an int-keyed msgpack map (the bundled encoder writes string keys).
function intMap(entries) {
  const parts = [0x80 | entries.length];
  for (const [k, v] of entries) {
    parts.push(...(k < 128 ? [k] : [0xcc, k]));
    parts.push(...msgpackEncode(v));
  }
  return new Uint8Array(parts);
}

// ---- §2.2: zero-length data field ----
{
  const dest = rnd(16);
  const h1 = new Uint8Array([0x00, 0x00, ...dest, 0x00]);               // 19 bytes, no data
  const h2 = new Uint8Array([0x40, 0x00, ...rnd(16), ...dest, 0x00]);   // 35 bytes, no data
  ok(parsePacket(h1) === null, "HEADER_1 frame with empty data must be rejected");
  ok(parsePacket(h2) === null, "HEADER_2 frame with empty data must be rejected");
  const good = buildPacket({ headerType: HEADER_1, destType: DEST_SINGLE, packetType: PACKET_DATA, destHash: dest, context: 0, payload: new Uint8Array([1]) });
  ok(parsePacket(good) !== null, "20-byte HEADER_1 frame must parse");
}

// ---- §4.8 discovery app_data ----
{
  const info = intMap([[0x00, "TCPServerInterface"], [0x01, true], [0xFF, "Hub West"], [0x02, "hub.example.net"], [0x06, 4242], [0x03, 52.5], [0x04, 13.4]]);
  const appData = new Uint8Array([0x00, ...info, ...rnd(32)]);
  const d = parseDiscoveryAppData(appData);
  ok(d && d.name === "Hub West" && d.type === "TCPServerInterface" && d.reachableOn === "hub.example.net" && d.port === 4242,
    `discovery info misparsed: ${JSON.stringify(d)}`);
  ok(d && d.lat === 52.5 && d.lon === 13.4 && d.transport === true, "discovery position/transport misparsed");
  ok(parseDiscoveryAppData(new Uint8Array([0x02, ...rnd(80)]))?.encrypted === true, "encrypted discovery not flagged");
  ok(lookupDestination("55aa39e85c3e045e9cb1")?.name === "rnstransport.discovery.interface", "discovery name_hash not known");
  ok(lookupDestination("9e059549ef49a8c64d18")?.name === "rnstransport.info.blackhole", "blackhole name_hash not known");
}

// ---- §5.9.5 PN_META_NAME (bin) in element [6], mixed value types ----
{
  const meta = intMap([[0x01, new TextEncoder().encode("North PN")], [0xFE, "lxmd"], [0x00, "1.3.1"]]);
  const head = msgpackEncode([false, 1750000000, true, 256, 10240, [16, 3, 18]]);
  // Splice the hand-built map in as element [6] of an 8-element array.
  const arr = new Uint8Array([0x98, ...head.subarray(1), ...meta, ...msgpackEncode([16.0, 3, 18])]);
  const p = parsePnAppData(arr);
  ok(p && p.name === "North PN", `PN name not read from element [6]: ${p && p.name}`);
}

// ---- §11.6.3 local-action link targets ----
{
  ok(parseLinkTarget("#rules").kind === "anchor" && parseLinkTarget("#rules").name === "rules", "#anchor not a local jump");
  ok(parseLinkTarget("#").kind === "anchor" && parseLinkTarget("#").name === "", "bare # not a jump-to-top");
  const p = parseLinkTarget("p:menu:footer");
  ok(p.kind === "partial" && p.ids.join(",") === "menu,footer", "p: partial refresh misparsed");
  ok(parseLinkTarget("rrc://" + "a".repeat(32) + "/lobby").kind === "rrc", "rrc:// not recognised");
  ok(parseLinkTarget("rrc@" + "a".repeat(32)).kind === "rrc", "rrc@ not recognised");
  ok(parseLinkTarget("/page/index.mu").kind === "page", "plain page path regressed");
  ok(parseLinkTarget("a".repeat(32) + ":/page/x.mu").kind === "node", "node target regressed");
}

// ---- micron anchors can't clobber app element ids ----
{
  const html = renderMicron("`:my-name\nhello");
  ok(html.includes('id="mu-anchor-my-name"') && !/id="my-name"/.test(html), `anchor id not namespaced: ${html}`);
}

if (fail) {
  console.error(`misc.mjs: ${fail} failed, ${pass} passed:\n  - ${errs.join("\n  - ")}`);
  process.exit(1);
}
console.log(`misc.mjs: ${pass} checks passed`);
