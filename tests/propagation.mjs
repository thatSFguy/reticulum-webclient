// tests/propagation.mjs
//
// Unit tests for the propagation-node wire-shape helpers (SPEC §5.8):
// announce app_data parsing (§5.8.5 — including the element-[5]-must-be-
// a-3-list interop trap), /get listing and bundle normalization (§5.8.3),
// and the /get request path hash (§11.1, vector pinned against Python's
// hashlib.sha256(b'/get')).
//
// Run with `node tests/propagation.mjs` (exits non-zero on any failure).

import { encode as msgpackEncode } from "@msgpack/msgpack";
import { parsePnAppData, normalizeIdList, normalizeMessageBundle, pnErrorName, pnResponseIsError, PN_GET_PATH } from "../js/propagation.js";
import { requestPathHash } from "../js/nomadnet.js";

let pass = 0, fail = 0; const errs = [];
const ok = (c, m) => { if (c) pass++; else { fail++; errs.push(m); } };

const toHex = (b) => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
const bytesEqual = (a, b) =>
  a instanceof Uint8Array && b instanceof Uint8Array &&
  a.length === b.length && a.every((x, i) => x === b[i]);

async function main() {
  // ---- §11.1 path hash: SHA256('/get')[:16], pinned against Python ----
  const pathHash = await requestPathHash(PN_GET_PATH);
  ok(toHex(pathHash) === "9dc1a72883468f57fed571e796e9ce98",
    `/get path hash mismatch: ${toHex(pathHash)}`);

  // ---- §5.8.5 announce app_data ----
  const goodAppData = msgpackEncode([
    false, 1750000000, true, 256, 1024, [16, 3, 18], { note: "test-node" },
  ]);
  const parsed = parsePnAppData(goodAppData);
  ok(parsed !== null, "valid 7-element app_data rejected");
  ok(parsed?.active === true, "active flag misparsed");
  ok(parsed?.timebase === 1750000000, "timebase misparsed");
  ok(parsed?.perTransferLimitKb === 256, "per-transfer limit misparsed");
  ok(parsed?.perSyncLimitKb === 1024, "per-sync limit misparsed");
  ok(parsed?.stampCost === 16 && parsed?.stampCostFlexibility === 3 && parsed?.peeringCost === 18,
    "element [5] cost triple misparsed");

  // The classic interop break: element [5] as a bare int must be rejected,
  // not silently misread (SPEC §5.8.5 warning).
  ok(parsePnAppData(msgpackEncode([false, 1, true, 0, 0, 16, {}])) === null,
    "app_data with int element [5] not rejected");
  ok(parsePnAppData(msgpackEncode([false, 1, true, 0, 0, [16, 3]])) === null,
    "6-element app_data not rejected");
  ok(parsePnAppData(new Uint8Array([0xff, 0x00])) === null,
    "garbage app_data not rejected");

  // ---- §5.8.3 listing normalization ----
  const id16 = new Uint8Array(16).fill(1);
  const id32 = new Uint8Array(32).fill(2);
  ok(normalizeIdList([id16, id32]).length === 2, "plain id list misparsed");
  const paired = normalizeIdList([[id32, 345], [id16, 12]]);
  ok(paired.length === 2 && bytesEqual(paired[0], id32),
    "[id, size] pair list misparsed");
  ok(normalizeIdList(null).length === 0, "null listing not normalized to []");
  ok(normalizeIdList([new Uint8Array(7), "junk", 42]).length === 0,
    "junk entries not filtered from listing");

  // ---- §5.8.3 message bundle normalization ----
  const blobA = new Uint8Array(40).fill(3);
  const blobB = new Uint8Array(60).fill(4);
  const canonical = normalizeMessageBundle([1750000123, [blobA, blobB]]);
  ok(canonical.timebase === 1750000123 && canonical.messages.length === 2,
    "canonical [timebase, [blobs]] bundle misparsed");
  const packed = normalizeMessageBundle(msgpackEncode([1750000123, [blobA]]));
  ok(packed.messages.length === 1 && bytesEqual(packed.messages[0], blobA),
    "still-packed bundle bytes misparsed");
  ok(normalizeMessageBundle(null).messages.length === 0,
    "null bundle not normalized to empty");
  ok(normalizeMessageBundle([blobA, blobB]).messages.length === 2,
    "bare blob list misparsed");
  let threw = false;
  try { normalizeMessageBundle(new Uint8Array([0xc1])); } catch { threw = true; }
  ok(threw, "malformed packed bundle did not throw");

  // ---- §5.8.2 error responses ----
  ok(pnResponseIsError(0xf0) && !pnResponseIsError([1]) && !pnResponseIsError(null),
    "error-response detection wrong");
  ok(pnErrorName(0xf0).includes("NO_IDENTITY"), "0xf0 error name wrong");
  ok(pnErrorName(0x99).includes("0x99"), "unknown error code not surfaced");

  console.log(`propagation.mjs: ${pass} passed, ${fail} failed`);
  for (const e of errs) console.error(`  FAIL: ${e}`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
