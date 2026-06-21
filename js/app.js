// js/app.js — Main controller for the Reticulum web client.

'use strict';

import { encode as msgpackEncode } from '@msgpack/msgpack';
import { RNode } from './rnode.js';
import { RnsdInterface } from './rnsd-interface.js';
import { toHex } from './kiss.js';
import { Identity, computeDestinationHash, computeNameHash, truncatedHash } from './identity.js';
import { parsePacket, buildPacket, PACKET_ANNOUNCE, PACKET_DATA, PACKET_LINKREQ, PACKET_PROOF, DEST_SINGLE, DEST_LINK, DEST_PLAIN, HEADER_1, HEADER_2, TRANSPORT_BROADCAST, TRANSPORT_TRANSPORT, PACKET_TYPE_NAMES } from './reticulum.js';
import { parseAnnounce, validateAnnounce, buildAnnounce, extractDisplayName, concatBytes, arraysEqual } from './announce.js';
import { encrypt, decrypt } from './crypto.js';
import { unpackMessage, unpackLinkMessage, verifyMessageSignature, packMessage } from './lxmf.js';
import { Link, LINK_ACTIVE, LINK_CLOSED, computePacketFullHash } from './link.js';
import { lookupDestination } from './known-destinations.js';
import { ed25519 } from '@noble/curves/ed25519';
import { CTX_REQUEST, CTX_RESPONSE, NN_DEFAULT_PATH, buildRequest, parseResponse, responseToText, stripPageHeaders, parseLinkTarget } from './nomadnet.js';
import { ResourceReceiver, parseAdvertisement, CTX_RESOURCE, CTX_RESOURCE_ADV, CTX_RESOURCE_HMU, CTX_RESOURCE_ICL } from './resource.js';
import { renderMicron } from './micron.js';

// Reticulum packet context values relevant to link traffic
const CTX_NONE          = 0x00;
const CTX_PATH_RESPONSE = 0x0B;
const CTX_KEEPALIVE     = 0xFA;
const CTX_LINKCLOSE     = 0xFC;
const CTX_LRRTT         = 0xFE;
const CTX_LRPROOF       = 0xFF;

// Outbound message state machine. A row in IndexedDB with
// direction='outgoing' transitions through these states as the
// retry tick drives it forward.
const MSG_STATE_PENDING   = 'pending';    // queued, radio off or prior send failed
const MSG_STATE_SENDING   = 'sending';    // TX in flight right now
const MSG_STATE_SENT      = 'sent';       // TX completed, awaiting delivery receipt
const MSG_STATE_DELIVERED = 'delivered';  // inbound PROOF matched this packet hash
const MSG_STATE_FAILED    = 'failed';     // all retries exhausted

const MSG_MAX_ATTEMPTS = 3;
// Wait-for-ack schedule. Index is (attempts - 1): first entry is
// the wait after the 1st send, second is after the 2nd retransmit,
// etc. After MSG_MAX_ATTEMPTS attempts the row transitions to failed.
const MSG_BACKOFF_MS = [5000, 15000, 60000];
const MSG_RETRY_TICK_MS = 5000;
import { openDatabase, saveIdentity, loadIdentity, saveContact, getContact, getAllContacts, deleteContact, deleteMessagesForContact, saveMessage, getMessages, getAllMessages, getMessageById, updateMessage, saveNode, getAllNodes, deleteNode, deleteAllNodes, saveBookmark, getAllBookmarks, deleteBookmark, addHistory } from './store.js';

const $ = id => document.getElementById(id);

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

// Sanity floor for "this is a real wall-clock timestamp": 2020-01-01
// UTC. Anything older almost certainly comes from a sender whose
// time.time() is seconds-since-boot because the device has no RTC.
const SANITY_TS_MIN_MS = Date.UTC(2020, 0, 1);

// Normalize an LXMF timestamp field to Unix ms. Upstream LXMF writes
// time.time() which is float seconds since epoch, but some encoders
// produce msgpack Timestamp extensions (which @msgpack/msgpack decodes
// to a JS Date) and some write integer milliseconds directly. Handle
// all three. Returns null if the value is absent or resolves to a
// pre-2020 wall-clock date, so callers can substitute receive time
// or hide the label.
function normalizeLxmfTimestamp(ts) {
  if (ts == null) return null;
  if (ts instanceof Date) {
    const ms = ts.getTime();
    return ms >= SANITY_TS_MIN_MS ? ms : null;
  }
  if (typeof ts === 'bigint') ts = Number(ts);
  if (typeof ts !== 'number' || !isFinite(ts)) return null;
  // Values above ~1e12 are already in milliseconds; below that they
  // are in seconds. The gap between plausible seconds (1.5e9–3e9)
  // and plausible ms (1.5e12–3e12) is wide enough to be unambiguous.
  const ms = ts > 1e12 ? ts : ts * 1000;
  return ms >= SANITY_TS_MIN_MS ? ms : null;
}

// Logging — declared early so error handlers can use it
function log(cls, msg) {
  const el = $('log');
  if (!el) { console.log(`[${cls}]`, msg); return; }
  const div = document.createElement('div');
  if (cls) div.className = cls;
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  div.textContent = `[${ts}] ${msg}`;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
  while (el.childNodes.length > 500) el.removeChild(el.firstChild);
}

// Global error handler — show errors in the visible log
window.addEventListener('error', (e) => {
  log('err', `JS error: ${e.message} (${e.filename}:${e.lineno})`);
});
window.addEventListener('unhandledrejection', (e) => {
  log('err', `Unhandled promise: ${e.reason?.message || e.reason}`);
});

let rnode = new RNode('ble');  // default; can be reassigned

// ---- State -----------------------------------------------------------

let myIdentity = null;     // Identity instance
let myDestHash = null;     // Our LXMF destination hash (16 bytes)
let contacts = new Map();  // hash_hex → { hash, publicKey, displayName, destHash, identity }
let activeContactHash = null;
let radioOn = false;
let links = new Map();     // hex link_id → Link instance (responder / incoming)
let initiatorLinks = new Map();  // hex link_id → { link, contact, resolve, reject, timer }
let lxmfNameHash = null;   // SHA256("lxmf.delivery")[:10], cached
let pathRequestDest = null;       // 16-byte dest hash of rnstransport.path.request (PLAIN dest)
const pathRequestDedup = new Set(); // "targetHex|tagHex" entries; bounded FIFO
const PATH_REQUEST_DEDUP_MAX = 256; // Cap on the dedup table; upstream caps at 32000 but a
                                    // leaf only sees requests for itself, so a small ring is fine
let announceTimer = null;  // setInterval handle for the periodic announce
let outboundRetryTimer = null;  // setInterval handle for the outbound retry tick

// Contact-list filter state. Persists across reloads via localStorage so a
// user who pinned a few peers and toggled "Pinned only" doesn't have to
// redo it every session. The search term is per-session only — typing
// resets on reload, which matches the usual UX expectation for a search
// box.
let contactFilterPinnedOnly = (() => {
  try { return localStorage.getItem('rlw.filterPinned') === 'true'; }
  catch (_) { return false; }
})();
let contactSearchTerm = '';

// Per-interface routing state. Reset on disconnect — a different rnsd
// has a different identity hash and a different mesh topology. We do
// not persist these across sessions because the upstream identity is
// rediscovered passively from the next batch of announces, and stale
// path-table entries would only cause silent send failures.
//
// pathTable: destHashHex → { hops, lastSeen }. Built from received
// announces (lxmf and non-lxmf). Bounded FIFO.
//
// upstreamTransportId: the 16-byte identity hash of the rnsd we're
// directly connected to over the WS bridge. Required by SPEC §2.3:
// when we send to a destination > 1 hop away, the originator MUST
// emit HEADER_2 with the next-hop transport_id, otherwise the relay
// silently drops the packet. Learned from announces that arrive with
// `pkt.hops == 0` over the WS interface — only the rnsd we are
// directly connected to originates announces visible to us with
// hops=0 (other peers' announces get incremented to >=1 by the time
// they reach us via michmesh).
//
// pendingPathRequests: destHashHex → resolver. The path-request
// preamble (SPEC §7.1, flows/send-opportunistic-lxmf.md step 4)
// blocks the send until either the path-response announce arrives
// or PATH_REQUEST_WAIT_MS elapses.
const pathTable = new Map();
const PATH_TABLE_MAX = 1000;
let upstreamTransportId = null;
const pendingPathRequests = new Map();
const PATH_REQUEST_WAIT_MS = 5000;

rnode._onLog = (msg) => log('info', msg);

// ---- Identity --------------------------------------------------------

async function initIdentity() {
  await openDatabase();

  const stored = await loadIdentity();
  myIdentity = new Identity();

  if (stored && stored.encPrivKey && stored.sigPrivKey) {
    await myIdentity.loadFromPrivateKeys(
      new Uint8Array(stored.encPrivKey),
      new Uint8Array(stored.sigPrivKey),
      stored.ratchetPrivKey ? new Uint8Array(stored.ratchetPrivKey) : null
    );
    log('ok', 'Identity loaded from storage');
    // One-time migration for identities saved before the ratchet
    // landed. Generating a ratchet is cheap and only touches the
    // identity row — it does NOT change encPrivKey, sigPrivKey,
    // publicKey, identity hash, or destination hash. The ratchet
    // is an additional keypair that coexists with the identity
    // X25519 key and is advertised in future announces.
    if (!myIdentity.ratchetPrivKey) {
      myIdentity.generateRatchet();
      await saveIdentity(myIdentity.exportPrivateKeys());
      log('info', 'Generated ratchet keypair for existing identity');
    }
  } else {
    await myIdentity.generate();
    await saveIdentity(myIdentity.exportPrivateKeys());
    log('ok', 'New identity generated and saved');
  }

  myDestHash = await computeDestinationHash('lxmf.delivery', myIdentity.hash);
  lxmfNameHash = await computeNameHash('lxmf.delivery');
  // PLAIN destination hash = SHA256(name_hash)[:16]. The well-known
  // value is 6b9f66014d9853faab220fba47d02761; peers send path? queries
  // here when they want to discover us. SPEC §7.2 requires every node
  // (incl. leaves) that owns the requested target to respond with a
  // path-response announce, otherwise peers can't message us once
  // their cached path expires.
  pathRequestDest = await truncatedHash(await computeNameHash('rnstransport.path.request'));
  setMyAddress(toHex(myDestHash));
  log('info', `LXMF address: ${toHex(myDestHash)}`);

  // Load saved contacts. Drop every legacy record that does not have
  // a stored name_hash, because before the announce parser learned
  // to filter by name_hash we accepted announces from any destination
  // (telemetry beacons, heartbeats, auxiliary destinations on the
  // same identity as a real LXMF presence) and there is no reliable
  // way to tell which legacy rows were legitimate after the fact.
  // Anything genuine will get re-added on the next announce we hear
  // from its owner, this time with name_hash present and verified.
  // Records that DO carry a name_hash and don't match lxmf.delivery
  // are also dropped — same reason, just a different code path.
  const savedContacts = await getAllContacts();
  const expectedNameHashHex = toHex(lxmfNameHash);
  let purged = 0;
  for (const c of savedContacts) {
    const noNameHash = !c.nameHash;
    const wrongNameHash = c.nameHash && toHex(new Uint8Array(c.nameHash)) !== expectedNameHashHex;
    if (noNameHash || wrongNameHash) {
      await deleteMessagesForContact(c.hash);
      await deleteContact(c.hash);
      purged++;
      continue;
    }
    // Placeholder contacts (created from an inbound LXMF whose sender's
    // announce we'd never seen) carry an empty publicKey. They survive
    // reload because we know their LXMF dest hash, but they're not
    // replyable until handleAnnounce upgrades them with a real key.
    let identity = null;
    if (c.publicKey && c.publicKey.length > 0) {
      identity = new Identity();
      await identity.loadFromPublicKey(new Uint8Array(c.publicKey));
    }
    // destHash may be stored as array; fall back to decoding the hex hash field
    // for legacy records saved before destHash was persisted.
    const destHash = c.destHash ? new Uint8Array(c.destHash) : hexToBytes(c.hash);
    // Rehydrate ratchet pub if this contact was learned from a
    // ratchet-bearing announce. Missing on legacy rows; sendMessage
    // falls back to the identity X25519 key in that case.
    const ratchetPub = c.ratchetPub ? new Uint8Array(c.ratchetPub) : null;
    contacts.set(c.hash, { ...c, identity, destHash, ratchetPub });
  }
  if (purged > 0) {
    log('info', `Removed ${purged} legacy contact${purged === 1 ? '' : 's'} (no verifiable name_hash); valid LXMF peers will return on their next announce`);
  }
  renderContactList();
  renderNodesList();
}

// ---- Packet handling -------------------------------------------------

async function onPacket(data, rssi, snr) {
  const pkt = parsePacket(data);
  if (!pkt) {
    log('rx', `RX ${data.length}B RSSI=${rssi} SNR=${snr} (invalid header)`);
    return;
  }

  const hashHex = toHex(pkt.destHash).substring(0, 12);
  const hdrLabel = pkt.headerType === 0x01 ? ' H2' : '';
  log('rx', `RX ${data.length}B RSSI=${rssi} SNR=${snr} hops=${pkt.hops}${hdrLabel} ${PACKET_TYPE_NAMES[pkt.packetType]} dest=${hashHex}...`);

  const rxInfo = { rssi, snr, hops: pkt.hops, headerType: pkt.headerType };

  if (pkt.packetType === PACKET_ANNOUNCE) {
    await handleAnnounce(pkt, rssi);
  } else if (pkt.packetType === PACKET_DATA) {
    if (pkt.destType === DEST_LINK) {
      await handleLinkData(pkt, rxInfo);
    } else {
      await handleData(pkt, rxInfo);
    }
  } else if (pkt.packetType === PACKET_LINKREQ) {
    if (myDestHash && arraysEqual(pkt.destHash, myDestHash)) {
      await handleLinkRequest(pkt);
    } else {
      log('info', `  LINKREQUEST dest=${toHex(pkt.destHash).substring(0,16)}... (not for us)`);
    }
  } else if (pkt.packetType === PACKET_PROOF) {
    // PROOF types we care about, in order of specificity:
    //   1. LRPROOF (context=0xFF) addressed to one of our pending
    //      initiator links — route to that link's validateProof().
    //   2. PROOF with dest_type=LINK and context=CTX_NONE addressed
    //      to an active initiator link — this is a per-packet
    //      delivery receipt for a message we sent on that link.
    //      The packet hash sits in data[0:32], not the dest slot.
    //   3. Opportunistic delivery PROOF: dest_type=SINGLE (or PLAIN),
    //      dest_hash is the truncated packet hash of the sent packet.
    //      Matched by handleDeliveryProof against saved outgoing rows.
    if (pkt.context === CTX_LRPROOF) {
      await handleInitiatorLinkProof(pkt);
    } else if (pkt.destType === DEST_LINK) {
      await handleLinkDeliveryProof(pkt);
    } else {
      await handleDeliveryProof(pkt);
    }
  }
}

rnode._onPacket = onPacket;

// ---- Announce handling -----------------------------------------------

async function handleAnnounce(pkt, rssi) {
  const announce = await parseAnnounce(pkt.payload, pkt.contextFlag, pkt.destHash);
  if (!announce) {
    log('info', '  (announce rejected: malformed or dest_hash mismatch)');
    return;
  }

  const idHash = toHex(announce.identityHash);

  // Filter by name_hash. The 10-byte name_hash field in the announce
  // identifies which application destination this announce belongs to;
  // we only want lxmf.delivery announces in our contact list. Repeater
  // telemetry beacons (rlr.telemetry), heartbeat destinations, and any
  // other non-LXMF destination produce signed-and-valid announces with
  // a different name_hash and previously polluted the contact list.
  // We still save them to the nodes store so the Nodes panel can show
  // what else is active on the mesh.
  if (!arraysEqual(announce.nameHash, lxmfNameHash)) {
    await handleNonLxmfAnnounce(announce, pkt, rssi);
    return;
  }

  // Display-name preservation. Minimal re-announces (no app_data, common
  // when relays trim or when bots auto-re-announce after handling a
  // message) carry no display name in the announce body, so the
  // extracted value is null. If we just fell straight through to the
  // idHash-prefix fallback we'd clobber a previously-saved real name
  // ("ratdeck1") with a hex prefix on every minimal re-announce, then
  // restore it on the next fat announce — visible UI churn.
  // Priority: extracted > existing > idHashPrefix.
  const extracted = extractDisplayName(announce.appData);
  const destHashHexForExisting = toHex(announce.destHash || pkt.destHash);
  const existing = contacts.get(destHashHexForExisting)?.displayName;
  const displayName = extracted || existing || idHash.substring(0, 8);

  // Skip our own announce (rebroadcast by relay/repeater)
  if (myIdentity && idHash === toHex(myIdentity.hash)) {
    log('info', '  (own announce, ignoring)');
    return;
  }

  // Validate signature
  const valid = validateAnnounce(announce, pkt.destHash);
  log(valid ? 'ok' : 'err', `  Announce from "${displayName}" [${idHash.substring(0,12)}...] sig=${valid ? 'valid' : 'INVALID'}`);

  if (!valid) return;

  // Validated — track in the routing path table. SPEC §2.3 / §12.2:
  // sendMessage uses pathTable to choose HEADER_1 vs HEADER_2 framing;
  // upstreamTransportId is learned from hops=0 announces over the WS
  // interface (only the rnsd we're directly connected to originates
  // announces visible to us with hops=0 — every transit hop bumps
  // hops by 1).
  trackPath(announce, pkt);

  // Store contact. Preserve user-controlled fields (pinned) from any
  // existing row — without this, every re-announce wipes the pin
  // because we'd construct a fresh contact object that doesn't carry
  // the field forward, then save it back to IDB. Don't preserve
  // `placeholder`: receiving a real announce IS the upgrade event,
  // so the row should drop the unannounced tag.
  const destHashBytes = announce.destHash || pkt.destHash;
  const destHashHex = toHex(destHashBytes);
  const existingContact = contacts.get(destHashHex);

  // Public-key-collision rejection (SPEC §4.5 step 4): first-announcer-wins.
  // Once a dest_hash is bound to a public key, refuse to replace that key
  // with a different one. The dest_hash check above already pins the key
  // cryptographically (dest_hash derives from identity_hash = SHA256(key)),
  // so a same-dest_hash/different-key announce implies a forgery attempt or
  // hash collision — drop it rather than overwrite the established identity.
  // A placeholder contact carrying no key yet is allowed to receive its first.
  if (existingContact?.publicKey?.length && !arraysEqual(announce.publicKey, existingContact.publicKey)) {
    log('err', `  Announce for ${destHashHex.substring(0,12)}... carries a different key — ignoring (first-announcer-wins)`);
    return;
  }

  const contact = {
    hash: destHashHex,
    identityHash: idHash,
    publicKey: Array.from(announce.publicKey),
    destHash: Array.from(destHashBytes),
    nameHash: Array.from(announce.nameHash),
    // If the announce carried a ratchet (context_flag=1), keep it
    // on the contact row so sendMessage can encrypt to it instead
    // of the long-term identity X25519 key. Falls back to the
    // identity key in sendMessage when this is null.
    ratchetPub: announce.ratchet ? Array.from(announce.ratchet) : null,
    displayName,
    pinned: !!existingContact?.pinned,
    lastSeen: Date.now(),
    rssi,
  };

  const identity = new Identity();
  await identity.loadFromPublicKey(announce.publicKey);
  const ratchetPubBytes = announce.ratchet ? new Uint8Array(announce.ratchet) : null;
  contacts.set(destHashHex, { ...contact, identity, destHash: destHashBytes, ratchetPub: ratchetPubBytes });

  await saveContact(contact);
  renderContactList();
  // Repeaters typically dual-announce an lxmf.delivery presence
  // AND a telemetry destination from the same identity. Re-render
  // the Nodes list so any matching telemetry beacon inherits this
  // contact's display name immediately.
  renderNodesList();
}

// ---- Non-LXMF announce handling (Nodes panel) ------------------------

// Repeater telemetry beacons, heartbeats, auxiliary destinations, and
// anything else on the mesh that is NOT lxmf.delivery. We keep these
// out of the Messages contact list but track them in a separate store
// so the Nodes panel can show what else is active.
async function handleNonLxmfAnnounce(announce, pkt, rssi) {
  const idHash = toHex(announce.identityHash);

  // Skip our own echoed announces — noisy and never useful.
  if (myIdentity && idHash === toHex(myIdentity.hash)) return;

  // Validate the Ed25519 signature before trusting anything in this
  // announce (SPEC §4.5 step 2). Non-LXMF announces feed trackPath (and
  // thus upstream rnsd identity learning) and the Nodes panel; an
  // unverified announce lets an attacker forge a service/telemetry beacon
  // to poison the path table or inject bogus map nodes. parseAnnounce has
  // already confirmed the dest_hash derives from this key (§4.5 step 3).
  const valid = validateAnnounce(announce, pkt.destHash);
  if (!valid) {
    log('err', `  Non-LXMF announce from ${idHash.substring(0,12)}... sig=INVALID — ignoring`);
    return;
  }

  // Track in pathTable. Non-LXMF announces are how we typically learn
  // the upstream rnsd's identity: rnsd announces a few SINGLE service
  // destinations (rnstransport.broadcasts etc.) that arrive at us
  // with hops=0 — only the directly-connected rnsd produces those.
  trackPath(announce, pkt);

  const destHashBytes = announce.destHash || pkt.destHash;
  const destHashHex = toHex(destHashBytes);
  const nameHashHex = toHex(announce.nameHash);

  // Try to decode the app_data for display. For rlr.telemetry these
  // are semicolon-delimited key=value strings like
  //   bat=3952;up=30;hpf=90720;...;lat=43.16;lon=-85.65;msl=280
  // For heartbeats or other destinations we may just get a name.
  // extractDisplayName already returns a usable string for both.
  const displayName = extractDisplayName(announce.appData) || `${nameHashHex.substring(0, 8)} / ${idHash.substring(0, 8)}`;

  // Parse telemetry out of displayName so nodes that carry lat/lon
  // in their key=value payload can be plotted on the map.
  const telemetry = parseTelemetry(displayName);
  const lat = telemetry ? parseFloat(telemetry.lat) : NaN;
  const lon = telemetry ? parseFloat(telemetry.lon) : NaN;

  // Identify the service from the 10-byte name_hash so the UI can
  // show "rlr.telemetry" etc. instead of the raw hex.
  const known = lookupDestination(announce.nameHash);

  const node = {
    hash: destHashHex,
    identityHash: idHash,
    nameHash: Array.from(announce.nameHash),
    appName: known ? known.name : null,
    appLabel: known ? known.label : null,
    displayName,
    // Persist the 64-byte public key so the NomadNet browser can open a
    // Link to nomadnetwork.node destinations (it needs the Ed25519 half to
    // verify the LRPROOF). The signature was already validated above.
    publicKey: Array.from(announce.publicKey),
    telemetry: telemetry || null,
    lat: Number.isFinite(lat) ? lat : null,
    lon: Number.isFinite(lon) ? lon : null,
    appDataHex: toHex(announce.appData),
    lastSeen: Date.now(),
    rssi,
  };
  await saveNode(node);

  const serviceLabel = known ? ` (${known.name})` : '';
  const coordsLabel = node.lat != null ? ` (lat=${node.lat.toFixed(4)}, lon=${node.lon.toFixed(4)})` : '';
  log('info', `  Non-LXMF announce from ${idHash.substring(0, 12)}...${serviceLabel} → Nodes panel${coordsLabel}`);
  renderNodesList();
}

// Parse a `key=value;key=value;...` telemetry string into an object.
// Returns null for strings that are not key/value telemetry so callers
// can fall back to a raw-label path. Tolerant of whitespace, trailing
// semicolons, and values that contain additional `=` signs.
function parseTelemetry(s) {
  if (!s || typeof s !== 'string') return null;
  if (!s.includes('=') || !s.includes(';')) {
    // Single-pair strings like `key=value` with no semicolons still
    // count; reject anything without an `=` outright.
    if (!s.includes('=')) return null;
  }
  const out = {};
  let hits = 0;
  for (const pair of s.split(';')) {
    if (!pair.trim()) continue;
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    const k = pair.substring(0, eq).trim();
    const v = pair.substring(eq + 1).trim();
    if (!k) continue;
    out[k] = v;
    hits++;
  }
  return hits > 0 ? out : null;
}

// Backfill telemetry/lat/lon and the service-name lookup on node rows
// that were saved before those features landed. Mutates and returns
// the row.
function enrichNode(n) {
  if (!n) return n;
  if (!n.appName && n.nameHash) {
    const known = lookupDestination(n.nameHash);
    if (known) {
      n.appName = known.name;
      n.appLabel = known.label;
    }
  }
  if (!n.telemetry && !(n.lat != null && n.lon != null)) {
    const tel = parseTelemetry(n.displayName);
    if (tel) {
      n.telemetry = tel;
      const lat = parseFloat(tel.lat);
      const lon = parseFloat(tel.lon);
      if (Number.isFinite(lat) && Number.isFinite(lon)) {
        n.lat = lat;
        n.lon = lon;
      }
    }
  }
  return n;
}

// Look up a human-readable node name for this identity by checking
// the contacts list. Repeater firmware (e.g. reticulum-lora-repeater)
// typically broadcasts both a telemetry destination AND an
// lxmf.delivery presence destination from the same identity. The
// lxmf.delivery one carries the configured display_name, which
// becomes a contact entry; we reuse that here so the matching
// telemetry beacon shows up as "Rptr-HFsolar5" instead of just a
// service label.
function nodeNameFromContacts(identityHashHex) {
  if (!identityHashHex) return null;
  for (const c of contacts.values()) {
    if (c.identityHash === identityHashHex) return c.displayName;
  }
  return null;
}

// Human-friendly one-liner for a node row. Preference order for the
// header prefix: contact-matched node name → matched service label
// → "Telemetry" placeholder. Telemetry beacons get a summarised
// "BAT / UP / coords" tail so the list stays readable.
function nodeDisplayLabel(n) {
  const nodeName = nodeNameFromContacts(n.identityHash);
  if (n.telemetry) {
    const bits = [];
    if (n.telemetry.bat) {
      const mv = parseInt(n.telemetry.bat, 10);
      if (Number.isFinite(mv)) bits.push(`${(mv / 1000).toFixed(2)} V`);
      else bits.push(`bat ${n.telemetry.bat}`);
    }
    if (n.telemetry.up) bits.push(`up ${n.telemetry.up}`);
    if (n.lat != null && n.lon != null) {
      bits.push(`${n.lat.toFixed(3)}, ${n.lon.toFixed(3)}`);
    }
    const prefix = nodeName || n.appLabel || 'Telemetry';
    return `${prefix} · ${bits.join(' · ') || 'no fields'}`;
  }
  if (nodeName) return nodeName;
  if (n.appLabel) return n.appLabel;
  return n.displayName || '(unknown)';
}

async function renderNodesList() {
  const list = $('nodes-list');
  if (!list) return;
  let rows;
  try {
    rows = await getAllNodes();
  } catch (e) {
    list.innerHTML = `<div class="err">Could not load nodes: ${escapeHtml(e.message)}</div>`;
    return;
  }
  if (!rows.length) {
    list.innerHTML = '<div class="nodes-empty">No non-LXMF announces yet. This view fills up with repeater telemetry, heartbeats, and anything else on the mesh that is not an LXMF delivery destination.</div>';
    updateMapMarkers([]);
    return;
  }
  // Enrich once, then sort newest-first.
  rows.forEach(enrichNode);
  rows.sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
  list.innerHTML = '';
  for (const n of rows) {
    const li = document.createElement('div');
    li.className = 'node-row';
    li.dataset.hash = n.hash;
    const ts = n.lastSeen ? new Date(n.lastSeen).toLocaleString() : '(unknown)';
    const rssi = (typeof n.rssi === 'number') ? `${n.rssi} dBm` : 'n/a';
    const label = nodeDisplayLabel(n);
    const hasCoords = n.lat != null && n.lon != null;
    const nameHashHex = toHex(new Uint8Array(n.nameHash)).substring(0, 12);
    const serviceCell = n.appName
      ? `<span>service <code>${escapeHtml(n.appName)}</code></span>`
      : `<span>name_hash <code>${nameHashHex}…</code></span>`;
    const identityCell = n.identityHash
      ? `<span title="Identity hash — stable per-node identifier">node <code>${n.identityHash.substring(0, 16)}…</code></span>`
      : '';
    li.innerHTML =
      `<div class="node-row-top">
         <div class="node-name">${escapeHtml(label)}${hasCoords ? ' <span class="node-geo-dot" title="Has coordinates">●</span>' : ''}</div>
         <button class="node-delete" title="Forget this node">\u00d7</button>
       </div>
       <div class="node-meta">
         ${identityCell}
         <span title="Destination hash — service endpoint on this node">dest <code>${n.hash.substring(0, 16)}…</code></span>
         ${serviceCell}
         <span>RSSI ${rssi}</span>
         <span>${ts}</span>
       </div>`;
    li.querySelector('.node-delete').addEventListener('click', async (e) => {
      e.stopPropagation();
      await deleteNode(n.hash);
      // Also drop the marker so the map stays in sync.
      const marker = nodeMarkers.get(n.hash);
      if (marker && nodesMap) nodesMap.removeLayer(marker);
      nodeMarkers.delete(n.hash);
      renderNodesList();
    });
    if (hasCoords) {
      li.addEventListener('click', () => focusNodeOnMap(n.hash));
    }
    list.appendChild(li);
  }

  // Push the enriched rows to the map so markers follow the list.
  updateMapMarkers(rows);
}

// ---- Nodes map (Leaflet, lazy-loaded) --------------------------------

let leafletLib = null;          // cached reference to the loaded L module
let nodesMap = null;             // L.Map instance, created on first view visit
let nodesTileLayer = null;       // active tile layer
let nodeMarkers = new Map();     // hash_hex → L.Marker

// Dynamically import Leaflet from the self-hosted bundle on first use.
// On a box where the file can't load this will reject; callers swallow
// that so the list still works and the map stays as the placeholder.
async function ensureLeaflet() {
  if (leafletLib) return leafletLib;
  const mod = await import('../lib/leaflet.js');
  leafletLib = mod.default || mod;
  return leafletLib;
}

// Create the map on the Nodes view's container the first time the
// user opens the tab. Leaflet needs a container with a non-zero size
// to lay out, which is why this runs after the view is activated.
async function initNodesMap() {
  if (nodesMap) return nodesMap;
  const container = $('nodes-map');
  if (!container) return null;
  let L;
  try {
    L = await ensureLeaflet();
  } catch (e) {
    log('info', `Map unavailable (Leaflet load failed): ${e.message}`);
    return null;
  }
  nodesMap = L.map(container, {
    worldCopyJump: true,
    zoomControl: true,
  }).setView([20, 0], 2);
  nodesTileLayer = L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© OpenStreetMap contributors',
    maxZoom: 19,
  }).addTo(nodesMap);
  // Paint any existing nodes from storage into the fresh map.
  try {
    const rows = (await getAllNodes()).map(enrichNode);
    updateMapMarkers(rows);
  } catch (_) { /* empty store is fine */ }
  return nodesMap;
}

// Sync markers with the given enriched node list. Called from
// renderNodesList every time the list changes and from initNodesMap
// on first creation. Safe to call when Leaflet is not yet loaded —
// it no-ops until the map exists.
function updateMapMarkers(rows) {
  if (!nodesMap || !leafletLib) return;
  const L = leafletLib;
  const seen = new Set();
  const pts = [];
  for (const n of rows) {
    if (n.lat == null || n.lon == null) continue;
    seen.add(n.hash);
    pts.push([n.lat, n.lon]);
    let marker = nodeMarkers.get(n.hash);
    if (!marker) {
      marker = L.marker([n.lat, n.lon]).addTo(nodesMap);
      nodeMarkers.set(n.hash, marker);
    } else {
      marker.setLatLng([n.lat, n.lon]);
    }
    marker.bindPopup(nodePopupHtml(n), { closeButton: true });
  }
  // Drop stale markers for nodes that disappeared.
  for (const [hash, marker] of nodeMarkers) {
    if (!seen.has(hash)) {
      nodesMap.removeLayer(marker);
      nodeMarkers.delete(hash);
    }
  }
  // Auto-fit to visible markers exactly once — the first render that
  // has at least one marker. After that we leave the viewport alone
  // so incoming announces don't yank the user's view around every
  // few seconds.
  if (pts.length > 0 && !nodesMap._autoFitDone) {
    nodesMap.fitBounds(pts, { padding: [48, 48], maxZoom: 13 });
    nodesMap._autoFitDone = true;
  }
}

// Popup markup for a node — reuses the same fields as the list row
// with the full telemetry object dumped below for detail.
function nodePopupHtml(n) {
  const rows = [];
  rows.push(`<div class="popup-title">${escapeHtml(nodeDisplayLabel(n))}</div>`);
  rows.push(`<div class="popup-sub">${n.hash.substring(0, 24)}…</div>`);
  const nodeName = nodeNameFromContacts(n.identityHash);
  if (nodeName) {
    rows.push(`<div class="popup-kv"><span class="popup-kv-key">name</span><span>${escapeHtml(nodeName)}</span></div>`);
  }
  if (n.identityHash) {
    rows.push(`<div class="popup-kv"><span class="popup-kv-key">node</span><span>${n.identityHash.substring(0, 16)}…</span></div>`);
  }
  if (n.appName) {
    rows.push(`<div class="popup-kv"><span class="popup-kv-key">service</span><span>${escapeHtml(n.appName)}</span></div>`);
  }
  if (n.telemetry) {
    for (const [k, v] of Object.entries(n.telemetry)) {
      rows.push(`<div class="popup-kv"><span class="popup-kv-key">${escapeHtml(k)}</span><span>${escapeHtml(v)}</span></div>`);
    }
  }
  if (typeof n.rssi === 'number') {
    rows.push(`<div class="popup-kv"><span class="popup-kv-key">rssi</span><span>${n.rssi} dBm</span></div>`);
  }
  if (n.lastSeen) {
    const ts = new Date(n.lastSeen).toLocaleString();
    rows.push(`<div class="popup-kv"><span class="popup-kv-key">seen</span><span>${escapeHtml(ts)}</span></div>`);
  }
  return rows.join('');
}

// Pan and zoom to a node, open its popup, and highlight the matching
// list row briefly. Called when a list row is clicked.
function focusNodeOnMap(hash) {
  if (!nodesMap) return;
  const marker = nodeMarkers.get(hash);
  if (!marker) return;
  nodesMap.setView(marker.getLatLng(), Math.max(nodesMap.getZoom(), 12), { animate: true });
  marker.openPopup();
  document.querySelectorAll('.node-row.highlighted').forEach(el => el.classList.remove('highlighted'));
  const row = document.querySelector(`.node-row[data-hash="${hash}"]`);
  if (row) row.classList.add('highlighted');
}

// ---- Data packet handling (incoming messages) -------------------------

async function handleData(pkt, rxInfo) {
  // Path-request DATA addressed to the well-known rnstransport.path.request
  // PLAIN destination — handle before the addressed-to-us check, since the
  // dest hash is the path-request service, not our LXMF address.
  if (pathRequestDest && arraysEqual(pkt.destHash, pathRequestDest)) {
    await handlePathRequest(pkt);
    return;
  }

  const incomingHex = toHex(pkt.destHash);
  const ourHex = myDestHash ? toHex(myDestHash) : '(none)';
  const matches = myDestHash && arraysEqual(pkt.destHash, myDestHash);

  log(matches ? 'ok' : 'info',
    `  DATA dest=${incomingHex.substring(0,16)}...  (ours=${ourHex.substring(0,16)}...)  ${matches ? 'MATCH' : 'no match'}`
  );

  if (!matches) return;

  log('info', '  Packet addressed to us — attempting decrypt...');

  try {
    // Try current ratchet, then the previous one (in-memory 1-deep
    // ring per SPEC §7.4 — covers messages already encrypted to the
    // outgoing ratchet by senders that haven't seen the new announce
    // yet), then the long-term identity X25519 key as the ultimate
    // fallback for senders that have no ratchet cached at all.
    const candidatePrivs = [
      myIdentity.ratchetPrivKey,
      myIdentity.previousRatchetPrivKey,
      myIdentity.encPrivKey,
    ].filter(Boolean);
    const plaintext = await decrypt(pkt.payload, candidatePrivs, myIdentity.hash);
    const msg = await unpackMessage(plaintext, myDestHash);
    await dispatchIncomingMessage(msg, rxInfo);

    // Send opportunistic delivery PROOF back so the sender (Sideband) sees
    // the message as delivered and stops retransmitting. Upstream RNS
    // Packet.prove() for opportunistic delivery builds a PROOF packet
    // whose destHash is the first 16 bytes of the received packet's
    // full SHA-256 hash, and whose payload is an Ed25519 signature over
    // that full 32-byte hash (signed with our long-term identity
    // signing key so the sender can verify against the sig_pub from
    // our announce). We send on every successful decrypt — even for
    // dupes — because the sender keeps retransmitting until it sees
    // its own packet's proof come back.
    try {
      const packetHash  = await computePacketFullHash(pkt);
      const signature   = ed25519.sign(packetHash, myIdentity.sigPrivKey);
      const proofPacket = buildPacket({
        headerType: HEADER_1,
        destType:   DEST_SINGLE,
        packetType: PACKET_PROOF,
        destHash:   packetHash.subarray(0, 16),
        context:    0x00,
        payload:    signature,
      });
      await rnode.sendPacket(proofPacket);
      log('info', `  Opportunistic PROOF sent, dest=${toHex(packetHash.subarray(0, 16))}`);
    } catch (e) {
      log('info', `  Proof send failed: ${e.message}`);
    }
  } catch (e) {
    // On HMAC failure, log enough context to diagnose a stale-cache
    // scenario: the sender's ephemeral pubkey (visible on the wire)
    // plus the first bytes of OUR current pubkeys so the user can
    // tell if Sideband encrypted to a ratchet we no longer have.
    const ephPubHex = pkt.payload.length >= 32 ? toHex(pkt.payload.subarray(0, 32)).substring(0, 16) : '(short)';
    const ratchetPubPrefix = myIdentity.ratchetPubKey ? toHex(myIdentity.ratchetPubKey).substring(0, 16) : '(none)';
    const encPubPrefix = myIdentity.encPubKey ? toHex(myIdentity.encPubKey).substring(0, 16) : '(none)';
    log('err', `  Decrypt/parse failed: ${e.message}`);
    log('info', `    sender eph pub: ${ephPubHex}...`);
    log('info', `    our ratchet pub: ${ratchetPubPrefix}... enc pub: ${encPubPrefix}...`);
    log('info', `    tried ${candidatePrivs.length} key(s). If sender has a stale contact, send an announce and ask them to retry.`);
  }
}

// Update pathTable from a received announce, and learn upstream
// transport_id from hops=0 announces over the WS interface.
//
// SPEC §2.3: when sending to a destination > 1 hop away, the
// originator MUST emit HEADER_2 with the next-hop transport_id.
// pathTable lets us know hops; upstreamTransportId lets us know
// which identity to insert.
//
// SPEC §2.4: hops is incremented by every transit relay. Only the
// originator emits hops=0 — so an announce arriving at us with
// pkt.hops==0 over the WS interface MUST have come from the rnsd
// we're directly connected to (every other peer's announce gets
// bumped to >=1 by the time it reaches us through that rnsd).
function trackPath(announce, pkt) {
  const destHashHex = toHex(announce.destHash || pkt.destHash);
  pathTable.set(destHashHex, { hops: pkt.hops, lastSeen: Date.now() });
  if (pathTable.size > PATH_TABLE_MAX) {
    const oldest = pathTable.keys().next().value;
    pathTable.delete(oldest);
  }

  // Learn the upstream rnsd's identity from inbound HEADER_2 packets.
  // Empirically (v0.4.1 testing on rns.michmesh.net), michmesh forwards
  // announces to TCPServerInterface peers as HEADER_2 with its own
  // identity in the transport_id field — so any H2 packet's
  // pkt.transportId IS our upstream's identity, exactly the value we
  // need to insert when emitting HEADER_2 sends per SPEC §2.3.
  //
  // We don't try the hops=0 ANNOUNCE channel in practice: many
  // production rnsd deployments don't emit SINGLE self-announces with
  // hops=0, and even when they do they're easy to miss (rare cadence).
  // The H2 transport_id channel fires on every inbound packet.
  //
  // Only learn when there's no RNode in the loop — over BLE/serial,
  // any transport_id we'd see is from a different topology.
  if (pkt.headerType === HEADER_2
      && pkt.transportId && pkt.transportId.length === 16
      && rnode && rnode.capabilities && rnode.capabilities.rnodeControl === false) {
    if (upstreamTransportId === null) {
      upstreamTransportId = new Uint8Array(pkt.transportId);
      log('info', `Learned upstream rnsd identity ${toHex(upstreamTransportId)} from inbound HEADER_2 transport_id (will use as next-hop for HEADER_2 sends per SPEC §2.3)`);
    } else if (!arraysEqual(pkt.transportId, upstreamTransportId)) {
      // Different transport_id seen — could mean we're behind a
      // multi-rnsd path or our learning was wrong. Don't log on every
      // packet (would flood); rely on the user to notice send failures.
    }
  }

  // Resolve any path? request that was waiting for this destination.
  const pending = pendingPathRequests.get(destHashHex);
  if (pending) {
    clearTimeout(pending.timer);
    pendingPathRequests.delete(destHashHex);
    pending.resolve(true);
  }
}

// Issue a path? request to the well-known rnstransport.path.request
// dest and wait up to PATH_REQUEST_WAIT_MS for a path-response
// announce to populate pathTable. Returns true if a path arrived in
// time, false on timeout. SPEC §7.1, flows/send-opportunistic-lxmf.md
// step 4.
//
// Payload (leaf form): target_dest_hash(16) || random_tag(16) — 32 bytes.
async function requestPath(destHash) {
  if (!pathRequestDest) {
    log('err', '  Cannot send path? — pathRequestDest not initialised');
    return false;
  }
  const destHashHex = toHex(destHash);

  // Already known — nothing to do.
  if (pathTable.has(destHashHex)) return true;

  // Coalesce: if a request is already in flight for this dest, wait
  // on the same promise rather than spamming duplicate path? packets.
  const existing = pendingPathRequests.get(destHashHex);
  if (existing) {
    return new Promise((resolve) => {
      const orig = existing.resolve;
      existing.resolve = (ok) => { orig(ok); resolve(ok); };
    });
  }

  const tag = new Uint8Array(16);
  crypto.getRandomValues(tag);
  const payload = new Uint8Array(32);
  payload.set(destHash, 0);
  payload.set(tag, 16);

  const packet = buildPacket({
    headerType: HEADER_1,
    destType: DEST_PLAIN,
    transportType: TRANSPORT_BROADCAST,
    packetType: PACKET_DATA,
    destHash: pathRequestDest,
    context: CTX_NONE,
    payload,
  });

  log('info', `  path? sent for ${destHashHex.substring(0,16)}... tag=${toHex(tag).substring(0,16)}`);
  await rnode.sendPacket(packet);

  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pendingPathRequests.delete(destHashHex);
      resolve(false);
    }, PATH_REQUEST_WAIT_MS);
    pendingPathRequests.set(destHashHex, { resolve, timer });
  });
}

// Path-request handler. Implements the minimum-leaf responsibility
// from SPEC §7.2.6 (verified against RNS 1.2.0 by upstream
// tools/verify_path_request.py):
//
//   1. Parse target_dest_hash + tag from the payload.
//   2. Drop tagless requests (upstream RNS logs and discards).
//   3. Drop duplicates via a (target || tag) dedup table — without
//      this we'd re-respond on every retransmit and storm the mesh.
//   4. If the target matches one of our destinations, emit a
//      path-response announce on the receiving interface.
//   5. Otherwise drop — leaves don't relay path? requests for
//      destinations they don't OWN.
//
// Payload layout (§7.2.1):
//   data[0:16]   target_dest_hash (mandatory)
//   leaf form (len == 32):     data[16:32] = tag
//   transport form (len > 32): data[16:32] = transport_id, data[32:48] = tag
async function handlePathRequest(pkt) {
  if (pkt.payload.length < 17) {
    // 16B target + at least 1B tag is the minimum acceptable shape.
    log('info', '  path? rx — tagless or short payload, dropped per §7.2.1');
    return;
  }
  const target = pkt.payload.subarray(0, 16);
  let tag;
  if (pkt.payload.length > 32) {
    // Transport-originator form; skip the 16B transport_id.
    tag = pkt.payload.subarray(32);
  } else {
    tag = pkt.payload.subarray(16);
  }
  if (tag.length === 0) {
    log('info', '  path? rx — tagless, dropped per §7.2.1');
    return;
  }
  if (tag.length > 16) tag = tag.subarray(0, 16);

  const targetHex = toHex(target);
  const tagHex = toHex(tag);
  const dedupKey = `${targetHex}|${tagHex}`;

  if (pathRequestDedup.has(dedupKey)) {
    log('info', `  path? rx for ${targetHex.substring(0,16)}... duplicate tag, ignored`);
    return;
  }
  pathRequestDedup.add(dedupKey);
  // FIFO eviction once over cap. Set iteration is insertion order.
  if (pathRequestDedup.size > PATH_REQUEST_DEDUP_MAX) {
    const oldest = pathRequestDedup.values().next().value;
    pathRequestDedup.delete(oldest);
  }

  if (!myDestHash || !arraysEqual(target, myDestHash)) {
    log('info', `  path? rx for ${targetHex.substring(0,16)}... (not us; not a transport node — dropped)`);
    return;
  }

  log('info', `  path? rx for us (tag=${tagHex.substring(0,16)}) — sending path-response announce`);
  await sendAnnounce({ pathResponse: true });
}

// Recent incoming LXMF dedupe set. A single logical message can
// arrive multiple times: relayed by repeaters, retransmitted by
// the sender's retry queue, or delivered via both opportunistic
// and link paths. All those variants carry the same
// (sourceHash, timestamp, content) tuple, so we hash that tuple
// into a dedupe key and drop subsequent hits within the same
// session. Persisted rows already contain only one copy because
// the dedupe ran before saving. The Map value tracks the saved
// message's IndexedDB id and a running count of duplicate
// arrivals so the UI can display "×3" next to the message.
const recentMessageMap = new Map();  // dedupeKey → { dbId, dupeCount }
const RECENT_MESSAGE_MAP_LIMIT = 500;

function messageDedupeKey(sourceHashHex, content, timestamp) {
  return `${sourceHashHex}|${timestamp ?? 'null'}|${content ?? ''}`;
}

// Play a short audible alert for new incoming messages. Uses Web
// Audio directly so no asset has to be bundled; a pair of short
// sine beeps at A5 is noticeable but not annoying. Web Audio is
// gated by the browser's autoplay policy, which is why we lazy-
// initialise the AudioContext on first use — by that time the
// user has already clicked Connect, which satisfies the user-
// gesture requirement. Also buzzes the phone briefly when the
// Vibration API is present (mobile browsers).
let _audioCtx = null;
function playMessageBeep() {
  try {
    if (!_audioCtx) {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      _audioCtx = new Ctx();
    }
    if (_audioCtx.state === 'suspended') _audioCtx.resume().catch(() => {});
    const now = _audioCtx.currentTime;
    for (let i = 0; i < 2; i++) {
      const osc = _audioCtx.createOscillator();
      const gain = _audioCtx.createGain();
      osc.type = 'sine';
      osc.frequency.value = 880;
      const t0 = now + i * 0.14;
      gain.gain.setValueAtTime(0, t0);
      gain.gain.linearRampToValueAtTime(0.18, t0 + 0.01);
      gain.gain.linearRampToValueAtTime(0, t0 + 0.11);
      osc.connect(gain);
      gain.connect(_audioCtx.destination);
      osc.start(t0);
      osc.stop(t0 + 0.13);
    }
  } catch (_) { /* audio is cosmetic — never let it break message handling */ }
  try {
    if (navigator.vibrate) navigator.vibrate(120);
  } catch (_) { /* ditto */ }
}

// Common post-decrypt handling shared between opportunistic (handleData)
// and link-delivered (handleLinkData) inbound LXMF messages.
// rxInfo = { rssi, snr, hops, headerType }
async function dispatchIncomingMessage(msg, rxInfo) {
  const sourceHashHex = toHex(msg.sourceHash);
  let senderName = sourceHashHex.substring(0, 8);
  let contactHash = null;

  log('info', `  LXMF payload: elements=${msg.payloadElementCount} raw_msgpack=${msg.msgpackData.length}B stripped=${msg.msgpackForHash.length}B destHashInBody=${toHex(msg.destHash).substring(0, 16)}...`);

  // Session-level dedupe. On a duplicate, increment the count on
  // the already-saved row and re-render so the user sees "×2", "×3",
  // etc. but no new bubble appears.
  const dedupeKey = messageDedupeKey(sourceHashHex, msg.content, msg.timestamp);
  const existing = recentMessageMap.get(dedupeKey);
  if (existing) {
    existing.dupeCount++;
    log('info', `  Duplicate #${existing.dupeCount} from ${sourceHashHex.substring(0, 12)}... (hops=${rxInfo.hops} RSSI=${rxInfo.rssi})`);
    await updateMessage(existing.dbId, { dupeCount: existing.dupeCount });
    if (activeContactHash) await renderMessages(activeContactHash);
    return;
  }

  for (const [hash, c] of contacts) {
    if (c.identityHash === sourceHashHex || hash === sourceHashHex) {
      senderName = c.displayName;
      contactHash = hash;
      // Skip the signature check for placeholder rows — they carry
      // no public key yet, so verifyMessageSignature would throw.
      // The check fires once the peer's announce upgrades the row.
      if (c.identity) {
        const result = verifyMessageSignature(msg, c.identity);
        if (result.ok) {
          log('ok', `  Signature: valid (${result.variant})`);
        } else {
          log('err', `  Signature: INVALID (both stripped and original failed)`);
        }
      } else {
        log('info', `  Signature: skipped (placeholder contact, no public key yet)`);
      }
      break;
    }
  }

  // No matching contact — auto-create a placeholder so the sidebar
  // surfaces the conversation. Public mesh peers commonly reach us
  // before their announce does (we restarted, the announce got
  // dropped on the radio, or they're propagated through a node we
  // can't see directly). Without this row the message lands in
  // IndexedDB and the ding fires but nothing appears in the UI.
  // handleAnnounce will overwrite this entry with the real key
  // material once we eventually hear from them; until then, the
  // contact is read-only (sendMessage refuses to encrypt without a
  // public key).
  if (!contactHash) {
    const placeholderName = sourceHashHex.substring(0, 8);
    const placeholderRow = {
      hash: sourceHashHex,
      identityHash: null,
      publicKey: [],   // empty signals "placeholder" to the hydrate path
      destHash: Array.from(msg.sourceHash),
      // We know it's an LXMF peer because the decrypt + msgpack unpack
      // succeeded as LXMF — so the purge filter on next reload will
      // accept this row.
      nameHash: Array.from(lxmfNameHash),
      ratchetPub: null,
      displayName: placeholderName,
      placeholder: true,
      lastSeen: Date.now(),
      rssi: rxInfo.rssi,
    };
    contacts.set(sourceHashHex, { ...placeholderRow, identity: null, destHash: msg.sourceHash });
    await saveContact(placeholderRow);
    contactHash = sourceHashHex;
    senderName = placeholderName;
    log('info', `  Created placeholder contact for unknown sender ${sourceHashHex.substring(0,16)}... (no announce seen yet — reply disabled until they announce)`);
  }

  const via = rxInfo.hops === 0 ? 'direct' : `${rxInfo.hops} hop${rxInfo.hops > 1 ? 's' : ''}`;
  log('ok', `  Message from "${senderName}" (${via}, RSSI=${rxInfo.rssi}, SNR=${rxInfo.snr}): ${msg.content}`);

  const senderTs = normalizeLxmfTimestamp(msg.timestamp);
  const savedMsg = {
    contactHash: contactHash || sourceHashHex,
    direction: 'incoming',
    content: msg.content,
    title: msg.title,
    timestamp: senderTs != null ? senderTs : Date.now(),
    senderTimeMissing: senderTs == null,
    rssi: rxInfo.rssi,
    snr: rxInfo.snr,
    hops: rxInfo.hops,
    headerType: rxInfo.headerType,
    dupeCount: 1,
  };
  const dbId = await saveMessage(savedMsg);
  log('info', `  Saved under contactHash=${savedMsg.contactHash.substring(0, 16)}... activeContact=${activeContactHash ? activeContactHash.substring(0, 16) + '...' : '(none)'}`);

  // Track in the dedupe map so future duplicates increment the count.
  recentMessageMap.set(dedupeKey, { dbId, dupeCount: 1 });
  if (recentMessageMap.size > RECENT_MESSAGE_MAP_LIMIT) {
    const iter = recentMessageMap.keys();
    recentMessageMap.delete(iter.next().value);
  }

  playMessageBeep();

  if (activeContactHash === savedMsg.contactHash) {
    await renderMessages(activeContactHash);
  }
  // Flag the contact as having unread traffic so the sidebar shows
  // something even when the user isn't currently in that conversation.
  const c = contacts.get(savedMsg.contactHash);
  if (c) {
    c.unreadCount = (c.unreadCount || 0) + 1;
    renderContactList();
  }
}

// ---- Link handling ---------------------------------------------------

async function handleLinkRequest(pkt) {
  const sizeOk = pkt.payload.length === 64 || pkt.payload.length === 67;
  if (!sizeOk) {
    log('err', `  LINKREQUEST addressed to us but payload size ${pkt.payload.length} is not 64 or 67, dropping`);
    return;
  }

  try {
    // Trace the inbound request for byte-level debugging of the link_id
    // derivation. First line shows the full header state (type, flags,
    // hops, and the context byte). Second line shows the 64 or 67 bytes
    // of LINKREQUEST data.
    log('info', `  LR header type=${pkt.headerType === HEADER_1 ? 'H1' : 'H2'} flags=0x${pkt.flags.toString(16).padStart(2,'0')} hops=${pkt.hops} ctx=0x${pkt.context.toString(16).padStart(2,'0')}`);
    log('info', `  LR data(${pkt.payload.length})=${toHex(pkt.payload)}`);

    const { link, proofData } = await Link.validateRequest(pkt, myIdentity);
    const linkIdHex = toHex(link.linkId);

    // If we've already accepted this exact request, just resend the
    // cached LRPROOF. Regenerating the ephemeral key would orphan the
    // initiator's existing session state.
    const existing = links.get(linkIdHex);
    const linkToStore = existing || link;
    if (!existing) links.set(linkIdHex, link);

    const proofPacket = buildPacket({
      headerType: HEADER_1,
      destType:   DEST_LINK,
      packetType: PACKET_PROOF,
      destHash:   linkToStore.linkId,
      context:    CTX_LRPROOF,
      payload:    linkToStore.cachedProofData,
    });

    // Dump everything needed to independently recompute the signature
    // and confirm the math is self-consistent without having to repro
    // on a second device.
    log('info', `  LR sigpub=${toHex(linkToStore.ourSigPub)}`);
    log('info', `  LR signed(${linkToStore.signedData.length})=${toHex(linkToStore.signedData)}`);
    log('info', `  LRPROOF tx(${proofPacket.length})=${toHex(proofPacket)}`);

    await rnode.sendPacket(proofPacket);

    log('ok', `  LINKREQUEST accepted, LRPROOF sent (link ${linkIdHex.substring(0,12)}...)`);
  } catch (e) {
    log('err', `  LINKREQUEST validation failed: ${e.message}`);
  }
}

async function handleLinkData(pkt, rxInfo) {
  const linkIdHex = toHex(pkt.destHash);
  const link = links.get(linkIdHex);
  if (!link) {
    log('info', `  DATA for unknown link ${linkIdHex.substring(0,16)}..., ignoring`);
    return;
  }

  try {
    switch (pkt.context) {
      case CTX_NONE: {
        // Full LXMF container encrypted with the link session key.
        const plaintext = await link.decrypt(pkt.payload);
        const msg = await unpackLinkMessage(plaintext);
        log('ok', `  Link ${linkIdHex.substring(0,12)}... delivered LXMF message`);
        await dispatchIncomingMessage(msg, rxInfo);
        // Send a link packet proof back so the sender's delivery
        // receipt timeout fires with success and it does not retry
        // the same message on a fresh link. Upstream's Link.receive
        // does this automatically via Packet.prove() whenever an
        // application-level data packet arrives on an established
        // link. The proof carries the full 32-byte SHA-256 of the
        // received packet's hashable_part plus an Ed25519 signature
        // over that hash. SPEC §6.5.1: the signing key is the LINK's
        // Ed25519 key (`Link.sig_prv`) — on the responder side that is
        // our long-term identity key, on the initiator side it is the
        // link's ephemeral key. `link.ourSigPriv` already holds the
        // right one for each role, so the peer verifies against the
        // matching pub (our announce key, or our LINKREQUEST ephemeral
        // key it cached).
        try {
          const packetHash = await computePacketFullHash(pkt);
          const signature  = ed25519.sign(packetHash, link.ourSigPriv);
          const proofData  = new Uint8Array(packetHash.length + signature.length);
          proofData.set(packetHash, 0);
          proofData.set(signature, packetHash.length);
          const proofPacket = buildPacket({
            headerType: HEADER_1,
            destType:   DEST_LINK,
            packetType: PACKET_PROOF,
            destHash:   link.linkId,
            context:    CTX_NONE,
            payload:    proofData,
          });
          await rnode.sendPacket(proofPacket);
        } catch (e) {
          log('info', `  Packet receipt send failed: ${e.message}`);
        }
        break;
      }
      case CTX_LRRTT: {
        // Decrypting it is how we confirm the initiator successfully
        // verified our LRPROOF; the RTT value itself is not useful here.
        await link.decrypt(pkt.payload);
        link.status = LINK_ACTIVE;
        link.establishedAt = Date.now();
        log('ok', `  Link ${linkIdHex.substring(0,12)}... ACTIVE (RTT ack received)`);
        break;
      }
      case CTX_LINKCLOSE: {
        const plaintext = await link.decrypt(pkt.payload);
        if (plaintext.length === link.linkId.length &&
            arraysEqual(plaintext, link.linkId)) {
          link.status = LINK_CLOSED;
          links.delete(linkIdHex);
          log('info', `  Link ${linkIdHex.substring(0,12)}... closed by peer`);
        } else {
          log('err', `  LINKCLOSE payload did not match link_id, ignoring`);
        }
        break;
      }
      case CTX_KEEPALIVE: {
        // KEEPALIVE is NOT Token-encrypted — the body is a single clear
        // sentinel byte: 0xFF = ping (initiator→responder), 0xFE = pong
        // (responder→initiator). SPEC §6.7.1: the responder MUST answer
        // an inbound ping with a pong, otherwise the initiator's watchdog
        // declares the link stale on its next cycle and tears it down. A
        // pong itself needs no reply — any inbound link traffic already
        // refreshes the peer's staleness clock.
        if (pkt.payload.length >= 1 && pkt.payload[0] === 0xFF) {
          const pong = buildPacket({
            headerType: HEADER_1,
            destType:   DEST_LINK,
            packetType: PACKET_DATA,
            destHash:   link.linkId,
            context:    CTX_KEEPALIVE,
            payload:    new Uint8Array([0xFE]),
          });
          try {
            await rnode.sendPacket(pong);
            log('info', `  Link ${linkIdHex.substring(0,12)}... keepalive ping → pong`);
          } catch (e) {
            log('info', `  Keepalive pong send failed: ${e.message}`);
          }
        }
        break;
      }
      case CTX_RESPONSE: {
        // Inline NomadNet RESPONSE (fits one packet) — msgpack [request_id, response].
        const plaintext = await link.decrypt(pkt.payload);
        const { requestId, response } = parseResponse(plaintext);
        await handleNomadNetResponse(link, requestId, response);
        break;
      }
      case CTX_RESOURCE_ADV: {
        // A large RESPONSE arriving as a Resource (§10).
        const plaintext = await link.decrypt(pkt.payload);
        const adv = parseAdvertisement(plaintext);
        startResourceReceive(link, adv);
        break;
      }
      case CTX_RESOURCE: {
        // A raw part slice — NOT individually decrypted (§10.6).
        if (link._resource) await link._resource.handlePart(pkt.payload);
        break;
      }
      case CTX_RESOURCE_HMU: {
        const plaintext = await link.decrypt(pkt.payload);
        if (link._resource) link._resource.handleHashmapUpdate(plaintext);
        break;
      }
      case CTX_RESOURCE_ICL: {
        if (link._resource) link._resource.cancel('sender cancelled the resource');
        break;
      }
      default: {
        log('info', `  Link packet context 0x${pkt.context.toString(16)} not handled`);
      }
    }
  } catch (e) {
    log('err', `  Link packet handling failed (ctx=0x${pkt.context.toString(16)}): ${e.message}`);
  }
}

// Cleanly tear down an active link by emitting a LINKCLOSE (SPEC §6.7.3):
// a DATA packet, context=LINKCLOSE, dest_hash=link_id, body = the 16-byte
// link_id Token-encrypted with the link session key. The peer decrypts and
// checks the plaintext equals link_id before closing, so the body is both
// encrypted and authenticated. Without this the peer holds the link open
// until its own watchdog declares it stale (2× keepalive later). Only
// meaningful for links that reached ACTIVE (have a derived session key);
// pending links are dropped silently. We do NOT echo a LINKCLOSE when the
// peer closes us (upstream doesn't), so this is for locally-initiated
// teardown only.
async function closeLink(link) {
  const linkIdHex = toHex(link.linkId);
  try {
    if (link.status === LINK_ACTIVE && link.derivedKey) {
      const encrypted = await link.encrypt(link.linkId);
      const closePacket = buildPacket({
        headerType: HEADER_1,
        destType:   DEST_LINK,
        packetType: PACKET_DATA,
        destHash:   link.linkId,
        context:    CTX_LINKCLOSE,
        payload:    encrypted,
      });
      await rnode.sendPacket(closePacket);
      log('info', `  Sent LINKCLOSE for link ${linkIdHex.substring(0,12)}...`);
    }
  } catch (e) {
    log('info', `  LINKCLOSE send failed for ${linkIdHex.substring(0,12)}...: ${e.message}`);
  } finally {
    link.status = LINK_CLOSED;
    links.delete(linkIdHex);
  }
}

// Cleanly close every active link — used on disconnect so peers tear down
// immediately instead of waiting out their watchdog.
async function closeAllLinks() {
  for (const link of Array.from(links.values())) {
    await closeLink(link);
  }
}

// ---- Initiator-side link establishment ------------------------------

// Open an outbound Link to the given contact. Returns a Promise that
// resolves to the active Link once the LRPROOF has verified and the
// LRRTT has been emitted, or rejects with an Error on timeout or
// signature failure. The caller then uses link.encrypt to wrap
// payloads and routes them through sendViaLink.
async function openLinkToContact(contact, timeoutMs = 15000) {
  if (!radioOn) throw new Error('Radio not on');
  if (!contact || !contact.identity || !contact.identity.sigPubKey) {
    throw new Error('Contact has no known sig pub; need an announce first');
  }

  const { link, requestData } = Link.createInitiator(
    contact.identity.sigPubKey,
    contact.destHash,
  );

  const lrPacket = buildPacket({
    headerType: HEADER_1,
    destType:   DEST_SINGLE,
    packetType: PACKET_LINKREQ,
    destHash:   contact.destHash,
    context:    CTX_NONE,
    payload:    requestData,
  });

  // link_id is derived from the packed LINKREQUEST packet, so it
  // must be computed AFTER buildPacket. Feed the parsed version back
  // through computeLinkId so the bytes match exactly what the
  // responder will compute on its end.
  const parsedLR = parsePacket(lrPacket);
  await link.setLinkIdFromPacket(parsedLR);
  const linkIdHex = toHex(link.linkId);

  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });

  const entry = {
    link,
    contact,
    resolve,
    reject,
    timer: setTimeout(() => {
      if (initiatorLinks.has(linkIdHex)) {
        initiatorLinks.delete(linkIdHex);
        log('err', `Link to "${contact.displayName}" timed out after ${timeoutMs}ms`);
        reject(new Error('Link establishment timeout'));
      }
    }, timeoutMs),
  };
  initiatorLinks.set(linkIdHex, entry);

  log('info', `Opening link to "${contact.displayName}" (link_id=${linkIdHex.substring(0,12)}...)`);
  try {
    await rnode.sendPacket(lrPacket);
  } catch (e) {
    clearTimeout(entry.timer);
    initiatorLinks.delete(linkIdHex);
    reject(e);
  }

  return promise;
}

// Handle an inbound LRPROOF that might belong to one of our pending
// initiator links. If the dest_hash matches an entry in our map,
// verify the proof and on success emit the LRRTT packet to transition
// the responder to ACTIVE on its side, then resolve the caller's
// promise with the active link.
async function handleInitiatorLinkProof(pkt) {
  const linkIdHex = toHex(pkt.destHash);
  const entry = initiatorLinks.get(linkIdHex);
  if (!entry) {
    // Not one of ours (responder-side LRPROOF addressed to someone
    // else's link, or an LRPROOF for a link we already torn down).
    return;
  }

  const result = await entry.link.validateProof(pkt);
  if (!result.ok) {
    log('err', `  LRPROOF rejected on link ${linkIdHex.substring(0,12)}...: ${result.reason}`);
    clearTimeout(entry.timer);
    initiatorLinks.delete(linkIdHex);
    entry.reject(new Error(result.reason));
    return;
  }

  log('ok', `  Link ${linkIdHex.substring(0,12)}... ACTIVE (rtt=${result.rtt.toFixed(3)}s)`);

  // Send the LRRTT packet back so the responder transitions its side
  // to ACTIVE. This is a DATA packet with context=LRRTT addressed to
  // the link_id, carrying the Token-encrypted msgpack of the rtt.
  const rttPacket = buildPacket({
    headerType: HEADER_1,
    destType:   DEST_LINK,
    packetType: PACKET_DATA,
    destHash:   entry.link.linkId,
    context:    CTX_LRRTT,
    payload:    result.rttData,
  });
  try {
    await rnode.sendPacket(rttPacket);
  } catch (e) {
    log('err', `  LRRTT send failed: ${e.message}`);
  }

  clearTimeout(entry.timer);
  initiatorLinks.delete(linkIdHex);
  // Keep the link itself reachable so sendViaLink can find it by id.
  links.set(linkIdHex, entry.link);

  entry.resolve(entry.link);
}

// Send a pre-packed LXMF container over an already-ACTIVE link.
// Returns the truncated packet hash suitable for matching a later
// delivery PROOF so the caller can update the outgoing message row.
async function sendViaLink(link, packedLxmf) {
  const encrypted = await link.encrypt(packedLxmf);
  const dataPacket = buildPacket({
    headerType: HEADER_1,
    destType:   DEST_LINK,
    packetType: PACKET_DATA,
    destHash:   link.linkId,
    context:    CTX_NONE,
    payload:    encrypted,
  });
  await rnode.sendPacket(dataPacket);

  // Compute the full 32-byte packet hash of what we just sent so a
  // subsequent link-delivery PROOF (which carries the packet hash
  // in its data, not in its dest slot) can be matched back to this
  // send. Truncated to 16 bytes because that's what our existing
  // outbound row stores for opportunistic matching.
  const parsed = parsePacket(dataPacket);
  const fullHash = await computePacketFullHash(parsed);
  return { packet: dataPacket, packetHash: fullHash };
}

// Match a link-delivered delivery PROOF back to an outbound row. The
// proof's dest_hash is the link_id, and data[0:32] is the original
// packet's full 32-byte hash. We store only the first 16 bytes on
// the row, so match on the prefix.
async function handleLinkDeliveryProof(pkt) {
  if (pkt.payload.length < 32) return;
  const packetHashPrefixHex = toHex(pkt.payload.subarray(0, 16));
  const rows = await getAllMessages();
  for (const row of rows) {
    if (row.direction !== 'outgoing') continue;
    if (row.packetHash !== packetHashPrefixHex) continue;
    if (row.state === MSG_STATE_DELIVERED) return;
    await updateMessage(row.id, { state: MSG_STATE_DELIVERED });
    const preview = (row.content || '').substring(0, 24);
    log('ok', `  Link delivery proof matched outbound "${preview}"`);
    if (activeContactHash === row.contactHash) {
      await renderMessages(activeContactHash);
    }
    return;
  }
}

// ---- NomadNet browser ------------------------------------------------
//
// Drives the existing initiator-link path (openLinkToContact → sendViaLink
// → handleLinkData) to fetch NomadNet pages over the REQUEST/RESPONSE
// protocol (§11), reassembling large pages via the Resource receiver (§10)
// and rendering micron markup.

const nnState = {
  destHashHex: null,   // node we're currently linked to
  link: null,          // active browse link
  path: null,          // current path
};
let nnHistory = [];
let nnHistoryIdx = -1;

function nnSetStatus(msg, kind = 'info') {
  const el = $('nn-status');
  if (el) { el.textContent = msg; el.className = `nn-status nn-status-${kind}`; }
  if (msg) log(kind === 'err' ? 'err' : 'info', `  NomadNet: ${msg}`);
}

function nnSetAddress(destHashHex, path) {
  const el = $('nn-address');
  if (el) el.value = `${destHashHex}:${path}`;
}

// Build a contact-shaped object for a nomadnetwork.node from its stored
// announce so openLinkToContact can establish a Link.
async function nnNodeContact(destHashHex) {
  const nodes = await getAllNodes();
  const node = nodes.find(n => n.hash === destHashHex);
  if (!node) throw new Error('node not seen yet — wait for its announce');
  if (!node.publicKey || node.publicKey.length !== 64) {
    throw new Error('node announce predates browser support — wait for a fresh announce');
  }
  const identity = new Identity();
  await identity.loadFromPublicKey(new Uint8Array(node.publicKey));
  const destHash = hexToBytes(destHashHex);
  return { identity, destHash, displayName: node.displayName || destHashHex.slice(0, 8), hash: destHashHex };
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

// Get an active link to destHashHex, reusing the current browse link when
// it targets the same node, otherwise opening a fresh one (closing the old).
async function nnEnsureLink(destHashHex) {
  if (nnState.link && nnState.link.status === LINK_ACTIVE && nnState.destHashHex === destHashHex) {
    return nnState.link;
  }
  if (nnState.link && nnState.link.status === LINK_ACTIVE) {
    closeLink(nnState.link).catch(() => {});
  }
  nnSetStatus(`opening link to ${destHashHex.slice(0, 12)}…`);
  const contact = await nnNodeContact(destHashHex);
  const link = await openLinkToContact(contact);
  nnState.link = link;
  nnState.destHashHex = destHashHex;
  return link;
}

// The send callback the ResourceReceiver uses to emit REQ/PRF/RCL packets.
function nnResourceSend(link) {
  return async (context, payload, isProof) => {
    let packet;
    if (isProof) {
      packet = buildPacket({
        headerType: HEADER_1, destType: DEST_LINK, packetType: PACKET_PROOF,
        destHash: link.linkId, context, payload,
      });
    } else {
      const enc = await link.encrypt(payload);
      packet = buildPacket({
        headerType: HEADER_1, destType: DEST_LINK, packetType: PACKET_DATA,
        destHash: link.linkId, context, payload: enc,
      });
    }
    await rnode.sendPacket(packet);
  };
}

// Create and start a Resource receiver for an inbound advertisement.
function startResourceReceive(link, adv) {
  // Only the browser drives resources today. An advertisement on a link
  // with no pending page request is something else (e.g. a large inbound
  // LXMF message over a responder link) — out of scope; don't misparse it.
  if (!link._nnRequest) {
    log('info', `  Resource advertised on link ${toHex(link.linkId).substring(0,12)}... with no pending request — ignoring`);
    return;
  }
  if (link._resource) { link._resource.cancel('superseded'); }
  nnSetStatus(`receiving page (${adv.parts} parts)…`);
  link._resource = new ResourceReceiver(link, adv, {
    send: nnResourceSend(link),
    onProgress: (frac) => nnSetStatus(`receiving page… ${Math.round(frac * 100)}%`),
    onError: (reason) => { link._resource = null; nnSetStatus(reason, 'err'); },
    onComplete: async ({ data }) => {
      link._resource = null;
      try {
        // A page RESPONSE delivered as a Resource carries the packed
        // [request_id, response] envelope (§11.2).
        const { requestId, response } = parseResponse(data);
        await handleNomadNetResponse(link, requestId, response);
      } catch (e) {
        nnSetStatus(`failed to parse page: ${e.message}`, 'err');
      }
    },
  });
  link._resource.start();
}

// Validate a response against the pending request and render it.
async function handleNomadNetResponse(link, requestId, response) {
  const pending = link._nnRequest;
  if (!pending) { nnSetStatus('unexpected response (no pending request)', 'err'); return; }
  if (!arraysEqual(requestId, pending.expectedId)) {
    // SPEC §11.2: drop responses whose request_id doesn't match.
    nnSetStatus('response request_id mismatch — dropped', 'err');
    return;
  }
  link._nnRequest = null;
  const text = responseToText(response);
  nnRenderPage(text, nnState.destHashHex, pending.path);
  nnSetStatus(`loaded ${pending.path}`, 'ok');
  await addHistory({ url: `${nnState.destHashHex}:${pending.path}`, title: pending.path, visited: Date.now() }).catch(() => {});
}

// Send a NomadNet page request over an active link.
async function nnSendRequest(link, path) {
  const body = await buildRequest(path, null);
  const enc = await link.encrypt(body);
  const packet = buildPacket({
    headerType: HEADER_1, destType: DEST_LINK, packetType: PACKET_DATA,
    destHash: link.linkId, context: CTX_REQUEST, payload: enc,
  });
  // request_id = SHA-256(request packet's hashable part)[:16] (§11.1).
  const fullHash = await computePacketFullHash(parsePacket(packet));
  link._nnRequest = { expectedId: fullHash.subarray(0, 16), path };
  nnSetStatus(`requesting ${path}…`);
  await rnode.sendPacket(packet);
}

// Navigate to a node/path: ensure link, send request. `push` records history.
async function nnNavigate(destHashHex, path, { push = true } = {}) {
  if (!radioOn) { nnSetStatus('radio is off', 'err'); return; }
  path = path || NN_DEFAULT_PATH;
  try {
    nnSetAddress(destHashHex, path);
    const link = await nnEnsureLink(destHashHex);
    nnState.path = path;
    if (push) {
      nnHistory = nnHistory.slice(0, nnHistoryIdx + 1);
      nnHistory.push({ destHashHex, path });
      nnHistoryIdx = nnHistory.length - 1;
    }
    await nnSendRequest(link, path);
  } catch (e) {
    nnSetStatus(e.message, 'err');
  }
  nnUpdateNavButtons();
}

// Render a fetched page: strip headers, render micron, wire links.
function nnRenderPage(rawText, destHashHex, path) {
  const { headers, body } = stripPageHeaders(rawText);
  const pageEl = $('nn-page');
  if (!pageEl) return;
  if (path.startsWith('/file/')) {
    pageEl.innerHTML = '<div class="mu-line">[file downloads not supported yet]</div>';
    return;
  }
  pageEl.innerHTML = renderMicron(body);
  if (headers.bg) pageEl.style.background = headers.bg.startsWith('#') ? headers.bg : `#${headers.bg}`;
  else pageEl.style.background = '';
  // Wire micron links.
  pageEl.querySelectorAll('a.mu-link').forEach((a) => {
    a.addEventListener('click', (ev) => {
      ev.preventDefault();
      const tgt = parseLinkTarget(a.dataset.target);
      if (tgt.kind === 'page') nnNavigate(destHashHex, tgt.path);
      else if (tgt.kind === 'node') nnNavigate(tgt.hash, tgt.path);
      else if (tgt.kind === 'lxmf') nnSetStatus(`link opens an LXMF conversation with ${tgt.hash.slice(0,12)}… (open it from Messages)`, 'info');
      else nnSetStatus('unsupported link target', 'err');
    });
  });
}

function nnUpdateNavButtons() {
  const back = $('nn-back'), fwd = $('nn-forward');
  if (back) back.disabled = nnHistoryIdx <= 0;
  if (fwd) fwd.disabled = nnHistoryIdx >= nnHistory.length - 1;
}

function nnGoBack() {
  if (nnHistoryIdx <= 0) return;
  nnHistoryIdx--;
  const { destHashHex, path } = nnHistory[nnHistoryIdx];
  nnNavigate(destHashHex, path, { push: false });
}

function nnGoForward() {
  if (nnHistoryIdx >= nnHistory.length - 1) return;
  nnHistoryIdx++;
  const { destHashHex, path } = nnHistory[nnHistoryIdx];
  nnNavigate(destHashHex, path, { push: false });
}

// Parse whatever is in the address bar and navigate.
function nnGoToAddress() {
  const raw = ($('nn-address')?.value || '').trim();
  if (!raw) return;
  const tgt = parseLinkTarget(raw);
  if (tgt.kind === 'node') nnNavigate(tgt.hash, tgt.path);
  else if (tgt.kind === 'page' && nnState.destHashHex) nnNavigate(nnState.destHashHex, tgt.path);
  else nnSetStatus('enter a node hash (32 hex), optionally with :/page/x.mu', 'err');
}

// Render the browser sidebar: discovered nomadnetwork.node nodes + bookmarks.
async function renderNomadNetSidebar() {
  const listEl = $('nn-nodes');
  if (!listEl) return;
  const nodes = (await getAllNodes()).filter(n => n.appName === 'nomadnetwork.node' && n.publicKey);
  const bookmarks = await getAllBookmarks();

  let html = '<div class="nn-side-title">Bookmarks</div>';
  if (bookmarks.length === 0) html += '<div class="nn-side-empty">none</div>';
  for (const b of bookmarks) {
    html += `<div class="nn-side-row" data-url="${b.url}"><span class="nn-side-name">${escapeHtml(b.title || b.url)}</span><button class="nn-side-del" data-del-bm="${b.url}">✕</button></div>`;
  }
  html += '<div class="nn-side-title">Nodes</div>';
  if (nodes.length === 0) html += '<div class="nn-side-empty">no NomadNet nodes seen yet</div>';
  for (const n of nodes) {
    html += `<div class="nn-side-row" data-hash="${n.hash}"><span class="nn-side-name">${escapeHtml(n.displayName || n.hash.slice(0,8))}</span><span class="nn-side-hash">${n.hash.slice(0,8)}</span></div>`;
  }
  listEl.innerHTML = html;

  listEl.querySelectorAll('.nn-side-row[data-hash]').forEach(el => {
    el.addEventListener('click', () => nnNavigate(el.dataset.hash, NN_DEFAULT_PATH));
  });
  listEl.querySelectorAll('.nn-side-row[data-url]').forEach(el => {
    el.addEventListener('click', (ev) => {
      if (ev.target.dataset.delBm) return;
      const [hash, path] = el.dataset.url.split(/:(.+)/);
      nnNavigate(hash, path);
    });
  });
  listEl.querySelectorAll('[data-del-bm]').forEach(btn => {
    btn.addEventListener('click', async (ev) => {
      ev.stopPropagation();
      await deleteBookmark(btn.dataset.delBm);
      renderNomadNetSidebar();
    });
  });
}

async function nnBookmarkCurrent() {
  if (!nnState.destHashHex || !nnState.path) { nnSetStatus('nothing to bookmark', 'err'); return; }
  const url = `${nnState.destHashHex}:${nnState.path}`;
  await saveBookmark({ url, title: url, added: Date.now() });
  nnSetStatus('bookmarked', 'ok');
  renderNomadNetSidebar();
}

// ---- Send message ----------------------------------------------------

async function sendMessage() {
  if (!activeContactHash) return;

  const content = $('msg-content').value.trim();
  if (!content) return;

  const contact = contacts.get(activeContactHash);
  if (!contact) { log('err', 'Contact not found'); return; }
  if (!contact.identity) {
    log('err', 'Cannot reply yet — peer has not announced; their public key is unknown. Wait for their next announce, then try again.');
    return;
  }

  try {
    // Path-request preamble (SPEC §7.1, flows/send-opportunistic-lxmf.md
    // step 4). Upstream LXMF issues a path? request before sending if the
    // local Transport.path_table has no entry. We mirror that for
    // destinations missing from our pathTable: without it, michmesh has
    // no cached path so our DATA gets dropped — and we can't tell from
    // the WS path whether a peer is reachable until we try.
    if (radioOn && !pathTable.has(toHex(contact.destHash))) {
      log('info', `  No path known to ${toHex(contact.destHash).substring(0,16)}... — issuing path? preamble`);
      const got = await requestPath(contact.destHash);
      if (got) {
        log('ok', `  Path response received in ${PATH_REQUEST_WAIT_MS}ms window`);
      } else {
        log('info', `  path? timed out after ${PATH_REQUEST_WAIT_MS}ms — sending anyway, may fail silently if rnsd has no route`);
      }
    }

    // Pack LXMF message. LXMF's source_hash field is the sender's
    // LXMF delivery *destination* hash, not the identity hash —
    // receivers key their contact table on destination hashes.
    const lxmfPayload = await packMessage(
      myIdentity, contact.destHash, myDestHash,
      '', content, {}
    );

    // Encrypt for recipient. Prefer their current ratchet pubkey
    // (learned from a ratchet-bearing announce) so the recipient's
    // forward-secrecy story benefits from our side too. Fall back
    // to the identity X25519 key if no ratchet is known.
    const recipientPub = contact.ratchetPub || contact.identity.encPubKey;
    const encrypted = await encrypt(lxmfPayload, recipientPub, contact.identity.hash);

    // SPEC §2.3 originator HEADER_1 → HEADER_2 conversion. The spec
    // says an originator MAY stay HEADER_1 only when the destination
    // is 0 hops away AND it's a local client of the receiving rnsd
    // (the for_local_client auto-fill branch). For a webapp connected
    // via WS bridge, "local client of michmesh" means another TCP
    // peer of michmesh's rnsd — basically nobody we'd actually message.
    // Any peer reachable via michmesh's broader mesh is at hops >= 1
    // and is NOT a local client, so HEADER_1 to that peer is silently
    // dropped at michmesh.
    //
    // Threshold is hops >= 1 (not > 1 like upstream Python does):
    // upstream's > 1 only works because share_instance handles the == 1
    // case. We're not on share_instance, so we have to convert at the
    // == 1 boundary too.
    //
    // Fires only when:
    //   - we have a pathTable entry with hops >= 1, AND
    //   - we know our upstream's identity hash (learned from inbound
    //     HEADER_2 transport_ids in trackPath).
    // For BLE/serial via RNode, upstreamTransportId stays null, so we
    // fall through to HEADER_1 — correct for a 1-hop LoRa mesh where
    // we ARE the originator on a single-hop link.
    const pathInfo = pathTable.get(toHex(contact.destHash));
    let packet;
    if (pathInfo && pathInfo.hops >= 1 && upstreamTransportId) {
      packet = buildPacket({
        headerType: HEADER_2,
        transportType: TRANSPORT_TRANSPORT,
        destType: DEST_SINGLE,
        packetType: PACKET_DATA,
        destHash: contact.destHash,
        transportId: upstreamTransportId,
        context: 0x00,
        payload: encrypted,
      });
      log('info', `  HEADER_2 send: dest ${pathInfo.hops} hops away, transport_id=${toHex(upstreamTransportId).substring(0,16)}...`);
    } else {
      packet = buildPacket({
        headerType: HEADER_1,
        destType: DEST_SINGLE,
        packetType: PACKET_DATA,
        destHash: contact.destHash,
        context: 0x00,
        payload: encrypted,
      });
      if (pathInfo && pathInfo.hops >= 1) {
        log('info', `  HEADER_1 send to ${pathInfo.hops}-hop dest (upstream identity not yet learned — packet will likely fail at the relay until we observe a HEADER_2 inbound packet to learn it)`);
      }
    }

    // Check size
    if (packet.length > 500) {
      log('err', `Packet too large (${packet.length} bytes, max 500). Shorten your message.`);
      return;
    }

    // Compute the truncated (16 B) packet hash so we can match any
    // delivery PROOF that comes back later. The dest_hash slot of a
    // non-link PROOF packet carries this truncated hash, so this is
    // the key we look up on.
    const packetHashHex = toHex(await computeOutboundPacketHashTruncated(packet));

    // Save a pending row before touching the radio so the message
    // is durable even if the send call throws or the user
    // reloads mid-transmission.
    const row = {
      contactHash: activeContactHash,
      direction: 'outgoing',
      content,
      title: '',
      timestamp: Date.now(),
      state: radioOn ? MSG_STATE_SENDING : MSG_STATE_PENDING,
      packetHash: packetHashHex,
      rawPacket: Array.from(packet),
      attempts: 0,
      nextRetryAt: 0,
    };
    const id = await saveMessage(row);

    $('msg-content').value = '';
    await renderMessages(activeContactHash);

    if (radioOn) {
      await doOutboundSend(id);
    } else {
      log('info', `Queued message to "${contact.displayName}" (radio off)`);
    }
  } catch (e) {
    log('err', `Send failed: ${e.message}`);
  }
}

// Compute the 16-byte truncated SHA-256 of the hashable part of a
// newly-built outbound packet. The dest_hash field of any inbound
// delivery PROOF for this packet will equal this value, so it is
// the key we store on the outgoing row and match on.
async function computeOutboundPacketHashTruncated(packet) {
  const flagsLow = packet[0] & 0x0F;
  // HEADER_1: skip flags + hops (2 bytes). HEADER_2 skips 18, but
  // every packet we originate is HEADER_1.
  const tail = packet.subarray(2);
  const hp = new Uint8Array(1 + tail.length);
  hp[0] = flagsLow;
  hp.set(tail, 1);
  const fullBuf = await crypto.subtle.digest('SHA-256', hp);
  return new Uint8Array(fullBuf).subarray(0, 16);
}

// Core outbound send/retry path. Reads the row from IndexedDB,
// transmits the stored rawPacket, and writes back the new state
// (sent + nextRetryAt on success, pending or failed on error).
// Invoked from sendMessage for a fresh row and from the retry tick
// for a row whose nextRetryAt has passed.
async function doOutboundSend(id) {
  const row = await getMessageById(id);
  if (!row) return;
  if (row.state === MSG_STATE_DELIVERED || row.state === MSG_STATE_FAILED) return;
  if (!row.rawPacket) return;   // legacy row without a packet — nothing to retransmit

  const contact = contacts.get(row.contactHash);
  const label = contact ? contact.displayName : row.contactHash.substring(0, 12);
  const attemptNumber = (row.attempts || 0) + 1;

  await updateMessage(id, { state: MSG_STATE_SENDING, attempts: attemptNumber });
  if (activeContactHash === row.contactHash) {
    await renderMessages(activeContactHash);
  }

  const packet = new Uint8Array(row.rawPacket);
  try {
    log('info', `Sending to "${label}"${attemptNumber > 1 ? ` (attempt ${attemptNumber})` : ''}...`);
    await rnode.sendPacket(packet);
    log('ok', `Sent ${packet.length}B to "${label}"`);

    // Transition to SENT and stop retrying. Opportunistic LXMF
    // destinations (Sideband, MeshChat, NomadNet) do NOT send
    // Packet-level delivery proofs — upstream Reticulum only
    // auto-proves destinations configured with PROVE_ALL, which
    // LXMF does not set. Retrying based on missing proofs would
    // endlessly resend a message that was actually delivered.
    // If a proof DOES arrive (rare, destination-specific), the
    // handleDeliveryProof path upgrades state to DELIVERED.
    await updateMessage(id, {
      state: MSG_STATE_SENT,
      nextRetryAt: 0,
      lastError: null,
    });
  } catch (e) {
    log('err', `Send failed: ${e.message}`);
    const isFinal = attemptNumber >= MSG_MAX_ATTEMPTS;
    const backoffIndex = Math.min(attemptNumber - 1, MSG_BACKOFF_MS.length - 1);
    await updateMessage(id, {
      state: isFinal ? MSG_STATE_FAILED : MSG_STATE_PENDING,
      nextRetryAt: isFinal ? 0 : Date.now() + MSG_BACKOFF_MS[backoffIndex],
      lastError: e.message,
    });
  }

  if (activeContactHash === row.contactHash) {
    await renderMessages(activeContactHash);
  }
}

// Walk every outgoing row and drive the state machine forward for
// anything that is overdue. Pending rows get a fresh send attempt
// now that the radio is up. Sent rows whose ack timeout has fired
// either retry or transition to failed. Terminal states are
// skipped. Runs on a setInterval that only lives while the radio
// is on.
async function outboundRetryTick() {
  if (!radioOn) return;
  const rows = await getAllMessages();
  const now = Date.now();

  for (const row of rows) {
    if (row.direction !== 'outgoing') continue;
    if (row.state === MSG_STATE_DELIVERED || row.state === MSG_STATE_FAILED) continue;

    if (row.state === MSG_STATE_PENDING && (row.attempts || 0) < MSG_MAX_ATTEMPTS) {
      await doOutboundSend(row.id);
      continue;
    }

    // Previously we would retransmit SENT rows whose proof timeout
    // fired. That produced endless duplicates for LXMF destinations
    // that never send opportunistic proofs (Sideband et al). SENT is
    // now a terminal state unless the retry path fails — only PENDING
    // rows are retried here.
  }
}

// Match an inbound PROOF packet against outstanding outgoing rows.
// The packet's destination_hash is the 16-byte truncated hash of the
// original packet being acknowledged, so it lines up directly with
// the packetHash we stored on the row at send time. If a match is
// found, mark the row as delivered.
async function handleDeliveryProof(pkt) {
  const hashHex = toHex(pkt.destHash);
  log('info', `  Opportunistic PROOF arrived, dest=${hashHex}`);
  const rows = await getAllMessages();
  const outgoing = rows.filter(r => r.direction === 'outgoing' && r.packetHash);
  log('info', `  Checking ${outgoing.length} outbound row(s) with stored packetHash`);
  for (const row of outgoing) {
    if (row.packetHash !== hashHex) continue;
    if (row.state === MSG_STATE_DELIVERED) return;
    await updateMessage(row.id, { state: MSG_STATE_DELIVERED });
    const preview = (row.content || '').substring(0, 24);
    log('ok', `  Delivery proof matched outbound "${preview}"`);
    if (activeContactHash === row.contactHash) {
      await renderMessages(activeContactHash);
    }
    return;
  }
  // No match — log the most recent outbound hashes so we can diff.
  const recent = outgoing.slice(-3).map(r => r.packetHash).join(', ');
  log('info', `  No outbound row matches. Recent packetHashes: ${recent || '(none)'}`);
}

// ---- Send announce ---------------------------------------------------

async function sendAnnounce({ pathResponse = false } = {}) {
  if (!radioOn || !myIdentity) { log('err', 'Radio not on or identity not ready'); return; }

  // Periodic / manual announces rotate the ratchet so transit nodes
  // don't dedupe successive announces on (destHash, ratchet_pub) and
  // silently drop them (SPEC §7.3). Path-response announces reuse the
  // current ratchet so we don't burn through ratchets on bursts of
  // path? requests.
  if (!pathResponse) {
    myIdentity.rotateRatchet();
    await saveIdentity(myIdentity.exportPrivateKeys());
  }

  const displayName = $('my-name').value.trim() || 'WebClient';
  // LXMF/Sideband format: msgpack([display_name_bytes, stamp_cost])
  const nameBytes = new TextEncoder().encode(displayName);
  const appData = new Uint8Array(msgpackEncode([nameBytes, 0]));

  const { destHash, payload, hasRatchet } = await buildAnnounce(
    myIdentity, 'lxmf.delivery', appData, myIdentity.ratchetPubKey
  );

  const packet = buildPacket({
    headerType: HEADER_1,
    // The context_flag bit of the header signals to receivers that
    // the payload contains a 32-byte ratchet pubkey between the
    // random hash and the signature. Must be 1 iff buildAnnounce
    // actually inserted a ratchet.
    contextFlag: hasRatchet ? 1 : 0,
    destType: DEST_SINGLE,
    packetType: PACKET_ANNOUNCE,
    destHash: destHash,
    // Path-response announces carry context = PATH_RESPONSE so that
    // listeners with receive_path_responses = False (the default per
    // SPEC §4.5 step 7) skip them at the application layer. The path
    // table side-effect still fires either way.
    context: pathResponse ? CTX_PATH_RESPONSE : CTX_NONE,
    payload: payload,
  });

  await rnode.sendPacket(packet);
  const label = pathResponse ? 'Path-response announce' : 'Announce';
  log('ok', `${label} sent as "${displayName}" [${toHex(destHash).substring(0,12)}...]${hasRatchet ? ' (ratchet)' : ''}`);
}

// ---- UI rendering ----------------------------------------------------

function renderContactList() {
  const list = $('contact-list');
  if (contacts.size === 0) {
    list.innerHTML = '<li class="contact-empty">Listening for announces…</li>';
    return;
  }

  // Apply pinned-only and search filters before rendering. Search
  // matches against displayName and hash (case-insensitive substring).
  const term = contactSearchTerm.trim().toLowerCase();
  const rows = [];
  for (const [hash, c] of contacts) {
    if (contactFilterPinnedOnly && !c.pinned) continue;
    if (term) {
      const name = (c.displayName || '').toLowerCase();
      if (!name.includes(term) && !hash.toLowerCase().includes(term)) continue;
    }
    rows.push([hash, c]);
  }
  // Pinned rows float to the top; otherwise preserve insertion order.
  rows.sort((a, b) => (b[1].pinned ? 1 : 0) - (a[1].pinned ? 1 : 0));

  if (rows.length === 0) {
    const msg = contactFilterPinnedOnly && contacts.size > 0
      ? 'No pinned contacts. Click ☆ on a contact to pin it.'
      : term
        ? `No contacts match "${escapeHtml(contactSearchTerm)}"`
        : 'Listening for announces…';
    list.innerHTML = `<li class="contact-empty">${msg}</li>`;
    return;
  }

  list.innerHTML = '';
  for (const [hash, c] of rows) {
    const li = document.createElement('li');
    li.className = hash === activeContactHash ? 'active' : '';

    const unread = c.unreadCount ? ` <span class="contact-unread">${c.unreadCount}</span>` : '';
    const initials = initialsFor(c.displayName || hash);
    const shortHash = `${hash.substring(0, 8)}…${hash.substring(hash.length - 4)}`;
    const placeholderTag = c.placeholder ? ' <span class="contact-tag">unannounced</span>' : '';
    const info = document.createElement('div');
    info.innerHTML = `
      <div class="contact-avatar">${escapeHtml(initials)}</div>
      <div style="flex:1; min-width:0">
        <div class="contact-name">${escapeHtml(c.displayName || hash.substring(0, 8))}${unread}${placeholderTag}</div>
        <div class="contact-hash">${shortHash}</div>
      </div>`;
    info.addEventListener('click', () => selectContact(hash));

    const pin = document.createElement('button');
    pin.className = c.pinned ? 'contact-pin-btn active' : 'contact-pin-btn';
    pin.title = c.pinned ? 'Unpin' : 'Pin to top';
    pin.textContent = '\u2605';   // black star \u2605
    pin.addEventListener('click', (e) => {
      e.stopPropagation();
      togglePin(hash);
    });

    const del = document.createElement('button');
    del.className = 'contact-delete';
    del.title = 'Delete contact';
    del.textContent = '\u00d7';
    del.addEventListener('click', (e) => {
      e.stopPropagation();
      removeContact(hash);
    });

    li.appendChild(info);
    li.appendChild(pin);
    li.appendChild(del);
    list.appendChild(li);
  }
}

async function togglePin(hash) {
  const c = contacts.get(hash);
  if (!c) return;
  c.pinned = !c.pinned;
  // Persist to IDB. Strip the in-memory-only fields (Identity instance,
  // raw byte arrays) into a plain serialisable object before writing.
  const stored = {
    hash: c.hash,
    identityHash: c.identityHash,
    publicKey: c.publicKey instanceof Uint8Array ? Array.from(c.publicKey) : (c.publicKey || []),
    destHash: c.destHash instanceof Uint8Array ? Array.from(c.destHash) : c.destHash,
    nameHash: c.nameHash instanceof Uint8Array ? Array.from(c.nameHash) : c.nameHash,
    ratchetPub: c.ratchetPub instanceof Uint8Array ? Array.from(c.ratchetPub) : (c.ratchetPub || null),
    displayName: c.displayName,
    placeholder: !!c.placeholder,
    pinned: c.pinned,
    lastSeen: c.lastSeen,
    rssi: c.rssi,
  };
  await saveContact(stored);
  renderContactList();
}

async function removeContact(hash) {
  const c = contacts.get(hash);
  const label = c ? `"${c.displayName}"` : hash.substring(0, 16);
  if (!confirm(`Delete ${label} and all messages with them?`)) return;

  contacts.delete(hash);
  await deleteMessagesForContact(hash);
  await deleteContact(hash);

  if (activeContactHash === hash) {
    activeContactHash = null;
    $('conv-title').textContent = 'Select a contact';
    $('compose-area').classList.add('hidden');
    $('message-list').innerHTML = '';
  }

  renderContactList();
  log('info', `Deleted contact ${label}`);
}

async function selectContact(hash) {
  activeContactHash = hash;
  const c = contacts.get(hash);
  if (c) c.unreadCount = 0;
  $('conv-title').textContent = c ? c.displayName : hash.substring(0, 16);
  $('compose-area').classList.remove('hidden');
  renderContactList();
  await renderMessages(hash);
}

async function renderMessages(contactHash) {
  const list = $('message-list');
  const msgs = await getMessages(contactHash);

  if (msgs.length === 0) {
    list.innerHTML = '<div class="message-empty">No messages yet</div>';
    return;
  }

  // Sort by the IndexedDB auto-increment id, which is strictly the
  // order the rows were saved. Using the stored timestamp would put
  // any historical messages that were saved before the bogus-sender-
  // clock fix at the top of the list, because those rows hold
  // seconds-since-boot values from clockless LoRa senders that
  // resolve to Jan 1, 1970.
  const ordered = msgs.slice().sort((a, b) => (a.id || 0) - (b.id || 0));

  list.innerHTML = '';
  for (const msg of ordered) {
    const div = document.createElement('div');
    div.className = `message ${msg.direction}`;
    const ts = normalizeLxmfTimestamp(msg.timestamp);
    const time = ts != null ? formatMessageTime(ts) : '(no time)';
    const stateIcon = renderOutgoingStateIcon(msg);
    const rxMeta = renderIncomingRxMeta(msg);
    div.innerHTML = `<div>${escapeHtml(msg.content)}</div><div class="meta">${time}${stateIcon}${rxMeta}</div>`;
    list.appendChild(div);
  }
  list.scrollTop = list.scrollHeight;
}

// Radio metadata for incoming messages: hops, RSSI, SNR, and dupe count.
// Returns an HTML fragment for the meta line. Outgoing rows and legacy
// rows (saved before these fields were added) return empty.
function renderIncomingRxMeta(msg) {
  if (msg.direction !== 'incoming') return '';
  const parts = [];
  if (typeof msg.hops === 'number') {
    parts.push(msg.hops === 0 ? 'direct' : `${msg.hops} hop${msg.hops > 1 ? 's' : ''}`);
  }
  if (typeof msg.rssi === 'number') parts.push(`${msg.rssi} dBm`);
  if (typeof msg.snr === 'number') parts.push(`SNR ${msg.snr}`);
  if (msg.dupeCount > 1) parts.push(`×${msg.dupeCount}`);
  if (parts.length === 0) return '';
  return ` <span class="rx-meta">${escapeHtml(parts.join(' · '))}</span>`;
}

// Small state indicator for outgoing rows. Returns HTML that lives
// inline next to the timestamp in the message meta line. Incoming
// rows and legacy outgoing rows (saved before the retry queue
// landed, no `state` field) return an empty string.
function renderOutgoingStateIcon(msg) {
  if (msg.direction !== 'outgoing' || !msg.state) return '';
  const labels = {
    [MSG_STATE_PENDING]:   ['\u23F3', 'pending'],    // hourglass
    [MSG_STATE_SENDING]:   ['\u2191', 'sending'],    // up arrow
    [MSG_STATE_SENT]:      ['\u2713', 'sent'],        // single check
    [MSG_STATE_DELIVERED]: ['\u2713\u2713', 'delivered'],   // double check
    [MSG_STATE_FAILED]:    ['\u2717', 'failed'],      // cross
  };
  const entry = labels[msg.state];
  if (!entry) return '';
  const [glyph, cls] = entry;
  const title = msg.state === MSG_STATE_FAILED && msg.lastError
    ? ` title="${escapeHtml(msg.lastError)}"`
    : '';
  return ` <span class="message-state ${cls}"${title}>${glyph}</span>`;
}

// Format a message timestamp. Shows "HH:MM" for messages from today,
// "MMM D, HH:MM" for older messages in the current year, and the full
// date for anything older than that. 24-hour time throughout so the
// earlier AM/PM confusion can't recur.
function formatMessageTime(ms) {
  const d = new Date(ms);
  const now = new Date();
  const sameDay = d.getFullYear() === now.getFullYear() &&
                  d.getMonth() === now.getMonth() &&
                  d.getDate() === now.getDate();
  const hhmm = d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
  if (sameDay) return hhmm;
  if (d.getFullYear() === now.getFullYear()) {
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ' ' + hhmm;
  }
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) + ' ' + hhmm;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ---- DOM mirror helpers ---------------------------------------------
// Several pieces of state are shown in more than one place (sidebar,
// right panel, settings). Each helper here writes the canonical element
// by id and then fans out to any `.js-*` mirror elements in the DOM.

function initialsFor(name) {
  if (!name) return '??';
  const clean = String(name).trim();
  if (!clean) return '??';
  const parts = clean.split(/\s+/);
  if (parts.length >= 2 && parts[0][0] && parts[1][0]) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  return clean.substring(0, 2).toUpperCase();
}

function setConnectionState(on, label) {
  const dot = $('conn-dot');
  if (dot) dot.classList.toggle('on', on);
  const text = $('conn-text');
  if (text) text.textContent = label;
  document.querySelectorAll('.js-conn-dot').forEach(el => el.classList.toggle('on', on));
  document.querySelectorAll('.js-conn-text').forEach(el => el.textContent = label);
}

function setRadioStatus(text, on) {
  const main = $('radio-status');
  if (main) {
    main.textContent = text;
    main.className = `js-radio-status ${on ? 'status-on' : 'status-muted'}`;
  }
  document.querySelectorAll('.js-radio-status').forEach(el => {
    if (el === main) return;
    el.textContent = text || '—';
    el.classList.toggle('status-on', !!on);
  });
}

function setMyAddress(hex) {
  const el = $('my-address');
  if (el) el.textContent = hex;
  const short = hex && hex.length > 12
    ? `${hex.substring(0, 6)}…${hex.substring(hex.length - 4)}`
    : (hex || '—');
  document.querySelectorAll('.js-address-short').forEach(el => { el.textContent = short; });
  updateAvatars();
}

function updateAvatars() {
  const name = ($('my-name')?.value || 'WebClient');
  const initials = initialsFor(name);
  ['my-avatar', 'my-avatar-rp'].forEach(id => {
    const el = $(id);
    if (el) el.textContent = initials;
  });
  ['my-name-display', 'my-name-display-rp'].forEach(id => {
    const el = $(id);
    if (el) el.textContent = name;
  });
}

// ---- View switching --------------------------------------------------

function switchView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const target = document.querySelector(`.view-${name}`);
  if (target) target.classList.add('active');
  document.querySelectorAll('[data-view]').forEach(n => {
    n.classList.toggle('active', n.dataset.view === name);
  });
  // Leaflet needs a sized container to lay out. The first time the
  // Nodes view is opened we create the map; on every subsequent
  // visit we invalidate its size so it recomputes against whatever
  // the CSS flex layout has handed it (important after a resize or
  // an orientation change).
  if (name === 'nodes') {
    initNodesMap().then((map) => {
      if (map) setTimeout(() => map.invalidateSize(), 50);
    }).catch(() => { /* handled inside initNodesMap */ });
  }
  if (name === 'nomadnet') {
    renderNomadNetSidebar().catch(() => { /* best effort */ });
  }
}

// ---- Theme -----------------------------------------------------------

const THEME_KEY = 'reticulum-theme';

function applyTheme(choice) {
  const effective = choice === 'system'
    ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
    : choice;
  document.documentElement.dataset.theme = effective;
  document.querySelectorAll('#theme-seg .seg-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.theme === choice);
  });
}

function setTheme(choice) {
  localStorage.setItem(THEME_KEY, choice);
  applyTheme(choice);
}

// ---- Event wiring ----------------------------------------------------

// Helpers: connect buttons live in three places (sidebar quick-connect,
// mobile hero, settings). Toggle them all at once by class so they
// stay in sync regardless of which one the user clicked.
function setConnectButtonsDisabled(disabled) {
  document.querySelectorAll('.js-connect-btn').forEach(b => { b.disabled = disabled; });
}
function setConnectButtonsHidden(hidden) {
  document.querySelectorAll('.js-connect-btn').forEach(b => {
    b.classList.toggle('hidden', hidden);
  });
}

// Show or remove the ws:// security warning banner. If the user
// connects to a remote host over unencrypted ws:// (as opposed to
// wss:// or localhost), a notice is injected at the top of the
// Settings connect card so it is visible in the same view where
// they entered the URL. Removed on disconnect.
function checkWsSecurityWarning(url) {
  document.querySelector('.ws-security-warning')?.remove();
  try {
    const parsed = new URL(url);
    const isLocal = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(parsed.hostname);
    const isSecure = parsed.protocol === 'wss:';
    if (isLocal || isSecure) return;
    const banner = document.createElement('div');
    banner.className = 'ws-security-warning notice err';
    banner.innerHTML =
      `<strong>Unencrypted WebSocket connection.</strong> ` +
      `Connected to <code>${escapeHtml(parsed.host)}</code> over ` +
      `<code>ws://</code>. Reticulum packet headers (destination hashes, ` +
      `packet types) are visible to network observers on this path. ` +
      `Message content remains end-to-end encrypted. Use <code>wss://</code> ` +
      `for remote connections if your bridge supports TLS.`;
    const card = document.querySelector('.view-settings .settings-card');
    if (card) card.prepend(banner);
    log('err', `WARNING: ws:// to remote host ${parsed.host} — packet headers are unencrypted on this path`);
  } catch (_) { /* URL parse failed — let connect() fail on its own */ }
}

// Connect
async function connect(transportType) {
  try {
    setConnectButtonsDisabled(true);

    // Pick the right interface based on transport type.
    //   'ble' / 'serial' → RNode-over-KISS (owns a radio)
    //   'ws'             → rnsd-over-HDLC (no radio, direct to a Reticulum daemon)
    if (transportType === 'ws') {
      const baseUrl = ($('ws-url').value || '').trim();
      const rnsdTarget = ($('ws-rnsd').value || '').trim();
      if (!baseUrl) { log('err', 'WebSocket URL is empty'); return; }

      // The Go bridge takes the rnsd target per-connection via query
      // params (?host=X&port=Y). The Python bridge ignores the query
      // and uses its own --rnsd-host/--rnsd-port flags, so the same
      // URL works against either bridge — the Python one just ignores
      // the extra params.
      let url = baseUrl;
      if (rnsdTarget) {
        const colonIx = rnsdTarget.lastIndexOf(':');
        if (colonIx <= 0) {
          log('err', `Reticulum daemon target must be host:port (got "${rnsdTarget}")`);
          return;
        }
        const host = rnsdTarget.slice(0, colonIx);
        const port = rnsdTarget.slice(colonIx + 1);
        if (!/^\d+$/.test(port)) {
          log('err', `Reticulum daemon port must be numeric (got "${port}")`);
          return;
        }
        const sep = baseUrl.includes('?') ? '&' : '?';
        url = `${baseUrl}${sep}host=${encodeURIComponent(host)}&port=${encodeURIComponent(port)}`;
      }

      // Persist both fields so the user doesn't re-type on every reload.
      try {
        localStorage.setItem('rlw.wsUrl', baseUrl);
        localStorage.setItem('rlw.wsRnsd', rnsdTarget);
      } catch (_) { /* private mode — non-fatal */ }

      rnode = new RnsdInterface(url);
      checkWsSecurityWarning(url);
    } else {
      rnode = new RNode(transportType);
    }
    rnode._onLog = (msg) => log('info', msg);
    rnode._onPacket = onPacket;
    rnode._onDisconnect = () => {
      log('err', 'Transport disconnected unexpectedly');
      if (announceTimer) { clearInterval(announceTimer); announceTimer = null; }
      if (outboundRetryTimer) { clearInterval(outboundRetryTimer); outboundRetryTimer = null; }
      // Routing state is per-interface — different rnsd has a different
      // identity hash and a different mesh topology. Clear so a future
      // reconnect rediscovers everything from the next batch of announces
      // rather than acting on stale data.
      pathTable.clear();
      upstreamTransportId = null;
      for (const [, p] of pendingPathRequests) clearTimeout(p.timer);
      pendingPathRequests.clear();
      setConnectionState(false, 'Disconnected');
      $('btn-disconnect').classList.add('hidden');
      setConnectButtonsHidden(false);
      $('ws-url-row').classList.remove('hidden');
      document.querySelector('.ws-security-warning')?.remove();
      radioOn = false;
      setRadioStatus('', false);
    };

    await rnode.connect();

    setConnectionState(true, `Connected (${transportType.toUpperCase()})`);
    $('btn-disconnect').classList.remove('hidden');
    setConnectButtonsHidden(true);
    $('ws-url-row').classList.add('hidden');

    // Interfaces with an RNode on the other side (BLE/Serial) need
    // the full detect/fw/battery/radio-config sequence. Interfaces
    // that talk directly to a Reticulum daemon via WebSocket skip
    // all of that — there is no radio to configure.
    const usesRnode = rnode.capabilities?.rnodeControl !== false;

    if (usesRnode) {
      const detected = await rnode.detect();
      if (!detected) { log('err', 'RNode detect failed'); return; }
      const fw = await rnode.getFirmwareVersion();
      const battery = await rnode.getBattery();
      log('ok', `RNode FW ${fw?.major}.${fw?.minor}, Bat ${battery}%`);
      await startRadio();
    } else {
      // WebSocket path: no radio config, no detect, no battery.
      // Go straight to the "ready for messaging" state that
      // startRadio would have reached for the RNode path.
      log('ok', `Connected to Reticulum network via WebSocket`);
      markInterfaceReady();
    }
  } catch (e) {
    log('err', 'Connect: ' + e.message);
  } finally {
    setConnectButtonsDisabled(false);
  }
}

// Flip the "we are ready to send and receive" bit, fire the startup
// auto-announce, start the periodic announce timer, and start the
// outbound retry tick. Called from both the RNode path (after
// startRadio reports the radio is on) and the WebSocket path (after
// the socket is up — there is no radio to wait for).
function markInterfaceReady() {
  radioOn = true;
  setRadioStatus('Ready', true);
  sendAnnounce().catch(e => log('info', `Startup announce skipped: ${e.message}`));
  if (announceTimer) clearInterval(announceTimer);
  announceTimer = setInterval(() => {
    if (radioOn) {
      sendAnnounce().catch(e => log('info', `Periodic announce skipped: ${e.message}`));
    }
  }, 5 * 60 * 1000);
  if (outboundRetryTimer) clearInterval(outboundRetryTimer);
  outboundRetryTimer = setInterval(() => {
    outboundRetryTick().catch(e => log('info', `Retry tick error: ${e.message}`));
  }, MSG_RETRY_TICK_MS);
  outboundRetryTick().catch(e => log('info', `Retry tick error: ${e.message}`));
}

// Wire every connect button (sidebar quick-connect, mobile hero,
// settings) through a single listener keyed on data-transport.
document.querySelectorAll('.js-connect-btn').forEach(b => {
  b.addEventListener('click', () => connect(b.dataset.transport));
});

$('btn-disconnect').addEventListener('click', async () => {
  if (announceTimer) { clearInterval(announceTimer); announceTimer = null; }
  if (outboundRetryTimer) { clearInterval(outboundRetryTimer); outboundRetryTimer = null; }
  // Gracefully LINKCLOSE any active links before the transport drops, so
  // peers don't hold them open until their watchdog expires (SPEC §6.7.3).
  if (radioOn) await closeAllLinks();
  await rnode.disconnect();
  setConnectionState(false, 'Disconnected');
  $('btn-disconnect').classList.add('hidden');
  setConnectButtonsHidden(false);
  $('ws-url-row').classList.remove('hidden');
  document.querySelector('.ws-security-warning')?.remove();
  radioOn = false;
  setRadioStatus('', false);
  log('info', 'Disconnected');
});

// Radio
async function startRadio() {
  try {
    const freq = parseInt($('cfg-freq').value);
    const bw = parseInt($('cfg-bw').value);
    const sf = parseInt($('cfg-sf').value);
    const cr = parseInt($('cfg-cr').value);
    const txp = parseInt($('cfg-txp').value);
    const on = await rnode.configureAndStart({ freq, bw, sf, cr, txp });
    setRadioStatus(on ? 'Radio: ON' : '', on);
    if (on) {
      log('ok', 'Radio on');
      markInterfaceReady();
    } else {
      radioOn = false;
    }
  } catch (e) { log('err', 'Radio: ' + e.message); }
}

$('btn-start-radio').addEventListener('click', startRadio);
$('btn-stop-radio').addEventListener('click', async () => {
  await rnode.setRadioState(false);
  radioOn = false;
  setRadioStatus('Radio: OFF', false);
});

// Identity — wire every announce button (right panel on desktop,
// Identity settings card on mobile) through the same handler.
document.querySelectorAll('.js-announce-btn').forEach(b => {
  b.addEventListener('click', sendAnnounce);
});

// Contact filter bar — search input + pinned-only toggle. The toggle's
// initial pressed state is restored from localStorage so the user's
// last filter choice survives reloads.
const _contactSearchEl = $('contact-search');
if (_contactSearchEl) {
  _contactSearchEl.addEventListener('input', (e) => {
    contactSearchTerm = e.target.value || '';
    renderContactList();
  });
}
const _contactFilterPinnedEl = $('contact-filter-pinned');
if (_contactFilterPinnedEl) {
  _contactFilterPinnedEl.setAttribute('aria-pressed', String(contactFilterPinnedOnly));
  _contactFilterPinnedEl.addEventListener('click', () => {
    contactFilterPinnedOnly = !contactFilterPinnedOnly;
    _contactFilterPinnedEl.setAttribute('aria-pressed', String(contactFilterPinnedOnly));
    try { localStorage.setItem('rlw.filterPinned', String(contactFilterPinnedOnly)); }
    catch (_) { /* private-mode storage refused; toggle still works for the session */ }
    renderContactList();
  });
}
$('btn-new-id').addEventListener('click', async () => {
  if (!confirm('Generate new identity? Your current address will change.')) return;
  myIdentity = new Identity();
  await myIdentity.generate();
  await saveIdentity(myIdentity.exportPrivateKeys());
  myDestHash = await computeDestinationHash('lxmf.delivery', myIdentity.hash);
  setMyAddress(toHex(myDestHash));
  log('ok', `New identity: ${toHex(myDestHash)}`);
});
$('btn-export-id').addEventListener('click', () => {
  const data = JSON.stringify(myIdentity.exportPrivateKeys());
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `reticulum-identity-${toHex(myDestHash).substring(0,8)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  log('ok', 'Identity exported');
});

// Messaging
$('btn-send').addEventListener('click', sendMessage);
$('msg-content').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
});

// Log
$('btn-clear-log').addEventListener('click', () => { $('log').innerHTML = ''; });

// Nodes panel — clear all forgets every stored non-LXMF announce.
// Fresh announces repopulate the list automatically.
$('btn-clear-nodes').addEventListener('click', async () => {
  if (!confirm('Forget all stored non-LXMF node announces?')) return;
  await deleteAllNodes();
  renderNodesList();
  log('info', 'Cleared all nodes');
});

// NomadNet browser controls.
$('nn-go')?.addEventListener('click', nnGoToAddress);
$('nn-address')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); nnGoToAddress(); } });
$('nn-back')?.addEventListener('click', nnGoBack);
$('nn-forward')?.addEventListener('click', nnGoForward);
$('nn-reload')?.addEventListener('click', () => { if (nnState.destHashHex && nnState.path) nnNavigate(nnState.destHashHex, nnState.path, { push: false }); });
$('nn-bookmark')?.addEventListener('click', nnBookmarkCurrent);

// Browser check — disable buttons for unsupported transports. Every
// connect surface (sidebar, mobile hero, settings) is selected by
// data-transport, so all of them get disabled together.
function disableTransport(name, label) {
  document.querySelectorAll(`[data-transport="${name}"]`).forEach(b => {
    b.disabled = true;
    if (b.id) b.textContent = label;  // only the settings button has the long label
  });
}
if (!navigator.bluetooth) disableTransport('ble', 'Connect (BLE — not supported)');
if (!navigator.serial) disableTransport('serial', 'Connect (Serial — not supported)');
if (typeof WebSocket === 'undefined') disableTransport('ws', 'Connect (WebSocket — not supported)');
if (!navigator.bluetooth && !navigator.serial && typeof WebSocket === 'undefined') {
  $('unsupported').classList.remove('hidden');
}

// ---- View / theme / misc UI wiring ----------------------------------

// Sidebar nav + mobile bottom-nav: both carry data-view="messages|nodes|settings"
document.querySelectorAll('[data-view]').forEach(n => {
  n.addEventListener('click', () => switchView(n.dataset.view));
});

// Mobile back button clears the active contact so the list re-appears.
$('btn-back')?.addEventListener('click', () => {
  activeContactHash = null;
  $('conv-title').textContent = 'Select a contact';
  $('compose-area').classList.add('hidden');
  $('message-list').innerHTML = '';
  renderContactList();
});

// Persist display name across sessions. Restore from localStorage on
// load so the user doesn't have to re-type it after every page reload,
// and save on every keystroke so it's always up to date.
const NAME_KEY = 'reticulum-display-name';
const savedName = localStorage.getItem(NAME_KEY);
if (savedName && $('my-name')) {
  $('my-name').value = savedName;
}
$('my-name')?.addEventListener('input', () => {
  localStorage.setItem(NAME_KEY, $('my-name').value);
  updateAvatars();
});

// Mobile scroll hint: shown by CSS on narrow viewports. Dismiss on
// first scroll (user has seen it and acted on it) or after 6 seconds
// (they've seen it and are ignoring it). The hint element itself is
// CSS display:none on desktop so the listeners are no-ops there.
(function wireScrollHint() {
  const hint = $('scroll-hint');
  if (!hint) return;
  let dismissed = false;
  const dismiss = () => {
    if (dismissed) return;
    dismissed = true;
    hint.classList.add('dismissed');
    setTimeout(() => hint.remove(), 400);
  };
  window.addEventListener('scroll', dismiss, { once: true, passive: true });
  // Also pick up scrolls on inner containers (message-list, nodes-list)
  // since the outer document may not move much on mobile.
  document.addEventListener('touchmove', dismiss, { once: true, passive: true });
  setTimeout(dismiss, 6000);
})();

// Theme: stored choice in localStorage, 'system' follows OS preference.
const storedTheme = localStorage.getItem(THEME_KEY) || 'system';
applyTheme(storedTheme);
document.querySelectorAll('#theme-seg .seg-btn').forEach(b => {
  b.addEventListener('click', () => setTheme(b.dataset.theme));
});
$('theme-toggle')?.addEventListener('click', () => {
  const current = document.documentElement.dataset.theme;
  setTheme(current === 'dark' ? 'light' : 'dark');
});
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if ((localStorage.getItem(THEME_KEY) || 'system') === 'system') applyTheme('system');
});

// Restore the WS bridge URL and the rnsd target from the previous
// session. Plain text fields, no validation here — connect() validates.
try {
  const savedWsUrl = localStorage.getItem('rlw.wsUrl');
  if (savedWsUrl && $('ws-url')) $('ws-url').value = savedWsUrl;
  const savedRnsd = localStorage.getItem('rlw.wsRnsd');
  if (savedRnsd && $('ws-rnsd')) $('ws-rnsd').value = savedRnsd;
} catch (_) { /* private mode — non-fatal */ }

// ---- Init ------------------------------------------------------------
updateAvatars();
initIdentity().catch(e => log('err', 'Identity init: ' + e.message));
