// js/aln-router.js — identity-addressed routing for the agnostic-LoRa-Net tunnel.
//
// JS port of the mobile app's AgnosticLoraRouter (Kotlin), verified against the
// firmware contract. The mesh's distributed directory maps an opaque id (our
// 16-byte RNS destination hash, 32 hex) to the node currently serving it. This
// router holds the client-side state of that scheme:
//
//   - bindings    — id → node, learned from `loc`/dirdump text lines and
//                   passively from inbound announces (the delivering node).
//   - link routes — link_id → node, learned when a LINKREQUEST passes through,
//                   so established-link traffic (dest = link_id) routes right.
//   - reverse routes — truncated-packet-hash → origin node, pinned on inbound
//                   DATA so its delivery proof (addressed to that hash) routes back.
//   - attached node — the node we are BLE-attached to (from the `registered …`
//                   ack / heartbeat). Excluded from every routing decision: a
//                   frame addressed to it loops back to us, never RF (BR-5).
//   - pending     — outbound packets buffered (bounded) until their dest
//                   resolves. Rule: never drop while unresolved, flush on resolve.
//   - cached self-announce — re-unicast to every newly discovered peer node.
//
// Pure protocol state — no I/O, no clock (callers pass nowMs) — so it is
// testable and shared. The transport owns I/O: it feeds text lines and inbound
// frames in, and executes the returned routing decisions.

'use strict';

import {
  parsePacket,
  DEST_LINK, DEST_PLAIN,
  PACKET_ANNOUNCE, PACKET_DATA, PACKET_LINKREQ, PACKET_PROOF,
} from './reticulum.js';
import { computeLinkId, computePacketFullHash } from './link.js';
import { toHexUpper, isValidNodeIdHex } from './aln-tunnel.js';

const BINDING_STALE_MS    = 10 * 60_000;   // local staleness window (directory TTL is 600s)
const MAX_PENDING         = 64;            // same bound as the reference interface's _pending
const MAX_REVERSE_ROUTES  = 256;           // proofs fire within seconds; only a few live at once

// Anchored (matchEntire) for the structured directory lines; unanchored (find)
// for the register-ack / heartbeat which carry the node id mid-line. Node ids
// are exactly 32 hex since firmware v2; the find-style ones guard the trailing
// boundary so a longer hex run (e.g. a 64-hex pubkey) can't satisfy {32}.
const LOC_RE        = /^loc\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]{32})$/;
const BINDING_RE    = /^([0-9A-Fa-f]+)\s*->\s*([0-9A-Fa-f]{32})\s+ttl=\d+s?$/;
const REGISTERED_RE = /registered\s+\d+-byte\s+id\s+at\s+([0-9A-Fa-f]{32})(?![0-9A-Fa-f])/;
const HB_NODE_RE    = /node=([0-9A-Fa-f]{32})(?![0-9A-Fa-f])/;

function tryParse(raw) {
  try { return parsePacket(raw); } catch (_) { return null; }
}

export class AlnRouter {
  constructor(selfIdHex, fallbackUplinkHex) {
    // Our directory id: the 16-byte RNS destination hash, upper-hex.
    this.selfIdHex = (selfIdHex || '').toUpperCase();
    // Optional static gateway — routes anything the directory can't. NOT
    // auto-filled from the attached node (the §0.5 trap). An invalid-width
    // value (e.g. a stale pre-v2 8-hex id) is dropped to null.
    const fb = (fallbackUplinkHex || '').trim().toUpperCase();
    this.fallbackUplinkHex = fb && isValidNodeIdHex(fb) ? fb : null;

    this.attachedNodeHex = null;
    this._bindings = new Map();        // idHex -> { nodeHex, lastSeenMs }
    this._linkRoutes = new Map();      // linkIdHex -> nodeHex
    this._reverseRoutes = new Map();   // truncHashHex -> { nodeHex, seenMs } (insertion-ordered)
    this._pending = [];                // raw packets buffered until routable
    this._cachedSelfAnnounce = null;
    this._announcedTo = new Set();     // nodes that got the cached announce
  }

  // ---- outbound ------------------------------------------------------

  // Decide where `raw` goes. Returns one of:
  //   { kind: 'send', targets: [nodeHex…] }
  //   { kind: 'buffered' }
  //   { kind: 'deferred', reason }
  async routeOutbound(raw, nowMs) {
    this._prune(nowMs);
    const packet = tryParse(raw);
    if (!packet) return { kind: 'deferred', reason: `unparseable packet (${raw.length}B)` };

    if (packet.packetType === PACKET_ANNOUNCE) {
      if (toHexUpper(packet.destHash) === this.selfIdHex) {
        this._cachedSelfAnnounce = raw;
        this._announcedTo.clear();   // fresh announce supersedes; re-send to all
      }
      const targets = this._fanoutTargets();
      if (targets.length === 0) return { kind: 'deferred', reason: 'no peers known yet' };
      for (const t of targets) this._announcedTo.add(t);
      return { kind: 'send', targets };
    }

    // PLAIN destinations are broadcast-ish (path requests etc.) — their dest
    // hash is never a directory id, so buffering would queue them forever.
    if (packet.destType === DEST_PLAIN) {
      const targets = this._fanoutTargets();
      if (targets.length === 0) return { kind: 'deferred', reason: 'broadcast with no peers known' };
      return { kind: 'send', targets };
    }

    const node = this._resolveNodeFor(packet);
    if (node == null) {
      // A delivery proof's dest is the proved packet's truncated hash — only
      // routable via the reverse table. With no route, buffering just spams
      // resolves; drop instead — the peer's retransmit re-pins and re-proofs.
      if (packet.packetType === PACKET_PROOF && packet.destType !== DEST_LINK) {
        return { kind: 'deferred', reason: 'proof origin unknown (no reverse route) — peer retry re-pins' };
      }
      if (this._pending.length >= MAX_PENDING) this._pending.shift();
      this._pending.push(raw);
      return { kind: 'buffered' };
    }
    await this._recordLinkRequest(raw, node);
    return { kind: 'send', targets: [node] };
  }

  // Route lookup for a single-recipient packet: link table for link dests,
  // bindings then reverse table otherwise, fallback last. The attached node is
  // never a valid answer (BR-5: a frame to it loops back instead of going RF).
  _resolveNodeFor(packet) {
    const destHex = toHexUpper(packet.destHash);
    let learned;
    if (packet.destType === DEST_LINK) {
      learned = this._linkRoutes.get(destHex);
    } else {
      learned = this._bindings.get(destHex)?.nodeHex ?? this._reverseRoutes.get(destHex)?.nodeHex;
    }
    if (learned && learned !== this.attachedNodeHex) return learned;
    return this._usableFallback();
  }

  _usableFallback() {
    return this.fallbackUplinkHex && this.fallbackUplinkHex !== this.attachedNodeHex
      ? this.fallbackUplinkHex : null;
  }

  // ---- inbound learning ----------------------------------------------

  // Learn from an inbound packet delivered by srcNodeHex: an announce binds its
  // dest to the delivering node, a LINKREQUEST pins its link_id there, a DATA
  // packet pins its truncated hash so the matching proof routes back.
  async onInbound(srcNodeHex, raw, nowMs) {
    const packet = tryParse(raw);
    if (!packet) return null;
    const src = srcNodeHex.toUpperCase();
    // A frame "from" our own node is a loopback of something we misaddressed
    // (fw 0.4.5 echoes self-addressed frames). Learning from it poisons the
    // tables (e.g. our looped-back LINKREQ re-pinning its link to us) — BR-5.
    if (src === this.attachedNodeHex) return null;
    switch (packet.packetType) {
      case PACKET_ANNOUNCE: {
        const id = toHexUpper(packet.destHash);
        if (id !== this.selfIdHex) return this._upsert(id, src, nowMs, 'announce');
        return null;
      }
      case PACKET_LINKREQ: {
        const linkId = toHexUpper(await computeLinkId(packet));
        this._linkRoutes.set(linkId, src);
        return { summary: '', newPeerNodes: [], routesChanged: true };
      }
      case PACKET_DATA: {
        const full = await computePacketFullHash(packet);
        const trunc = toHexUpper(full.slice(0, 16));
        this._reverseRoutes.delete(trunc);
        this._reverseRoutes.set(trunc, { nodeHex: src, seenMs: nowMs });
        while (this._reverseRoutes.size > MAX_REVERSE_ROUTES) {
          this._reverseRoutes.delete(this._reverseRoutes.keys().next().value);
        }
        return null;
      }
      default:
        return null;
    }
  }

  // Parse a console line from the node. Recognized (node id = 32 hex):
  //   `loc <idhex> <nodehex>`                  — resolve answer
  //   `<idhex> -> <NODEHEX>  ttl=<S>s`         — dirdump binding row
  //   `registered <n>-byte id at <NODE>`       — attached-node ack
  //   `[hb] … node=<NODE> …`                   — heartbeat (silent)
  onTextLine(line, nowMs) {
    const trimmed = line.trim();
    let m = LOC_RE.exec(trimmed);
    if (m) return this._upsert(m[1].toUpperCase(), m[2].toUpperCase(), nowMs, 'loc');
    m = BINDING_RE.exec(trimmed);
    if (m) return this._upsert(m[1].toUpperCase(), m[2].toUpperCase(), nowMs, 'dirdump');
    if (/^registered/i.test(trimmed)) {
      const rm = REGISTERED_RE.exec(trimmed);
      const note = rm ? this._learnAttachedNode(rm[1].toUpperCase()) : '';
      return { summary: `register ack: ${trimmed}${note}`, newPeerNodes: [], routesChanged: false };
    }
    if (trimmed.startsWith('[hb]')) {
      const hm = HB_NODE_RE.exec(trimmed);
      if (hm) this._learnAttachedNode(hm[1].toUpperCase());
      return null;   // heartbeats stay silent
    }
    return null;
  }

  // Record which node we are attached to and scrub it from every table —
  // frames addressed to it loop back to us instead of going RF (BR-5). Returns
  // a log note for the first learn, '' otherwise.
  _learnAttachedNode(nodeHex) {
    if (this.attachedNodeHex === nodeHex) return '';
    this.attachedNodeHex = nodeHex;
    for (const [k, v] of this._bindings) if (v.nodeHex === nodeHex) this._bindings.delete(k);
    for (const [k, v] of this._linkRoutes) if (v === nodeHex) this._linkRoutes.delete(k);
    for (const [k, v] of this._reverseRoutes) if (v.nodeHex === nodeHex) this._reverseRoutes.delete(k);
    return this.fallbackUplinkHex === nodeHex
      ? ` — attached node ${nodeHex}; configured fallback IS this node, ignoring it (BR-5)`
      : ` — attached node ${nodeHex}`;
  }

  _upsert(idHex, nodeHex, nowMs, origin) {
    if (idHex === this.selfIdHex) {
      // Our own registration echoing back. Bootstrap the attached-node fact
      // from it only while unknown (a stale flood echo can name an old node;
      // the register ack / heartbeat stay authoritative).
      if (this.attachedNodeHex == null) this._learnAttachedNode(nodeHex);
      return null;
    }
    // One BLE client per node: a "peer" binding at our own node is a stale or
    // echoed registration, and routing to it would loop back to us.
    if (nodeHex === this.attachedNodeHex) return null;
    const existing = this._bindings.get(idHex);
    const isNewNode = !this._announcedTo.has(nodeHex) &&
      ![...this._bindings.values()].some((b) => b.nodeHex === nodeHex);
    const moved = existing != null && existing.nodeHex !== nodeHex;
    if (existing == null) {
      this._bindings.set(idHex, { nodeHex, lastSeenMs: nowMs });
    } else {
      existing.nodeHex = nodeHex;
      existing.lastSeenMs = nowMs;
    }
    if (existing != null && !moved && !isNewNode) return null;   // ttl refresh only
    return {
      summary: existing == null ? `peer discovered (${origin}): ${idHex} @ ${nodeHex}`
                                 : `peer moved (${origin}): ${idHex} -> ${nodeHex}`,
      newPeerNodes: isNewNode ? [nodeHex] : [],
      routesChanged: existing == null || moved,
    };
  }

  // ---- flush / directory upkeep --------------------------------------

  // Pending packets that became routable — send each, in order. The still-
  // unroutable remainder stays queued. Returns [ [raw, nodeHex], … ].
  async drainRoutable(nowMs) {
    if (this._pending.length === 0) return [];
    const out = [];
    const keep = [];
    while (this._pending.length > 0) {
      const raw = this._pending.shift();
      const packet = tryParse(raw);
      const node = packet ? this._resolveNodeFor(packet) : null;
      if (node && packet) {
        await this._recordLinkRequest(raw, node);
        out.push([raw, node]);
      } else if (packet) {
        keep.push(raw);
      }
    }
    for (const r of keep) this._pending.push(r);
    return out;
  }

  // Our cached announce for a newly discovered nodeHex, or null if none cached
  // / that node already got the current one. Marks it sent.
  cachedAnnounceFor(nodeHex) {
    const n = nodeHex.toUpperCase();
    const a = this._cachedSelfAnnounce;
    if (!a) return null;
    if (this._announcedTo.has(n)) return null;
    this._announcedTo.add(n);
    return a;
  }

  // Directory ids worth `resolve`-ing now: destinations of buffered packets
  // (link-dest packets resolve via traffic, not the directory).
  resolveWanted() {
    const want = new Set();
    for (const raw of this._pending) {
      const p = tryParse(raw);
      if (p && p.destType !== DEST_LINK) want.add(toHexUpper(p.destHash));
    }
    return [...want];
  }

  hasPending() { return this._pending.length > 0; }

  knownPeerNodes() {
    return [...new Set([...this._bindings.values()].map((b) => b.nodeHex))];
  }

  // Every known peer node plus the fallback, deduped, insertion order. Never
  // the attached node — that's us (BR-5).
  _fanoutTargets() {
    const targets = new Set();
    for (const b of this._bindings.values()) targets.add(b.nodeHex);
    const fb = this._usableFallback();
    if (fb) targets.add(fb);
    if (this.attachedNodeHex) targets.delete(this.attachedNodeHex);
    return [...targets];
  }

  async _recordLinkRequest(raw, targetNode) {
    const packet = tryParse(raw);
    if (!packet || packet.packetType !== PACKET_LINKREQ) return;
    this._linkRoutes.set(toHexUpper(await computeLinkId(packet)), targetNode);
  }

  _prune(nowMs) {
    for (const [k, v] of this._bindings) {
      if (nowMs - v.lastSeenMs > BINDING_STALE_MS) this._bindings.delete(k);
    }
    for (const [k, v] of this._reverseRoutes) {
      if (nowMs - v.seenMs > BINDING_STALE_MS) this._reverseRoutes.delete(k);
    }
  }
}
