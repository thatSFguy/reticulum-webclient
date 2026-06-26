// js/aln-interface.js — Reticulum-over-agnostic-LoRa-Net tunnel interface.
//
// Tunnels raw Reticulum packets across an agnostic-LoRa-Net ("ALN") mesh by
// talking to an ALN node over Web Bluetooth. The node runs the mesh (routing,
// per-hop ARQ, SAR fragmentation); we hand it opaque RNS packets and it carries
// them to the node serving each destination — NOT RNode emulation.
//
// This is a faithful port of the mobile app's AgnosticLoraBleTransport wiring
// (identity-addressed mode): on connect we `register` our 16-byte RNS
// destination hash with the mesh's distributed directory and `dirdump` to
// enumerate peers; the AlnRouter then routes each outbound packet to the node
// currently serving its destination, fans announces out to every known peer,
// buffers until destinations resolve, and pins link/proof reverse-routes. The
// optional fallback peer node id is just a static gateway pin.
//
// Same {connect/sendPacket/_onPacket/capabilities/…} shape as rnsd-interface.js
// so app.js drives it without branching.
//
// Notes:
//   * BLE auto-enters tunnel mode on connect — no "tunnel\n" (that's USB only).
//   * The node multiplexes HDLC tunnel frames AND text console lines on one
//     stream; NusDemux splits them. Frames carry the typed locator envelope
//     [0x01][16][node][packet]; text lines drive the directory router.
//   * No radio to configure and no RSSI in tunnel frames — capabilities report
//     no RNode control, and we pass rssi=0/snr=0 into _onPacket like rnsd.
//   * The BLE link is PIN-paired on ALN nodes; the OS handles the pairing
//     prompt when we subscribe to the encrypted characteristic.

'use strict';

import { BleTransport } from './ble-transport.js';
import { encodeFrame } from './hdlc.js';
import { NusDemux } from './nus-demux.js';
import { AlnRouter } from './aln-router.js';
import {
  encodeLocatorFrame, decodeFrame, sourceFromFrame, locatorFromHex,
} from './aln-tunnel.js';

const POLL_TICK_MS       = 5_000;     // resolve retries while sends are buffered
const DIRDUMP_INTERVAL_MS = 600_000;  // slow re-enumeration safety net

export class AlnInterface {
  // selfIdHex: our 16-byte LXMF destination hash (32 hex) — the directory id.
  // fallbackPeerHex: optional static gateway node id (blank = directory only).
  constructor(selfIdHex, fallbackPeerHex) {
    this.transport = new BleTransport();
    this.router = new AlnRouter(selfIdHex, fallbackPeerHex);
    this._onPacket = null;
    this._onDisconnect = null;
    this._onLog = null;

    this._pollTimer = null;
    this._sinceDirdump = 0;
    this._writeChain = Promise.resolve();   // serialize all writes (frames + text)
    this._inboundQueue = [];                // ordered inbound items
    this._draining = false;

    this._demux = new NusDemux(
      (frame) => this._onDemuxFrame(frame),
      (line)  => this._enqueue({ kind: 'text', line }),
    );
    this.transport._onReceive = (bytes) => this._demux.feed(bytes);
  }

  get connected() { return this.transport.connected; }

  // No radio and no RNode command set on the far side — app.js uses these to
  // skip the detect/firmware/battery/radio-config sequence (same as rnsd).
  get capabilities() {
    return { rnodeControl: false, radioConfig: false };
  }

  _log(msg) { if (this._onLog) this._onLog(msg); }

  async connect() {
    this.transport._onLog = (msg) => this._log(msg);
    this.transport._onDisconnect = () => {
      this._stopPoll();
      this._demux.reset();
      if (this._onDisconnect) this._onDisconnect();
    };
    await this.transport.connect();
    this._demux.reset();
    this._inboundQueue = [];

    // Directory bring-up: register once per BLE session (the serving node
    // re-floods every ~240s), enumerate peers, then poll. Use the router's
    // normalized (uppercase) id — directory lookups are case-sensitive, so
    // registration and resolves must agree.
    await this._writeText(`register ${this.router.selfIdHex}`);
    await this._writeText('dirdump');
    this._startPoll();
    this._log(`ALN tunnel ready (id ${this.router.selfIdHex}${
      this.router.fallbackUplinkHex ? `, fallback ${this.router.fallbackUplinkHex}` : ', directory addressing'})`);
  }

  async disconnect() {
    this._stopPoll();
    await this.transport.disconnect();
  }

  // RNode command stubs so any un-gated app.js caller still works without
  // branching (same as rnsd-interface.js).
  async detect()             { return true; }
  async getFirmwareVersion() { return { major: 0, minor: 0 }; }
  async getPlatform()        { return 0; }
  async getBoard()           { return 0; }
  async getBattery()         { return 0; }
  async setFrequency()       { return 0; }
  async setBandwidth()       { return 0; }
  async setSpreadingFactor() { return 0; }
  async setCodingRate()      { return 0; }
  async setTxPower()         { return 0; }
  async setRadioState()      { return true; }
  async configureAndStart()  { return true; }
  async blink()              { }

  // Send a raw Reticulum packet. The router decides which mesh node(s) it goes
  // to; we write a typed-locator tunnel frame to each.
  async sendPacket(data) {
    if (!this.transport.connected) throw new Error('ALN not connected');
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    const d = await this.router.routeOutbound(bytes, Date.now());
    if (d.kind === 'send') {
      for (const node of d.targets) await this._writeTunnelFrame(node, bytes);
    } else if (d.kind === 'buffered') {
      const wanted = this.router.resolveWanted();
      this._log(`ALN: buffered ${bytes.length}B until destination resolves (${wanted.length} wanted)`);
      for (const id of wanted.slice(0, 4)) await this._writeText(`resolve ${id}`);
    } else {
      this._log(`ALN: deferred ${bytes.length}B — ${d.reason}`);
    }
  }

  // ---- inbound -------------------------------------------------------

  _onDemuxFrame(frame) {
    const payload = decodeFrame(frame);
    if (!payload) { this._log(`ALN rx: drop ${frame.length}B (not LOCATOR / truncated)`); return; }
    const src = sourceFromFrame(frame);
    if (!src) return;
    // fw 0.4.5 loops self-addressed frames back to the sender. Seeing one means
    // WE misaddressed a frame to our own node — drop before the engine (BR-5).
    if (src === this.router.attachedNodeHex) {
      this._log(`ALN rx: loopback ${payload.length}B from ${src} — we addressed our own node (BR-5); dropped`);
      return;
    }
    this._enqueue({ kind: 'frame', src, payload });
  }

  _enqueue(item) {
    this._inboundQueue.push(item);
    if (!this._draining) this._drainInbound();
  }

  // Single ordered consumer: the router learns from a packet (link pins above
  // all) BEFORE the engine can react to it, and one failing item never kills
  // the pump (BR-10).
  async _drainInbound() {
    this._draining = true;
    try {
      while (this._inboundQueue.length > 0) {
        const item = this._inboundQueue.shift();
        try {
          if (item.kind === 'frame') {
            const ev = await this.router.onInbound(item.src, item.payload, Date.now());
            if (this._onPacket) this._onPacket(item.payload, 0, 0);
            if (ev) await this._handleDirectoryEvent(ev);
          } else {
            const ev = this.router.onTextLine(item.line, Date.now());
            if (ev) await this._handleDirectoryEvent(ev);
          }
        } catch (e) {
          this._log(`ALN: inbound item failed (pump continues): ${e.message}`);
        }
      }
    } finally {
      this._draining = false;
    }
  }

  // React to directory changes: greet new peer nodes with our cached announce,
  // and flush sends that just became routable.
  async _handleDirectoryEvent(ev) {
    if (ev.summary) this._log(`ALN: ${ev.summary}`);
    for (const node of ev.newPeerNodes) {
      const announce = this.router.cachedAnnounceFor(node);
      if (!announce) continue;
      this._log(`ALN: sending cached announce to new peer node ${node}`);
      try { await this._writeTunnelFrame(node, announce); }
      catch (e) { this._log(`ALN: announce to ${node} failed: ${e.message}`); }
    }
    if (ev.routesChanged) {
      const flushed = await this.router.drainRoutable(Date.now());
      for (const [raw, node] of flushed) {
        this._log(`ALN: flushing buffered ${raw.length}B -> ${node}`);
        try { await this._writeTunnelFrame(node, raw); }
        catch (e) { this._log(`ALN: flush to ${node} failed: ${e.message}`); }
      }
    }
  }

  // ---- directory poll ------------------------------------------------

  _startPoll() {
    this._stopPoll();
    this._sinceDirdump = 0;
    this._pollTimer = setInterval(async () => {
      try {
        if (this.router.hasPending()) {
          for (const id of this.router.resolveWanted().slice(0, 4)) await this._writeText(`resolve ${id}`);
        }
        this._sinceDirdump += POLL_TICK_MS;
        if (this._sinceDirdump >= DIRDUMP_INTERVAL_MS) {
          this._sinceDirdump = 0;
          await this._writeText('dirdump');
        }
      } catch (e) { this._log(`ALN: directory poll error: ${e.message}`); }
    }, POLL_TICK_MS);
  }

  _stopPoll() {
    if (this._pollTimer) { clearInterval(this._pollTimer); this._pollTimer = null; }
  }

  // ---- writes (serialized) -------------------------------------------

  _writeTunnelFrame(nodeHex, packet) {
    const locator = locatorFromHex(nodeHex);
    if (!locator) return Promise.reject(new Error(`unroutable node id '${nodeHex}'`));
    return this._enqueueWrite(encodeFrame(encodeLocatorFrame(locator, packet)));
  }

  _writeText(line) {
    const bytes = new Uint8Array((line + '\n').length);
    for (let i = 0; i < bytes.length; i++) bytes[i] = (line + '\n').charCodeAt(i) & 0xFF;
    return this._enqueueWrite(bytes);
  }

  // Serialize every write (frames AND text commands) so a command never
  // interleaves mid-frame on the BLE link. The transport chunks each write to
  // its negotiated size and the node reassembles byte-by-byte.
  _enqueueWrite(bytes) {
    this._writeChain = this._writeChain.then(() => this.transport.write(bytes), () => this.transport.write(bytes));
    return this._writeChain;
  }
}
