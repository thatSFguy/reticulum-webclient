// js/websocket-transport.js — WebSocket byte-stream transport.
//
// Used to talk to a local or remote rnsd via a small WebSocket-to-TCP
// bridge (see tools/ws_bridge.py). Browsers cannot open raw TCP
// sockets, so a WebSocket hop is mandatory for any "TCP" connection
// from the browser. Each binary WebSocket message carries one or
// more HDLC-framed Reticulum packets; the HdlcParser in the caller
// handles frame boundaries across arbitrary chunking.

'use strict';

export class WebSocketTransport {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this._onReceive = null;
    this._onDisconnect = null;
    this._onLog = null;
    this._abortConnect = null;
  }

  get connected() {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  _log(msg) {
    if (this._onLog) this._onLog(msg);
  }

  async connect() {
    if (typeof WebSocket === 'undefined') {
      throw new Error('WebSocket not supported in this environment');
    }

    this._log(`Opening WebSocket to ${this.url}...`);

    await this.disconnect();

    return new Promise((resolve, reject) => {
      let ws;
      try {
        ws = new WebSocket(this.url);
      } catch (e) {
        reject(new Error(`WebSocket constructor failed: ${e.message}`));
        return;
      }
      ws.binaryType = 'arraybuffer';

      let opened = false;
      const timeout = setTimeout(() => {
        if (this.ws !== ws || opened) return;
        this.ws = null;
        this._abortConnect = null;
        ws.close();
        reject(new Error('WebSocket connection timed out'));
      }, 12000);
      this._abortConnect = () => {
        clearTimeout(timeout);
        reject(new Error('WebSocket connection cancelled'));
      };

      ws.addEventListener('open', () => {
        clearTimeout(timeout);
        if (this.ws !== ws) { ws.close(); return; }
        opened = true;
        this._abortConnect = null;
        this._log(`WebSocket connected`);
        resolve();
      }, { once: true });

      ws.addEventListener('error', (e) => {
        // The error event does not carry a detailed message in most
        // browsers. If the WS closes before open we reject here;
        // once open, errors become disconnects handled below.
        if (this.ws !== ws) return;
        if (!opened) {
          clearTimeout(timeout);
          reject(new Error('WebSocket error before open'));
        } else {
          this._log('WebSocket error');
        }
      });

      ws.addEventListener('message', (evt) => {
        if (this.ws !== ws) return;
        if (!this._onReceive) return;
        // WebSocket can deliver Blob or ArrayBuffer depending on the
        // binaryType and the send side. We requested ArrayBuffer;
        // fall back defensively if the server sent strings.
        if (evt.data instanceof ArrayBuffer) {
          this._onReceive(new Uint8Array(evt.data));
        } else if (evt.data && evt.data.byteLength !== undefined) {
          this._onReceive(new Uint8Array(evt.data));
        } else if (typeof evt.data === 'string') {
          // A server that sent text is broken for our use case, but
          // log and skip rather than crashing the receive loop.
          this._log(`Ignoring text WebSocket message (${evt.data.length} chars)`);
        }
      });

      ws.addEventListener('close', () => {
        clearTimeout(timeout);
        if (this.ws !== ws) return;
        this._log('WebSocket disconnected');
        this.ws = null;
        this._abortConnect = null;
        if (!opened) reject(new Error('WebSocket closed before opening'));
        else if (this._onDisconnect) this._onDisconnect();
      });

      this.ws = ws;
    });
  }

  async disconnect() {
    const ws = this.ws;
    this.ws = null;
    this._abortConnect?.();
    this._abortConnect = null;
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) ws.close();
  }

  async write(data) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket not connected');
    }
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    // WebSocket.send accepts ArrayBuffer directly; copy into a
    // fresh buffer because the underlying ArrayBuffer may be a
    // view on a shared Uint8Array.
    this.ws.send(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
  }
}
