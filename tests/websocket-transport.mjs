import assert from 'node:assert/strict';
import test from 'node:test';
import { WebSocketTransport } from '../js/websocket-transport.js';

class FakeWebSocket extends EventTarget {
  static CONNECTING = 0; static OPEN = 1; static CLOSING = 2; static CLOSED = 3;
  static instances = [];
  constructor() { super(); this.readyState = 0; FakeWebSocket.instances.push(this); }
  open() { this.readyState = 1; this.dispatchEvent(new Event('open')); }
  close() { this.readyState = 2; }
  finishClose() { this.readyState = 3; this.dispatchEvent(new Event('close')); }
  send(data) { this.sent = data; }
}
globalThis.WebSocket = FakeWebSocket;
const flush = async () => { for (let i = 0; i < 4; i++) await Promise.resolve(); };

test('close before open rejects rather than hanging', async () => {
  const transport = new WebSocketTransport('wss://example.test/ws');
  const pending = transport.connect();
  const rejected = assert.rejects(pending, /closed before opening/);
  await flush(); FakeWebSocket.instances.at(-1).finishClose(); await rejected;
  assert.equal(transport.connected, false);
});

test('manual disconnect cancels an in-progress handshake without an unexpected-disconnect callback', async () => {
  const transport = new WebSocketTransport('wss://example.test/ws');
  let disconnects = 0; transport._onDisconnect = () => disconnects++;
  const pending = transport.connect();
  const rejected = assert.rejects(pending, /cancelled/);
  await flush(); const socket = FakeWebSocket.instances.at(-1);
  await transport.disconnect(); socket.finishClose(); await rejected;
  assert.equal(disconnects, 0);
});

test('a stale close event cannot clear a replacement socket', async () => {
  const transport = new WebSocketTransport('wss://example.test/ws');
  const first = transport.connect(); await flush();
  const oldSocket = FakeWebSocket.instances.at(-1); oldSocket.open(); await first;
  await transport.disconnect();
  const second = transport.connect(); await flush();
  const current = FakeWebSocket.instances.at(-1); current.open(); await second;
  oldSocket.finishClose();
  assert.equal(transport.connected, true);
  assert.equal(transport.ws, current);
  await transport.disconnect(); current.finishClose();
});
