import assert from 'node:assert/strict';
import test from 'node:test';
import { ReconnectController } from '../js/reconnect.js';

function fixture({ remembered = false, session = true } = {}) {
  const document = new EventTarget(); document.hidden = false;
  const window = new EventTarget();
  const navigator = { onLine: true };
  const saved = new Map(remembered ? [['rlw.wsKeepConnected', '1']] : []);
  const timers = new Map(); let nextTimer = 0;
  const state = { connects: 0, disconnects: 0, connected: false, session, fail: false, states: [] };
  const controller = new ReconnectController({
    connect: async () => { state.connects++; state.connected = !state.fail; return state.connected; },
    disconnect: () => { state.disconnects++; state.connected = false; },
    isConnected: () => state.connected,
    checkSession: async () => state.session,
    onState: (name, delay) => state.states.push([name, delay]),
    storage: { getItem: key => saved.get(key), setItem: (key, value) => saved.set(key, value) },
    document, window, navigator, jitter: () => 0,
    setTimer: (fn, delay) => { const id = ++nextTimer; timers.set(id, { fn, delay }); return id; },
    clearTimer: id => timers.delete(id),
  });
  return { controller, state, document, window, navigator, saved, timers };
}
const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };

test('refresh restores only a previously requested connection', async () => {
  const fresh = fixture(); await fresh.controller.restore();
  assert.equal(fresh.state.connects, 0);
  const remembered = fixture({ remembered: true }); await remembered.controller.restore();
  assert.equal(remembered.state.connects, 1);
  assert.ok(remembered.state.connected);
});

test('locking pauses without retries; returning reconnects once', async () => {
  const f = fixture(); await f.controller.start();
  f.document.hidden = true; f.document.dispatchEvent(new Event('visibilitychange'));
  assert.equal(f.state.connected, false);
  assert.equal(f.timers.size, 0);
  f.document.hidden = false; f.document.dispatchEvent(new Event('visibilitychange'));
  f.window.dispatchEvent(new Event('pageshow'));
  await flush();
  assert.equal(f.state.connects, 2);
  assert.ok(f.state.connected);
});

test('manual Disconnect stays disconnected through resume and refresh', async () => {
  const f = fixture(); await f.controller.start(); f.controller.stop();
  f.window.dispatchEvent(new Event('pageshow'));
  await f.controller.restore(); await flush();
  assert.equal(f.state.connects, 1);
  assert.equal(f.saved.get('rlw.wsKeepConnected'), '0');
  assert.equal(f.timers.size, 0);
});

test('network failures use bounded exponential backoff', async () => {
  const f = fixture(); f.state.fail = true; await f.controller.start();
  for (const delay of [1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000]) {
    assert.equal(f.timers.size, 1);
    const [id, timer] = [...f.timers][0];
    assert.equal(timer.delay, delay);
    f.timers.delete(id); timer.fn(); await flush();
  }
  f.controller.stop(); assert.equal(f.timers.size, 0);
});

test('offline waits for online instead of retrying', async () => {
  const f = fixture(); f.navigator.onLine = false; await f.controller.start();
  assert.equal(f.state.connects, 0);
  assert.equal(f.timers.size, 0);
  f.navigator.onLine = true; f.window.dispatchEvent(new Event('online')); await flush();
  assert.equal(f.state.connects, 1);
});

test('expired login requests a single sign-in, not repeated authentication attempts', async () => {
  const f = fixture({ session: false }); await f.controller.start();
  assert.equal(f.state.connects, 0);
  assert.equal(f.timers.size, 0);
  assert.ok(f.state.states.some(([name]) => name === 'authentication'));
  f.state.session = true; await f.controller.resume();
  assert.equal(f.state.connects, 1);
});

test('a late session check cannot connect after manual disconnect', async () => {
  const f = fixture(); let resolve;
  f.controller.checkSession = () => new Promise(done => { resolve = done; });
  const pending = f.controller.start(); f.controller.stop(); resolve(true); await pending;
  assert.equal(f.state.connects, 0);
  assert.equal(f.timers.size, 0);
});
