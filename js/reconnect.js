// Restore an explicitly requested WebSocket connection, never background iOS.
'use strict';

export class ReconnectController {
  constructor({ connect, disconnect, isConnected, checkSession, onState,
    storage = globalThis.localStorage, document = globalThis.document, window = globalThis.window,
    navigator = globalThis.navigator, setTimer = (...args) => globalThis.setTimeout(...args),
    clearTimer = id => globalThis.clearTimeout(id), jitter = Math.random }) {
    Object.assign(this, { connect, disconnect, isConnected, checkSession, onState, storage,
      document, window, navigator, setTimer, clearTimer, jitter });
    this.wanted = false;
    this.connecting = false;
    this.authPaused = false;
    this.generation = 0;
    this.failures = 0;
    this.timer = null;
    this.document.addEventListener('visibilitychange', () => {
      if (this.document.hidden) this.pause('paused'); else this.resume();
    });
    this.window.addEventListener('pagehide', () => this.pause('paused'));
    this.window.addEventListener('pageshow', () => this.resume());
    this.window.addEventListener('offline', () => this.pause('offline'));
    this.window.addEventListener('online', () => this.resume());
  }

  usable() { return !this.document.hidden && this.navigator.onLine !== false; }

  persist() {
    // This flag is connection intent, never an authentication secret.
    try { this.storage.setItem('rlw.wsKeepConnected', this.wanted ? '1' : '0'); } catch (_) {}
  }

  restore() {
    try { if (this.storage.getItem('rlw.wsKeepConnected') === '1') return this.start(); } catch (_) {}
  }

  start() {
    this.wanted = true;
    this.persist();
    return this.resume();
  }

  stop() {
    this.wanted = false;
    this.persist();
    this.pause('disconnected');
  }

  pause(state) {
    this.generation++;
    if (this.timer !== null) this.clearTimer(this.timer);
    this.timer = null;
    if (this.wanted || state === 'disconnected') {
      Promise.resolve(this.disconnect()).catch(() => {});
      this.onState(state);
    }
  }

  resume() {
    if (!this.wanted) return;
    if (!this.usable()) { this.pause(this.document.hidden ? 'paused' : 'offline'); return; }
    this.authPaused = false;
    if (this.timer !== null) this.clearTimer(this.timer);
    this.timer = null;
    if (!this.isConnected()) return this.run();
  }

  lost() {
    if (!this.connecting) this.schedule();
  }

  schedule(immediate = false) {
    if (!this.wanted || !this.usable() || this.authPaused || this.timer !== null) return;
    const delay = immediate ? 0 : Math.min(60000, 1000 * 2 ** Math.min(this.failures++, 6)) + Math.floor(this.jitter() * 300);
    this.onState('retry', Math.ceil(delay / 1000));
    this.timer = this.setTimer(() => { this.timer = null; this.run(); }, delay);
  }

  async run() {
    if (this.connecting || !this.wanted || !this.usable() || this.isConnected()) return;
    const generation = this.generation;
    const current = () => generation === this.generation && this.wanted && this.usable();
    this.connecting = true;
    let failed = false;
    try {
      if (!await this.checkSession()) {
        if (current()) { this.authPaused = true; this.onState('authentication'); }
        return;
      }
      if (!current()) return;
      this.onState('connecting');
      const connected = await this.connect();
      if (!current()) return;
      if (connected && this.isConnected()) {
        this.failures = 0;
        this.onState('connected');
      } else failed = true;
    } catch (_) {
      if (current()) failed = true;
    } finally {
      this.connecting = false;
      if (current() && failed) this.schedule();
      else if (generation !== this.generation && this.wanted && this.usable() && !this.isConnected()) this.schedule(true);
    }
  }
}
