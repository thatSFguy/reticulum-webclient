// js/transport-config.js — driver for the reticulum-lora-repeater
// configuration protocol over Web Bluetooth (GATT) or Web Serial.
// Wire format and command set live in the repeater repo:
//   ../reticulum-lora-repeater/docs/CONFIG_FORMAT.md
//   ../reticulum-lora-repeater/docs/SERIAL_PROTOCOL.md
// Firmware-side authoritative reference is src/Ble.cpp /
// src/SerialConsole.cpp / src/Config.cpp in that same repo.

import { Encoder, decode } from '../lib/msgpack.js';

// forceFloat32 makes the encoder emit msgpack 0xCA (float32) instead of
// 0xCB (float64) for non-integer numbers. The transport firmware reads
// batt_mult strictly as float32 and rejects float64 with
// "malformed set_config payload" — see the repeater repo's CONFIG_FORMAT.md.
const encoder = new Encoder({ forceFloat32: true });
const encode  = (obj) => encoder.encode(obj);

const SERVICE_UUID  = '00000000-a5a5-524c-7272-00000100726c';
const REQUEST_UUID  = '00000000-a5a5-524c-7272-00000200726c';
const RESPONSE_UUID = '00000000-a5a5-524c-7272-00000300726c';

const SERIAL_BAUD       = 115200;
const SERIAL_MAX_FRAME  = 1024;
const RESPONSE_TIMEOUT  = 5000;

// On the response side, get_config wire-emits all integers as msgpack
// uints (per transport repo docs §3.3), so signed fields
// arrive as uint32 bit patterns and must be re-cast to int32. Outbound
// requests do NOT need this conversion — the firmware's read_int
// accepts negative-fixint / int8/16/32/64 natively, and forcing the
// uint32 bit pattern would now fail the per-field range check.
const SIGNED_INT32_FIELDS = ['txp_dbm', 'lat_udeg', 'lon_udeg', 'alt_m'];

function decodeSignedFields(obj) {
  const out = { ...obj };
  for (const k of SIGNED_INT32_FIELDS) {
    if (k in out && typeof out[k] === 'number') out[k] = (out[k] | 0);
  }
  return out;
}

// Fields the firmware reads strictly as float32 (msgpack 0xCA). The
// encoder's forceFloat32 option only chooses between float32 and
// float64; it does NOT redirect integer-valued JS numbers through the
// float path — Number.isSafeInteger(1.0) is true, so parseFloat("1.000")
// would otherwise be wire-emitted as fixint(0x01) and rejected with
// "malformed set_config payload". Nudging the value below float32
// resolution forces the integer test to fail without changing the
// 32-bit pattern that lands on the device.
const FLOAT32_FIELDS = ['batt_mult'];

function ensureFloatTypes(obj) {
  const out = { ...obj };
  for (const k of FLOAT32_FIELDS) {
    const v = out[k];
    if (typeof v === 'number' && Number.isSafeInteger(v)) {
      out[k] = v === 0 ? Number.MIN_VALUE : v * (1 + Number.EPSILON);
    }
  }
  return out;
}

class TransportClient {
  constructor(logFn) {
    this.log = logFn || (() => {});
    this.transport = null;
    this.kind = null;       // 'ble' | 'serial'
    this.pending = null;    // { resolve, reject, timer }
    this.onDisconnect = null;
  }

  isConnected() { return this.transport !== null; }

  async connectBle() {
    if (!('bluetooth' in navigator)) throw new Error('Web Bluetooth not supported');
    const device = await navigator.bluetooth.requestDevice({
      filters: [{ services: [SERVICE_UUID] }],
    });
    const server = await device.gatt.connect();
    const svc    = await server.getPrimaryService(SERVICE_UUID);
    const reqCh  = await svc.getCharacteristic(REQUEST_UUID);
    const rspCh  = await svc.getCharacteristic(RESPONSE_UUID);

    rspCh.addEventListener('characteristicvaluechanged', (ev) => {
      const buf = new Uint8Array(ev.target.value.buffer.slice(
        ev.target.value.byteOffset,
        ev.target.value.byteOffset + ev.target.value.byteLength,
      ));
      this._handleResponse(buf);
    });
    await rspCh.startNotifications();

    device.addEventListener('gattserverdisconnected', () => {
      this.log('info', 'BLE disconnected');
      this.transport = null;
      this.kind = null;
      if (this.onDisconnect) this.onDisconnect();
    });

    this.transport = { device, server, svc, reqCh, rspCh };
    this.kind = 'ble';
    this.log('ok', 'BLE connected to ' + (device.name || 'rlr-transport'));
  }

  async connectSerial() {
    if (!('serial' in navigator)) throw new Error('Web Serial not supported');
    const port = await navigator.serial.requestPort();
    await port.open({
      baudRate: SERIAL_BAUD, dataBits: 8, stopBits: 1, parity: 'none',
    });

    const reader = port.readable.getReader();
    const writer = port.writable.getWriter();

    const deframer = new SerialDeframer((frame) => this._handleResponse(frame));
    const readLoop = (async () => {
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          if (!value) continue;
          for (let i = 0; i < value.length; i++) deframer.push(value[i]);
        }
      } catch (e) { /* expected during close */ }
    })();

    this.transport = { port, reader, writer, readLoop };
    this.kind = 'serial';
    this.log('ok', 'Serial connected at ' + SERIAL_BAUD + ' baud');
  }

  async disconnect() {
    if (!this.transport) return;
    try {
      if (this.kind === 'ble') {
        try { await this.transport.rspCh.stopNotifications(); } catch (e) {}
        try { this.transport.server.disconnect(); } catch (e) {}
      } else if (this.kind === 'serial') {
        try { await this.transport.reader.cancel(); } catch (e) {}
        try { this.transport.reader.releaseLock(); } catch (e) {}
        try { this.transport.writer.releaseLock(); } catch (e) {}
        try { await this.transport.port.close(); } catch (e) {}
      }
    } finally {
      this.transport = null;
      this.kind = null;
      if (this.pending) {
        clearTimeout(this.pending.timer);
        this.pending.reject(new Error('disconnected'));
        this.pending = null;
      }
    }
  }

  // Send one msgpack-encoded request; await one msgpack-encoded
  // response. Concurrent calls are serialised by the caller — this
  // class assumes one in-flight request at a time.
  async call(request) {
    if (!this.transport) throw new Error('not connected');
    if (this.pending) throw new Error('request already in flight');

    const bytes = encode(request);
    if (this.kind === 'ble' && bytes.length > 244) {
      throw new Error('request exceeds BLE ATT MTU (244 bytes)');
    }
    if (this.kind === 'serial' && bytes.length > SERIAL_MAX_FRAME) {
      throw new Error('request exceeds serial frame cap (' + SERIAL_MAX_FRAME + ')');
    }

    return new Promise(async (resolve, reject) => {
      this.pending = {
        resolve, reject,
        timer: setTimeout(() => {
          this.pending = null;
          reject(new Error('response timeout'));
        }, RESPONSE_TIMEOUT),
      };
      try {
        if (this.kind === 'ble') {
          await this.transport.reqCh.writeValueWithoutResponse(bytes);
        } else {
          const framed = new Uint8Array(2 + bytes.length);
          framed[0] = (bytes.length >>> 8) & 0xff;
          framed[1] = bytes.length & 0xff;
          framed.set(bytes, 2);
          await this.transport.writer.write(framed);
        }
      } catch (e) {
        clearTimeout(this.pending.timer);
        this.pending = null;
        reject(e);
      }
    });
  }

  _handleResponse(bytes) {
    if (!this.pending) {
      this.log('info', 'unsolicited response (' + bytes.length + 'B), ignoring');
      return;
    }
    const p = this.pending;
    this.pending = null;
    clearTimeout(p.timer);
    try {
      const obj = decode(bytes);
      p.resolve(obj);
    } catch (e) {
      p.reject(new Error('msgpack decode failed: ' + e.message));
    }
  }

  // ---- High-level commands -----------------------------------------

  async ping() {
    const r = await this.call({ cmd: 'ping' });
    if (!r.ok) throw new Error(r.err || 'ping failed');
    return r;
  }

  async getConfig() {
    const r = await this.call({ cmd: 'get_config' });
    if (!r.ok) throw new Error(r.err || 'get_config failed');
    return decodeSignedFields(r);
  }

  // `fields` is an object containing any subset of the writable Config
  // fields. JS numbers are passed through msgpack natively — negative
  // ints encode as negative-fixint / int8/16/32, which the firmware's
  // read_int accepts directly. ensureFloatTypes nudges integer-valued
  // float32 fields off the safe-integer path so the encoder routes
  // them through the float branch.
  async setConfig(fields) {
    const r = await this.call({ cmd: 'set_config', ...ensureFloatTypes(fields) });
    if (!r.ok) throw new Error(r.err || 'set_config failed');
    return r;
  }

  async commit() {
    const r = await this.call({ cmd: 'commit' });
    if (!r.ok) throw new Error(r.err || 'commit failed');
    return r;
  }
}

// Serial deframer: u16BE length prefix + payload. Drops malformed
// frames silently and resyncs on the next length-hi byte.
class SerialDeframer {
  constructor(onFrame) {
    this.state = 'LEN_HI';
    this.expected = 0;
    this.received = 0;
    this.buf = null;
    this.onFrame = onFrame;
  }
  push(byte) {
    switch (this.state) {
      case 'LEN_HI':
        this.expected = byte << 8;
        this.state = 'LEN_LO';
        break;
      case 'LEN_LO':
        this.expected |= byte;
        if (this.expected === 0 || this.expected > SERIAL_MAX_FRAME) {
          this.state = 'LEN_HI';
          break;
        }
        this.buf = new Uint8Array(this.expected);
        this.received = 0;
        this.state = 'PAYLOAD';
        break;
      case 'PAYLOAD':
        this.buf[this.received++] = byte;
        if (this.received >= this.expected) {
          this.onFrame(this.buf);
          this.state = 'LEN_HI';
        }
        break;
    }
  }
}

// Convert lat/lon between human degrees (37.7749) and microdegrees (37774900).
export function latLonToUdeg(deg) {
  return Math.round(deg * 1_000_000);
}
export function udegToLatLon(udeg) {
  return udeg / 1_000_000;
}

// Convert frequency between Hz and MHz for UI fields.
export function hzToMhz(hz) { return hz / 1_000_000; }
export function mhzToHz(mhz) { return Math.round(mhz * 1_000_000); }

export { TransportClient, SERVICE_UUID, REQUEST_UUID, RESPONSE_UUID };
