// js/nus-demux.js — demux for the agnostic-LoRa-Net node's NUS byte stream.
//
// JS port of the mobile app's NusDemux (Kotlin), itself a byte-for-byte port of
// AgnosticLoraInterface.py::_read_loop. The node multiplexes two things onto one
// byte stream:
//   - HDLC frames (0x7E … 0x7E) carrying tunnel envelopes, and
//   - plain text console lines (`loc …`, `registered …`, `[dir] …`,
//     heartbeat) terminated by LF.
//
// Semantics (kept faithful — these differ from a generic HDLC parser):
//   - FLAG (0x7E) TOGGLES frame state: first FLAG opens, second closes. The node
//     emits frames as discrete FLAG…FLAG pairs, never sharing a delimiter.
//   - Any FLAG clears the text accumulator: a frame boundary is never part of a
//     console line.
//   - In-frame: ESC (0x7D) + next^0x20 un-escaping; oversize frames stop
//     accumulating (bytes dropped) but stay in-frame until the closing FLAG.
//   - Out-of-frame: LF emits the accumulated line, CR is dropped, lines capped.
//   - Empty frame (two FLAGs back-to-back) is a keepalive, not a frame.

'use strict';

const HDLC_FLAG     = 0x7E;
const HDLC_ESC      = 0x7D;
const HDLC_ESC_MASK = 0x20;

export class NusDemux {
  constructor(onFrame, onTextLine) {
    this.onFrame = onFrame;
    this.onTextLine = onTextLine;
    this._inFrame = false;
    this._escape = false;
    this._frame = [];
    this._text = '';
    this._maxFrameBytes = 500 + 8;   // HW_MTU + 8 (reference cap)
    this._maxLineChars = 200;
  }

  feed(bytes) {
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i] & 0xFF;
      if (b === HDLC_FLAG) {
        if (this._inFrame) {
          this._inFrame = false;
          if (this._frame.length > 0) this.onFrame(new Uint8Array(this._frame));
        } else {
          this._inFrame = true;
          this._escape = false;
          this._frame = [];
        }
        this._text = '';   // a frame boundary is never part of a line
        continue;
      }
      if (this._inFrame) {
        if (this._frame.length < this._maxFrameBytes) {
          if (this._escape) {
            this._escape = false;
            this._frame.push(b ^ HDLC_ESC_MASK);
          } else if (b === HDLC_ESC) {
            this._escape = true;
          } else {
            this._frame.push(b);
          }
        }
        continue;
      }
      // Out-of-frame: console text.
      if (b === 0x0A) {
        const line = this._text;
        this._text = '';
        if (line.trim().length > 0) this.onTextLine(line);
      } else if (b !== 0x0D && this._text.length < this._maxLineChars) {
        this._text += String.fromCharCode(b);
      }
    }
  }

  reset() {
    this._inFrame = false;
    this._escape = false;
    this._frame = [];
    this._text = '';
  }
}
