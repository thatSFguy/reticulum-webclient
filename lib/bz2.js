// lib/bz2.js — minimal bzip2 (bunzip2) decompressor for the browser.
//
// Reticulum Resources (SPEC §10) bz2-compress their body when it shrinks
// (flag `c`), and browsers have no native bz2. This is a from-scratch
// decoder for that one job: input is a complete bzip2 stream (starts with
// "BZh"), output is the decompressed bytes.
//
// `maxOutputLength` bounds the output — Resource advertisements carry an
// attacker-controlled size, and a small bz2 input can legitimately expand
// to gigabytes (SPEC §10.4 decompression-bomb callout). We abort the
// moment the running output exceeds the cap.
//
// Scope: standard (non-randomized) bzip2 streams, the only kind RNS emits.
// Randomized blocks (deprecated since bzip2 0.9.5) throw.

'use strict';

// MSB-first bit reader over a Uint8Array. Uses Number arithmetic (not <<)
// so multi-byte reads never overflow 32-bit signed bitwise math.
class BitReader {
  constructor(bytes) {
    this.bytes = bytes;
    this.pos = 0;
    this.buf = 0;       // up to ~31 pending bits, as a plain number
    this.count = 0;     // number of valid bits in buf
  }
  // Read n bits (n <= 24) MSB-first, returning an unsigned integer.
  read(n) {
    while (this.count < n) {
      if (this.pos >= this.bytes.length) throw new Error('bz2: unexpected end of input');
      this.buf = this.buf * 256 + this.bytes[this.pos++];
      this.count += 8;
    }
    this.count -= n;
    const div = Math.pow(2, this.count);
    const val = Math.floor(this.buf / div);
    this.buf -= val * div;   // keep only the low `count` bits
    return val;
  }
  read32() { return this.read(16) * 0x10000 + this.read(16); }
  read48() { return [this.read(24), this.read(24)]; }
}

const BLOCK_MAGIC_HI = 0x314159, BLOCK_MAGIC_LO = 0x265359;  // pi
const EOS_MAGIC_HI   = 0x177245, EOS_MAGIC_LO   = 0x385090;  // sqrt(pi)

// Build canonical Huffman decode tables from per-symbol code lengths,
// following the bzip2 reference (huffman.c BZ2_hbCreateDecodeTables).
function createDecodeTables(lengths, alphaSize) {
  let minLen = 32, maxLen = 0;
  for (let i = 0; i < alphaSize; i++) {
    if (lengths[i] > maxLen) maxLen = lengths[i];
    if (lengths[i] < minLen) minLen = lengths[i];
  }
  const limit = new Int32Array(maxLen + 2);
  const base  = new Int32Array(maxLen + 2);
  const perm  = new Int32Array(alphaSize);

  let pp = 0;
  for (let len = minLen; len <= maxLen; len++)
    for (let i = 0; i < alphaSize; i++)
      if (lengths[i] === len) perm[pp++] = i;

  for (let i = 0; i < alphaSize; i++) base[lengths[i] + 1]++;
  for (let i = 1; i < base.length; i++) base[i] += base[i - 1];

  let vec = 0;
  for (let len = minLen; len <= maxLen; len++) {
    vec += base[len + 1] - base[len];
    limit[len] = vec - 1;
    vec <<= 1;
  }
  for (let len = minLen + 1; len <= maxLen; len++)
    base[len] = ((limit[len - 1] + 1) << 1) - base[len];

  return { limit, base, perm, minLen, maxLen };
}

// Inverse Burrows-Wheeler transform via LF-mapping (textbook form).
// L = last column (the decoded MTF/RLE2 output), origPtr = row of the
// original string among the sorted rotations.
function inverseBWT(L, n, origPtr) {
  const C = new Int32Array(256);
  for (let i = 0; i < n; i++) C[L[i]]++;
  let sum = 0;
  for (let ch = 0; ch < 256; ch++) { const t = C[ch]; C[ch] = sum; sum += t; }

  const LF = new Int32Array(n);
  const occ = new Int32Array(256);
  for (let i = 0; i < n; i++) { const ch = L[i]; LF[i] = C[ch] + occ[ch]++; }

  const out = new Uint8Array(n);
  let p = origPtr;
  for (let k = n - 1; k >= 0; k--) { out[k] = L[p]; p = LF[p]; }
  return out;
}

// Decode one bzip2 block's MTF/RLE2 Huffman stream into the BWT last
// column. Returns { bwt, length }.
function decodeBlockSymbols(br, blockSize) {
  // Symbol-presence map: 16 group bits, then 16 bits per present group.
  const used16 = br.read(16);
  const inUse = new Uint8Array(256);
  for (let i = 0; i < 16; i++) {
    if (used16 & (0x8000 >> i)) {
      const bits = br.read(16);
      for (let j = 0; j < 16; j++) if (bits & (0x8000 >> j)) inUse[16 * i + j] = 1;
    }
  }
  const seqToUnseq = [];
  for (let i = 0; i < 256; i++) if (inUse[i]) seqToUnseq.push(i);
  const nInUse = seqToUnseq.length;
  if (nInUse === 0) throw new Error('bz2: empty symbol map');
  const alphaSize = nInUse + 2;
  const EOB = alphaSize - 1;

  // Selectors (which Huffman table applies to each 50-symbol group).
  const nGroups = br.read(3);
  const nSelectors = br.read(15);
  if (nGroups < 2 || nGroups > 6) throw new Error('bz2: bad group count');
  const selectorMtf = new Uint8Array(nSelectors);
  for (let i = 0; i < nSelectors; i++) {
    let j = 0;
    while (br.read(1) === 1) { j++; if (j >= nGroups) throw new Error('bz2: bad selector'); }
    selectorMtf[i] = j;
  }
  const mtfPos = [];
  for (let i = 0; i < nGroups; i++) mtfPos.push(i);
  const selectors = new Uint8Array(nSelectors);
  for (let i = 0; i < nSelectors; i++) {
    let v = selectorMtf[i];
    const tmp = mtfPos[v];
    while (v > 0) { mtfPos[v] = mtfPos[v - 1]; v--; }
    mtfPos[0] = tmp;
    selectors[i] = tmp;
  }

  // Huffman code lengths per group, delta-encoded.
  const tables = [];
  for (let g = 0; g < nGroups; g++) {
    const lengths = new Int32Array(alphaSize);
    let c = br.read(5);
    for (let s = 0; s < alphaSize; s++) {
      for (;;) {
        if (c < 1 || c > 20) throw new Error('bz2: bad code length');
        if (br.read(1) === 0) break;
        if (br.read(1) === 0) c++; else c--;
      }
      lengths[s] = c;
    }
    tables.push(createDecodeTables(lengths, alphaSize));
  }

  // Main decode: Huffman symbols → MTF/RLE2 → BWT last column.
  const bwt = new Uint8Array(blockSize);
  let bwtLen = 0;
  const yy = seqToUnseq.slice();  // MTF list of actual byte values

  let groupPos = 0, groupNo = -1, table = null;
  const nextSymbol = () => {
    if (groupPos === 0) { groupNo++; table = tables[selectors[groupNo]]; groupPos = 50; }
    groupPos--;
    let zn = table.minLen;
    let zvec = br.read(zn);
    while (zvec > table.limit[zn]) { zn++; zvec = (zvec << 1) | br.read(1); }
    return table.perm[zvec - table.base[zn]];
  };

  let sym = nextSymbol();
  while (sym !== EOB) {
    if (sym === 0 || sym === 1) {
      // RUNA/RUNB: bijective base-2 run length of the MTF-front byte.
      let es = 0, N = 1;
      do {
        es += (sym === 0 ? 1 : 2) * N;
        N *= 2;
        sym = nextSymbol();
      } while (sym === 0 || sym === 1);
      const b = yy[0];
      if (bwtLen + es > blockSize) throw new Error('bz2: block overflow');
      for (let k = 0; k < es; k++) bwt[bwtLen++] = b;
    } else {
      // Real symbol: MTF index = sym - 1; move that byte to front.
      const j = sym - 1;
      const tmp = yy[j];
      for (let k = j; k > 0; k--) yy[k] = yy[k - 1];
      yy[0] = tmp;
      if (bwtLen >= blockSize) throw new Error('bz2: block overflow');
      bwt[bwtLen++] = tmp;
      sym = nextSymbol();
    }
  }

  return { bwt, length: bwtLen };
}

// Final RLE pass (bzip2 RLE1): a run of 4 identical bytes is followed by a
// count byte of additional repeats (0-255). `out` grows into `sink`.
function rle1Decode(data, n, sink) {
  let i = 0;
  while (i < n) {
    const b = data[i];
    let run = 1; i++;
    while (i < n && run < 4 && data[i] === b) { i++; run++; }
    sink.push(b, run);
    if (run === 4) {
      if (i >= n) break;
      const extra = data[i]; i++;
      if (extra > 0) sink.push(b, extra);
    }
  }
}

// Growable byte sink with a hard cap (decompression-bomb defense).
class ByteSink {
  constructor(cap) { this.cap = cap; this.chunks = []; this.len = 0; }
  push(byte, count) {
    if (this.len + count > this.cap) throw new Error('bz2: output exceeds cap');
    const c = new Uint8Array(count);
    c.fill(byte);
    this.chunks.push(c);
    this.len += count;
  }
  toBytes() {
    const out = new Uint8Array(this.len);
    let o = 0;
    for (const c of this.chunks) { out.set(c, o); o += c.length; }
    return out;
  }
}

// Decompress a complete bzip2 stream. Returns Uint8Array.
export function bunzip2(bytes, maxOutputLength = 8 * 1024 * 1024) {
  const br = new BitReader(bytes);
  if (br.read(8) !== 0x42 || br.read(8) !== 0x5a || br.read(8) !== 0x68) {
    throw new Error('bz2: bad stream magic (expected "BZh")');
  }
  const level = br.read(8) - 0x30;
  if (level < 1 || level > 9) throw new Error('bz2: bad block-size level');
  const blockSize = level * 100000;

  const sink = new ByteSink(maxOutputLength);
  for (;;) {
    const [hi, lo] = br.read48();
    if (hi === EOS_MAGIC_HI && lo === EOS_MAGIC_LO) {
      br.read32();  // stream-level combined CRC — not verified
      break;
    }
    if (hi !== BLOCK_MAGIC_HI || lo !== BLOCK_MAGIC_LO) {
      throw new Error('bz2: bad block magic');
    }
    br.read32();                    // block CRC — not verified
    if (br.read(1) !== 0) throw new Error('bz2: randomized blocks unsupported');
    const origPtr = br.read(24);

    const { bwt, length } = decodeBlockSymbols(br, blockSize);
    if (origPtr >= length) throw new Error('bz2: bad origPtr');
    const transformed = inverseBWT(bwt, length, origPtr);
    rle1Decode(transformed, length, sink);
  }
  return sink.toBytes();
}

export default bunzip2;
