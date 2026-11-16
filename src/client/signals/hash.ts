/**
 * Shared low-level primitives for the client-side signal collectors.
 *
 * - `stableStringify`: deterministic JSON serialization (object keys sorted,
 *   typed arrays inlined, circulars marked) so identical logical payloads
 *   always hash to the same digest.
 * - `stableHash32` / `hashBytes32`: synchronous 128-bit digest rendered as
 *   32 lowercase hex characters (first 128 bits of a pure-JS SHA-256).
 *   Web Crypto (`crypto.subtle.digest`) is intentionally not used because it
 *   is asynchronous; collectors need synchronous hashes. No Node APIs.
 */

/* eslint-disable no-bitwise */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const rotr = (x: number, n: number): number => (x >>> n) | (x << (32 - n));

/** Pure-JS SHA-256 over raw bytes; returns the 32 digest bytes. */
export function sha256Bytes(bytes: Uint8Array): Uint8Array {
  try {
    const bitLen = bytes.length * 8;
    const paddedLen = (bytes.length + 9 + 63) & ~63;
    const buf = new Uint8Array(paddedLen);
    buf.set(bytes);
    buf[bytes.length] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(paddedLen - 8, Math.floor(bitLen / 4294967296) >>> 0, false);
    dv.setUint32(paddedLen - 4, bitLen >>> 0, false);

    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const w = new Uint32Array(64);

    for (let off = 0; off < paddedLen; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const a15 = w[i - 15];
        const a2 = w[i - 2];
        const s0 = rotr(a15, 7) ^ rotr(a15, 18) ^ (a15 >>> 3);
        const s1 = rotr(a2, 17) ^ rotr(a2, 19) ^ (a2 >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const mj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + mj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }

    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    const state = [h0, h1, h2, h3, h4, h5, h6, h7];
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, state[i], false);
    return out;
  } catch {
    // Unreachable in a healthy engine; keeps the helper total.
    return new Uint8Array(32);
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
  return hex;
}

function utf8Bytes(input: string): Uint8Array {
  try {
    const out: number[] = [];
    for (let i = 0; i < input.length; i++) {
      let code = input.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff && i + 1 < input.length) {
        const low = input.charCodeAt(i + 1);
        if (low >= 0xdc00 && low <= 0xdfff) {
          code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
          i++;
        }
      }
      if (code < 0x80) out.push(code);
      else if (code < 0x800) out.push(0xc0 | (code >> 6), 0x80 | (code & 63));
      else if (code < 0x10000) out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
      else out.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 63), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
    }
    return new Uint8Array(out);
  } catch {
    return new Uint8Array(0);
  }
}

/** 32-char lowercase hex digest (128 bits) of the raw bytes. */
export function hashBytes32(bytes: Uint8Array): string {
  try {
    return bytesToHex(sha256Bytes(bytes)).slice(0, 32);
  } catch {
    return '00000000000000000000000000000000';
  }
}

/** 32-char lowercase hex digest (128 bits) of a UTF-8 string. */
export function stableHash32(input: string): string {
  return hashBytes32(utf8Bytes(input));
}

/** Convenience: hash a list of strings (sorted copies recommended by callers). */
export function hashStrings(list: readonly string[]): string {
  return stableHash32(JSON.stringify([...list]));
}

function numberToString(value: number): string {
  return Number.isFinite(value) ? String(value) : 'null';
}

/**
 * Deterministic JSON serialization. Object keys are sorted lexicographically
 * (UTF-16 code units), arrays keep their order, `undefined` object values and
 * functions are dropped, typed/array-like values are inlined as arrays.
 */
export function stableStringify(value: unknown): string {
  const seen = new Set<object>();

  const walk = (v: unknown): string => {
    if (v === null) return 'null';
    if (typeof v === 'string') return JSON.stringify(v);
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (typeof v === 'number') return numberToString(v);
    if (typeof v === 'undefined') return 'null';
    if (typeof v === 'bigint') return `"${v.toString()}n"`;
    if (typeof v === 'function') return '"[Function]"';
    if (typeof v === 'symbol') return '"[Symbol]"';
    if (typeof v !== 'object') return '"[Unknown]"';

    const obj = v as object;
    if (seen.has(obj)) return '"[Circular]"';
    seen.add(obj);
    try {
      if (Array.isArray(v)) {
        return `[${v.map((item) => (item === undefined ? 'null' : walk(item))).join(',')}]`;
      }
      if (v instanceof Date) return JSON.stringify(v.toISOString());
      if (v instanceof RegExp) return JSON.stringify(v.toString());
      if (ArrayBuffer.isView(v)) {
        const view = v as unknown as ArrayLike<number>;
        return `[${Array.from(view, (item) => numberToString(Number(item))).join(',')}]`;
      }
      if (v instanceof Set) {
        return `[${Array.from(v).map((item) => (item === undefined ? 'null' : walk(item))).join(',')}]`;
      }
      if (v instanceof Map) {
        return `[${
          Array.from(v)
            .map(([key, val]) => `[${walk(key)},${val === undefined ? 'null' : walk(val)}]`)
            .join(',')
        }]`;
      }
      const keys = Object.keys(obj).sort();
      const parts: string[] = [];
      for (const key of keys) {
        const val = (obj as Record<string, unknown>)[key];
        if (val === undefined || typeof val === 'function') continue;
        parts.push(`${JSON.stringify(key)}:${walk(val)}`);
      }
      return `{${parts.join(',')}}`;
    } catch {
      return '"[Unserializable]"';
    } finally {
      seen.delete(obj);
    }
  };

  try {
    return walk(value);
  } catch {
    return '"[Unserializable]"';
  }
}

/** Normalize any thrown value into a string for `error` fields. */
export function errorMessage(value: unknown): string {
  if (value instanceof Error) return value.message || value.name || 'Error';
  if (typeof value === 'string' && value.length > 0) return value;
  try {
    return String(value);
  } catch {
    return 'unknown error';
  }
}
