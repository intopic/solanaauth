/** Ndihmës për bytes: shkrimi little endian dhe konvertimet. */

export class Writer {
  private parts: Uint8Array[] = [];

  bytes(b: Uint8Array | number[]): this {
    this.parts.push(Uint8Array.from(b));
    return this;
  }

  u8(v: number): this {
    if (!Number.isInteger(v) || v < 0 || v > 0xff) throw new RangeError(`u8: ${v}`);
    return this.bytes([v]);
  }

  u16(v: number): this {
    if (!Number.isInteger(v) || v < 0 || v > 0xffff) throw new RangeError(`u16: ${v}`);
    return this.bytes([v & 0xff, v >> 8]);
  }

  u32(v: number): this {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v, true);
    return this.bytes(b);
  }

  u64(v: bigint | number): this {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(v), true);
    return this.bytes(b);
  }

  i64(v: bigint | number): this {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigInt64(0, BigInt(v), true);
    return this.bytes(b);
  }

  /** Gjatësia (u8 ose u16) dhe pastaj bytes. */
  vec8(b: Uint8Array): this {
    return this.u8(b.length).bytes(b);
  }

  vec16(b: Uint8Array): this {
    return this.u16(b.length).bytes(b);
  }

  finish(): Uint8Array {
    const n = this.parts.reduce((a, p) => a + p.length, 0);
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of this.parts) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  }
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export function concat(...parts: Uint8Array[]): Uint8Array {
  const w = new Writer();
  for (const p of parts) w.bytes(p);
  return w.finish();
}

export function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function fromHex(h: string): Uint8Array {
  if (h.length % 2) throw new Error("hex me gjatësi tek");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Numër (bigint ose decimal) → `len` bytes big endian. */
export function toBigEndian(v: bigint | string, len = 32): Uint8Array {
  let n = BigInt(v);
  if (n < 0n) throw new RangeError("numër negativ");
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new RangeError(`numri s'futet në ${len} bytes`);
  return out;
}

export function fromBigEndian(b: Uint8Array): bigint {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
}

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function base64UrlEncode(b: Uint8Array): string {
  let out = "";
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i] << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    const chars = Math.min(3, b.length - i) + 1;
    for (let k = 0; k < chars; k++) out += B64URL[(n >> (18 - 6 * k)) & 63];
  }
  return out;
}

/** Base64 standard me padding. */
export function base64Encode(b: Uint8Array): string {
  const s = base64UrlEncode(b).replace(/-/g, "+").replace(/_/g, "/");
  return s + "=".repeat((4 - (s.length % 4)) % 4);
}

export function base64UrlDecode(s: string): Uint8Array {
  const clean = s.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const c of clean) {
    const v = B64URL.indexOf(c);
    if (v < 0) throw new Error("base64url i pavlefshëm");
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}
