/**
 * zkLogin në anën e klientit: nonce-i, address seed, kodimi i provës së prover-it për
 * instruksionet e `solanaauth`.
 *
 * Formati i prover-it (Mysten) është i njëjtë me `ZkLoginInputs` të Sui-t:
 * `{ proofPoints: { a, b, c }, issBase64Details: { value, indexMod4 }, headerBase64, addressSeed }`.
 */
import * as P from "poseidon-lite";

import { Writer, base64UrlDecode, base64UrlEncode, toBigEndian, utf8 } from "./bytes.js";

export const BN254_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export interface ProofPoints {
  a: string[];
  b: string[][];
  c: string[];
}

export interface ZkLoginInputs {
  proofPoints: ProofPoints;
  issBase64Details: { value: string; indexMod4: number };
  headerBase64: string;
  /** Decimal. */
  addressSeed: string;
}

/** Pranon edhe formatin snake_case (`proof_points`, `iss_base64_details`, ...). */
export function normalizeInputs(raw: any): ZkLoginInputs {
  const pp = raw.proofPoints ?? raw.proof_points;
  const iss = raw.issBase64Details ?? raw.iss_base64_details;
  return {
    proofPoints: pp,
    issBase64Details: { value: iss.value, indexMod4: iss.indexMod4 ?? iss.index_mod_4 },
    headerBase64: raw.headerBase64 ?? raw.header_base64,
    addressSeed: String(raw.addressSeed ?? raw.address_seed),
  };
}

/** `A || B || C` (256 bytes) big endian; G2 si `x.c1, x.c0, y.c1, y.c0` (EIP-197). */
export function proofToBytes(p: ProofPoints): Uint8Array {
  if (p.a[2] !== "1" || p.c[2] !== "1" || p.b[2][0] !== "1" || p.b[2][1] !== "0") {
    throw new Error("prova nuk është në koordinata afine (z = 1)");
  }
  return new Writer()
    .bytes(toBigEndian(p.a[0]))
    .bytes(toBigEndian(p.a[1]))
    .bytes(toBigEndian(p.b[0][1]))
    .bytes(toBigEndian(p.b[0][0]))
    .bytes(toBigEndian(p.b[1][1]))
    .bytes(toBigEndian(p.b[1][0]))
    .bytes(toBigEndian(p.c[0]))
    .bytes(toBigEndian(p.c[1]))
    .finish();
}

/**
 * Blloku zk i instruksioneve (`programs/solanaauth/src/zk.rs`).
 * `vkTest`: prova nga prover-i dev i Mysten (verifying key test, vetëm devnet).
 */
export function encodeZkBlock(inputs: ZkLoginInputs, maxEpoch: bigint | number, vkTest = false): Uint8Array {
  return new Writer()
    .u8(vkTest ? 1 : 0)
    .bytes(proofToBytes(inputs.proofPoints))
    .u64(maxEpoch)
    .bytes(toBigEndian(inputs.addressSeed))
    .u8(inputs.issBase64Details.indexMod4)
    .vec8(utf8(inputs.issBase64Details.value))
    .vec16(utf8(inputs.headerBase64))
    .finish();
}

/**
 * Nonce-i i JWT-së, si `generateNonce` i Sui-t: `Poseidon(eph_hi, eph_lo, max_epoch, randomness)`,
 * 20 bytes e fundit në base64url. Çelësi ephemeral është Ed25519 me flag-un 0x00 përpara.
 * Këtu `maxEpoch` është timestamp Unix (D2).
 */
export function generateNonce(ephPublicKey: Uint8Array, maxEpoch: bigint | number, randomness: bigint | string): string {
  if (ephPublicKey.length !== 32) throw new Error("çelësi ephemeral duhet të jetë 32 bytes");
  const withFlag = new Uint8Array(33);
  withFlag.set(ephPublicKey, 1);
  let n = 0n;
  for (const x of withFlag) n = (n << 8n) | BigInt(x);
  const hi = n >> 128n;
  const lo = n & ((1n << 128n) - 1n);
  const h = poseidonHash([hi, lo, BigInt(maxEpoch), BigInt(randomness)]);
  const bytes = toBigEndian(h, 32).slice(12);
  return base64UrlEncode(bytes);
}

/** 16 bytes të rastit si numër (si `generateRandomness` i Sui-t). */
export function generateRandomness(): bigint {
  const b = new Uint8Array(16);
  globalThis.crypto.getRandomValues(b);
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
}

const MAX_KEY_CLAIM_NAME_LENGTH = 32;
const MAX_KEY_CLAIM_VALUE_LENGTH = 115;
const MAX_AUD_VALUE_LENGTH = 145;
const PACK_WIDTH = 248;

function chunkArray<T>(a: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = a.length; i > 0; i -= size) out.unshift(a.slice(Math.max(0, i - size), i));
  return out;
}

const POSEIDON: Record<number, (x: bigint[]) => bigint> = {
  1: P.poseidon1, 2: P.poseidon2, 3: P.poseidon3, 4: P.poseidon4, 5: P.poseidon5, 6: P.poseidon6,
  7: P.poseidon7, 8: P.poseidon8, 9: P.poseidon9, 10: P.poseidon10, 11: P.poseidon11,
  12: P.poseidon12, 13: P.poseidon13, 14: P.poseidon14, 15: P.poseidon15, 16: P.poseidon16,
};

/** Poseidon si `poseidonHash` i Sui-t (17–32 input-e: dy gjysma nga e majta). */
export function poseidonHash(inputs: bigint[]): bigint {
  if (inputs.length >= 1 && inputs.length <= 16) return POSEIDON[inputs.length](inputs);
  if (inputs.length <= 32) {
    return poseidonHash([poseidonHash(inputs.slice(0, 16)), poseidonHash(inputs.slice(16))]);
  }
  throw new Error(`poseidon: ${inputs.length} input-e`);
}

/** `hashASCIIStrToField` i Sui-t: copa 31-byte, Poseidon i tyre. */
export function hashASCIIStrToField(str: string, maxSize: number): bigint {
  if (str.length > maxSize) throw new Error(`vargu më i gjatë se ${maxSize}`);
  const padded = Array.from(str.padEnd(maxSize, "\0"), (c) => c.charCodeAt(0));
  const packed = chunkArray(padded, PACK_WIDTH / 8).map((chunk) => {
    let n = 0n;
    for (const x of chunk) n = (n << 8n) | BigInt(x);
    return n;
  });
  return poseidonHash(packed);
}

/** `genAddressSeed(salt, name, value, aud)` i Sui-t. */
export function genAddressSeed(salt: bigint | string, name: string, value: string, aud: string): bigint {
  return poseidonHash([
    hashASCIIStrToField(name, MAX_KEY_CLAIM_NAME_LENGTH),
    hashASCIIStrToField(value, MAX_KEY_CLAIM_VALUE_LENGTH),
    hashASCIIStrToField(aud, MAX_AUD_VALUE_LENGTH),
    poseidonHash([BigInt(salt)]),
  ]);
}

export interface JwtClaims {
  iss: string;
  aud: string;
  sub: string;
  nonce?: string;
  exp?: number;
  [k: string]: unknown;
}

/** Dekodon payload-in e JWT-së (pa verifikim: verifikimi bëhet nga prova dhe JWK registry). */
export function decodeJwt(jwt: string): JwtClaims {
  const [, payload] = jwt.split(".");
  if (!payload) throw new Error("JWT i pavlefshëm");
  const claims = JSON.parse(new TextDecoder().decode(base64UrlDecode(payload)));
  if (Array.isArray(claims.aud)) claims.aud = claims.aud[0];
  return claims;
}

export function decodeJwtHeader(jwt: string): { kid: string; alg: string } {
  return JSON.parse(new TextDecoder().decode(base64UrlDecode(jwt.split(".")[0])));
}

/** Vlera e `iss` nga copa base64 e prover-it (si programi on-chain). */
export function issFromBase64Details(d: { value: string; indexMod4: number }): string {
  const bits: number[] = [];
  const B = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  for (const c of d.value) {
    const v = B.indexOf(c);
    for (let i = 5; i >= 0; i--) bits.push((v >> i) & 1);
  }
  const front = 2 * d.indexMod4;
  const r = (d.indexMod4 + d.value.length - 1) % 4;
  if (r === 0) throw new Error("copa base64 e iss ka gjatësi të pavlefshme");
  const back = [0, 4, 2, 0][r];
  const used = bits.slice(front, bits.length - back);
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= used.length; i += 8) {
    bytes.push(used.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  }
  const claim = new TextDecoder().decode(Uint8Array.from(bytes));
  const m = /^"iss":"([^"\\]+)"[,}]$/.exec(claim);
  if (!m) throw new Error(`claim iss i pavlefshëm: ${claim}`);
  return m[1];
}

