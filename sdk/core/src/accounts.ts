/** Dekodimi i llogarive të programit (`programs/solanaauth/src/state.rs`). */
import { Connection, PublicKey } from "@solana/web3.js";

import { MAX_LIMITS, MAX_PASSKEYS, MAX_PROGRAMS, MAX_ZK } from "./constants.js";

class R {
  constructor(private d: Uint8Array, public o = 0) {}
  private view = () => new DataView(this.d.buffer, this.d.byteOffset, this.d.byteLength);
  u8() { return this.d[this.o++]; }
  skip(n: number) { this.o += n; return this; }
  bytes(n: number) { const b = this.d.slice(this.o, this.o + n); this.o += n; return b; }
  key() { return new PublicKey(this.bytes(32)); }
  u16() { const v = this.view().getUint16(this.o, true); this.o += 2; return v; }
  u32() { const v = this.view().getUint32(this.o, true); this.o += 4; return v; }
  u64() { const v = this.view().getBigUint64(this.o, true); this.o += 8; return v; }
  i64() { const v = this.view().getBigInt64(this.o, true); this.o += 8; return v; }
}

const isZero = (b: Uint8Array) => b.every((x) => x === 0);

export interface WalletAccount {
  walletId: Uint8Array;
  createdAt: bigint;
  nonce: bigint;
  zkIdentities: { slot: number; identity: Uint8Array; addedAt: bigint }[];
  passkeys: { slot: number; publicKey: Uint8Array; addedAt: bigint }[];
  thresholdLamports: bigint;
  recovery: { kind: "none" | "add_passkey" | "add_zk"; slot: number; eta: bigint; data: Uint8Array };
  sessionsOpened: number;
  thresholdWindowStart: bigint;
  thresholdSpent: bigint;
}

export function decodeWallet(data: Uint8Array): WalletAccount {
  if (data.length !== 416 || data[0] !== 3) throw new Error("s'është llogari Wallet");
  const r = new R(data, 8);
  const walletId = r.bytes(32);
  const createdAt = r.i64();
  const nonce = r.u64();
  const zkIdentities = [];
  for (let i = 0; i < MAX_ZK; i++) {
    const identity = r.bytes(32);
    const addedAt = r.i64();
    if (!isZero(identity)) zkIdentities.push({ slot: i, identity, addedAt });
  }
  const passkeys = [];
  for (let i = 0; i < MAX_PASSKEYS; i++) {
    const publicKey = r.bytes(33);
    r.skip(7);
    const addedAt = r.i64();
    if (!isZero(publicKey)) passkeys.push({ slot: i, publicKey, addedAt });
  }
  const thresholdLamports = r.u64();
  const kind = (["none", "add_passkey", "add_zk"] as const)[r.u8()] ?? "none";
  const slot = r.u8();
  r.skip(6);
  const eta = r.i64();
  const rdata = r.bytes(40);
  const sessionsOpened = r.u32();
  r.skip(4);
  return {
    walletId, createdAt, nonce, zkIdentities, passkeys, thresholdLamports,
    recovery: { kind, slot, eta, data: rdata },
    sessionsOpened, thresholdWindowStart: r.i64(), thresholdSpent: r.u64(),
  };
}

export interface SessionAccount {
  version: 1 | 2;
  revoked: boolean;
  wallet: PublicKey;
  sessionKey: PublicKey;
  createdAt: bigint;
  expiresAt: bigint;
  label: string;
  allowedPrograms: PublicKey[];
  unrestrictedPrograms: boolean;
  unrestrictedAssets: boolean;
  limits: { mint: PublicKey; amount: bigint; periodSecs: number; windowStart: bigint; spent: bigint; periodicEnabled: boolean; maxPerExecute?: bigint }[];
  frequency?: { maxExecutions: number; periodSecs: number; executions: number; windowStart: bigint };
  policyHash?: Uint8Array;
}

export function decodeSession(data: Uint8Array): SessionAccount {
  if (data[0] !== 4 || !((data.length === 640 && data[1] === 1) || (data.length === 728 && data[1] === 2))) throw new Error("s'është llogari Session");
  const version = data[1] as 1 | 2;
  const flags = version === 2 ? data[6] : 0;
  const revoked = data[3] !== 0;
  const nPrograms = data[4];
  const nLimits = data[5];
  if (nPrograms > MAX_PROGRAMS || nLimits > MAX_LIMITS || flags & ~7 || (version === 2 && data[7] !== 0)) throw new Error("invalid session layout");
  const r = new R(data, 8);
  const wallet = r.key();
  const sessionKey = r.key();
  const createdAt = r.i64();
  const expiresAt = r.i64();
  const labelBytes = r.bytes(32);
  const label = new TextDecoder().decode(labelBytes.slice(0, labelBytes.indexOf(0) >= 0 ? labelBytes.indexOf(0) : 32));
  r.skip(8);
  const allowedPrograms: PublicKey[] = [];
  for (let i = 0; i < MAX_PROGRAMS; i++) {
    const k = r.key();
    if (i < nPrograms) allowedPrograms.push(k);
  }
  const limits = [];
  for (let i = 0; i < MAX_LIMITS; i++) {
    const mint = r.key();
    const amount = r.u64();
    const periodSecs = r.u32();
    const limitFlags = r.u8();
    r.skip(3);
    const windowStart = r.i64();
    const spent = r.u64();
    if (i < nLimits) limits.push({ mint, amount, periodSecs, windowStart, spent, periodicEnabled: version === 1 || !!(limitFlags & 1), maxPerExecute: version === 2 && limitFlags & 2 ? new DataView(data.buffer, data.byteOffset, data.byteLength).getBigUint64(640 + 8 * i, true) : undefined });
  }
  let frequency;
  let policyHash;
  if (version === 2) {
    r.skip(32);
    const maxExecutions = r.u32(), periodSecs = r.u32(), executions = r.u32();
    r.skip(4);
    const windowStart = r.i64();
    policyHash = r.bytes(32);
    if (flags & 4) frequency = { maxExecutions, periodSecs, executions, windowStart };
  }
  return { version, revoked, wallet, sessionKey, createdAt, expiresAt, label, allowedPrograms, limits, unrestrictedPrograms: !!(flags & 1), unrestrictedAssets: !!(flags & 2), frequency, policyHash };
}

export async function fetchWallet(c: Connection, wallet: PublicKey): Promise<WalletAccount | null> {
  const acc = await c.getAccountInfo(wallet);
  return acc ? decodeWallet(acc.data) : null;
}

export async function fetchSession(c: Connection, session: PublicKey): Promise<SessionAccount | null> {
  const acc = await c.getAccountInfo(session);
  return acc ? decodeSession(acc.data) : null;
}

/** Portofolet ku `identity` është në një nga dy slot-et zk (offset 56 dhe 96). */
export async function findWalletsByIdentity(c: Connection, programId: PublicKey, identity: Uint8Array): Promise<PublicKey[]> {
  if (typeof (c as Partial<Connection>).getProgramAccounts !== "function") return [];
  const bytes = new PublicKey(identity).toBase58();
  const out: PublicKey[] = [];
  for (const offset of [56, 96]) {
    const accs = await c.getProgramAccounts(programId, { filters: [{ dataSize: 416 }, { memcmp: { offset, bytes } }] });
    for (const a of accs) if (!out.some((x) => x.equals(a.pubkey))) out.push(a.pubkey);
  }
  return out;
}

/** Sesionet e një portofoli (offset 8 = `wallet`). */
export async function fetchSessions(c: Connection, programId: PublicKey, wallet: PublicKey): Promise<{ address: PublicKey; session: SessionAccount }[]> {
  const groups = await Promise.all([640, 728].map(dataSize => c.getProgramAccounts(programId, { filters: [{ dataSize }, { memcmp: { offset: 8, bytes: wallet.toBase58() } }] })));
  const accs = new Map(groups.flat().map(a => [a.pubkey.toBase58(), a]));
  return [...accs.values()].map((a) => ({ address: a.pubkey, session: decodeSession(a.account.data) }));
}

export interface JwkKeyInfo {
  modulusHash: Uint8Array;
  modulusBits: number;
  validFrom: bigint;
  validUntil: bigint;
}

export interface JwkAccount {
  revoked: boolean;
  issHash: Uint8Array;
  kidHash: Uint8Array;
  active: JwkKeyInfo | null;
  pending: (JwkKeyInfo & { eta: bigint }) | null;
}

export function decodeJwk(data: Uint8Array): JwkAccount {
  if (data.length !== 192 || data[0] !== 2) throw new Error("s'është llogari Jwk");
  const hasPending = data[3] === 1;
  const revoked = data[4] === 1;
  const r = new R(data, 8);
  const issHash = r.bytes(32);
  const kidHash = r.bytes(32);
  const key = (): JwkKeyInfo => {
    const modulusHash = r.bytes(32);
    const modulusBits = r.u16();
    r.skip(6);
    return { modulusHash, modulusBits, validFrom: r.i64(), validUntil: r.i64() };
  };
  const active = key();
  const pending = key();
  const eta = r.i64();
  return {
    revoked,
    issHash,
    kidHash,
    active: isZero(active.modulusHash) ? null : active,
    pending: hasPending ? { ...pending, eta } : null,
  };
}

export async function fetchJwk(c: Connection, jwk: PublicKey): Promise<JwkAccount | null> {
  const a = await c.getAccountInfo(jwk);
  return a ? decodeJwk(a.data) : null;
}
