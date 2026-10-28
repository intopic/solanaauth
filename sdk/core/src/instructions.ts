import { Buffer } from "buffer";
/**
 * Ndërtuesit e instruksioneve të `solanaauth`. Formati është i njëjtë me
 * `programs/solanaauth/src/{processor,execute,authority}.rs`; vektorët e testit
 * (`fixtures/sdk-vectors.json`) dalin nga klienti Rust i testeve.
 */
import { AccountMeta, PublicKey, TransactionInstruction } from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha256";

import { Writer, utf8 } from "./bytes.js";
import {
  INSTRUCTIONS_SYSVAR_ID,
  MAX_LIMITS,
  MAX_PROGRAMS,
  Op,
  SOL_MINT,
  SYSTEM_PROGRAM_ID,
} from "./constants.js";
import {
  configAddress,
  jwkAddress,
  programDataAddress,
  sessionAddress,
  vaultAddress,
} from "./pda.js";

export interface SpendLimit {
  /** `SOL_MINT` për SOL. */
  mint: PublicKey;
  amount?: bigint | number;
  periodSecs?: number;
  /** Optional maximum aggregate net debit in one execute. Zero forbids any debit. */
  maxPerExecute?: bigint | number;
}

export interface Policy {
  /** V1 preserves the original deny-by-default wire format. V2 supports optional rules. */
  version?: 1 | 2;
  /** Sa sekonda jeton sesioni (kufizohet edhe nga `max_epoch` i provës). */
  expiresIn: number;
  /** Deri në 32 bytes UTF-8, p.sh. emri i agjentit. */
  label?: string;
  /** V2: omitted = unrestricted; [] = no programs. */
  allowedPrograms?: PublicKey[];
  /** V2: sparse per-asset constraints; omitted = no asset constraints. */
  limits?: SpendLimit[];
  /** V2: if true, only mints appearing in limits may be debited. Default false. */
  restrictAssets?: boolean;
  /** Optional successful execute count per fixed window. Zero max blocks execution. */
  frequency?: { maxExecutions: number; periodSecs: number };
}

export const isPolicyV2 = (p: Policy): boolean => p.version === 2 || (p.version !== 1 && (
  p.allowedPrograms === undefined || p.limits === undefined || p.restrictAssets !== undefined || p.frequency !== undefined || p.limits.some(l => l.maxPerExecute !== undefined || l.amount === undefined)));

/** Preserve legacy restriction semantics when promoting an existing policy to delegated V2. */
export const delegationPolicy = (p: Policy): Policy => ({ ...p, version: 2, restrictAssets: p.restrictAssets ?? !isPolicyV2(p) });
export const policyHash = (p: Policy): Uint8Array => sha256(encodePolicy(p));

export function encodePolicy(p: Policy): Uint8Array {
  const v2 = isPolicyV2(p);
  const programs = p.allowedPrograms ?? [];
  const limits = p.limits ?? [];
  if (p.version === 1 && (p.allowedPrograms === undefined || p.limits === undefined || p.frequency || p.restrictAssets !== undefined || limits.some(l => l.maxPerExecute !== undefined))) throw new Error("V2 rules cannot be encoded as V1");
  if (!Number.isSafeInteger(p.expiresIn) || p.expiresIn <= 0) throw new RangeError("expiresIn must be positive");
  if (programs.length > MAX_PROGRAMS) throw new Error(`më shumë se ${MAX_PROGRAMS} programe`);
  if (limits.length > MAX_LIMITS) throw new Error(`më shumë se ${MAX_LIMITS} limite`);
  if (new Set(programs.map(k => k.toBase58())).size !== programs.length || new Set(limits.map(l => l.mint.toBase58())).size !== limits.length) throw new Error("duplicate policy entry");
  const label = new Uint8Array(32);
  const l = utf8(p.label ?? "");
  if (l.length > 32) throw new Error("label > 32 bytes");
  label.set(l);
  const flags = (p.allowedPrograms === undefined ? 1 : 0) | (!p.restrictAssets ? 2 : 0) | (p.frequency ? 4 : 0);
  const w = new Writer();
  if (v2) w.u32(0).u8(2).u8(flags).u32(p.expiresIn);
  else w.u32(p.expiresIn).u64(0);
  w.bytes(label).u8(programs.length);
  for (const prog of programs) w.bytes(prog.toBytes());
  w.u8(limits.length);
  for (const lim of limits) {
    const periodic = lim.amount !== undefined;
    if ((periodic && (!Number.isSafeInteger(lim.periodSecs) || lim.periodSecs! <= 0)) || (!periodic && lim.periodSecs !== undefined)) throw new Error("amount and positive periodSecs must be supplied together");
    w.bytes(lim.mint.toBytes());
    if (v2) w.u8((periodic ? 1 : 0) | (lim.maxPerExecute !== undefined ? 2 : 0));
    w.u64(lim.amount ?? 0).u32(lim.periodSecs ?? 0);
    if (v2) w.u64(lim.maxPerExecute ?? 0);
  }
  if (p.frequency) {
    if (!Number.isSafeInteger(p.frequency.periodSecs) || p.frequency.periodSecs <= 0) throw new Error("frequency periodSecs must be positive");
    w.u32(p.frequency.maxExecutions).u32(p.frequency.periodSecs);
  }
  return w.finish();
}

export const solLimit = (lamports: bigint | number, periodSecs: number): SpendLimit => ({
  mint: SOL_MINT,
  amount: lamports,
  periodSecs,
});

const w = (pubkey: PublicKey, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: true });
const r = (pubkey: PublicKey, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: false });

function ix(programId: PublicKey, data: Uint8Array, keys: AccountMeta[]): TransactionInstruction {
  return new TransactionInstruction({ programId, keys, data: Buffer.from(data) });
}

export interface ConfigParams {
  admin: PublicKey;
  oracle: PublicKey;
  jwkTimelockSecs: number;
  maxSessionSecs: number;
  recoveryDelaySecs: number;
  allowTestVk: boolean;
}

function configData(op: number, c: ConfigParams): Uint8Array {
  return new Writer()
    .u8(op)
    .bytes(c.admin.toBytes())
    .bytes(c.oracle.toBytes())
    .i64(c.jwkTimelockSecs)
    .i64(c.maxSessionSecs)
    .i64(c.recoveryDelaySecs)
    .u8(c.allowTestVk ? 1 : 0)
    .finish();
}

export function initConfig(programId: PublicKey, authority: PublicKey, c: ConfigParams) {
  return ix(programId, configData(Op.InitConfig, c), [
    w(authority, true),
    w(configAddress(programId)),
    r(programDataAddress(programId)),
    r(SYSTEM_PROGRAM_ID),
  ]);
}

export function updateConfig(programId: PublicKey, admin: PublicKey, c: ConfigParams) {
  return ix(programId, configData(Op.UpdateConfig, c), [r(admin, true), w(configAddress(programId))]);
}

export interface JwkParams {
  iss: string;
  kid: string;
  /** Modulus-i RSA big endian (fusha `n` e JWKS, e dekoduar). */
  modulus: Uint8Array;
  validFrom: bigint | number;
  validUntil: bigint | number;
}

export function proposeJwk(programId: PublicKey, authority: PublicKey, payer: PublicKey, j: JwkParams) {
  const data = new Writer()
    .u8(Op.ProposeJwk)
    .vec8(utf8(j.iss))
    .vec8(utf8(j.kid))
    .vec16(j.modulus)
    .i64(j.validFrom)
    .i64(j.validUntil)
    .finish();
  return ix(programId, data, [
    r(authority, true),
    w(payer, true),
    r(configAddress(programId)),
    w(jwkAddress(programId, j.iss, j.kid)),
    r(SYSTEM_PROGRAM_ID),
  ]);
}

export function applyJwk(programId: PublicKey, jwk: PublicKey) {
  return ix(programId, Uint8Array.of(Op.ApplyJwk), [w(jwk)]);
}

export function revokeJwk(programId: PublicKey, admin: PublicKey, jwk: PublicKey) {
  return ix(programId, Uint8Array.of(Op.RevokeJwk), [r(admin, true), r(configAddress(programId)), w(jwk)]);
}

export interface ZkAccounts {
  /** Çelësi ephemeral i provës; nënshkruan transaksionin. */
  sessionKey: PublicKey;
  jwk: PublicKey;
  wallet: PublicKey;
  /** V2 execution key, distinct from the OAuth-authorized sessionKey. */
  delegatedKey?: PublicKey;
}

/** `create_wallet`, me sesion kur jepet `policy` (hyrja e parë në një transaksion). */
export function createWallet(
  programId: PublicKey,
  payer: PublicKey,
  a: ZkAccounts,
  zkBlock: Uint8Array,
  policy?: Policy,
) {
  const d = new Writer().u8(Op.CreateWallet).bytes(zkBlock);
  const keys = [
    w(payer, true),
    r(a.sessionKey, true),
    r(configAddress(programId)),
    r(a.jwk),
    w(a.wallet),
    r(SYSTEM_PROGRAM_ID),
  ];
  if (policy) {
    const v2 = isPolicyV2(policy);
    if (v2 && (!a.delegatedKey || a.delegatedKey.equals(a.sessionKey))) throw new Error("V2 requires a distinct delegatedKey");
    d.u8(v2 ? 2 : 1).bytes(encodePolicy(policy));
    keys.push(w(sessionAddress(programId, a.wallet, v2 ? a.delegatedKey! : a.sessionKey)));
    if (v2) keys.push(r(a.delegatedKey!));
  } else {
    d.u8(0);
  }
  return ix(programId, d.finish(), keys);
}

export function openSession(programId: PublicKey, payer: PublicKey, a: ZkAccounts, zkBlock: Uint8Array, policy: Policy) {
  const v2 = isPolicyV2(policy);
  if (v2 && (!a.delegatedKey || a.delegatedKey.equals(a.sessionKey))) throw new Error("V2 requires a distinct delegatedKey");
  const data = new Writer().u8(Op.OpenSession).bytes(zkBlock).bytes(encodePolicy(policy)).finish();
  return ix(programId, data, [
    w(payer, true),
    r(a.sessionKey, true),
    r(configAddress(programId)),
    r(a.jwk),
    w(a.wallet),
    w(sessionAddress(programId, a.wallet, v2 ? a.delegatedKey! : a.sessionKey)),
    r(SYSTEM_PROGRAM_ID),
    ...(v2 ? [r(a.delegatedKey!)] : []),
  ]);
}

/**
 * Llogaritë dhe pjesa e të dhënave të `execute` pas `flags`: instruksionet e brendshme kodohen
 * me indekse mbi listën e llogarive. Vault-i nënshkruan nga programi (PDA).
 */
export function executeParts(
  programId: PublicKey,
  sessionKey: PublicKey,
  wallet: PublicKey,
  inner: TransactionInstruction[],
): { keys: AccountMeta[]; rest: Uint8Array } {
  const keys: AccountMeta[] = [
    r(sessionKey, true),
    w(wallet),
    w(sessionAddress(programId, wallet, sessionKey)),
    w(vaultAddress(programId, wallet)),
  ];
  const indexOf = (k: PublicKey, writable: boolean): number => {
    const i = keys.findIndex((m) => m.pubkey.equals(k));
    if (i >= 0) {
      if (writable) keys[i].isWritable = true;
      return i;
    }
    keys.push(writable ? w(k) : r(k));
    return keys.length - 1;
  };
  const d = new Writer().u8(inner.length);
  for (const x of inner) {
    d.u8(indexOf(x.programId, false)).u8(x.keys.length);
    for (const m of x.keys) {
      d.u8(indexOf(m.pubkey, m.isWritable)).u8((m.isWritable ? 1 : 0) | (m.isSigner ? 2 : 0));
    }
    d.vec16(Uint8Array.from(x.data));
  }
  return { keys, rest: d.finish() };
}

export function execute(programId: PublicKey, sessionKey: PublicKey, wallet: PublicKey, inner: TransactionInstruction[]) {
  const { keys, rest } = executeParts(programId, sessionKey, wallet, inner);
  return ix(programId, new Writer().u8(Op.Execute).u8(0).bytes(rest).finish(), keys);
}

export function revokeSessionSelf(programId: PublicKey, sessionKey: PublicKey, wallet: PublicKey) {
  return ix(programId, Uint8Array.of(Op.RevokeSession, 0), [
    r(sessionKey, true),
    r(wallet),
    w(sessionAddress(programId, wallet, sessionKey)),
  ]);
}

/** Revokon `session` me një provë të re zk (çelësi i ri ephemeral nënshkruan). */
export function revokeSessionZk(programId: PublicKey, a: ZkAccounts, session: PublicKey, zkBlock: Uint8Array) {
  return ix(programId, new Writer().u8(Op.RevokeSession).u8(1).bytes(zkBlock).finish(), [
    r(a.sessionKey, true),
    r(a.wallet),
    w(session),
    r(configAddress(programId)),
    r(a.jwk),
  ]);
}

export function closeSession(programId: PublicKey, wallet: PublicKey, session: PublicKey) {
  return ix(programId, Uint8Array.of(Op.CloseSession), [r(wallet), w(session), w(vaultAddress(programId, wallet))]);
}

export function addPasskeyZk(programId: PublicKey, a: ZkAccounts, zkBlock: Uint8Array, slot: number, pubkey: Uint8Array) {
  const data = new Writer().u8(Op.AddPasskey).u8(0).bytes(zkBlock).u8(slot).bytes(pubkey).finish();
  return ix(programId, data, zkMetas(programId, a));
}

export function zkMetas(programId: PublicKey, a: ZkAccounts): AccountMeta[] {
  return [r(a.sessionKey, true), r(configAddress(programId)), r(a.jwk), w(a.wallet)];
}

export function beginRecoveryAddPasskey(
  programId: PublicKey,
  a: ZkAccounts,
  zkBlock: Uint8Array,
  slot: number,
  pubkey: Uint8Array,
) {
  const data = new Writer().u8(Op.BeginRecovery).u8(1).bytes(zkBlock).u8(slot).bytes(pubkey).finish();
  return ix(programId, data, zkMetas(programId, a));
}

export function cancelRecoveryZk(programId: PublicKey, a: ZkAccounts, zkBlock: Uint8Array) {
  return ix(programId, new Writer().u8(Op.CancelRecovery).u8(0).bytes(zkBlock).finish(), zkMetas(programId, a));
}

export function finishRecovery(programId: PublicKey, wallet: PublicKey) {
  return ix(programId, Uint8Array.of(Op.FinishRecovery), [r(configAddress(programId)), w(wallet)]);
}

export { ix as rawInstruction, r as readonlyMeta, w as writableMeta, INSTRUCTIONS_SYSVAR_ID };
