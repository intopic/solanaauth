/**
 * Një agjent (bot, AI, cron) vepron me një çelës sesioni, jo me çelësin e përdoruesit. Politika
 * on-chain e sesionit është kufiri: programet e lejuara, limitet për periudhë dhe skadimi. Agjenti
 * kontrollon lokalisht para se të dërgojë, por vendimi është gjithmonë i programit.
 *
 * Përdoruesi mund ta revokojë sesionin në çdo kohë nga faqja e portofolit (zk ose passkey).
 */
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction } from "@solana/web3.js";
import {
  Policy,
  SOL_MINT,
  Session,
  SessionAccount,
  SolanaAuth,
  SolanaAuthOptions,
  TOKEN_PROGRAM_ID,
  decodeError,
  deserializeSession,
  fetchSession,
  serializeSession,
  delegationPolicy, policyHash, sessionAddress, vaultAddress,
} from "@solanaauth/core";

export const ATA_PROGRAM_ID = new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

export function associatedTokenAddress(owner: PublicKey, mint: PublicKey, tokenProgram = TOKEN_PROGRAM_ID): PublicKey {
  return PublicKey.findProgramAddressSync([owner.toBuffer(), tokenProgram.toBuffer(), mint.toBuffer()], ATA_PROGRAM_ID)[0];
}

/** SPL `TransferChecked` (12). */
export function transferChecked(
  source: PublicKey, mint: PublicKey, dest: PublicKey, owner: PublicKey, amount: bigint, decimals: number, tokenProgram = TOKEN_PROGRAM_ID,
): TransactionInstruction {
  const data = Buffer.alloc(10);
  data[0] = 12;
  data.writeBigUInt64LE(amount, 1);
  data[9] = decimals;
  return new TransactionInstruction({
    programId: tokenProgram,
    data,
    keys: [
      { pubkey: source, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: dest, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: true, isWritable: false },
    ],
  });
}

export class PolicyError extends Error {
  constructor(public code: string, message: string) {
    super(message);
  }
}

export interface Allowance {
  mint: PublicKey;
  limit: bigint;
  remaining: bigint | null;
  maxPerExecute?: bigint;
  periodSecs: number;
  resetsAt: bigint;
}

export interface AgentStatus {
  wallet: PublicKey;
  vault: PublicKey;
  sessionKey: PublicKey;
  label: string;
  expiresAt: bigint;
  revoked: boolean;
  allowedPrograms: PublicKey[];
  allowances: Allowance[];
  unrestrictedPrograms: boolean;
  unrestrictedAssets: boolean;
  frequency?: SessionAccount["frequency"];
}

export function allowances(s: SessionAccount, now: bigint): Allowance[] {
  return s.limits.map((l) => {
    const expired = now >= l.windowStart + BigInt(l.periodSecs);
    return {
      mint: l.mint,
      limit: l.amount,
      remaining: l.periodicEnabled ? (expired ? l.amount : l.amount - l.spent) : null,
      maxPerExecute: l.maxPerExecute,
      periodSecs: l.periodSecs,
      resetsAt: expired ? now + BigInt(l.periodSecs) : l.windowStart + BigInt(l.periodSecs),
    };
  });
}

export class AgentWallet {
  /** Ora për kontrollin lokal (unix sekonda). */
  clock: () => bigint = () => BigInt(Math.floor(Date.now() / 1000));

  constructor(readonly auth: SolanaAuth, readonly session: Session) {}

  get connection(): Connection {
    return this.auth.connection;
  }
  get vault() {
    return this.session.vault;
  }
  get address() {
    return this.session.vault;
  }

  static load(auth: SolanaAuth, file: string): AgentWallet {
    return new AgentWallet(auth, deserializeSession(readFileSync(file, "utf8")));
  }

  /** Ruhet me leje 0600: çelësi i sesionit është sekret, edhe pse i kufizuar nga politika. */
  save(file: string) {
    writeFileSync(file, serializeSession(this.session), { mode: 0o600 });
    chmodSync(file, 0o600);
  }

  async status(now?: bigint): Promise<AgentStatus> {
    const s = await fetchSession(this.connection, this.session.session);
    if (!s) throw new PolicyError("SessionClosed", "sesioni nuk ekziston më");
    if (s.version !== 2) throw new PolicyError("InvalidDelegation", "legacy session: create a client-approved V2 delegation before using an agent");
    const t = now ?? this.clock();
    return {
      wallet: this.session.wallet,
      vault: this.session.vault,
      sessionKey: s.sessionKey,
      label: s.label,
      expiresAt: s.expiresAt,
      revoked: s.revoked,
      allowedPrograms: s.allowedPrograms,
      allowances: allowances(s, t),
      unrestrictedPrograms: s.unrestrictedPrograms,
      unrestrictedAssets: s.unrestrictedAssets,
      frequency: s.frequency,
    };
  }

  /** Kontroll lokal (pa garanci: programi vendos). */
  async check(programs: PublicKey[], spend: { mint: PublicKey; amount: bigint }[], now?: bigint) {
    const st = await this.status(now);
    const t = now ?? this.clock();
    if (st.revoked) throw new PolicyError("SessionRevoked", "sesioni është revokuar");
    if (t >= st.expiresAt) throw new PolicyError("SessionExpired", "sesioni ka skaduar");
    if (st.frequency && t < st.frequency.windowStart + BigInt(st.frequency.periodSecs) && st.frequency.executions >= st.frequency.maxExecutions) throw new PolicyError("FrequencyExceeded", "limiti i veprimeve u arrit");
    if (st.frequency?.maxExecutions === 0) throw new PolicyError("FrequencyExceeded", "ekzekutimi është ndaluar");
    for (const p of programs) {
      if (!st.unrestrictedPrograms && !st.allowedPrograms.some((a) => a.equals(p))) throw new PolicyError("ProgramNotAllowed", `programi ${p.toBase58()} s'lejohet`);
    }
    for (const s of spend) {
      const a = st.allowances.find((x) => x.mint.equals(s.mint));
      if (!a) { if (st.unrestrictedAssets) continue; throw new PolicyError("AssetNotAllowed", `aseti ${s.mint.toBase58()} s'ka limit`); }
      if (a.maxPerExecute !== undefined && s.amount > a.maxPerExecute) throw new PolicyError("PerExecuteLimitExceeded", "limiti për veprim u tejkalua");
      if (a.remaining !== null && s.amount > a.remaining) throw new PolicyError("SpendLimitExceeded", `mbeten ${a.remaining}, kërkohen ${s.amount}`);
    }
    return st;
  }

  async execute(instructions: TransactionInstruction[]): Promise<string> {
    try {
      await this.status();
      return await this.auth.execute(this.session, instructions);
    } catch (e) {
      const code = decodeError(e);
      if (code) throw new PolicyError(code, `programi refuzoi: ${code}`);
      throw e;
    }
  }

  async transferSol(to: PublicKey, lamports: bigint, opts: { precheck?: boolean } = {}): Promise<string> {
    if (opts.precheck !== false) await this.check([SystemProgram.programId], [{ mint: SOL_MINT, amount: lamports }]);
    return this.execute([SystemProgram.transfer({ fromPubkey: this.vault, toPubkey: to, lamports })]);
  }

  /** `to` është pronari; token account-i i destinacionit (ATA) duhet të ekzistojë. */
  async transferToken(mint: PublicKey, to: PublicKey, amount: bigint, decimals: number, opts: { precheck?: boolean; tokenProgram?: PublicKey } = {}) {
    const tp = opts.tokenProgram ?? TOKEN_PROGRAM_ID;
    if (opts.precheck !== false) await this.check([tp], [{ mint, amount }]);
    return this.execute([
      transferChecked(associatedTokenAddress(this.vault, mint, tp), mint, associatedTokenAddress(to, mint, tp), this.vault, amount, decimals, tp),
    ]);
  }
}

/** Agent side: sends only its public key to the client's trusted wallet approval flow. */
export interface AgentLoginOptions {
  config: SolanaAuthOptions;
  policy: Policy;
  now?: number;
  /** Deprecated OAuth hints. Authentication must run in the client wallet, never the agent. */
  provider?: "google" | "apple";
  clientId?: string;
  authorize?: (request: { sessionKey: PublicKey; policy: Policy }) => Promise<{
    wallet: PublicKey; signature: string; created: boolean; identity?: Uint8Array;
  }>;
}

export async function loginAgent(o: AgentLoginOptions): Promise<{ wallet: AgentWallet; created: boolean; signature: string }> {
  if (!o.authorize) {
    if (o.provider === "apple") throw new Error("Apple requires an HTTPS domain callback in the client wallet; provide authorize");
    throw new Error("Client wallet authorization required: provide authorize; OAuth credentials must not enter the agent");
  }
  const auth = new SolanaAuth({ ...o.config, client: "agent" });
  const sessionKey = Keypair.generate();
  const policy = delegationPolicy(o.policy);
  const expectedHash = policyHash(policy);
  const reply = await o.authorize({ sessionKey: sessionKey.publicKey, policy });
  const address = sessionAddress(auth.programId, reply.wallet, sessionKey.publicKey);
  const info = await auth.connection.getAccountInfo(address);
  if (!info || !info.owner?.equals(auth.programId)) throw new PolicyError("InvalidDelegation", "missing program-owned approval");
  const approved = await fetchSession(auth.connection, address);
  const now = o.now ?? Math.floor(Date.now() / 1000);
  if (!approved || approved.version !== 2 || approved.revoked || approved.expiresAt <= BigInt(now)
      || !approved.wallet.equals(reply.wallet) || !approved.sessionKey.equals(sessionKey.publicKey)
      || !approved.policyHash?.every((b, i) => b === expectedHash[i])) {
    throw new PolicyError("InvalidDelegation", "on-chain approval does not match the requested key and policy");
  }
  const session: Session = {
    wallet: reply.wallet, vault: vaultAddress(auth.programId, reply.wallet), session: address,
    sessionKey, expiresAt: Number(approved.expiresAt), identity: reply.identity ?? new Uint8Array(32),
  };
  return { wallet: new AgentWallet(auth, session), created: reply.created, signature: reply.signature };
}
export * from "./x402.js";
