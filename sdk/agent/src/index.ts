/**
 * Një agjent (bot, AI, cron) vepron me një çelës sesioni, jo me çelësin e përdoruesit. Politika
 * on-chain e sesionit është kufiri: programet e lejuara, limitet për periudhë dhe skadimi. Agjenti
 * kontrollon lokalisht para se të dërgojë, por vendimi është gjithmonë i programit.
 *
 * Përdoruesi mund ta revokojë sesionin në çdo kohë nga faqja e portofolit (zk ose passkey).
 */
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { AddressInfo } from "node:net";
import { Connection, PublicKey, SystemProgram, Transaction, TransactionInstruction } from "@solana/web3.js";
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
  remaining: bigint;
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
}

export function allowances(s: SessionAccount, now: bigint): Allowance[] {
  return s.limits.map((l) => {
    const expired = now >= l.windowStart + BigInt(l.periodSecs);
    return {
      mint: l.mint,
      limit: l.amount,
      remaining: expired ? l.amount : l.amount - l.spent,
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
    };
  }

  /** Kontroll lokal (pa garanci: programi vendos). */
  async check(programs: PublicKey[], spend: { mint: PublicKey; amount: bigint }[], now?: bigint) {
    const st = await this.status(now);
    const t = now ?? this.clock();
    if (st.revoked) throw new PolicyError("SessionRevoked", "sesioni është revokuar");
    if (t >= st.expiresAt) throw new PolicyError("SessionExpired", "sesioni ka skaduar");
    for (const p of programs) {
      if (!st.allowedPrograms.some((a) => a.equals(p))) throw new PolicyError("ProgramNotAllowed", `programi ${p.toBase58()} s'lejohet`);
    }
    for (const s of spend) {
      const a = st.allowances.find((x) => x.mint.equals(s.mint));
      if (!a) throw new PolicyError("AssetNotAllowed", `aseti ${s.mint.toBase58()} s'ka limit`);
      if (s.amount > a.remaining) throw new PolicyError("SpendLimitExceeded", `mbeten ${a.remaining}, kërkohen ${s.amount}`);
    }
    return st;
  }

  async execute(instructions: TransactionInstruction[]): Promise<string> {
    try {
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

const CALLBACK_HTML = `<!doctype html><meta charset="utf-8"><title>solanaauth</title>
<body style="font:16px system-ui;margin:3rem">Po lidh agjentin…<script>
fetch("/token",{method:"POST",body:location.hash.slice(1)}).then(r=>r.text()).then(t=>document.body.textContent=t);
history.replaceState(null,"","/");
</script>`;

export interface AgentLoginOptions {
  config: SolanaAuthOptions;
  provider: "google" | "apple";
  clientId: string;
  policy: Policy;
  /** Porti lokal i loopback-ut; redirect URI `http://127.0.0.1:<port>/callback` duhet regjistruar te OAuth. */
  port?: number;
  /** Hap URL-në (p.sh. `open`); parazgjedhja e printon. */
  open?: (url: string) => void;
  /** Kohëzgjatja e provës (`max_epoch` = tani + kjo). Parazgjedhja: `policy.expiresIn`. */
  sessionSecs?: number;
  /** Ora (unix sekonda); për teste. */
  now?: number;
  /** Paguesi i transaksionit; parazgjedhja: çelësi i sesionit (duhet SOL). */
  submit?: (tx: Transaction) => Promise<string>;
}

/**
 * Hyrja nga terminali: hap OAuth në shfletues, merr `id_token` në një server lokal (127.0.0.1),
 * dhe hap sesionin për çelësin e agjentit. Përdoruesi sheh politikën në ekranin e pëlqimit
 * (faqja e portofolit, M5); këtu ajo printohet para hyrjes.
 */
export async function loginAgent(o: AgentLoginOptions): Promise<{ wallet: AgentWallet; created: boolean; signature: string }> {
  const auth = new SolanaAuth({ client: "agent", ...o.config });
  const pending = auth.beginLogin(o.sessionSecs ?? o.policy.expiresIn, o.now);
  const state = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("hex");
  let resolve!: (jwt: string) => void;
  let reject!: (e: Error) => void;
  const got = new Promise<string>((a, b) => ((resolve = a), (reject = b)));
  const server = createServer(async (req, res) => {
    if (req.method === "GET" && req.url?.startsWith("/callback")) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      return res.end(CALLBACK_HTML);
    }
    if (req.method === "POST" && req.url === "/token") {
      let body = "";
      for await (const c of req) body += c;
      const p = new URLSearchParams(body);
      if (p.get("state") !== state) {
        res.writeHead(400).end("state nuk përputhet");
        return reject(new Error("state nuk përputhet"));
      }
      const jwt = p.get("id_token");
      if (!jwt) {
        res.writeHead(400).end("mungon id_token");
        return reject(new Error(p.get("error") ?? "mungon id_token"));
      }
      res.writeHead(200).end("Agjenti u lidh. Mund ta mbyllësh këtë faqe.");
      return resolve(jwt);
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(o.port ?? 0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  const url = SolanaAuth.oauthUrl({ provider: o.provider, clientId: o.clientId, redirectUri: `http://127.0.0.1:${port}/callback`, nonce: pending.nonce, state });
  (o.open ?? ((u) => console.log(`Hap në shfletues:\n${u}`)))(url);
  try {
    const jwt = await got;
    const { transaction, session, created } = await auth.completeLogin(jwt, pending, o.policy);
    let signature: string;
    if (o.submit) signature = await o.submit(transaction);
    else if (auth.feePayer) signature = await auth.feePayer.submit(transaction);
    else {
      transaction.sign(session.sessionKey);
      signature = await auth.connection.sendRawTransaction(transaction.serialize());
    }
    return { wallet: new AgentWallet(auth, session), created, signature };
  } finally {
    server.close();
  }
}
