/**
 * Paymaster-i opsional (OFF si parazgjedhje). Aplikacioni e aktivizon nga dashboard-i dhe e
 * financon me një depozitë paraprake; ne nuk japim kredi.
 *
 * Për çdo transaksion: kontrolle statike (programet, pozicionet e paymaster-it, priority fee),
 * limitet (për përdorues/ditë, globale/ditë), simulim për koston reale (tarifë + rent), dhe vetëm
 * pastaj nënshkrim. Depozita ngarkohet me koston reale + marzhin e konfigurueshëm.
 */
import { ComputeBudgetProgram, Keypair, PublicKey, Transaction } from "@solana/web3.js";
import { Op, SECP256R1_PROGRAM_ID, confirmTransaction, validateComputeBudget } from "@solanaauth/core";

import { Pricing, micro, monthRange } from "./pricing.js";
import { App, Store, Sponsorship, sha256hex, effectivePlan } from "./store.js";

export interface PaymasterChain {
  /** Simulon tx-in e nënshkruar dhe kthen bilancin e paymaster-it para/pas. */
  simulate(tx: Transaction, payer: PublicKey): Promise<{ err: string | null; before: number; after: number; logs: string[] }>;
  send(raw: Uint8Array): Promise<string>;
  /** Confirmed cost from transaction metadata, when the adapter supports it. */
  spent?(signature: string, payer: PublicKey): Promise<number>;
}

export interface PriceSource {
  solUsd(): Promise<number>;
}

export class SponsorError extends Error {
  constructor(public code: string, message: string, public status = 400) {
    super(message);
  }
}

export interface PaymasterOptions {
  store: Store;
  pricing: Pricing;
  chain: PaymasterChain;
  price: PriceSource;
  feePayer: Keypair;
  programId: PublicKey;
  network: "devnet" | "mainnet";
  onLowBalance?: (app: App) => void;
  now?: () => number;
}

const SPONSORED_OPS = new Set<number>([
  Op.CreateWallet, Op.OpenSession, Op.Execute, Op.RevokeSession, Op.CloseSession,
  Op.AddPasskey, Op.RemovePasskey, Op.SetThreshold, Op.BeginRecovery, Op.CancelRecovery, Op.FinishRecovery,
]);
/** Instruksionet ku paymaster-i mund të jetë llogaria 0 (paguesi i rent-it). */
const PAYER_OPS = new Set<number>([Op.CreateWallet, Op.OpenSession]);

/** Programet e brendshme të një `execute` (sipas kodimit te `executeParts`). */
export function executeInnerPrograms(data: Uint8Array, keys: PublicKey[]): PublicKey[] {
  let o = 2;
  if (data[1] & 1) o += 2 + (data[o] | (data[o + 1] << 8));
  const n = data[o++];
  const out: PublicKey[] = [];
  for (let i = 0; i < n; i++) {
    const prog = data[o++];
    const nAcc = data[o++];
    o += 2 * nAcc;
    const len = data[o] | (data[o + 1] << 8);
    o += 2 + len;
    if (keys[prog] === undefined) throw new SponsorError("InvalidTransaction", "indeks programi i pavlefshëm");
    out.push(keys[prog]);
  }
  return out;
}

export class Paymaster {
  constructor(private o: PaymasterOptions) {}

  get feePayer(): PublicKey {
    return this.o.feePayer.publicKey;
  }

  private now() {
    return this.o.now?.() ?? Math.floor(Date.now() / 1000);
  }

  /** Kontrollet statike. Kthen subjektin (portofolin) dhe nëse tx-i krijon llogari me rent nga paymaster-i. */
  inspect(app: App, tx: Transaction): { subject: string; createsAccounts: number } {
    const me = this.feePayer;
    if (!tx.feePayer?.equals(me)) throw new SponsorError("WrongFeePayer", "fee payer-i duhet të jetë paymaster-i");
    let subject: string | null = null;
    let createsAccounts = 0;
    const allowed = new Set(app.paymaster.allowedPrograms);
    try { validateComputeBudget(tx.instructions, BigInt(this.o.pricing.paymaster.maxPriorityMicroLamports), BigInt(this.o.pricing.paymaster.maxLamportsPerTx)); }
    catch (e) { throw new SponsorError("PriorityFeeTooHigh", (e as Error).message); }
    for (const ix of tx.instructions) {
      const p = ix.programId;
      if (p.equals(ComputeBudgetProgram.programId)) {
        // SetComputeUnitPrice (3): priority fee me kufi.
        if (ix.data[0] === 3) {
          const price = Buffer.from(ix.data).readBigUInt64LE(1);
          if (price > BigInt(this.o.pricing.paymaster.maxPriorityMicroLamports)) {
            throw new SponsorError("PriorityFeeTooHigh", "priority fee mbi kufirin");
          }
        }
        continue;
      }
      if (p.equals(SECP256R1_PROGRAM_ID)) continue;
      if (!p.equals(this.o.programId)) throw new SponsorError("ProgramNotSponsored", `programi ${p.toBase58()} nuk sponsorizohet`);
      const op = ix.data[0];
      if (!SPONSORED_OPS.has(op)) throw new SponsorError("ProgramNotSponsored", `instruksioni ${op} nuk sponsorizohet`);
      ix.keys.forEach((k, i) => {
        if (k.pubkey.equals(me) && !(i === 0 && PAYER_OPS.has(op))) {
          throw new SponsorError("PayerMisuse", "paymaster-i s'mund të jetë llogari e instruksionit");
        }
      });
      if (op === Op.Execute) {
        const keys = ix.keys.map((k) => k.pubkey);
        for (const inner of executeInnerPrograms(ix.data, keys)) {
          if (!allowed.has(inner.toBase58())) throw new SponsorError("ProgramNotSponsored", `programi ${inner.toBase58()} s'është në listën e aplikacionit`);
        }
      }
      const walletIndex = PAYER_OPS.has(op) ? 4 : op === Op.CloseSession ? 0
        : op === Op.BeginRecovery || (op === Op.AddPasskey || op === Op.CancelRecovery) && ix.data[1] === 0 ? 3 : 1;
      const wallet = ix.keys[walletIndex]?.pubkey.toBase58();
      if (!wallet) throw new SponsorError("InvalidTransaction", "mungon portofoli");
      if (subject !== null && subject !== wallet) throw new SponsorError("MixedWallets", "një transaksion i sponsorizuar duhet t'i përkasë një portofoli");
      subject = wallet;
      if (PAYER_OPS.has(op) && ix.keys[0].pubkey.equals(me)) createsAccounts++;
    }
    if (subject === null) throw new SponsorError("InvalidTransaction", "asnjë instruksion i solanaauth");
    return { subject, createsAccounts };
  }

  private checkLimits(app: App, subject: string, createsAccounts: number) {
    const t = this.now();
    const all = this.o.store.usage(app.id, t - 86400, t + 1);
    const day = all.filter((u) => u.kind === "sponsored_tx");
    const pending = this.o.store.pending(app.id);
    if (day.length + pending.length >= app.paymaster.globalDailyTx) throw new SponsorError("GlobalLimit", "limiti ditor i aplikacionit u arrit", 429);
    const hash = sha256hex(subject);
    if (day.filter((u) => u.subject === hash).length + pending.filter(s => s.subject === subject).length >= app.paymaster.perUserDailyTx) {
      throw new SponsorError("UserLimit", "limiti ditor për këtë përdorues u arrit", 429);
    }
    // Rent-i i sesioneve kthehet te vault-i i përdoruesit kur mbyllen; pa këtë kufi një përdorues
    // mund ta kthente depozitën e aplikacionit në SOL për vete (D27).
    if (createsAccounts && all.filter((u) => u.kind === "sponsored_account" && u.subject === hash).length + pending.filter(s => s.subject === subject).reduce((n, s) => n + s.accountOperations, 0) + createsAccounts > app.paymaster.perUserDailyAccounts) {
      throw new SponsorError("UserAccountLimit", "limiti ditor i hyrjeve të sponsorizuara për këtë përdorues u arrit", 429);
    }
  }

  /** Kostoja në mikro-USD: kostoja reale + marzhi (pa marzh brenda kuotës së planit; devnet falas). */
  async cost(app: App, lamports: number): Promise<{ microUsd: number; marginMicroUsd: number }> {
    if (this.o.network === "devnet") return { microUsd: 0, marginMicroUsd: 0 };
    const solUsd = await this.o.price.solUsd();
    if (!Number.isFinite(solUsd) || solUsd <= 0) throw new SponsorError("InvalidPrice", "çmim SOL i pavlefshëm", 503);
    const [from, to] = monthRange(new Date(this.now() * 1000).toISOString().slice(0, 7));
    const used = this.o.store.usage(app.id, from, to).filter((u) => u.kind === "sponsored_tx" && u.network !== "devnet").length;
    const included = this.o.pricing.plans[effectivePlan(app, this.now())].includedPaymasterTx ?? Infinity;
    const marginMicroUsd = used < included ? 0 : micro(this.o.pricing.paymaster.marginUsd);
    return { microUsd: micro((lamports / 1e9) * solUsd) + marginMicroUsd, marginMicroUsd };
  }

  /** Nënshkruan dhe dërgon. `raw`: tx i serializuar, i nënshkruar nga të gjithë përveç paymaster-it. */
  async sponsor(apiKey: string, raw: Uint8Array): Promise<{ signature: string; chargedMicroUsd: number; lamports: number }> {
    const app = this.o.store.appByApiKey(apiKey);
    if (!app) throw new SponsorError("Unauthorized", "API key i pavlefshëm", 401);
    return this.o.store.withApp(app.id, () => this.sponsorLocked(apiKey, raw));
  }

  private async sponsorLocked(apiKey: string, raw: Uint8Array): Promise<{ signature: string; chargedMicroUsd: number; lamports: number }> {
    const app = this.o.store.appByApiKey(apiKey);
    if (!app) throw new SponsorError("Unauthorized", "API key i pavlefshëm", 401);
    if (!app.paymaster.enabled) throw new SponsorError("PaymasterDisabled", "paymaster-i s'është aktivizuar për këtë aplikacion", 403);
    let tx: Transaction;
    try {
      tx = Transaction.from(raw);
    } catch {
      throw new SponsorError("InvalidTransaction", "tx i pavlefshëm");
    }
    const { subject, createsAccounts } = this.inspect(app, tx);
    const id = sha256hex(tx.serializeMessage().toString("base64"));
    const receipt = this.o.store.sponsorship(id);
    if (receipt) {
      if (receipt.appId !== app.id) throw new SponsorError("WrongApp", "transaksioni i përket një aplikacioni tjetër", 403);
      if (receipt.status === "confirmed") return { signature: receipt.signature!, chargedMicroUsd: receipt.chargedMicroUsd!, lamports: receipt.lamports };
      if (receipt.status === "failed") throw new SponsorError("TransactionFailed", "transaksioni ka dështuar; ndërto një transaksion të ri", 422);
      return this.submit(app, receipt);
    }
    this.checkLimits(app, subject, createsAccounts);

    tx.partialSign(this.o.feePayer);
    if (!tx.verifySignatures(true)) throw new SponsorError("MissingSignature", "mungojnë nënshkrimet e klientit");
    const sim = await this.o.chain.simulate(tx, this.feePayer);
    if (sim.err) throw new SponsorError("SimulationFailed", `simulimi dështoi: ${sim.err}`, 422);
    const lamports = sim.before - sim.after;
    if (!Number.isSafeInteger(lamports) || lamports < 0 || lamports > this.o.pricing.paymaster.maxLamportsPerTx) {
      throw new SponsorError("CostTooHigh", `kostoja ${lamports} lamports jashtë kufirit`, 422);
    }
    const { microUsd } = await this.cost(app, this.o.pricing.paymaster.maxLamportsPerTx);
    const reserved = this.o.store.pending(app.id).reduce((n, s) => n + s.reservedMicroUsd, 0);
    if (app.balanceMicroUsd - reserved < microUsd || (this.o.network === "mainnet" && app.balanceMicroUsd <= 0)) {
      throw new SponsorError("DepositExhausted", "depozita e paymaster-it mbaroi", 402);
    }
    const reservation: Sponsorship = { id, appId: app.id, subject, accountOperations: createsAccounts, createdAt: this.now(), status: "pending", signedTransaction: tx.serialize().toString("base64"), reservedMicroUsd: microUsd, lamports, network: this.o.network };
    this.o.store.reserve(reservation);
    return this.submit(app, reservation);
  }

  private async submit(app: App, reservation: Sponsorship): Promise<{ signature: string; chargedMicroUsd: number; lamports: number }> {
    let signature: string;
    try { signature = await this.o.chain.send(Buffer.from(reservation.signedTransaction, "base64")); }
    catch (e) {
      if (e instanceof SponsorError && e.code === "TransactionFailed") this.o.store.failSponsorship(reservation);
      // A transport failure may happen AFTER landing. Keep the reservation and signed bytes
      // durably, so retrying the same intent cannot overspend or broadcast a different intent.
      throw e;
    }
    const lamports = this.o.chain.spent ? await this.o.chain.spent(signature, this.feePayer) : reservation.lamports;
    if (!Number.isSafeInteger(lamports) || lamports < 0) throw new SponsorError("InvalidSettlement", "kosto e konfirmuar e pavlefshme", 503);
    const charged = await this.cost(app, lamports);
    // Unexpected cost/price movement is absorbed by the operator, never by an overdraft.
    const microUsd = Math.min(charged.microUsd, reservation.reservedMicroUsd);
    const t = this.now();
    this.o.store.completeSponsorship(reservation, signature, microUsd, lamports, t);
    const low = app.paymaster.lowBalanceMicroUsd;
    if (app.balanceMicroUsd < low && app.balanceMicroUsd + microUsd >= low) this.o.onLowBalance?.(app);
    return { signature, chargedMicroUsd: microUsd, lamports };
  }
}

/** Zbatimi me RPC: simulim me bilancin e paymaster-it pas tx-it. */
export function rpcChain(connection: import("@solana/web3.js").Connection): PaymasterChain {
  return {
    async simulate(tx, payer) {
      const before = await connection.getBalance(payer, "confirmed");
      const r = await connection.simulateTransaction(tx, undefined, [payer]);
      const after = r.value.accounts?.[0]?.lamports ?? before;
      return { err: r.value.err ? JSON.stringify(r.value.err) : null, before, after, logs: r.value.logs ?? [] };
    },
    async send(raw) {
      const sig = await connection.sendRawTransaction(raw);
      const result = await connection.confirmTransaction(sig, "confirmed");
      if (result.value.err) throw new SponsorError("TransactionFailed", JSON.stringify(result.value.err), 422);
      return sig;
    },
    async spent(signature, payer) {
      const tx = await connection.getTransaction(signature, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
      if (!tx?.meta || tx.meta.err) throw new SponsorError("SettlementPending", "mungon rezultati i konfirmuar", 503);
      const index = tx.transaction.message.staticAccountKeys.findIndex(k => k.equals(payer));
      if (index < 0) throw new SponsorError("InvalidSettlement", "mungon paguesi", 503);
      return tx.meta.preBalances[index] - tx.meta.postBalances[index];
    },
  };
}

/** Çmimi SOL/USD nga Pyth Hermes; `SOL_USD` fiks si rezervë. */
export function pythPrice(fallback?: number): PriceSource {
  const id = "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";
  let cache: { v: number; t: number } | null = null;
  return {
    async solUsd() {
      if (cache && Date.now() - cache.t < 30_000) return cache.v;
      try {
        const r = await fetch(`https://hermes.pyth.network/v2/updates/price/latest?ids[]=${id}&parsed=true`);
        const p = (await r.json()).parsed[0].price;
        const v = Number(p.price) * 10 ** Number(p.expo);
        cache = { v, t: Date.now() };
        return v;
      } catch (e) {
        if (fallback) return fallback;
        throw e;
      }
    },
  };
}

