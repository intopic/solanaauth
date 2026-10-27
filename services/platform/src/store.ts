/**
 * Gjendja e platformës. `MemoryStore` për teste dhe `FileStore` (JSON, shkrim atomik) për një
 * instancë të vetme. Për prodhim me shumë instanca zëvendësohet me një bazë të dhënash pas të
 * njëjtës ndërfaqe.
 */
import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

export type PlanId = "free" | "starter" | "growth" | "enterprise";

export interface ApiKey {
  id: string;
  /** sha256 e çelësit; çelësi i plotë shfaqet vetëm një herë. */
  hash: string;
  prefix: string;
  createdAt: number;
  revoked: boolean;
}

export interface PaymasterSettings {
  enabled: boolean;
  /** Programet që sesionet mund të thërrasin në `execute` të sponsorizuar. */
  allowedPrograms: string[];
  perUserDailyTx: number;
  /** Hyrje (`create_wallet`/`open_session`) për përdorues/ditë: paymaster-i paguan rent-in. */
  perUserDailyAccounts: number;
  globalDailyTx: number;
  lowBalanceMicroUsd: number;
}

export interface App {
  id: string;
  name: string;
  owner: string;
  plan: PlanId;
  createdAt: number;
  apiKeys: ApiKey[];
  oauth: { google: string[]; apple: string[] };
  /** Shabllon politike (id nga `templates.ts`) ose politikë e personalizuar. */
  policyTemplate: string;
  paymaster: PaymasterSettings;
  /** Depozita e paymaster-it në mikro-USD (1e-6 USD). */
  balanceMicroUsd: number;
  /** Paguar deri (unix sekonda) për planin. */
  paidUntil: number;
  /** Referencat e kërkesave për depozita në Solana (për kontrollin e pagesave). */
  depositRefs?: { reference: string; createdAt: number }[];
}

export interface LedgerEntry {
  id: string;
  appId: string;
  ts: number;
  kind: "deposit" | "charge" | "refund";
  microUsd: number;
  /** Nënshkrimi on-chain, ID e Stripe, etj. Unik për depozitat (idempotencë). */
  ref: string;
  details?: Record<string, unknown>;
}

export type UsageKind = "login" | "agent" | "proof" | "sponsored_tx" | "sponsored_account";

export interface UsageEvent {
  appId: string;
  ts: number;
  kind: UsageKind;
  /** Hash i subjektit (përdoruesi/portofoli), jo identifikues i lexueshëm. */
  subject: string;
  network?: "devnet" | "mainnet";
}

export interface Sponsorship {
  id: string;
  appId: string;
  subject: string;
  accountOperations: number;
  createdAt: number;
  status: "pending" | "confirmed" | "failed";
  signedTransaction: string;
  reservedMicroUsd: number;
  lamports: number;
  signature?: string;
  chargedMicroUsd?: number;
  network: "devnet" | "mainnet";
}

interface Data {
  apps: App[];
  ledger: LedgerEntry[];
  usage: UsageEvent[];
  sponsorships: Sponsorship[];
}

export const newId = (p: string) => `${p}_${randomBytes(9).toString("base64url")}`;
export const sha256hex = (s: string) => createHash("sha256").update(s).digest("hex");
export const effectivePlan = (app: App, now = Math.floor(Date.now() / 1000)): PlanId =>
  (app.plan === "starter" || app.plan === "growth") && app.paidUntil <= now ? "free" : app.plan;

export class MemoryStore {
  protected d: Data = { apps: [], ledger: [], usage: [], sponsorships: [] };
  private queues = new Map<string, Promise<unknown>>();

  /** One shared queue per app, including across Paymaster instances using this store. */
  async withApp<T>(appId: string, fn: () => Promise<T>): Promise<T> {
    const previous = this.queues.get(appId) ?? Promise.resolve();
    const next = previous.catch(() => undefined).then(fn);
    this.queues.set(appId, next);
    try { return await next; }
    finally { if (this.queues.get(appId) === next) this.queues.delete(appId); }
  }

  sponsorship(id: string): Sponsorship | undefined { return this.d.sponsorships.find(s => s.id === id); }
  pending(appId: string): Sponsorship[] { return this.d.sponsorships.filter(s => s.appId === appId && s.status === "pending"); }
  reserve(s: Sponsorship) {
    if (this.sponsorship(s.id)) throw new Error("duplicate sponsorship");
    const app = this.app(s.appId);
    const reserved = this.pending(s.appId).reduce((n, p) => n + p.reservedMicroUsd, 0);
    if (!app || !Number.isSafeInteger(s.reservedMicroUsd) || s.reservedMicroUsd < 0 || app.balanceMicroUsd - reserved < s.reservedMicroUsd) throw new Error("insufficient reservation balance");
    this.d.sponsorships.push(s);
    this.save();
  }

  failSponsorship(s: Sponsorship) { s.status = "failed"; this.save(); }

  /** Persist the debit, usage and receipt in a single snapshot. Retries do not debit again. */
  completeSponsorship(s: Sponsorship, signature: string, microUsd: number, lamports: number, ts: number) {
    if (s.status === "confirmed") return;
    if (s.status !== "pending" || !Number.isSafeInteger(microUsd) || microUsd < 0 || microUsd > s.reservedMicroUsd) throw new Error("invalid settlement");
    const app = this.app(s.appId)!;
    if (app.balanceMicroUsd < microUsd) throw new Error("reservation invariant violated");
    if (this.hasRef(signature)) throw new Error("signature already settled");
    app.balanceMicroUsd -= microUsd;
    this.d.ledger.push({ id: newId("le"), appId: app.id, ts, kind: "charge", microUsd, ref: signature, details: { lamports, subject: s.subject } });
    const event = { appId: app.id, ts, subject: sha256hex(s.subject), network: s.network };
    this.d.usage.push({ ...event, kind: "sponsored_tx" });
    for (let i = 0; i < s.accountOperations; i++) this.d.usage.push({ ...event, kind: "sponsored_account" });
    s.status = "confirmed";
    s.signature = signature;
    s.chargedMicroUsd = microUsd;
    s.lamports = lamports;
    this.save();
  }

  protected save() {}

  apps(owner?: string): App[] {
    return owner ? this.d.apps.filter((a) => a.owner === owner) : this.d.apps;
  }

  app(id: string): App | undefined {
    return this.d.apps.find((a) => a.id === id);
  }

  putApp(a: App) {
    const i = this.d.apps.findIndex((x) => x.id === a.id);
    if (i >= 0) this.d.apps[i] = a;
    else this.d.apps.push(a);
    this.save();
  }

  appByApiKey(key: string): App | undefined {
    const h = sha256hex(key);
    return this.d.apps.find((a) => a.apiKeys.some((k) => !k.revoked && k.hash === h));
  }

  ledger(appId: string): LedgerEntry[] {
    return this.d.ledger.filter((e) => e.appId === appId);
  }

  hasRef(ref: string): boolean {
    return this.d.ledger.some((e) => e.ref === ref);
  }

  /** Shton një hyrje dhe ndryshon bilancin atomikisht. Kthen false nëse `ref` ekziston (depozitë e dyfishtë). */
  addLedger(e: Omit<LedgerEntry, "id">): boolean {
    if (this.hasRef(e.ref)) return false;
    const app = this.app(e.appId);
    if (!app) throw new Error("aplikacion i panjohur");
    if (!Number.isSafeInteger(e.microUsd) || e.microUsd < 0) throw new Error("invalid ledger amount");
    const reserved = this.pending(app.id).reduce((n, s) => n + s.reservedMicroUsd, 0);
    if (e.kind === "charge" && app.balanceMicroUsd - reserved < e.microUsd) throw new Error("insufficient balance");
    app.balanceMicroUsd += e.kind === "charge" ? -e.microUsd : e.microUsd;
    this.d.ledger.push({ id: newId("le"), ...e });
    this.save();
    return true;
  }

  record(e: UsageEvent) {
    this.d.usage.push(e);
    this.save();
  }

  usage(appId: string, from: number, to: number): UsageEvent[] {
    return this.d.usage.filter((u) => u.appId === appId && u.ts >= from && u.ts < to);
  }
}

export class FileStore extends MemoryStore {
  constructor(private path: string) {
    super();
    if (existsSync(path)) this.d = JSON.parse(readFileSync(path, "utf8"));
    this.d.sponsorships ??= [];
  }

  protected override save() {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.d), { mode: 0o600 });
    renameSync(tmp, this.path);
  }
}

export type Store = MemoryStore;
