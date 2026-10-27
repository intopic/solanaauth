/**
 * Operacionet e platformës: aplikacionet dhe çelësat, salt-i dhe prova me matje të përdorimit.
 * Lista e `aud` të lejuara për salt/prover vjen nga OAuth client ID-të e aplikacionit në dashboard.
 */
import { randomBytes } from "node:crypto";
import { decodeJwt } from "jose";
import { createSaltService } from "@solanaauth/salt-service";
import type { JWTVerifyGetKey } from "jose";

import { Pricing, micro, monthRange, summarize } from "./pricing.js";
import { App, ApiKey, PlanId, Store, newId, sha256hex } from "./store.js";

export class PlatformError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export interface PlatformOptions {
  store: Store;
  pricing: Pricing;
  saltMasterSeed: Uint8Array;
  network: "devnet" | "mainnet";
  /** URL e prover-it (p.sh. `services/prover`). */
  proverUrl?: string;
  /** Për teste: burimi i çelësave për lëshuesit. */
  keys?: Record<string, JWTVerifyGetKey>;
  fetch?: typeof fetch;
  now?: () => number;
}

export class Platform {
  constructor(readonly o: PlatformOptions) {}

  private now() {
    return this.o.now?.() ?? Math.floor(Date.now() / 1000);
  }

  createApp(owner: string, name: string): App {
    if (!name || name.length > 64) throw new PlatformError(400, "emër i pavlefshëm");
    const pm = this.o.pricing.paymaster;
    const app: App = {
      id: newId("app"),
      name,
      owner,
      plan: "free",
      createdAt: this.now(),
      apiKeys: [],
      oauth: { google: [], apple: [] },
      policyTemplate: "game",
      paymaster: {
        enabled: false,
        allowedPrograms: [],
        perUserDailyTx: pm.defaultPerUserDailyTx,
        perUserDailyAccounts: pm.defaultPerUserDailyAccounts,
        globalDailyTx: pm.defaultGlobalDailyTx,
        lowBalanceMicroUsd: micro(pm.defaultLowBalanceUsd),
      },
      balanceMicroUsd: 0,
      paidUntil: 0,
    };
    this.o.store.putApp(app);
    return app;
  }

  owned(owner: string, appId: string): App {
    const a = this.o.store.app(appId);
    if (!a || a.owner !== owner) throw new PlatformError(404, "aplikacioni nuk u gjet");
    return a;
  }

  /** Kthen çelësin e plotë vetëm këtu; ruhet vetëm hash-i. */
  createApiKey(app: App): { key: string; meta: ApiKey } {
    const key = `sa_${this.o.network === "devnet" ? "test" : "live"}_${randomBytes(24).toString("base64url")}`;
    const meta: ApiKey = { id: newId("key"), hash: sha256hex(key), prefix: key.slice(0, 12), createdAt: this.now(), revoked: false };
    app.apiKeys.push(meta);
    this.o.store.putApp(app);
    return { key, meta };
  }

  revokeApiKey(app: App, keyId: string) {
    const k = app.apiKeys.find((x) => x.id === keyId);
    if (!k) throw new PlatformError(404, "çelësi nuk u gjet");
    k.revoked = true;
    this.o.store.putApp(app);
  }

  update(app: App, patch: Partial<Pick<App, "name" | "oauth" | "policyTemplate">> & { paymaster?: Partial<App["paymaster"]> }) {
    if (patch.name !== undefined) app.name = String(patch.name).slice(0, 64);
    if (patch.oauth) {
      const clean = (xs: unknown) => (Array.isArray(xs) ? xs.map(String).map((s) => s.trim()).filter(Boolean).slice(0, 10) : []);
      app.oauth = { google: clean(patch.oauth.google), apple: clean(patch.oauth.apple) };
    }
    if (patch.policyTemplate !== undefined) app.policyTemplate = String(patch.policyTemplate);
    if (patch.paymaster) {
      const p = patch.paymaster;
      const pos = (x: unknown, d: number) => (Number.isInteger(x) && (x as number) >= 0 ? (x as number) : d);
      app.paymaster = {
        enabled: p.enabled ?? app.paymaster.enabled,
        allowedPrograms: p.allowedPrograms ? p.allowedPrograms.map(String).slice(0, 16) : app.paymaster.allowedPrograms,
        perUserDailyTx: pos(p.perUserDailyTx, app.paymaster.perUserDailyTx),
        perUserDailyAccounts: pos(p.perUserDailyAccounts, app.paymaster.perUserDailyAccounts),
        globalDailyTx: pos(p.globalDailyTx, app.paymaster.globalDailyTx),
        lowBalanceMicroUsd: pos(p.lowBalanceMicroUsd, app.paymaster.lowBalanceMicroUsd),
      };
    }
    this.o.store.putApp(app);
    return app;
  }

  setPlan(app: App, plan: PlanId) {
    app.plan = plan;
    this.o.store.putApp(app);
  }

  appForKey(apiKey: string | undefined): App {
    const app = apiKey ? this.o.store.appByApiKey(apiKey) : undefined;
    if (!app) throw new PlatformError(401, "API key i pavlefshëm");
    return app;
  }

  /** Plani Falas në mainnet: një përdorues i ri përtej kuotës MAU refuzohet (s'ka mbi-kuotë). */
  private enforceQuota(app: App, subject: string) {
    if (this.o.network === "devnet") return;
    const plan = this.o.pricing.plans[app.plan];
    if (plan.overageMauUsd !== null || plan.includedMau === null) return;
    const [from, to] = monthRange(new Date(this.now() * 1000).toISOString().slice(0, 7));
    const ev = this.o.store.usage(app.id, from, to);
    if (ev.some((e) => e.kind === "login" && e.subject === subject)) return;
    if (summarize(ev).mau >= plan.includedMau) throw new PlatformError(402, "kuota MAU e planit Falas u arrit");
  }

  /** `POST /v1/salt`: JWT e verifikuar me `aud` nga dashboard-i; regjistron MAU (ose agjent). */
  async salt(apiKey: string | undefined, jwt: string, client?: string): Promise<{ salt: string }> {
    const app = this.appForKey(apiKey);
    const auds = [...app.oauth.google, ...app.oauth.apple];
    if (auds.length === 0) throw new PlatformError(400, "aplikacioni s'ka OAuth client ID");
    const svc = createSaltService({ masterSeed: this.o.saltMasterSeed, allowedAudiences: auds, keys: this.o.keys });
    let r;
    try {
      r = await svc(jwt);
    } catch (e) {
      throw new PlatformError((e as { status?: number }).status ?? 400, (e as Error).message);
    }
    const subject = sha256hex(`${r.iss}|${r.sub}`);
    this.enforceQuota(app, subject);
    this.o.store.record({ appId: app.id, ts: this.now(), kind: client === "agent" ? "agent" : "login", subject, network: this.o.network });
    if (client === "agent") this.o.store.record({ appId: app.id, ts: this.now(), kind: "login", subject, network: this.o.network });
    return { salt: r.salt };
  }

  /** `POST /v1/prove`: përcjell te prover-i pas kontrollit të `aud`; regjistron provën. */
  async prove(apiKey: string | undefined, body: { jwt?: string }): Promise<{ status: number; body: string }> {
    const app = this.appForKey(apiKey);
    if (!this.o.proverUrl) throw new PlatformError(503, "prover-i s'është konfiguruar");
    let aud: unknown;
    try {
      aud = decodeJwt(String(body.jwt)).aud;
    } catch {
      throw new PlatformError(400, "JWT i pavlefshëm");
    }
    const a = Array.isArray(aud) ? aud[0] : aud;
    if (![...app.oauth.google, ...app.oauth.apple].includes(String(a))) throw new PlatformError(403, "aud i palejuar");
    const t0 = Date.now();
    const res = await (this.o.fetch ?? fetch)(this.o.proverUrl, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const text = await res.text();
    if (res.ok) this.o.store.record({ appId: app.id, ts: this.now(), kind: "proof", subject: `${Date.now() - t0}ms`, network: this.o.network });
    return { status: res.status, body: text };
  }
}
