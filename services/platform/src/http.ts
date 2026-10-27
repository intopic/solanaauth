/**
 * Rrugët HTTP të platformës.
 *
 * Publike (me `x-api-key`): `GET /v1/paymaster`, `POST /v1/salt`, `POST /v1/prove`,
 * `POST /v1/sponsor`, `GET /v1/templates`.
 * Dashboard (me `authorization: Bearer <token>`): `/auth/google`, `/apps…`.
 * Webhook: `POST /webhooks/stripe`.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { PublicKey } from "@solana/web3.js";

import { OwnerAuth } from "./auth.js";
import {
  BillingError, DepositChain, StripeOptions, creditDeposits, depositRequest, handleStripeEvent, stripeCheckout, verifyStripeSignature,
} from "./billing.js";
import { Paymaster, PriceSource, SponsorError } from "./paymaster.js";
import { Platform, PlatformError } from "./platform.js";
import { invoice, monthRange } from "./pricing.js";
import { App, effectivePlan } from "./store.js";
import { TEMPLATES } from "./templates.js";

export interface HandlerDeps {
  platform: Platform;
  auth: OwnerAuth;
  paymaster?: Paymaster;
  stripe?: StripeOptions;
  deposits?: { chain: DepositChain; treasury: PublicKey; usdcMint: PublicKey; price: PriceSource };
  corsOrigins?: string[];
}

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

const publicApp = (a: App) => ({
  ...a,
  plan: effectivePlan(a),
  apiKeys: a.apiKeys.map(({ hash: _h, ...k }) => k),
});

async function readBody(req: IncomingMessage, max = 64 * 1024): Promise<string> {
  let body = "";
  for await (const c of req) {
    body += c;
    if (body.length > max) throw new HttpError(413, "kërkesë shumë e madhe");
  }
  return body;
}

export function createHandler(d: HandlerDeps) {
  const p = d.platform;
  return async (req: IncomingMessage, res: ServerResponse) => {
    const origin = req.headers.origin ?? "";
    const cors = d.corsOrigins ?? ["*"];
    const allow = cors.includes("*") ? "*" : cors.includes(origin) ? origin : "";
    if (allow) res.setHeader("access-control-allow-origin", allow);
    res.setHeader("access-control-allow-headers", "content-type, authorization, x-api-key, x-solanaauth-client");
    res.setHeader("access-control-allow-methods", "GET, POST, PATCH, DELETE, OPTIONS");
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
    };
    if (req.method === "OPTIONS") return res.writeHead(204).end();
    const url = new URL(req.url ?? "/", "http://x");
    const path = url.pathname;
    const apiKey = req.headers["x-api-key"] as string | undefined;
    try {
      if (req.method === "GET" && path === "/health") return json(200, { ok: true });

      // ---- Webhook i Stripe (trupi i papërpunuar për nënshkrimin)
      if (req.method === "POST" && path === "/webhooks/stripe") {
        if (!d.stripe) throw new HttpError(503, "Stripe s'është konfiguruar");
        const raw = await readBody(req, 512 * 1024);
        if (!verifyStripeSignature(raw, String(req.headers["stripe-signature"] ?? ""), d.stripe.webhookSecret)) throw new HttpError(400, "nënshkrim i pavlefshëm");
        return json(200, { result: handleStripeEvent(p.o.store, JSON.parse(raw)) });
      }

      // ---- API publike
      if (path.startsWith("/v1/")) {
        if (req.method === "GET" && path === "/v1/templates") return json(200, TEMPLATES);
        if (req.method === "GET" && path === "/v1/paymaster") {
          const app = p.appForKey(apiKey);
          return json(200, { enabled: app.paymaster.enabled && !!d.paymaster, feePayer: d.paymaster?.feePayer.toBase58() ?? null });
        }
        const body = JSON.parse((await readBody(req)) || "{}");
        if (req.method === "POST" && path === "/v1/salt") return json(200, await p.salt(apiKey, body.jwt, req.headers["x-solanaauth-client"] as string));
        if (req.method === "POST" && path === "/v1/prove") {
          const r = await p.prove(apiKey, body);
          res.writeHead(r.status, { "content-type": "application/json" });
          return res.end(r.body);
        }
        if (req.method === "POST" && path === "/v1/sponsor") {
          if (!d.paymaster) throw new HttpError(503, "paymaster-i s'është konfiguruar");
          const r = await d.paymaster.sponsor(apiKey ?? "", Buffer.from(String(body.transaction ?? ""), "base64"));
          return json(200, r);
        }
        throw new HttpError(404, "not found");
      }

      // ---- Dashboard
      if (req.method === "POST" && path === "/auth/google") {
        const body = JSON.parse(await readBody(req));
        try {
          return json(200, await d.auth.login(String(body.id_token)));
        } catch (e) {
          throw new HttpError(401, (e as Error).message);
        }
      }
      const owner = d.auth.verify((req.headers.authorization ?? "").replace(/^Bearer /, ""));
      if (!owner) throw new HttpError(401, "hyr në dashboard");
      const parts = path.split("/").filter(Boolean);
      if (parts[0] !== "apps") throw new HttpError(404, "not found");
      if (parts.length === 1) {
        if (req.method === "GET") return json(200, p.o.store.apps(owner).map(publicApp));
        if (req.method === "POST") return json(201, publicApp(p.createApp(owner, JSON.parse(await readBody(req)).name)));
      }
      const app = p.owned(owner, parts[1]);
      const sub = parts.slice(2).join("/");
      const body = req.method === "GET" || req.method === "DELETE" ? {} : JSON.parse((await readBody(req)) || "{}");
      if (sub === "" && req.method === "GET") return json(200, publicApp(app));
      if (sub === "" && req.method === "PATCH") return json(200, publicApp(p.update(app, body)));
      if (sub === "keys" && req.method === "POST") {
        const { key, meta } = p.createApiKey(app);
        const { hash: _h, ...m } = meta;
        return json(201, { key, ...m });
      }
      if (parts[2] === "keys" && parts[3] && req.method === "DELETE") {
        p.revokeApiKey(app, parts[3]);
        return json(200, { ok: true });
      }
      if (sub === "usage" && req.method === "GET") {
        const month = url.searchParams.get("month") ?? new Date().toISOString().slice(0, 7);
        const [from, to] = monthRange(month);
        return json(200, invoice(p.o.pricing, effectivePlan(app), month, p.o.store.usage(app.id, from, to)));
      }
      if (sub === "ledger" && req.method === "GET") return json(200, { balanceMicroUsd: app.balanceMicroUsd, entries: p.o.store.ledger(app.id).slice(-200).reverse() });
      if (sub === "checkout" && req.method === "POST") {
        if (!d.stripe) throw new HttpError(503, "Stripe s'është konfiguruar");
        const k = body.kind === "plan" ? { kind: "plan" as const, plan: body.plan } : { kind: "deposit" as const, amountUsd: Number(body.amountUsd) };
        return json(200, await stripeCheckout(d.stripe, p.o.pricing, app.id, k));
      }
      if (sub === "deposits/solana" && req.method === "POST") {
        if (!d.deposits) throw new HttpError(503, "depozitat në Solana s'janë konfiguruar");
        const r = depositRequest(d.deposits.treasury, body.asset === "SOL" ? null : d.deposits.usdcMint, app.id);
        app.depositRefs = [...(app.depositRefs ?? []).slice(-19), { reference: r.reference, createdAt: Math.floor(Date.now() / 1000) }];
        p.o.store.putApp(app);
        return json(201, r);
      }
      if (sub === "deposits/solana/check" && req.method === "POST") {
        if (!d.deposits) throw new HttpError(503, "depozitat në Solana s'janë konfiguruar");
        let credited = 0;
        for (const r of app.depositRefs ?? []) {
          credited += await creditDeposits(p.o.store, d.deposits.chain, d.deposits.price, {
            appId: app.id, reference: new PublicKey(r.reference), treasury: d.deposits.treasury, usdcMint: d.deposits.usdcMint,
          });
        }
        return json(200, { creditedMicroUsd: credited, balanceMicroUsd: app.balanceMicroUsd });
      }
      throw new HttpError(404, "not found");
    } catch (e) {
      if (e instanceof HttpError || e instanceof PlatformError || e instanceof BillingError) return json(e.status, { error: e.message });
      if (e instanceof SponsorError) return json(e.status, { error: e.message, code: e.code });
      if (e instanceof SyntaxError) return json(400, { error: "JSON i pavlefshëm" });
      console.error(e);
      return json(500, { error: "gabim i brendshëm" });
    }
  };
}
