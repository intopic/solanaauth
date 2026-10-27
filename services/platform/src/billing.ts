/**
 * Pagesat: Stripe (kartë) për planin dhe për depozitën e paymaster-it, dhe USDC/SOL në Solana
 * për depozitën. Çelësat e Stripe vijnë vetëm nga mjedisi (`STRIPE_SECRET_KEY`,
 * `STRIPE_WEBHOOK_SECRET`); asnjë çelës në repo.
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";

import { PriceSource } from "./paymaster.js";
import { Pricing, micro } from "./pricing.js";
import { PlanId, Store } from "./store.js";

export const USDC_MINT = {
  mainnet: new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
  devnet: new PublicKey("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"),
};

export class BillingError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

// ---------------------------------------------------------------- Stripe

export interface StripeOptions {
  secretKey: string;
  webhookSecret: string;
  successUrl: string;
  cancelUrl: string;
  fetch?: typeof fetch;
}

export type CheckoutKind = { kind: "deposit"; amountUsd: number } | { kind: "plan"; plan: PlanId };

/** Krijon një Stripe Checkout Session (API REST, pa SDK). */
export async function stripeCheckout(o: StripeOptions, pricing: Pricing, appId: string, k: CheckoutKind): Promise<{ id: string; url: string }> {
  let amountUsd: number;
  let name: string;
  if (k.kind === "deposit") {
    if (!(k.amountUsd >= 5 && k.amountUsd <= 10_000)) throw new BillingError(400, "depozita duhet të jetë 5–10,000 USD");
    amountUsd = k.amountUsd;
    name = "Depozitë paymaster";
  } else {
    const p = pricing.plans[k.plan];
    if (!p || !p.monthlyUsd) throw new BillingError(400, "plan pa çmim mujor");
    amountUsd = p.monthlyUsd;
    name = `Plani ${p.name} (1 muaj)`;
  }
  const form = new URLSearchParams({
    mode: "payment",
    success_url: o.successUrl,
    cancel_url: o.cancelUrl,
    "line_items[0][quantity]": "1",
    "line_items[0][price_data][currency]": pricing.currency,
    "line_items[0][price_data][unit_amount]": String(Math.round(amountUsd * 100)),
    "line_items[0][price_data][product_data][name]": name,
    "metadata[appId]": appId,
    "metadata[kind]": k.kind,
    ...(k.kind === "plan" ? { "metadata[plan]": k.plan } : {}),
  });
  const res = await (o.fetch ?? fetch)("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: { authorization: `Bearer ${o.secretKey}`, "content-type": "application/x-www-form-urlencoded" },
    body: form,
  });
  const body = await res.json();
  if (!res.ok) throw new BillingError(502, `Stripe: ${body.error?.message ?? res.status}`);
  return { id: body.id, url: body.url };
}

/** Verifikimi i `Stripe-Signature` (t=…, v1=HMAC-SHA256(secret, "t.payload")), tolerancë 5 min. */
export function verifyStripeSignature(payload: string, header: string, secret: string, now = Math.floor(Date.now() / 1000)): boolean {
  const parts = Object.fromEntries(header.split(",").map((p) => p.split("=", 2) as [string, string]));
  const t = Number(parts.t);
  if (!t || Math.abs(now - t) > 300) return false;
  const want = createHmac("sha256", secret).update(`${t}.${payload}`).digest();
  return header
    .split(",")
    .filter((p) => p.startsWith("v1="))
    .some((p) => {
      const got = Buffer.from(p.slice(3), "hex");
      return got.length === want.length && timingSafeEqual(got, want);
    });
}

/** Përpunon webhook-un e Stripe. Idempotent sipas ID-së së sesionit. */
export function handleStripeEvent(store: Store, event: any, now = Math.floor(Date.now() / 1000)): string {
  if (event.type !== "checkout.session.completed") return "ignored";
  const s = event.data.object;
  if (s.payment_status !== "paid") return "unpaid";
  const appId = s.metadata?.appId;
  const app = appId && store.app(appId);
  if (!app) return "unknown app";
  const ref = `stripe:${s.id}`;
  if (s.metadata.kind === "deposit") {
    return store.addLedger({ appId, ts: now, kind: "deposit", microUsd: s.amount_total * 10_000, ref, details: { via: "stripe" } }) ? "deposit" : "duplicate";
  }
  if (s.metadata.kind === "plan") {
    if (store.hasRef(ref)) return "duplicate";
    store.addLedger({ appId, ts: now, kind: "deposit", microUsd: 0, ref, details: { via: "stripe", plan: s.metadata.plan, paidUsd: s.amount_total / 100 } });
    app.plan = s.metadata.plan;
    app.paidUntil = Math.max(app.paidUntil, now) + 30 * 86400;
    store.putApp(app);
    return "plan";
  }
  return "ignored";
}

// ---------------------------------------------------------------- Solana (USDC / SOL)

export interface DepositRequest {
  recipient: string;
  reference: string;
  /** URL Solana Pay; `amount` është opsional, depozita llogaritet nga shuma e marrë. */
  url: string;
}

/** Kërkesë depozite në stilin e Solana Pay: një `reference` unik lidh transferin me aplikacionin. */
export function depositRequest(treasury: PublicKey, mint: PublicKey | null, appId: string): DepositRequest {
  const reference = Keypair.generate().publicKey.toBase58();
  const q = new URLSearchParams({ reference, label: "solanaauth", message: `Depozitë paymaster ${appId}` });
  if (mint) q.set("spl-token", mint.toBase58());
  return { recipient: treasury.toBase58(), reference, url: `solana:${treasury.toBase58()}?${q}` };
}

export interface DepositChain {
  signaturesFor(reference: PublicKey): Promise<string[]>;
  /** Ndryshimi i bilancit të thesarit në tx: lamports dhe token-a (sipas mint-it, në njësi bazë). */
  credited(signature: string, treasury: PublicKey): Promise<{ lamports: number; tokens: Record<string, bigint>; ok: boolean } | null>;
}

export function rpcDepositChain(c: Connection): DepositChain {
  return {
    async signaturesFor(reference) {
      return (await c.getSignaturesForAddress(reference, undefined, "finalized")).filter((s) => !s.err).map((s) => s.signature);
    },
    async credited(signature, treasury) {
      const t = await c.getTransaction(signature, { commitment: "finalized", maxSupportedTransactionVersion: 0 });
      if (!t?.meta) return null;
      const keys = t.transaction.message.getAccountKeys({ accountKeysFromLookups: t.meta.loadedAddresses }).staticAccountKeys;
      const i = keys.findIndex((k) => k.equals(treasury));
      const lamports = i >= 0 ? t.meta.postBalances[i] - t.meta.preBalances[i] : 0;
      const tokens: Record<string, bigint> = {};
      const owned = (b: { owner?: string }) => b.owner === treasury.toBase58();
      for (const post of t.meta.postTokenBalances ?? []) {
        if (!owned(post)) continue;
        const pre = t.meta.preTokenBalances?.find((p) => p.accountIndex === post.accountIndex);
        tokens[post.mint] = (tokens[post.mint] ?? 0n) + BigInt(post.uiTokenAmount.amount) - BigInt(pre?.uiTokenAmount.amount ?? "0");
      }
      return { lamports, tokens, ok: t.meta.err === null };
    },
  };
}

/**
 * Kreditimi i depozitave për një `reference`: USDC 1:1 (6 decimale = mikro-USD), SOL me çmimin
 * aktual. Idempotent sipas nënshkrimit.
 */
export async function creditDeposits(
  store: Store, chain: DepositChain, price: PriceSource, o: { appId: string; reference: PublicKey; treasury: PublicKey; usdcMint: PublicKey },
  now = Math.floor(Date.now() / 1000),
): Promise<number> {
  let credited = 0;
  for (const sig of await chain.signaturesFor(o.reference)) {
    const ref = `solana:${sig}`;
    if (store.hasRef(ref)) continue;
    const c = await chain.credited(sig, o.treasury);
    if (!c?.ok) continue;
    const usdc = c.tokens[o.usdcMint.toBase58()] ?? 0n;
    let microUsd = 0;
    if (usdc > 0n) microUsd += Number(usdc);
    if (c.lamports > 0) microUsd += micro((c.lamports / 1e9) * (await price.solUsd()));
    if (microUsd <= 0) continue;
    store.addLedger({ appId: o.appId, ts: now, kind: "deposit", microUsd, ref, details: { via: "solana", usdc: usdc.toString(), lamports: c.lamports } });
    credited += microUsd;
  }
  return credited;
}
