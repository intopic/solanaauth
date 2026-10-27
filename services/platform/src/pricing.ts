import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import type { PlanId, UsageEvent } from "./store.js";

export interface Plan {
  name: string;
  monthlyUsd: number | null;
  includedMau: number | null;
  includedPaymasterTx: number | null;
  includedAgents: number | null;
  overageMauUsd: number | null;
  overageAgentUsd: number | null;
  devnetUnlimited?: boolean;
  contract?: boolean;
}

export interface Pricing {
  currency: string;
  plans: Record<PlanId, Plan>;
  paymaster: {
    marginUsd: number;
    maxLamportsPerTx: number;
    maxPriorityMicroLamports: number;
    defaultPerUserDailyTx: number;
    defaultPerUserDailyAccounts: number;
    defaultGlobalDailyTx: number;
    defaultLowBalanceUsd: number;
  };
}

export function loadPricing(path = process.env.PRICING_FILE ?? fileURLToPath(new URL("../../../config/pricing.json", import.meta.url))): Pricing {
  return JSON.parse(readFileSync(path, "utf8"));
}

export const usd = (microUsd: number) => microUsd / 1e6;
export const micro = (usdAmount: number) => Math.round(usdAmount * 1e6);

/** Fillimi dhe fundi i muajit UTC (sekonda). */
export function monthRange(ym: string): [number, number] {
  const [y, m] = ym.split("-").map(Number);
  return [Date.UTC(y, m - 1, 1) / 1000, Date.UTC(y, m, 1) / 1000];
}

export interface UsageSummary {
  mau: number;
  agents: number;
  proofs: number;
  sponsoredTx: number;
}

/** MAU dhe agjentët = subjekte të ndryshëm në muaj, vetëm mainnet (devnet është falas). */
export function summarize(events: UsageEvent[]): UsageSummary {
  const main = events.filter((e) => e.network !== "devnet");
  const distinct = (k: UsageEvent["kind"]) => new Set(main.filter((e) => e.kind === k).map((e) => e.subject)).size;
  return {
    mau: distinct("login"),
    agents: distinct("agent"),
    proofs: main.filter((e) => e.kind === "proof").length,
    sponsoredTx: main.filter((e) => e.kind === "sponsored_tx").length,
  };
}

export interface InvoiceLine {
  description: string;
  quantity: number;
  unitUsd: number;
  amountUsd: number;
}

export interface Invoice {
  month: string;
  plan: PlanId;
  usage: UsageSummary;
  lines: InvoiceLine[];
  totalUsd: number;
  /** Plani Falas s'ka mbi-kuotë: tejkalimi bllokon hyrjet e reja (s'faturohet). */
  overQuota: boolean;
  contract: boolean;
}

const round2 = (x: number) => Math.round(x * 100) / 100;

export function invoice(pricing: Pricing, plan: PlanId, month: string, events: UsageEvent[]): Invoice {
  const p = pricing.plans[plan];
  const u = summarize(events);
  const lines: InvoiceLine[] = [];
  if (p.contract) return { month, plan, usage: u, lines, totalUsd: 0, overQuota: false, contract: true };
  if (p.monthlyUsd) lines.push({ description: `Plani ${p.name}`, quantity: 1, unitUsd: p.monthlyUsd, amountUsd: p.monthlyUsd });
  let overQuota = false;
  const over = (used: number, incl: number | null, price: number | null, what: string) => {
    if (incl === null || used <= incl) return;
    if (price === null) {
      overQuota = true;
      return;
    }
    const q = used - incl;
    lines.push({ description: `${what} mbi kuotë`, quantity: q, unitUsd: price, amountUsd: round2(q * price) });
  };
  over(u.mau, p.includedMau, p.overageMauUsd, "MAU");
  over(u.agents, p.includedAgents, p.overageAgentUsd, "Agjentë aktivë");
  return { month, plan, usage: u, lines, totalUsd: round2(lines.reduce((s, l) => s + l.amountUsd, 0)), overQuota, contract: false };
}
