/**
 * x402 (HTTP 402 Payment Required), skema "exact" në Solana: serveri kthen kërkesat e pagesës;
 * agjenti ndërton një tx `execute` me një `TransferChecked` nga vault-i, me fee payer-in e
 * facilitator-it (`extra.feePayer`), e nënshkruan me çelësin e sesionit dhe e dërgon në `X-PAYMENT`.
 * Facilitator-i e verifikon, e nënshkruan si fee payer dhe e dërgon.
 *
 * Limitet janë ato të sesionit on-chain: një agjent me 20 USDC/ditë s'mund të paguajë më shumë,
 * edhe nëse një prompt e bind ta provojë. D25 garanton që facilitator-i s'rrezikon asgjë si fee payer.
 */
import { PublicKey, Transaction } from "@solana/web3.js";
import { execute } from "@solanaauth/core";

import { AgentWallet, PolicyError, associatedTokenAddress, transferChecked } from "./index.js";

export interface PaymentRequirements {
  scheme: "exact";
  network: string;
  maxAmountRequired: string;
  asset: string;
  payTo: string;
  resource: string;
  description?: string;
  extra?: { feePayer?: string; decimals?: number };
}

export interface X402Options {
  /** Shuma maksimale për një kërkesë (njësi bazë), kontroll shtesë mbi limitet e sesionit. */
  maxPerRequest?: bigint;
  /** Para pagesës: p.sh. log ose konfirmim nga njeriu për shuma të mëdha. */
  onPayment?: (r: PaymentRequirements) => void | Promise<void>;
  fetch?: typeof fetch;
}

const toB64 = (b: Uint8Array) => Buffer.from(b).toString("base64");

export async function buildX402Payment(w: AgentWallet, r: PaymentRequirements): Promise<string> {
  if (r.scheme !== "exact") throw new PolicyError("UnsupportedScheme", `skema ${r.scheme} s'mbështetet`);
  if (!r.extra?.feePayer) throw new PolicyError("UnsupportedScheme", "mungon extra.feePayer");
  const mint = new PublicKey(r.asset);
  const amount = BigInt(r.maxAmountRequired);
  const decimals = r.extra.decimals ?? 6;
  const ix = transferChecked(associatedTokenAddress(w.vault, mint), mint, associatedTokenAddress(new PublicKey(r.payTo), mint), w.vault, amount, decimals);
  const feePayer = new PublicKey(r.extra.feePayer);
  const tx = await w.auth.transaction([execute(w.auth.programId, w.session.sessionKey.publicKey, w.session.wallet, [ix])], feePayer);
  tx.partialSign(w.session.sessionKey);
  const transaction = toB64(tx.serialize({ requireAllSignatures: false, verifySignatures: false }));
  return toB64(new TextEncoder().encode(JSON.stringify({ x402Version: 1, scheme: "exact", network: r.network, payload: { transaction } })));
}

/** `fetch` që paguan automatikisht kur serveri kthen 402, brenda politikës së sesionit. */
export async function x402Fetch(w: AgentWallet, input: string | URL, init: RequestInit = {}, o: X402Options = {}): Promise<Response> {
  const f = o.fetch ?? fetch;
  const first = await f(input, init);
  if (first.status !== 402) return first;
  const body = await first.json();
  const reqs: PaymentRequirements[] = body.accepts ?? [];
  const st = await w.status();
  const r = reqs.find((x) => x.scheme === "exact" && st.allowances.some((a) => a.mint.toBase58() === x.asset));
  if (!r) throw new PolicyError("AssetNotAllowed", "asnjë mënyrë pagese brenda politikës së sesionit");
  const amount = BigInt(r.maxAmountRequired);
  if (o.maxPerRequest !== undefined && amount > o.maxPerRequest) throw new PolicyError("SpendLimitExceeded", `kërkesa kërkon ${amount}, kufiri për kërkesë ${o.maxPerRequest}`);
  await w.check([new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")], [{ mint: new PublicKey(r.asset), amount }]);
  await o.onPayment?.(r);
  const headers = new Headers(init.headers);
  headers.set("X-PAYMENT", await buildX402Payment(w, r));
  return f(input, { ...init, headers });
}

/** Dekodimi i `X-PAYMENT` (për facilitator-in). */
export function decodeX402Payment(header: string): { network: string; transaction: Transaction } {
  const p = JSON.parse(Buffer.from(header, "base64").toString());
  if (p.x402Version !== 1 || p.scheme !== "exact") throw new Error("pagesë x402 e pavlefshme");
  return { network: p.network, transaction: Transaction.from(Buffer.from(p.payload.transaction, "base64")) };
}
