/**
 * Mjedisi:
 * - `NETWORK` (devnet|mainnet), `RPC_URL`, `PROGRAM_ID`, `PORT`, `DATA_FILE`, `CORS_ORIGINS`
 * - `SALT_MASTER_SEED` (hex 32 bytes), `PROVER_URL`
 * - `DASHBOARD_GOOGLE_CLIENT_ID`, `DASHBOARD_SESSION_SECRET` (hex ≥ 32 bytes)
 * - Paymaster (opsional): `PAYMASTER_KEYPAIR` (shteg; vetëm devnet në këtë fazë), `SOL_USD` (rezervë)
 * - Stripe (opsional): `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `DASHBOARD_URL`
 * - Depozita Solana (opsionale): `TREASURY` (adresë publike)
 */
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";

import { OwnerAuth } from "./auth.js";
import { USDC_MINT, rpcDepositChain } from "./billing.js";
import { createHandler } from "./http.js";
import { Paymaster, pythPrice, rpcChain } from "./paymaster.js";
import { Platform } from "./platform.js";
import { loadPricing } from "./pricing.js";
import { FileStore } from "./store.js";

const env = (k: string, d?: string) => {
  const v = process.env[k] ?? d;
  if (v === undefined || v === "") throw new Error(`mungon ${k}`);
  return v;
};
const hex = (k: string, min: number) => {
  const b = Buffer.from(env(k), "hex");
  if (b.length < min) throw new Error(`${k} duhet të ketë ≥ ${min} bytes hex`);
  return b;
};

const network = env("NETWORK", "devnet") as "devnet" | "mainnet";
const connection = new Connection(env("RPC_URL", "https://api.devnet.solana.com"), "confirmed");
const store = new FileStore(env("DATA_FILE", "platform-data.json"));
const pricing = loadPricing();
const price = pythPrice(process.env.SOL_USD ? Number(process.env.SOL_USD) : undefined);
const platform = new Platform({ store, pricing, network, saltMasterSeed: hex("SALT_MASTER_SEED", 32).subarray(0, 32), proverUrl: process.env.PROVER_URL });
const auth = new OwnerAuth({ secret: hex("DASHBOARD_SESSION_SECRET", 32), googleClientId: env("DASHBOARD_GOOGLE_CLIENT_ID") });

let paymaster: Paymaster | undefined;
if (process.env.PAYMASTER_KEYPAIR) {
  const feePayer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(process.env.PAYMASTER_KEYPAIR, "utf8"))));
  paymaster = new Paymaster({
    store, pricing, price, feePayer, network,
    chain: rpcChain(connection),
    programId: new PublicKey(env("PROGRAM_ID")),
    onLowBalance: (a) => console.warn(`[alarm] depozita e ${a.id} (${a.name}) ra nën pragun`),
  });
}
const dashboard = process.env.DASHBOARD_URL ?? "http://localhost:5174";
const stripe = process.env.STRIPE_SECRET_KEY
  ? { secretKey: env("STRIPE_SECRET_KEY"), webhookSecret: env("STRIPE_WEBHOOK_SECRET"), successUrl: `${dashboard}/?paid=1`, cancelUrl: `${dashboard}/` }
  : undefined;
const deposits = process.env.TREASURY
  ? { chain: rpcDepositChain(connection), treasury: new PublicKey(process.env.TREASURY), usdcMint: USDC_MINT[network], price }
  : undefined;

const handler = createHandler({ platform, auth, paymaster, stripe, deposits, corsOrigins: (process.env.CORS_ORIGINS ?? "*").split(",") });
createServer(handler).listen(Number(env("PORT", "8790")), () => console.log(`platform (${network}) në ${env("PORT", "8790")}`));
