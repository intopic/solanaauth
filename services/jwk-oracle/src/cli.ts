/**
 * `node dist/cli.js [--once]`
 *
 * Mjedisi: `RPC_URL`, `PROGRAM_ID`, `ORACLE_KEYPAIR` (shteg te një keypair JSON; vetëm devnet në këtë
 * fazë), `PROVIDERS` (parazgjedhja `google,apple`), `INTERVAL_SECS` (parazgjedhja 600).
 */
import { readFileSync } from "node:fs";
import { Connection, Keypair, PublicKey, Transaction } from "@solana/web3.js";

import { PROVIDERS, fetchJwks, planSync } from "./index.js";

const env = (k: string, d?: string) => {
  const v = process.env[k] ?? d;
  if (v === undefined) throw new Error(`mungon ${k}`);
  return v;
};

const connection = new Connection(env("RPC_URL", "https://api.devnet.solana.com"), "confirmed");
const programId = new PublicKey(env("PROGRAM_ID"));
const oracle = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(env("ORACLE_KEYPAIR"), "utf8"))));
const providers = env("PROVIDERS", "google,apple").split(",");
const interval = Number(env("INTERVAL_SECS", "600"));

const chain = {
  getAccountData: async (a: PublicKey) => (await connection.getAccountInfo(a))?.data ?? null,
  now: async () => {
    const slot = await connection.getSlot();
    return (await connection.getBlockTime(slot)) ?? Math.floor(Date.now() / 1000);
  },
};

async function tick() {
  for (const p of providers) {
    const { iss, jwksUrl } = PROVIDERS[p] ?? (() => { throw new Error(`ofrues i panjohur ${p}`); })();
    const actions = await planSync(chain, iss, await fetchJwks(jwksUrl), { programId, oracle: oracle.publicKey, payer: oracle.publicKey });
    for (const a of actions) {
      if (a.kind === "propose" || a.kind === "apply") {
        const tx = new Transaction().add(a.instruction);
        tx.feePayer = oracle.publicKey;
        tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
        tx.sign(oracle);
        const sig = await connection.sendRawTransaction(tx.serialize());
        await connection.confirmTransaction(sig, "confirmed");
        console.log(`${a.kind} ${iss} ${a.kid}: ${sig}`);
      } else {
        console.log(`${a.kind} ${iss} ${a.kid}${"eta" in a ? ` eta=${a.eta}` : ""}${"reason" in a ? ` (${a.reason})` : ""}`);
      }
    }
  }
}

do {
  try {
    await tick();
  } catch (e) {
    console.error(e);
    if (process.argv.includes("--once")) process.exit(1);
  }
  if (process.argv.includes("--once")) break;
  await new Promise((r) => setTimeout(r, interval * 1000));
} while (true);
