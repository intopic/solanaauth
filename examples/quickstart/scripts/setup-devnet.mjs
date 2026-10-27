// Përgatit programin solanaauth në devnet për quickstart-in:
//   1. init_config (admin = oracle = deployer-i devnet; timelock i JWK-ve 0 vetëm në devnet),
//   2. propose_jwk + apply_jwk për çelësat aktualë të Google dhe Apple (si oracle-i),
//   3. raport me nënshkrimet dhe CU.
//
//   node scripts/setup-devnet.mjs <PROGRAM_ID> <keypair.json> [raporti.md]
//
// Vetëm çelës devnet pa vlerë reale.
import { readFileSync, writeFileSync } from "node:fs";
import { Connection, Keypair, PublicKey, Transaction } from "@solana/web3.js";
import * as sa from "@solanaauth/core";
import { PROVIDERS, fetchJwks, planSync } from "@solanaauth/jwk-oracle";

const [programArg, keyfile, out = "results/devnet-solanaauth.md"] = process.argv.slice(2);
if (!programArg || !keyfile) {
  console.error("përdorimi: setup-devnet.mjs <PROGRAM_ID> <keypair.json> [raporti.md]");
  process.exit(1);
}
const programId = new PublicKey(programArg);
const deployer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(keyfile, "utf8"))));
const connection = new Connection(process.env.DEVNET_RPC_URL ?? "https://api.devnet.solana.com", "confirmed");
const rows = [];

async function send(label, ixs) {
  const tx = new Transaction().add(...ixs);
  tx.feePayer = deployer.publicKey;
  tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
  tx.sign(deployer);
  const sig = await connection.sendRawTransaction(tx.serialize());
  await connection.confirmTransaction(sig, "confirmed");
  const t = await connection.getTransaction(sig, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
  rows.push({ label, sig, cu: t?.meta?.computeUnitsConsumed ?? null });
  console.log(`${label}: ${sig}`);
}

const cfgAddr = sa.configAddress(programId);
if (!(await connection.getAccountInfo(cfgAddr))) {
  await send("init_config", [
    sa.initConfig(programId, deployer.publicKey, {
      admin: deployer.publicKey,
      oracle: deployer.publicKey,
      jwkTimelockSecs: 0,
      maxSessionSecs: 30 * 86400,
      recoveryDelaySecs: 48 * 3600,
      allowTestVk: true,
    }),
  ]);
} else {
  console.log("config ekziston");
}

const chain = {
  getAccountData: async (a) => (await connection.getAccountInfo(a))?.data ?? null,
  now: async () => (await connection.getBlockTime(await connection.getSlot())) ?? Math.floor(Date.now() / 1000),
};
for (const p of ["google", "apple"]) {
  const { iss, jwksUrl } = PROVIDERS[p];
  const keys = await fetchJwks(jwksUrl);
  // Dy kalime: propose, pastaj apply (timelock 0).
  for (let pass = 0; pass < 2; pass++) {
    const plan = await planSync(chain, iss, keys, { programId, oracle: deployer.publicKey, payer: deployer.publicKey });
    for (const a of plan) {
      if (a.kind === "propose" || a.kind === "apply") await send(`${a.kind}_jwk ${p} ${a.kid.slice(0, 12)}`, [a.instruction]);
      else if (pass === 1) console.log(`${a.kind} ${p} ${a.kid}`);
    }
  }
}

const md = [
  "## solanaauth në devnet",
  "",
  `Program ID: \`${programId.toBase58()}\` · config: \`${cfgAddr.toBase58()}\``,
  "",
  "| Transaksioni | CU | Nënshkrimi |",
  "|---|---:|---|",
  ...rows.map((r) => `| ${r.label} | ${r.cu?.toLocaleString("en-US") ?? "?"} | [${r.sig.slice(0, 16)}…](https://explorer.solana.com/tx/${r.sig}?cluster=devnet) |`),
  "",
].join("\n");
writeFileSync(out, md);
console.log(md);
