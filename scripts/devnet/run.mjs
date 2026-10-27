// Ekzekuton instruksionet nga target/devnet-ix.json kundër programit në devnet.
// Përdorimi: node run.mjs <program_id> <ix.json> <report.md>
// Çelësi: env DEVNET_DEPLOYER_KEYPAIR (JSON array 64 bytes), vetëm devnet, pa vlerë reale.
import fs from "node:fs";
import {
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

const [programIdArg, ixPath, reportPath] = process.argv.slice(2);
const rpc = process.env.DEVNET_RPC_URL || "https://api.devnet.solana.com";
const connection = new Connection(rpc, "confirmed");
const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(process.env.DEVNET_DEPLOYER_KEYPAIR)));
const programId = new PublicKey(programIdArg);
const items = JSON.parse(fs.readFileSync(ixPath, "utf8"));

const rows = [];
let failures = 0;
for (const { label, data } of items) {
  const tx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
    new TransactionInstruction({ programId, keys: [], data: Buffer.from(data, "base64") }),
  );
  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [payer], { commitment: "confirmed" });
    const info = await connection.getTransaction(sig, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
    const prefix = `Program ${programId.toBase58()} consumed `;
    const line = (info?.meta?.logMessages || []).find((l) => l.startsWith(prefix));
    const cu = line ? Number(line.slice(prefix.length).split(" ")[0]) : info?.meta?.computeUnitsConsumed;
    const bytes = tx.serialize().length;
    rows.push(`| ${label} | ${cu?.toLocaleString("en-US")} | ${bytes} | [${sig.slice(0, 16)}…](https://explorer.solana.com/tx/${sig}?cluster=devnet) |`);
    console.log(`OK   ${label}: ${cu} CU, ${bytes} bytes, ${sig}`);
  } catch (e) {
    failures++;
    rows.push(`| ${label} | — | — | DËSHTOI: ${String(e.message || e).split("\n")[0]} |`);
    console.error(`FAIL ${label}:`, e);
  }
}

const md = [
  "## Devnet",
  "",
  `Programi: [\`${programId.toBase58()}\`](https://explorer.solana.com/address/${programId.toBase58()}?cluster=devnet) · ${new Date().toISOString()} · commit \`${process.env.GITHUB_SHA || "lokal"}\``,
  "",
  "| Instruksioni | CU (programi) | Tx (bytes) | Nënshkrimi |",
  "|---|---:|---:|---|",
  ...rows,
  "",
].join("\n");
fs.writeFileSync(reportPath, md);
console.log(md);
process.exit(failures ? 1 : 0);
