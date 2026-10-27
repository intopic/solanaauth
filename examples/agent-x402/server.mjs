// Server demo x402 në devnet: `/weather` kushton 5 USDC (devnet).
//   RPC_URL, PROGRAM_ID, USDC_MINT (parazgjedhja: USDC i Circle në devnet), PAY_TO, FACILITATOR_KEYPAIR, PORT
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";

import { x402Handler } from "./facilitator.mjs";

const connection = new Connection(process.env.RPC_URL ?? "https://api.devnet.solana.com", "confirmed");
const feePayer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(process.env.FACILITATOR_KEYPAIR, "utf8"))));
const handler = x402Handler({
  network: "solana-devnet",
  programId: new PublicKey(process.env.PROGRAM_ID),
  mint: new PublicKey(process.env.USDC_MINT ?? "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"),
  decimals: 6,
  payTo: new PublicKey(process.env.PAY_TO),
  price: 5_000_000n,
  feePayer,
  description: "parashikimi i motit",
  chain: {
    async send(raw) {
      const sig = await connection.sendRawTransaction(raw);
      await connection.confirmTransaction(sig, "confirmed");
      return sig;
    },
  },
  serve: async () => ({ forecast: "diell", at: new Date().toISOString() }),
});
createServer(handler).listen(Number(process.env.PORT ?? 4021), () => console.log(`x402 në ${process.env.PORT ?? 4021}/weather`));
