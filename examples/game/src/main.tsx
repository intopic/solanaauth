import { Connection, LAMPORTS_PER_SOL, PublicKey } from "@solana/web3.js";
import { FeePayer, SYSTEM_PROGRAM_ID, paymasterFeePayer, solLimit } from "@solanaauth/core";
import { SolanaAuthProvider } from "@solanaauth/react";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";

const env = import.meta.env;
import { GAME } from "./config";
const connection = new Connection(env.VITE_RPC_URL ?? "https://api.devnet.solana.com", "confirmed");

// Sesioni i lojës: 24 orë, vetëm programi i lojës (+ System për `join`), 0.01 SOL në ditë për rent-in.
const policy = {
  expiresIn: 24 * 3600,
  label: "loja",
  allowedPrograms: [GAME, SYSTEM_PROGRAM_ID],
  limits: [solLimit(BigInt(LAMPORTS_PER_SOL / 100), 24 * 3600)],
};

async function fundSessionKey(key: PublicKey, c: Connection) {
  if ((await c.getBalance(key)) >= 0.01 * LAMPORTS_PER_SOL) return;
  await c.confirmTransaction(await c.requestAirdrop(key, 0.05 * LAMPORTS_PER_SOL), "confirmed");
}

async function start() {
  let feePayer: FeePayer | undefined;
  if (env.VITE_USE_PAYMASTER === "true") feePayer = await paymasterFeePayer(env.VITE_PLATFORM_URL, env.VITE_API_KEY);
  const config = {
    connection,
    programId: new PublicKey(env.VITE_PROGRAM_ID),
    proverUrl: `${env.VITE_PLATFORM_URL}/v1/prove`,
    saltUrl: `${env.VITE_PLATFORM_URL}/v1/salt`,
    apiKey: env.VITE_API_KEY,
    feePayer,
  };
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <SolanaAuthProvider config={config} clientIds={{ google: env.VITE_GOOGLE_CLIENT_ID }} redirectUri={window.location.origin} policy={policy} fundSessionKey={fundSessionKey}>
        <App paymaster={!!feePayer} />
      </SolanaAuthProvider>
    </StrictMode>,
  );
}
start();
