import { Connection, LAMPORTS_PER_SOL, PublicKey } from "@solana/web3.js";
import { SYSTEM_PROGRAM_ID, solLimit } from "@solanaauth/core";
import { SolanaAuthProvider } from "@solanaauth/react";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";

const env = import.meta.env;
const connection = new Connection(env.VITE_RPC_URL ?? "https://api.devnet.solana.com", "confirmed");
const config = {
  connection,
  programId: new PublicKey(env.VITE_PROGRAM_ID),
  proverUrl: env.VITE_PROVER_URL,
  saltUrl: env.VITE_SALT_URL,
};

// Sesioni: vetëm System Program, 0.5 SOL në ditë, 24 orë.
const policy = {
  expiresIn: 24 * 3600,
  label: "quickstart",
  allowedPrograms: [SYSTEM_PROGRAM_ID],
  limits: [solLimit(BigInt(LAMPORTS_PER_SOL / 2), 24 * 3600)],
};

// Pa paymaster (M5): në devnet çelësi i sesionit merr një airdrop të vogël për rent-in dhe tarifën.
async function fundSessionKey(key: PublicKey, c: Connection) {
  if ((await c.getBalance(key)) >= 0.01 * LAMPORTS_PER_SOL) return;
  const sig = await c.requestAirdrop(key, 0.05 * LAMPORTS_PER_SOL);
  await c.confirmTransaction(sig, "confirmed");
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <SolanaAuthProvider
      config={config}
      clientIds={{ google: env.VITE_GOOGLE_CLIENT_ID, apple: env.VITE_APPLE_CLIENT_ID }}
      redirectUri={window.location.origin}
      policy={policy}
      fundSessionKey={fundSessionKey}
    >
      <App />
    </SolanaAuthProvider>
  </StrictMode>,
);
