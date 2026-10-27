// Agjent demo: hyn një herë (loopback Google), ruan sesionin (20 USDC/ditë, vetëm Token Program)
// dhe thërret një API me pagesë x402 derisa limiti e ndalon.
//   RPC_URL, PROGRAM_ID, PLATFORM_URL, API_KEY, GOOGLE_CLIENT_ID, USDC_MINT, API_URL
import { existsSync } from "node:fs";
import { Connection, PublicKey } from "@solana/web3.js";
import { AgentWallet, PolicyError, loginAgent, x402Fetch } from "@solanaauth/agent";
import { SolanaAuth, paymasterFeePayer } from "@solanaauth/core";

const env = process.env;
const FILE = env.SESSION_FILE ?? "agent-session.json";
const connection = new Connection(env.RPC_URL ?? "https://api.devnet.solana.com", "confirmed");
const usdc = new PublicKey(env.USDC_MINT ?? "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");
const config = {
  connection,
  programId: new PublicKey(env.PROGRAM_ID),
  saltUrl: `${env.PLATFORM_URL}/v1/salt`,
  proverUrl: `${env.PLATFORM_URL}/v1/prove`,
  apiKey: env.API_KEY,
  client: "agent",
  feePayer: env.USE_PAYMASTER === "true" ? await paymasterFeePayer(env.PLATFORM_URL, env.API_KEY) : undefined,
};

let wallet;
if (existsSync(FILE)) {
  wallet = AgentWallet.load(new SolanaAuth(config), FILE);
} else {
  const policy = {
    expiresIn: 7 * 86400,
    label: "agjent-x402",
    allowedPrograms: [new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")],
    limits: [{ mint: usdc, amount: 20_000_000n, periodSecs: 86400 }],
  };
  console.log("Politika: vetëm transferta USDC, 20 USDC në ditë, 7 ditë.");
  ({ wallet } = await loginAgent({ config, provider: "google", clientId: env.GOOGLE_CLIENT_ID, policy, port: 8976 }));
  wallet.save(FILE);
  console.log(`Vault-i i agjentit: ${wallet.vault.toBase58()} (dërgo USDC devnet këtu)`);
}

for (let i = 1; ; i++) {
  try {
    const r = await x402Fetch(wallet, env.API_URL ?? "http://localhost:4021/weather", {}, { onPayment: (p) => console.log(`#${i}: paguan ${Number(p.maxAmountRequired) / 1e6} USDC`) });
    console.log(`#${i}: ${r.status}`, await r.json());
  } catch (e) {
    if (e instanceof PolicyError) {
      console.log(`#${i}: u ndal nga politika (${e.code}): ${e.message}`);
      break;
    }
    throw e;
  }
}
