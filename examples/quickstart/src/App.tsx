import { LAMPORTS_PER_SOL, PublicKey, SystemProgram } from "@solana/web3.js";
import { useSolanaAuth, useVaultBalance } from "@solanaauth/react";
import { useState } from "react";

const sol = (l: bigint | null) => (l === null ? "…" : (Number(l) / LAMPORTS_PER_SOL).toFixed(4));

export function App() {
  const { status, session, created, error, login, logout, execute } = useSolanaAuth();
  const balance = useVaultBalance();
  const [to, setTo] = useState("");
  const [amount, setAmount] = useState("0.01");
  const [result, setResult] = useState("");

  if (status === "proving") return <main><p>Po krijohet prova zkLogin dhe sesioni…</p></main>;
  if (!session) {
    return (
      <main>
        <h1>solanaauth quickstart</h1>
        <p>Hyr me Google. Portofoli është një PDA e programit; ne nuk mbajmë asnjë çelës privat.</p>
        <button onClick={() => login("google")}>Hyr me Google</button>{" "}
        {import.meta.env.VITE_APPLE_CLIENT_ID && <button onClick={() => login("apple")}>Hyr me Apple</button>}
        {error && <p style={{ color: "crimson" }}>{error.message}</p>}
      </main>
    );
  }

  const send = async () => {
    setResult("Po dërgohet…");
    try {
      const sig = await execute([
        SystemProgram.transfer({ fromPubkey: session.vault, toPubkey: new PublicKey(to), lamports: Math.round(Number(amount) * LAMPORTS_PER_SOL) }),
      ]);
      setResult(`https://explorer.solana.com/tx/${sig}?cluster=devnet`);
    } catch (e) {
      setResult((e as Error).message);
    }
  };

  return (
    <main>
      <h1>Portofoli {created && "(i ri)"}</h1>
      <p>Adresa (vault): <code>{session.vault.toBase58()}</code></p>
      <p>Bilanci: {sol(balance)} SOL · sesioni skadon: {new Date(session.expiresAt * 1000).toLocaleString()}</p>
      <p>
        <input placeholder="adresa e marrësit" value={to} onChange={(e) => setTo(e.target.value)} size={46} />{" "}
        <input value={amount} onChange={(e) => setAmount(e.target.value)} size={6} /> SOL{" "}
        <button onClick={send} disabled={!to}>Dërgo</button>
      </p>
      <p>Limiti i sesionit: 0.5 SOL në ditë, vetëm transferta SOL. Mbi limitin programi e refuzon.</p>
      {result && <p><code>{result}</code></p>}
      <button onClick={() => logout(true)}>Dil (revokon sesionin on-chain)</button>
    </main>
  );
}
