import { useSolanaAuth } from "@solanaauth/react";
import { useCallback, useEffect, useState } from "react";

import { decodeScore, join, play, playerState } from "./game";
import { GAME } from "./config";

export function App({ paymaster }: { paymaster: boolean }) {
  const { status, session, error, login, logout, execute, auth } = useSolanaAuth();
  const [score, setScore] = useState<bigint | null>(null);
  const [log, setLog] = useState<string[]>([]);
  const refresh = useCallback(async () => {
    if (!session) return;
    const a = await auth.connection.getAccountInfo(playerState(GAME, session.vault));
    setScore(a ? decodeScore(a.data).score : null);
  }, [session, auth]);
  useEffect(() => void refresh(), [refresh]);

  if (status === "proving") return <main><p>Po hyn…</p></main>;
  if (!session) {
    return (
      <main>
        <h1>Loja</h1>
        <p>Hyr me Google dhe luaj pa asnjë konfirmim: sesioni lejon vetëm programin e lojës për 24 orë.</p>
        <p className="muted">Paymaster: {paymaster ? "ON (s'të duhet SOL)" : "OFF"}</p>
        <button onClick={() => login("google")}>Hyr me Google</button>
        {error && <p style={{ color: "crimson" }}>{error.message}</p>}
      </main>
    );
  }
  const act = async (label: string, ixs: Parameters<typeof execute>[0]) => {
    try {
      const sig = await execute(ixs);
      setLog((l) => [`${label}: ${sig.slice(0, 12)}…`, ...l].slice(0, 10));
      await refresh();
    } catch (e) {
      setLog((l) => [`${label}: ${(e as Error).message}`, ...l]);
    }
  };
  return (
    <main>
      <h1>Pikët: {score === null ? "—" : score.toString()}</h1>
      {score === null ? (
        <button onClick={() => act("join", [join(GAME, session.vault)])}>Fillo lojën</button>
      ) : (
        <button style={{ fontSize: 24, padding: "12px 32px" }} onClick={() => act("play", [play(GAME, session.vault)])}>Luaj</button>
      )}
      <ul>{log.map((l, i) => <li key={i}><code>{l}</code></li>)}</ul>
      <button onClick={() => logout(true)}>Dil</button>
    </main>
  );
}
