import { LAMPORTS_PER_SOL, PublicKey } from "@solana/web3.js";
import { SessionAccount } from "@solanaauth/core";
import { useCallback, useEffect, useState } from "react";

import * as w from "./wallet";

export function WalletPage() {
  const [s, setS] = useState<w.State | null>(null);
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  useEffect(() => {
    if (!window.location.hash.includes("id_token")) return;
    setBusy("Po krijohet prova zkLogin…");
    w.finishLogin().then((r) => r && setS(r)).catch((e) => setErr(e.message)).finally(() => setBusy(""));
  }, []);
  const run = async (label: string, f: () => Promise<unknown>) => {
    setBusy(label);
    setErr("");
    try {
      await f();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy("");
    }
  };

  if (!s) {
    return (
      <main>
        <h1>Portofoli im</h1>
        <p className="muted">Shiko asetet, tërhiq, anulo sesionet dhe menaxho passkey-t. Funksionon pa aplikacionin që e krijoi portofolin.</p>
        <div className="row">
          <button className="primary" onClick={() => w.startLogin("google")}>Hyr me Google</button>
          {import.meta.env.VITE_APPLE_CLIENT_ID && <button onClick={() => w.startLogin("apple")}>Hyr me Apple</button>}
          <button onClick={() => run("Po pritet passkey-i…", async () => setS(await w.passkeyLogin()))}>Hyr me passkey</button>
        </div>
        {busy && <p>{busy}</p>}
        {err && <p className="bad">{err}</p>}
      </main>
    );
  }
  return <Dashboard s={s} setS={setS} run={run} busy={busy} err={err} />;
}

function Dashboard({ s, setS, run, busy, err }: { s: w.State; setS: (s: w.State | null) => void; run: (l: string, f: () => Promise<unknown>) => Promise<void>; busy: string; err: string }) {
  const [assets, setAssets] = useState<w.Asset[]>([]);
  const [sessions, setSessions] = useState<{ address: PublicKey; session: SessionAccount }[]>([]);
  const [acc, setAcc] = useState(s.account);
  const refresh = useCallback(async () => {
    setAssets(await w.assets(s.vault));
    setSessions(await w.sessions(s.wallet).catch(() => []));
    setAcc(await w.loadWallet(s.wallet));
  }, [s]);
  useEffect(() => void refresh(), [refresh]);
  const now = Math.floor(Date.now() / 1000);
  const mode = s.session ? "Google/Apple" : s.zk?.foreign ? "llogari e re Google/Apple (rikuperim)" : "passkey";

  return (
    <main>
      <header>
        <h1>Portofoli im</h1>
        <div className="row"><span className="muted">hyrë me {mode}</span><button onClick={() => setS(null)}>Dil</button></div>
      </header>
      <p>Adresa për depozita: <code>{s.vault.toBase58()}</code></p>
      {!s.passkey && !!acc?.passkeys.length && <button onClick={() => run("Po lidhet passkey-i…", async () => setS(await w.attachPasskey(s)))}>Lidh passkey ekzistues</button>}
      {s.passkey && !s.zk && <div className="row">
        <button onClick={() => w.startLogin("google", s.wallet)}>Lidh Google për tërheqje ose rikuperim</button>
        {import.meta.env.VITE_APPLE_CLIENT_ID && <button onClick={() => w.startLogin("apple", s.wallet)}>Lidh Apple për tërheqje ose rikuperim</button>}
      </div>}
      {busy && <p>{busy}</p>}
      {err && <p className="bad">{err}</p>}
      {!acc && <p className="muted">Portofoli s'është krijuar ende.</p>}

      {acc && acc.recovery.kind !== "none" && (
        <div className="tile">
          <b className="bad" style={{ fontSize: 16 }}>Rikuperim në pritje</b>
          {acc.recovery.kind === "add_passkey" ? "Shtohet një passkey i ri" : "Shtohet një identitet i ri Google/Apple"} pas{" "}
          {new Date(Number(acc.recovery.eta) * 1000).toLocaleString()}.
          <div className="row">
            {(s.passkey || (s.zk && !s.zk.foreign)) && <button onClick={() => run("Po anulohet…", () => w.cancelRecovery(s).then(refresh))}>Nuk e kam nisur unë: anulo</button>}
            {Number(acc.recovery.eta) <= now && <button className="primary" onClick={() => run("Po përfundohet…", () => w.completeRecovery(s.wallet).then(refresh))}>Përfundo rikuperimin</button>}
          </div>
        </div>
      )}

      {s.zk?.foreign && acc && acc.recovery.kind === "none" && (
        <div className="tile">
          Kjo llogari Google/Apple nuk është ende autoritet i portofolit.{" "}
          <button className="primary" onClick={() => run("Po fillon rikuperimi…", () => w.recoverZk(s).then(refresh))}>Shtoje me rikuperim (pas timelock-ut)</button>
        </div>
      )}

      <h2>Asetet</h2>
      <Assets s={s} assets={assets} run={run} refresh={refresh} />

      <h2>Sesionet</h2>
      <table>
        <thead><tr><th>Etiketa</th><th>Skadon</th><th>Programet</th><th>Gjendja</th><th /></tr></thead>
        <tbody>
          {sessions.map(({ address, session: x }) => {
            const active = !x.revoked && Number(x.expiresAt) > now;
            return (
              <tr key={address.toBase58()}>
                <td>{x.label || "—"}{s.session?.session.equals(address) && <span className="muted"> (kjo faqe)</span>}</td>
                <td>{new Date(Number(x.expiresAt) * 1000).toLocaleString()}</td>
                <td>{x.allowedPrograms.length}</td>
                <td className={active ? "ok" : "muted"}>{x.revoked ? "e revokuar" : active ? "aktive" : "e skaduar"}</td>
                <td>{active && (s.passkey || (s.zk && !s.zk.foreign)) && <button onClick={() => run("Po revokohet…", () => w.revokeSession(s, address).then(refresh))}>Anulo</button>}</td>
              </tr>
            );
          })}
        </tbody>
      </table>

      {acc && (
        <>
          <h2>Passkey-t</h2>
          <table>
            <tbody>
              {acc.passkeys.map((p) => (
                <tr key={p.slot}>
                  <td>Slot {p.slot}</td>
                  <td><code>{Array.from(p.publicKey.slice(0, 8), (b) => b.toString(16).padStart(2, "0")).join("")}…</code></td>
                  <td>{new Date(Number(p.addedAt) * 1000).toLocaleDateString()}</td>
                  <td>{s.passkey && <button onClick={() => run("Po hiqet…", () => w.removePasskey(s, p.slot).then(refresh))}>Hiq</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="row">
            <button onClick={() => run("Po shtohet passkey-i…", async () => { const r = await w.addPasskey(s); if (!s.passkey) setS({ ...s, passkey: r.signer }); await refresh(); })}>Shto passkey</button>
            {acc.passkeys.length > 0 && !s.passkey && s.zk && !s.zk.foreign && (
              <button onClick={() => run("Po fillon rikuperimi…", () => w.recoverPasskey(s).then(refresh))}>Humba passkey-n: rikupero me Google (48 orë)</button>
            )}
          </div>
          <Threshold s={s} acc={acc} run={run} refresh={refresh} />
        </>
      )}
    </main>
  );
}

function Assets({ s, assets, run, refresh }: { s: w.State; assets: w.Asset[]; run: (l: string, f: () => Promise<unknown>) => Promise<void>; refresh: () => Promise<void> }) {
  const [sel, setSel] = useState(0);
  const [to, setTo] = useState("");
  const [amount, setAmount] = useState("");
  const a = assets[sel];
  return (
    <>
      <table>
        <thead><tr><th>Aseti</th><th className="n">Sasia</th></tr></thead>
        <tbody>{assets.map((x, i) => <tr key={i}><td>{x.symbol}</td><td className="n">{w.fmt(x.amount, x.decimals)}</td></tr>)}</tbody>
      </table>
      {s.session ? (
        <div className="row">
          <select value={sel} onChange={(e) => setSel(Number(e.target.value))}>{assets.map((x, i) => <option key={i} value={i}>{x.symbol}</option>)}</select>
          <input placeholder="sasia" value={amount} onChange={(e) => setAmount(e.target.value)} style={{ width: 110 }} />
          <input placeholder="adresa e marrësit" value={to} onChange={(e) => setTo(e.target.value)} size={44} />
          <button className="primary" disabled={!a || !to || !amount} onClick={() => run("Po tërhiqet…", async () => {
            await w.withdraw(s, a, new PublicKey(to), w.parseAmount(amount, a.decimals));
            setAmount("");
            await refresh();
          })}>Tërhiq</button>
        </div>
      ) : (
        <p className="muted">Tërheqja kërkon hyrje me Google/Apple; me passkey mund të anulosh sesionet dhe rikuperimet.</p>
      )}
      {s.session && s.passkey && <p className="muted">Tërheqjet nënshkruhen edhe me passkey, pra kalojnë pragun ditor.</p>}
    </>
  );
}

function Threshold({ s, acc, run, refresh }: { s: w.State; acc: NonNullable<w.State["account"]>; run: (l: string, f: () => Promise<unknown>) => Promise<void>; refresh: () => Promise<void> }) {
  const [v, setV] = useState("");
  const cur = Number(acc.thresholdLamports) / LAMPORTS_PER_SOL;
  return (
    <>
      <h2>Pragu ditor pa passkey</h2>
      <p>{acc.thresholdLamports > 0n ? `${cur} SOL në 24 orë; mbi të kërkohet passkey.` : "Pa prag: sesionet kufizohen vetëm nga politikat e tyre."}</p>
      {s.passkey && (
        <div className="row">
          <input placeholder="SOL" value={v} onChange={(e) => setV(e.target.value)} style={{ width: 100 }} />
          <button onClick={() => run("Po ndryshohet pragu…", () => w.setThreshold(s, w.parseAmount(v, 9)).then(refresh))}>Ndrysho</button>
        </div>
      )}
    </>
  );
}
