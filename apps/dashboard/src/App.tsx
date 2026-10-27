import { useCallback, useEffect, useState } from "react";

import { api, finishLogin, googleLogin, token, usd } from "./api";

type App = any;

export function Root() {
  const [authed, setAuthed] = useState(!!token.get());
  const [err, setErr] = useState("");
  useEffect(() => {
    finishLogin().then((ok) => ok && setAuthed(true)).catch((e) => setErr(e.message));
  }, []);
  if (!authed) {
    return (
      <main>
        <h1>solanaauth · dashboard</h1>
        <p className="muted">Regjistro aplikacionin, merr API key, zgjidh politikat dhe aktivizo paymaster-in (opsional).</p>
        <button className="primary" onClick={googleLogin}>Hyr me Google</button>
        {err && <p className="bad">{err}</p>}
      </main>
    );
  }
  return <Apps onLogout={() => (token.clear(), setAuthed(false))} />;
}

function Apps({ onLogout }: { onLogout: () => void }) {
  const [apps, setApps] = useState<App[]>([]);
  const [sel, setSel] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [err, setErr] = useState("");
  const load = useCallback(() => api("GET", "/apps").then(setApps).catch((e) => (setErr(e.message), !token.get() && onLogout())), [onLogout]);
  useEffect(() => void load(), [load]);
  const create = async () => {
    try {
      const a = await api("POST", "/apps", { name });
      setName("");
      await load();
      setSel(a.id);
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <main>
      <header>
        <h1>solanaauth · {import.meta.env.VITE_NETWORK ?? "devnet"}</h1>
        <div className="row">
          <select value={sel ?? ""} onChange={(e) => setSel(e.target.value || null)}>
            <option value="">Aplikacionet ({apps.length})</option>
            {apps.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
          </select>
          <button onClick={onLogout}>Dil</button>
        </div>
      </header>
      {err && <p className="bad">{err}</p>}
      {sel ? (
        <AppView id={sel} onChange={load} />
      ) : (
        <>
          <h2>Aplikacion i ri</h2>
          <div className="row">
            <input placeholder="Emri" value={name} onChange={(e) => setName(e.target.value)} />
            <button className="primary" disabled={!name} onClick={create}>Krijo</button>
          </div>
        </>
      )}
    </main>
  );
}

const TABS = ["Përdorimi", "Çelësat", "OAuth", "Politikat", "Paymaster", "Faturimi"] as const;

function AppView({ id, onChange }: { id: string; onChange: () => void }) {
  const [app, setApp] = useState<App | null>(null);
  const [tab, setTab] = useState<(typeof TABS)[number]>("Përdorimi");
  const [err, setErr] = useState("");
  const load = useCallback(() => api("GET", `/apps/${id}`).then(setApp).catch((e) => setErr(e.message)), [id]);
  useEffect(() => void load(), [load]);
  const patch = async (p: unknown) => {
    try {
      setApp(await api("PATCH", `/apps/${id}`, p));
      setErr("");
      onChange();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  if (!app) return <p className="muted">Po ngarkohet…</p>;
  return (
    <>
      <h2>{app.name} <span className="muted">· {app.id} · plani {app.plan}</span></h2>
      <nav>{TABS.map((t) => <button key={t} className={t === tab ? "on" : ""} onClick={() => setTab(t)}>{t}</button>)}</nav>
      {err && <p className="bad">{err}</p>}
      {tab === "Përdorimi" && <Usage id={id} />}
      {tab === "Çelësat" && <Keys app={app} reload={load} />}
      {tab === "OAuth" && <OAuth app={app} patch={patch} />}
      {tab === "Politikat" && <Policies app={app} patch={patch} />}
      {tab === "Paymaster" && <PaymasterTab app={app} patch={patch} reload={load} />}
      {tab === "Faturimi" && <Billing app={app} />}
    </>
  );
}

function Usage({ id }: { id: string }) {
  const [month, setMonth] = useState(new Date().toISOString().slice(0, 7));
  const [inv, setInv] = useState<any>(null);
  useEffect(() => void api("GET", `/apps/${id}/usage?month=${month}`).then(setInv), [id, month]);
  if (!inv) return null;
  const u = inv.usage;
  return (
    <>
      <div className="row"><input type="month" value={month} onChange={(e) => setMonth(e.target.value)} /></div>
      <div className="grid">
        <div className="tile">MAU<b>{u.mau.toLocaleString()}</b></div>
        <div className="tile">Agjentë aktivë<b>{u.agents.toLocaleString()}</b></div>
        <div className="tile">Prova<b>{u.proofs.toLocaleString()}</b></div>
        <div className="tile">Tx paymaster<b>{u.sponsoredTx.toLocaleString()}</b></div>
      </div>
      <p className="muted">Vetëm mainnet numërohet për faturim; devnet është pa limit në planin Falas.</p>
      {inv.overQuota && <p className="bad">Kuota e planit Falas u arrit: përdoruesit e rinj refuzohen deri në muajin tjetër ose deri në kalimin në një plan me pagesë.</p>}
    </>
  );
}

function Keys({ app, reload }: { app: App; reload: () => void }) {
  const [fresh, setFresh] = useState("");
  return (
    <>
      <p className="muted">Çelësi shfaqet vetëm një herë; ruhet vetëm hash-i i tij.</p>
      <button className="primary" onClick={async () => { setFresh((await api("POST", `/apps/${app.id}/keys`)).key); reload(); }}>Çelës i ri</button>
      {fresh && <p>Kopjoje tani: <code>{fresh}</code></p>}
      <table>
        <thead><tr><th>Prefiksi</th><th>Krijuar</th><th>Gjendja</th><th /></tr></thead>
        <tbody>
          {app.apiKeys.map((k: any) => (
            <tr key={k.id}>
              <td><code>{k.prefix}…</code></td>
              <td>{new Date(k.createdAt * 1000).toLocaleString()}</td>
              <td className={k.revoked ? "bad" : "ok"}>{k.revoked ? "i revokuar" : "aktiv"}</td>
              <td>{!k.revoked && <button onClick={async () => { await api("DELETE", `/apps/${app.id}/keys/${k.id}`); reload(); }}>Revoko</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function OAuth({ app, patch }: { app: App; patch: (p: unknown) => void }) {
  const [google, setGoogle] = useState(app.oauth.google.join("\n"));
  const [apple, setApple] = useState(app.oauth.apple.join("\n"));
  const lines = (s: string) => s.split("\n").map((x) => x.trim()).filter(Boolean);
  return (
    <>
      <p className="muted">Salt-i dhe prover-i pranojnë vetëm JWT me `aud` nga këto ID. Një për rresht.</p>
      <h2>Google (Web client ID)</h2>
      <textarea rows={3} cols={70} value={google} onChange={(e) => setGoogle(e.target.value)} />
      <h2>Apple (Services ID)</h2>
      <textarea rows={2} cols={70} value={apple} onChange={(e) => setApple(e.target.value)} />
      <div className="row"><button className="primary" onClick={() => patch({ oauth: { google: lines(google), apple: lines(apple) } })}>Ruaj</button></div>
    </>
  );
}

function Policies({ app, patch }: { app: App; patch: (p: unknown) => void }) {
  const [templates, setTemplates] = useState<any[]>([]);
  useEffect(() => void api("GET", "/v1/templates").then(setTemplates), []);
  const t = templates.find((x) => x.id === app.policyTemplate);
  return (
    <>
      <div className="row">
        <select value={app.policyTemplate} onChange={(e) => patch({ policyTemplate: e.target.value })}>
          {templates.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}
        </select>
      </div>
      {t && (
        <>
          <p>{t.description}</p>
          <p className="muted">Politika zbatohet on-chain. Kodi për SDK-në:</p>
          <pre><code>{`const policy = {
  expiresIn: ${t.expiresIn},
  label: "${t.id}",
  allowedPrograms: [${t.programs.map((p: string) => `new PublicKey("${p}")`).join(", ")}],
  limits: [${t.limits.map((l: any) => `{ mint: ${l.mint === "SOL" ? "SOL_MINT" : l.mint === "USDC" ? "USDC_MINT" : `new PublicKey("${l.mint}")`}, amount: ${l.amount}n, periodSecs: ${l.periodSecs} }`).join(", ")}],
};`}</code></pre>
        </>
      )}
    </>
  );
}

function PaymasterTab({ app, patch, reload }: { app: App; patch: (p: unknown) => void; reload: () => void }) {
  const pm = app.paymaster;
  const [programs, setPrograms] = useState(pm.allowedPrograms.join("\n"));
  const [limits, setLimits] = useState({ perUserDailyTx: pm.perUserDailyTx, perUserDailyAccounts: pm.perUserDailyAccounts, globalDailyTx: pm.globalDailyTx, lowBalanceUsd: pm.lowBalanceMicroUsd / 1e6 });
  const [ledger, setLedger] = useState<any>(null);
  const [deposit, setDeposit] = useState<any>(null);
  const [amount, setAmount] = useState(50);
  const [msg, setMsg] = useState("");
  useEffect(() => void api("GET", `/apps/${app.id}/ledger`).then(setLedger), [app.id, app.balanceMicroUsd]);
  const act = (f: () => Promise<void>) => f().catch((e) => setMsg(e.message));
  return (
    <>
      <div className="row">
        <b>Paymaster-i: <span className={pm.enabled ? "ok" : "muted"}>{pm.enabled ? "ON" : "OFF"}</span></b>
        <button onClick={() => patch({ paymaster: { enabled: !pm.enabled } })}>{pm.enabled ? "Çaktivizo" : "Aktivizo"}</button>
        <span className="muted">Pa paymaster: paguan përdoruesi, serveri i aplikacionit ose Kora.</span>
      </div>
      <div className="grid">
        <div className="tile">Depozita<b>{usd(app.balanceMicroUsd)}</b></div>
        <div className="tile">Alarm nën<b>{usd(pm.lowBalanceMicroUsd)}</b></div>
      </div>
      {app.balanceMicroUsd <= pm.lowBalanceMicroUsd && <p className="bad">Depozita është nën pragun; kur mbaron, sponsorizimi ndalon.</p>}
      <h2>Depozitë</h2>
      <div className="row">
        <input type="number" min={5} value={amount} onChange={(e) => setAmount(Number(e.target.value))} style={{ width: 100 }} /> USD
        <button onClick={() => act(async () => { window.location.assign((await api("POST", `/apps/${app.id}/checkout`, { kind: "deposit", amountUsd: amount })).url); })}>Me kartë (Stripe)</button>
        <button onClick={() => act(async () => setDeposit(await api("POST", `/apps/${app.id}/deposits/solana`, { asset: "USDC" })))}>Me USDC</button>
        <button onClick={() => act(async () => setDeposit(await api("POST", `/apps/${app.id}/deposits/solana`, { asset: "SOL" })))}>Me SOL</button>
      </div>
      {deposit && (
        <p>
          Dërgo te <code>{deposit.recipient}</code> me referencën <code>{deposit.reference}</code> (Solana Pay: <a href={deposit.url}>hap në portofol</a>).{" "}
          <button onClick={() => act(async () => { const r = await api("POST", `/apps/${app.id}/deposits/solana/check`); setMsg(`U kreditua ${usd(r.creditedMicroUsd)}`); reload(); })}>Kontrollo pagesën</button>
        </p>
      )}
      {msg && <p>{msg}</p>}
      <h2>Programet e lejuara në `execute` të sponsorizuar</h2>
      <textarea rows={3} cols={60} value={programs} onChange={(e) => setPrograms(e.target.value)} />
      <h2>Limitet</h2>
      <div className="row">
        <label>Tx/përdorues/ditë <input type="number" value={limits.perUserDailyTx} onChange={(e) => setLimits({ ...limits, perUserDailyTx: Number(e.target.value) })} style={{ width: 90 }} /></label>
        <label>Hyrje/përdorues/ditë <input type="number" value={limits.perUserDailyAccounts} onChange={(e) => setLimits({ ...limits, perUserDailyAccounts: Number(e.target.value) })} style={{ width: 70 }} /></label>
        <label>Tx/ditë gjithsej <input type="number" value={limits.globalDailyTx} onChange={(e) => setLimits({ ...limits, globalDailyTx: Number(e.target.value) })} style={{ width: 100 }} /></label>
        <label>Alarm (USD) <input type="number" value={limits.lowBalanceUsd} onChange={(e) => setLimits({ ...limits, lowBalanceUsd: Number(e.target.value) })} style={{ width: 80 }} /></label>
      </div>
      <button className="primary" onClick={() => patch({ paymaster: {
        allowedPrograms: programs.split("\n").map((s: string) => s.trim()).filter(Boolean),
        perUserDailyTx: limits.perUserDailyTx, perUserDailyAccounts: limits.perUserDailyAccounts, globalDailyTx: limits.globalDailyTx,
        lowBalanceMicroUsd: Math.round(limits.lowBalanceUsd * 1e6),
      } })}>Ruaj</button>
      <h2>Historiku</h2>
      <table>
        <thead><tr><th>Koha</th><th>Lloji</th><th className="n">Shuma</th><th>Referenca</th></tr></thead>
        <tbody>
          {ledger?.entries.map((e: any) => (
            <tr key={e.id}>
              <td>{new Date(e.ts * 1000).toLocaleString()}</td>
              <td>{e.kind === "deposit" ? "depozitë" : e.kind === "charge" ? "tx" : e.kind}</td>
              <td className={`n ${e.kind === "charge" ? "bad" : "ok"}`}>{e.kind === "charge" ? "−" : "+"}{usd(e.microUsd)}</td>
              <td><code>{String(e.ref).slice(0, 24)}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function Billing({ app }: { app: App }) {
  const month = new Date().toISOString().slice(0, 7);
  const [inv, setInv] = useState<any>(null);
  const [err, setErr] = useState("");
  useEffect(() => void api("GET", `/apps/${app.id}/usage?month=${month}`).then(setInv), [app.id, month]);
  const upgrade = (plan: string) => api("POST", `/apps/${app.id}/checkout`, { kind: "plan", plan }).then((r) => window.location.assign(r.url)).catch((e) => setErr(e.message));
  return (
    <>
      <p>Plani aktual: <b>{app.plan}</b>{app.paidUntil > 0 && <span className="muted"> · paguar deri {new Date(app.paidUntil * 1000).toLocaleDateString()}</span>}</p>
      <div className="row">
        <button onClick={() => upgrade("starter")}>Starter · $49/muaj</button>
        <button onClick={() => upgrade("growth")}>Growth · $199/muaj</button>
        <span className="muted">Enterprise: me marrëveshje. Çmimet vijnë nga konfigurimi i platformës.</span>
      </div>
      {err && <p className="bad">{err}</p>}
      {inv && (
        <>
          <h2>Fatura e parashikuar · {inv.month}</h2>
          <table>
            <thead><tr><th>Përshkrimi</th><th className="n">Sasia</th><th className="n">Çmimi</th><th className="n">Shuma</th></tr></thead>
            <tbody>
              {inv.lines.map((l: any, i: number) => (
                <tr key={i}><td>{l.description}</td><td className="n">{l.quantity.toLocaleString()}</td><td className="n">${l.unitUsd}</td><td className="n">${l.amountUsd.toFixed(2)}</td></tr>
              ))}
              <tr><th colSpan={3}>Totali</th><th className="n">${inv.totalUsd.toFixed(2)}</th></tr>
            </tbody>
          </table>
          <p className="muted">Paymaster-i paguhet nga depozita (kosto reale + marzh), jo nga fatura. Nuk marrim fee nga transaksionet e përdoruesve.</p>
        </>
      )}
    </>
  );
}
