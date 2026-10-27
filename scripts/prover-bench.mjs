#!/usr/bin/env node
// Koha e gjenerimit të provës zkLogin (p50/p95) kundër një prover-i që po punon.
//
//   npm run build -w sdk/core
//   node scripts/prover-bench.mjs --prover http://localhost:8080/v1 --client-id <GOOGLE_CLIENT_ID> [--n 20]
//
// Prova kërkon një JWT të freskët me nonce-in e çelësit ephemeral, prandaj skripti hap një hyrje
// Google në shfletues (loopback 127.0.0.1, si agjentët) dhe pastaj thërret prover-in N herë me të
// njëjtën JWT. Kjo s'mund të bëhet në CI pa një person që hyn (DIZAJNI D36); numrat e prodhuar
// këtu printohen dhe nuk shkruhen në `results/`.
import { createServer } from "node:http";
import { parseArgs } from "node:util";
import { SolanaAuth } from "../sdk/core/dist/index.js";

const { values: a } = parseArgs({
  options: {
    prover: { type: "string" },
    "client-id": { type: "string" },
    provider: { type: "string", default: "google" },
    n: { type: "string", default: "20" },
    port: { type: "string", default: "0" },
  },
});
if (!a.prover || !a["client-id"]) {
  console.error("përdorimi: --prover <URL> --client-id <OAuth client ID> [--n 20]");
  process.exit(2);
}
const N = Number(a.n);

const CALLBACK = `<!doctype html><meta charset="utf-8"><script>
const p = new URLSearchParams(location.hash.slice(1));
fetch("/token", { method: "POST", body: p.toString() }).then(() => document.body.textContent = "Mund ta mbyllësh këtë faqe.");
</script>`;

const auth = new SolanaAuth({ connection: null, programId: null, proverUrl: a.prover, saltUrl: "" });
const pending = auth.beginLogin(3600);
const jwt = await new Promise((resolve, reject) => {
  const server = createServer(async (req, res) => {
    if (req.url?.startsWith("/callback")) return res.writeHead(200, { "content-type": "text/html" }).end(CALLBACK);
    if (req.method === "POST" && req.url === "/token") {
      let body = "";
      for await (const c of req) body += c;
      const t = new URLSearchParams(body).get("id_token");
      res.writeHead(t ? 200 : 400).end();
      server.closeAllConnections();
      server.close();
      return t ? resolve(t) : reject(new Error("mungon id_token"));
    }
    res.writeHead(404).end();
  });
  server.listen(Number(a.port), "127.0.0.1", () => {
    const redirectUri = `http://127.0.0.1:${server.address().port}/callback`;
    console.log("Hap në shfletues (redirect URI duhet të jetë i lejuar te client ID):\n" +
      SolanaAuth.oauthUrl({ provider: a.provider, clientId: a["client-id"], redirectUri, nonce: pending.nonce }));
  });
});

// Salt-i s'ndikon në kohë; një vlerë e rastësishme 16-byte mjafton për matjen.
const salt = BigInt("0x" + Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("hex"));
const ms = [];
for (let i = 0; i < N; i++) {
  const t = performance.now();
  await auth.prove(jwt, pending, salt);
  ms.push(performance.now() - t);
  process.stderr.write(`provë ${i + 1}/${N}: ${ms.at(-1).toFixed(0)} ms\n`);
}
const sorted = [...ms].sort((x, y) => x - y);
const q = (p) => sorted[Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1)];
console.log(`\n| Prova | n | p50 (ms) | p95 (ms) | min | max |\n|---|---:|---:|---:|---:|---:|`);
console.log(`| zkLogin (${a.prover}) | ${N} | ${q(0.5).toFixed(0)} | ${q(0.95).toFixed(0)} | ${sorted[0].toFixed(0)} | ${sorted.at(-1).toFixed(0)} |`);
