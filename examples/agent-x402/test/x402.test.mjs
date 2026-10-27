// Testi i pranimit "agjent me limit ditor": paguan brenda limitit, refuzohet mbi të (lokalisht dhe
// on-chain), anulimi e ndalon menjëherë.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { Keypair } from "@solana/web3.js";
import * as sa from "@solanaauth/core";
import { AgentWallet, PolicyError, buildX402Payment, x402Fetch } from "@solanaauth/agent";
import { A, TOKEN, ata, available, createMint, fixtureLogin, mintTo, svmConnection, tokenBalance, world } from "@solanaauth/testkit";

import { x402Handler } from "../facilitator.mjs";

test("agjent x402: 20 USDC/ditë", { skip: !available && "mungon solanaauth.so" }, async () => {
  const w = world();
  const issuer = Keypair.generate();
  w.svm.airdrop(A(issuer.publicKey), 10_000_000_000n);
  const usdc = createMint(w.svm, issuer, 6);
  const merchant = Keypair.generate().publicKey;
  mintTo(w.svm, issuer, usdc, merchant, 0);

  // Përdoruesi hap sesionin e agjentit: vetëm Token Program, 20 USDC në ditë.
  const payer = Keypair.generate();
  w.svm.airdrop(A(payer.publicKey), 1_000_000_000n);
  const policy = { expiresIn: 3600, label: "agent-x402", allowedPrograms: [TOKEN], limits: [{ mint: usdc, amount: 20_000_000n, periodSecs: 86400 }] };
  const { client, session } = await fixtureLogin(w, { policy, feePayer: payer });
  mintTo(w.svm, issuer, usdc, session.vault, 100_000_000);
  const agent = new AgentWallet(client, session);
  agent.clock = () => 2n;

  const connection = svmConnection(w.svm);
  const facilitator = Keypair.generate();
  w.svm.airdrop(A(facilitator.publicKey), 1_000_000_000n);
  const server = createServer(x402Handler({
    network: "solana-devnet", programId: w.programId, mint: usdc, decimals: 6, payTo: merchant, price: 5_000_000n,
    feePayer: facilitator, chain: { send: (raw) => connection.sendRawTransaction(raw) },
    description: "parashikimi i motit", serve: async (path) => ({ path, forecast: "diell" }),
  }));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}/weather`;
  try {
    // 4 × 5 USDC = 20: brenda limitit.
    for (let i = 0; i < 4; i++) {
      const r = await x402Fetch(agent, url);
      assert.equal(r.status, 200);
      assert.equal((await r.json()).forecast, "diell");
      assert.ok(r.headers.get("x-payment-response"));
    }
    assert.equal(tokenBalance(w.svm, ata(merchant, usdc)), 20_000_000n);
    assert.equal((await agent.status(2n)).allowances[0].remaining, 0n);

    // E 5-ta: refuzohet lokalisht para pagesës…
    await assert.rejects(x402Fetch(agent, url), (e) => e instanceof PolicyError && e.code === "SpendLimitExceeded");
    // …dhe on-chain nëse agjenti (p.sh. i manipuluar) e anashkalon kontrollin lokal.
    const reqs = (await (await fetch(url)).json()).accepts[0];
    const r5 = await fetch(url, { headers: { "x-payment": await buildX402Payment(agent, reqs) } });
    assert.equal(r5.status, 402);
    assert.match((await r5.json()).error, /0x21|Custom\(33\)/);
    assert.equal(tokenBalance(w.svm, ata(merchant, usdc)), 20_000_000n);

    // Përdoruesi e anulon sesionin (nga faqja e portofolit ose vetë sesioni) → ndalon menjëherë.
    await client.revoke(session, { feePayer: payer });
    await assert.rejects(x402Fetch(agent, url), (e) => e instanceof PolicyError && e.code === "SessionRevoked");
    const r6 = await fetch(url, { headers: { "x-payment": await buildX402Payment(agent, reqs) } });
    assert.equal(r6.status, 402);
    assert.match((await r6.json()).error, /0x1f|Custom\(31\)/);
    assert.equal(tokenBalance(w.svm, ata(merchant, usdc)), 20_000_000n);
  } finally {
    server.closeAllConnections();
    server.close();
  }
});
