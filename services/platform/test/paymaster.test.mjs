// Paymaster-i kundër programit të vërtetë në LiteSVM.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction } from "@solana/web3.js";
import * as sa from "@solanaauth/core";

import { MemoryStore, Paymaster, Platform, loadPricing } from "../dist/index.js";
import { A, FX, available, world } from "./world.mjs";

const pricing = loadPricing(new URL("../../../config/pricing.json", import.meta.url).pathname);

test("paymaster: hyrja dhe execute të sponsorizuara; refuzimet", { skip: !available && "mungon solanaauth.so" }, async () => {
  const { svm, programId, feePayer, chain, iss } = world();
  const store = new MemoryStore();
  let now = 1_800_000_000;
  const platform = new Platform({ store, pricing, network: "mainnet", saltMasterSeed: new Uint8Array(32), now: () => now });
  const app = platform.createApp("dev@example.com", "Loja");
  const { key } = platform.createApiKey(app);
  const low = [];
  const pm = new Paymaster({
    store, pricing, chain, feePayer, programId, network: "mainnet",
    price: { solUsd: async () => 150 }, now: () => now, onLowBalance: (a) => low.push(a.id),
  });

  const eph = Keypair.fromSeed(sa.fromHex(FX.ephemeral_private_key_hex));
  const inputs = sa.normalizeInputs(FX.inputs);
  const auth = new sa.SolanaAuth({ connection: null, programId, proverUrl: "", saltUrl: "" });
  const { wallet, vault } = auth.walletFor(iss, inputs.addressSeed);
  const jwk = sa.jwkAddress(programId, iss, FX.jwk.kid);
  const policy = { expiresIn: 3600, label: "loja", allowedPrograms: [sa.SYSTEM_PROGRAM_ID], limits: [sa.solLimit(1_000_000_000n, 3600)] };

  const build = (ixs, signers) => {
    svm.expireBlockhash();
    const tx = new Transaction();
    tx.recentBlockhash = svm.latestBlockhash();
    tx.feePayer = feePayer.publicKey;
    tx.add(...ixs);
    if (signers.length) tx.partialSign(...signers);
    return tx.serialize({ requireAllSignatures: false });
  };
  const code = async (p) => { try { await p; return "ok"; } catch (e) { return e.code; } };
  const createIx = sa.createWallet(programId, feePayer.publicKey, { sessionKey: eph.publicKey, jwk, wallet }, sa.encodeZkBlock(inputs, FX.max_epoch), policy);

  // OFF si parazgjedhje.
  assert.equal(await code(pm.sponsor(key, build([createIx], [eph]))), "PaymasterDisabled");
  platform.update(app, { paymaster: { enabled: true, allowedPrograms: [sa.SYSTEM_PROGRAM_ID.toBase58()], perUserDailyTx: 3 } });
  assert.equal(await code(pm.sponsor("sa_live_x", build([createIx], [eph]))), "Unauthorized");
  // Pa depozitë → refuzim (ne nuk japim kredi).
  assert.equal(await code(pm.sponsor(key, build([createIx], [eph]))), "DepositExhausted");

  store.addLedger({ appId: app.id, ts: now, kind: "deposit", microUsd: 6_000_000, ref: "test:1" });
  const before = Number(svm.getBalance(A(feePayer.publicKey)));
  const r1 = await pm.sponsor(key, build([createIx], [eph]));
  const spent = before - Number(svm.getBalance(A(feePayer.publicKey)));
  assert.equal(r1.lamports, spent, "kostoja e simuluar = kostoja reale");
  // Brenda kuotës së planit (5,000 tx) pa marzh: vetëm kostoja reale me 150 USD/SOL.
  assert.equal(r1.chargedMicroUsd, Math.round((spent / 1e9) * 150 * 1e6));
  assert.equal(app.balanceMicroUsd, 6_000_000 - r1.chargedMicroUsd);
  assert.equal(low.length, 1, "alarm kur depozita bie nën 5 USD");
  // Hyrje të tjera me rent nga paymaster-i: kufi i veçantë për përdorues/ditë (D27).
  platform.update(app, { paymaster: { perUserDailyAccounts: 1 } });
  const openIx = sa.openSession(programId, feePayer.publicKey, { sessionKey: eph.publicKey, jwk, wallet }, sa.encodeZkBlock(inputs, FX.max_epoch), policy);
  assert.equal(await code(pm.sponsor(key, build([openIx], [eph]))), "UserAccountLimit");

  svm.airdrop(A(vault), 5_000_000_000n);
  const dest = Keypair.generate().publicKey;
  const transfer = (n) => SystemProgram.transfer({ fromPubkey: vault, toPubkey: dest, lamports: n });
  const r2 = await pm.sponsor(key, build([sa.execute(programId, eph.publicKey, wallet, [transfer(1_000_000)])], [eph]));
  assert.equal(r2.lamports, 10_000, "tarifa bazë: 2 nënshkrime");
  assert.equal(svm.getBalance(A(dest)), 1_000_000n);

  // Program jashtë listës së aplikacionit.
  const memo = new TransactionInstruction({ programId: new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"), keys: [], data: Buffer.from("x") });
  assert.equal(await code(pm.sponsor(key, build([sa.execute(programId, eph.publicKey, wallet, [memo])], [eph]))), "ProgramNotSponsored");
  // Instruksion i nivelit të parë jashtë solanaauth (p.sh. transfer nga paymaster-i).
  const drain = SystemProgram.transfer({ fromPubkey: feePayer.publicKey, toPubkey: dest, lamports: 1_000_000 });
  assert.equal(await code(pm.sponsor(key, build([drain], []))), "ProgramNotSponsored");
  // Paymaster-i si llogari e një instruksioni të brendshëm.
  const innerDrain = SystemProgram.transfer({ fromPubkey: feePayer.publicKey, toPubkey: dest, lamports: 1 });
  assert.equal(await code(pm.sponsor(key, build([sa.execute(programId, eph.publicKey, wallet, [innerDrain])], [eph]))), "PayerMisuse");
  // Fee payer tjetër.
  const other = Keypair.generate();
  const tx = new Transaction({ feePayer: other.publicKey, blockhash: svm.latestBlockhash(), lastValidBlockHeight: 1 }).add(sa.execute(programId, eph.publicKey, wallet, [transfer(1)]));
  tx.partialSign(eph);
  assert.equal(await code(pm.sponsor(key, tx.serialize({ requireAllSignatures: false }))), "WrongFeePayer");
  // Pa nënshkrimin e sesionit.
  assert.equal(await code(pm.sponsor(key, build([sa.execute(programId, eph.publicKey, wallet, [transfer(1)])], []))), "MissingSignature");
  // Simulimi dështon (mbi limitin e sesionit) → asnjë ngarkesë.
  const bal = app.balanceMicroUsd;
  assert.equal(await code(pm.sponsor(key, build([sa.execute(programId, eph.publicKey, wallet, [transfer(2_000_000_000)])], [eph]))), "SimulationFailed");
  assert.equal(app.balanceMicroUsd, bal);

  // Limiti për përdorues/ditë: 3 (create + 1 execute + ky) → i katërti refuzohet.
  await pm.sponsor(key, build([sa.execute(programId, eph.publicKey, wallet, [transfer(1001)])], [eph]));
  assert.equal(await code(pm.sponsor(key, build([sa.execute(programId, eph.publicKey, wallet, [transfer(1002)])], [eph]))), "UserLimit");
  now += 86401;
  await pm.sponsor(key, build([sa.execute(programId, eph.publicKey, wallet, [transfer(1003)])], [eph]));

  // Depozita mbaron → ndalon.
  store.addLedger({ appId: app.id, ts: now, kind: "charge", microUsd: app.balanceMicroUsd - 100, ref: "test:drain" });
  assert.equal(await code(pm.sponsor(key, build([sa.execute(programId, eph.publicKey, wallet, [transfer(1004)])], [eph]))), "DepositExhausted");

  // Libri: depozita - ngarkesat = bilanci.
  const L = store.ledger(app.id);
  const sum = L.reduce((s, e) => s + (e.kind === "charge" ? -e.microUsd : e.microUsd), 0);
  assert.equal(sum, app.balanceMicroUsd);
  assert.equal(L.filter((e) => e.kind === "charge" && e.details?.lamports).length, 4);
});

test("paymaster: marzhi pas kuotës së planit; devnet falas", async () => {
  const store = new MemoryStore();
  const now = 1_800_000_000;
  const platform = new Platform({ store, pricing, network: "mainnet", saltMasterSeed: new Uint8Array(32), now: () => now });
  const app = platform.createApp("o", "A");
  const mk = (network) => new Paymaster({ store, pricing, chain: null, feePayer: Keypair.generate(), programId: PublicKey.default, network, price: { solUsd: async () => 100 }, now: () => now });
  assert.deepEqual(await mk("mainnet").cost(app, 5000), { microUsd: 500, marginMicroUsd: 0 });
  for (let i = 0; i < 5000; i++) store.record({ appId: app.id, ts: now, kind: "sponsored_tx", subject: "s", network: "mainnet" });
  assert.deepEqual(await mk("mainnet").cost(app, 5000), { microUsd: 700, marginMicroUsd: 200 });
  assert.deepEqual(await mk("devnet").cost(app, 5000), { microUsd: 0, marginMicroUsd: 0 });
});
