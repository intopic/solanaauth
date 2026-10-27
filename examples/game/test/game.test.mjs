// Testi i pranimit "sesion loje": 20 veprime pa asnjë konfirmim (vetëm çelësi i sesionit
// nënshkruan), një veprim te një program jo i lejuar refuzohet. Me paymaster ON dhe OFF.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { Keypair, LAMPORTS_PER_SOL, PublicKey, TransactionInstruction } from "@solana/web3.js";
import * as sa from "@solanaauth/core";
import { MemoryStore, Paymaster, Platform, loadPricing } from "@solanaauth/platform";
import { A, GAME_PROGRAM_ID, GAME_SO, available, fixtureLogin, world } from "@solanaauth/testkit";

import { decodeScore, join, play, playerState } from "../lib/game.js";

const ok = available && existsSync(GAME_SO);
if (!ok && process.env.CI) throw new Error("mungojnë programet");
const pricing = loadPricing(new URL("../../../config/pricing.json", import.meta.url).pathname);

for (const mode of ["ON", "OFF"]) {
  test(`loja: 20 veprime pa konfirmim, program i palejuar refuzohet (paymaster ${mode})`, { skip: !ok && "mungojnë programet" }, async () => {
    const w = world({ game: true });
    const policy = {
      expiresIn: 24 * 3600, label: "loja", allowedPrograms: [GAME_PROGRAM_ID, sa.SYSTEM_PROGRAM_ID],
      limits: [sa.solLimit(BigInt(LAMPORTS_PER_SOL / 100), 24 * 3600)],
    };
    let feePayer;
    let store;
    let app;
    if (mode === "ON") {
      store = new MemoryStore();
      const platform = new Platform({ store, pricing, network: "devnet", saltMasterSeed: new Uint8Array(32) });
      app = platform.createApp("dev@x.com", "Loja");
      const { key } = platform.createApiKey(app);
      platform.update(app, { paymaster: { enabled: true, allowedPrograms: [GAME_PROGRAM_ID.toBase58(), sa.SYSTEM_PROGRAM_ID.toBase58()], perUserDailyTx: 50 } });
      const pm = new Paymaster({ store, pricing, chain: w.chain, feePayer: w.feePayer, programId: w.programId, network: "devnet", price: { solUsd: async () => 150 } });
      feePayer = { publicKey: pm.feePayer, submit: async (tx) => (await pm.sponsor(key, tx.serialize({ requireAllSignatures: false }))).signature };
    } else {
      // Serveri i aplikacionit paguan tarifat (Keypair në Node).
      feePayer = Keypair.generate();
      w.svm.airdrop(A(feePayer.publicKey), 1_000_000_000n);
    }
    const { client, session } = await fixtureLogin(w, { policy, feePayer });
    // Vault-i paguan rent-in e gjendjes së lojtarit (brenda limitit 0.01 SOL/ditë).
    w.svm.airdrop(A(session.vault), 100_000_000n);
    const opts = mode === "OFF" ? { feePayer } : {};

    await client.execute(session, [join(GAME_PROGRAM_ID, session.vault)], opts);
    for (let i = 0; i < 20; i++) await client.execute(session, [play(GAME_PROGRAM_ID, session.vault)], opts);
    const st = w.svm.getAccount(A(playerState(GAME_PROGRAM_ID, session.vault)));
    assert.equal(decodeScore(Uint8Array.from(st.data)).score, 20n);

    const memo = new TransactionInstruction({ programId: new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"), keys: [], data: Buffer.from("x") });
    await assert.rejects(
      client.execute(session, [memo], opts),
      mode === "ON" ? (e) => e.code === "ProgramNotSponsored" : (e) => sa.decodeError(`${e.message} ${JSON.stringify(e.logs ?? [])}`) === "ProgramNotAllowed",
    );
    if (mode === "ON") {
      // Hyrja + join + 20 lojëra; refuzimi s'ngarkohet.
      assert.equal(store.ledger(app.id).filter((e) => e.kind === "charge").length, 22);
    }
  });
}
