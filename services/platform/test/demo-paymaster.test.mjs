// Demo M5: e njëjta hyrje + execute me SDK-në, me paymaster ON (përdoruesi pa SOL) dhe OFF
// (paguan serveri i aplikacionit si fee payer).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { Keypair, SystemProgram, Transaction } from "@solana/web3.js";
import * as sa from "@solanaauth/core";

import { MemoryStore, OwnerAuth, Paymaster, Platform, createHandler, loadPricing } from "../dist/index.js";
import { A, FX, available, svmConnection, world } from "./world.mjs";

const pricing = loadPricing(new URL("../../../config/pricing.json", import.meta.url).pathname);
const listen = async (handler) => {
  const s = createServer(handler);
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  return { s, url: `http://127.0.0.1:${s.address().port}` };
};

for (const mode of ["ON", "OFF"]) {
  test(`demo: paymaster ${mode}`, { skip: !available && "mungon solanaauth.so" }, async () => {
    const { svm, programId, feePayer, chain, iss } = world();
    const connection = svmConnection(svm);
    const store = new MemoryStore();
    const platform = new Platform({ store, pricing, network: "devnet", saltMasterSeed: new Uint8Array(32) });
    const app = platform.createApp("dev@x.com", "Demo");
    const { key } = platform.createApiKey(app);
    platform.update(app, { paymaster: { enabled: mode === "ON", allowedPrograms: [sa.SYSTEM_PROGRAM_ID.toBase58()] } });
    const paymaster = new Paymaster({ store, pricing, chain, feePayer, programId, network: "devnet", price: { solUsd: async () => 150 } });
    const auth = new OwnerAuth({ secret: new Uint8Array(32), googleClientId: "x" });
    const api = await listen(createHandler({ platform, auth, paymaster }));

    // OFF: serveri i aplikacionit paguan (i njëjti protokoll `POST { transaction }`).
    const appPayer = Keypair.generate();
    svm.airdrop(A(appPayer.publicKey), 5_000_000_000n);
    const appServer = await listen(async (req, res) => {
      let body = "";
      for await (const c of req) body += c;
      const tx = Transaction.from(Buffer.from(JSON.parse(body).transaction, "base64"));
      tx.partialSign(appPayer);
      try {
        const signature = await connection.sendRawTransaction(tx.serialize());
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ signature }));
      } catch (e) {
        res.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: e.message }));
      }
    });

    try {
      let payer;
      if (mode === "ON") payer = await sa.paymasterFeePayer(api.url, key);
      else {
        await assert.rejects(sa.paymasterFeePayer(api.url, key), /s'është aktiv/);
        payer = sa.appServerFeePayer(appServer.url, appPayer.publicKey);
      }
      const client = new sa.SolanaAuth({ connection, programId, proverUrl: "", saltUrl: "", apiKey: key, feePayer: payer });

      const eph = Keypair.fromSeed(sa.fromHex(FX.ephemeral_private_key_hex));
      const pending = { ephemeralSecretKey: eph.secretKey, maxEpoch: FX.max_epoch, randomness: "1", nonce: "n" };
      const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
      const jwt = [b64({ alg: "RS256", kid: FX.jwk.kid }), b64({ iss, aud: "a", sub: "s" }), "x"].join(".");
      const policy = { expiresIn: 3600, label: "demo", allowedPrograms: [sa.SYSTEM_PROGRAM_ID], limits: [sa.solLimit(1_000_000_000n, 3600)] };
      const { transaction, session, created } = await client.buildLogin(jwt, pending, sa.normalizeInputs(FX.inputs), policy);
      assert.equal(created, true);
      await payer.submit(transaction);
      assert.equal(svm.getBalance(A(eph.publicKey)) ?? 0n, 0n, "përdoruesi s'ka pasur kurrë SOL");

      svm.airdrop(A(session.vault), 2_000_000_000n);
      const dest = Keypair.generate().publicKey;
      await client.execute(session, [SystemProgram.transfer({ fromPubkey: session.vault, toPubkey: dest, lamports: 1_000_000 })]);
      assert.equal(svm.getBalance(A(dest)), 1_000_000n);
      await assert.rejects(
        client.execute(session, [SystemProgram.transfer({ fromPubkey: session.vault, toPubkey: dest, lamports: 1_500_000_000 })]),
        mode === "ON" ? /SimulationFailed/ : /0x21|Custom\(33\)/,
      );
      await client.revoke(session);
      const charged = store.ledger(app.id).filter((e) => e.kind === "charge").length;
      assert.equal(charged, mode === "ON" ? 3 : 0);
    } finally {
      for (const x of [api.s, appServer.s]) { x.closeAllConnections(); x.close(); }
    }
  });
}
