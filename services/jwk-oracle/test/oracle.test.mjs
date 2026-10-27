// Oracle → programi i vërtetë në LiteSVM: propose, pritja e timelock-ut, apply, pastaj "ok".
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { Keypair, PublicKey, Transaction } from "@solana/web3.js";
import { LiteSVM, Clock, FailedTransactionMetadata } from "litesvm";
import { address, getTransactionDecoder } from "@solana/kit";
import * as sa from "@solanaauth/core";

import { planSync } from "../dist/index.js";

const root = new URL("../../../", import.meta.url);
const SO = process.env.SOLANAAUTH_SO ?? new URL("programs/solanaauth/target/deploy/solanaauth.so", root).pathname;
const FX = JSON.parse(readFileSync(new URL("fixtures/proofs/google-mainnet-v1.json", root)));
const available = existsSync(SO);
if (!available && process.env.CI) throw new Error(`mungon ${SO}`);

const A = (pk) => address(pk.toBase58());

test("oracle: propose → wait → apply → ok", { skip: !available && "mungon solanaauth.so" }, async () => {
  const svm = new LiteSVM();
  const programId = new PublicKey(new Uint8Array(32).fill(9));
  svm.addProgramFromFile(A(programId), SO);
  const admin = Keypair.generate();
  const oracle = Keypair.generate();
  for (const k of [admin, oracle]) svm.airdrop(A(k.publicKey), 10_000_000_000n);
  const pd = svm.getAccount(A(sa.programDataAddress(programId)));
  const pdData = Uint8Array.from(pd.data);
  pdData[12] = 1;
  pdData.set(admin.publicKey.toBytes(), 13);
  svm.setAccount({ ...pd, data: pdData });
  const setTime = (t) => {
    const c = svm.getClock();
    svm.setClock(new Clock(c.slot, c.epochStartTimestamp, c.epoch, c.leaderScheduleEpoch, BigInt(t)));
  };
  const send = (ixs, signers) => {
    svm.expireBlockhash();
    const tx = new Transaction();
    tx.recentBlockhash = svm.latestBlockhash();
    tx.feePayer = signers[0].publicKey;
    tx.add(...ixs);
    tx.sign(...signers);
    const r = svm.sendTransaction(getTransactionDecoder().decode(tx.serialize()));
    assert.ok(!(r instanceof FailedTransactionMetadata), r.toString?.());
  };
  setTime(100);
  send([sa.initConfig(programId, admin.publicKey, {
    admin: admin.publicKey, oracle: oracle.publicKey, jwkTimelockSecs: 3600, maxSessionSecs: 86400, recoveryDelaySecs: 172800, allowTestVk: false,
  })], [admin]);

  const chain = {
    getAccountData: async (a) => { const x = svm.getAccount(A(a)); return x?.exists === false || !x?.data ? null : Uint8Array.from(x.data); },
    now: async () => Number(svm.getClock().unixTimestamp),
  };
  const keys = [
    { kty: "RSA", kid: FX.jwk.kid, n: FX.jwk.n, e: "AQAB", alg: "RS256", use: "sig" },
    { kty: "EC", kid: "ec1" },
    { kty: "RSA", kid: "e3", n: FX.jwk.n, e: "Aw" },
  ];
  const opts = { programId, oracle: oracle.publicKey, payer: oracle.publicKey };
  const iss = "https://accounts.google.com";

  let plan = await planSync(chain, iss, keys, opts);
  assert.deepEqual(plan.map((a) => a.kind), ["propose", "skip", "skip"]);
  send([plan[0].instruction], [oracle]);

  plan = await planSync(chain, iss, keys.slice(0, 1), opts);
  assert.equal(plan[0].kind, "wait");
  assert.equal(plan[0].eta, 3700n);

  setTime(3700);
  plan = await planSync(chain, iss, keys.slice(0, 1), opts);
  assert.equal(plan[0].kind, "apply");
  send([plan[0].instruction], [oracle]);

  plan = await planSync(chain, iss, keys.slice(0, 1), opts);
  assert.equal(plan[0].kind, "ok");
  const jwk = sa.decodeJwk(await chain.getAccountData(sa.jwkAddress(programId, iss, FX.jwk.kid)));
  assert.equal(jwk.active.modulusBits, 2048);
  assert.equal(jwk.pending, null);
});
