// SDK → programi i vërtetë (solanaauth.so) në LiteSVM: transaksionet që ndërton SDK-ja pranohen
// nga programi. Prova është ajo e fixture-it të Google (max_epoch = 10), ndaj ora mbahet nën 10.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { Keypair, PublicKey, SystemProgram, Transaction, ComputeBudgetProgram } from "@solana/web3.js";
import { LiteSVM, Clock, FailedTransactionMetadata } from "litesvm";
import { address, getTransactionDecoder } from "@solana/kit";

import * as sa from "../dist/index.js";

const root = new URL("../../../", import.meta.url);
const SO = process.env.SOLANAAUTH_SO ?? new URL("programs/solanaauth/target/deploy/solanaauth.so", root).pathname;
const FX = JSON.parse(readFileSync(new URL("fixtures/proofs/google-mainnet-v1.json", root)));

const available = existsSync(SO);
if (!available && process.env.CI) throw new Error(`mungon ${SO}`);

// LiteSVM 1.x përdor @solana/kit: transaksioni i web3.js serializohet dhe dekodohet.
const A = (pk) => address(pk.toBase58());
const data = (svm, pk) => Uint8Array.from(svm.getAccount(A(pk)).data);
const balance = (svm, pk) => svm.getBalance(A(pk));

function send(svm, ixs, signers) {
  svm.expireBlockhash();
  const tx = new Transaction();
  tx.recentBlockhash = svm.latestBlockhash();
  tx.feePayer = signers[0].publicKey;
  tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }), ...ixs);
  tx.sign(...signers);
  const r = svm.sendTransaction(getTransactionDecoder().decode(tx.serialize()));
  if (r instanceof FailedTransactionMetadata) {
    return { ok: false, err: r.toString(), logs: r.meta().logs() };
  }
  return { ok: true, logs: r.logs() };
}

function setTime(svm, t) {
  const c = svm.getClock();
  svm.setClock(new Clock(c.slot, c.epochStartTimestamp, c.epoch, c.leaderScheduleEpoch, BigInt(t)));
}

test("SDK end-to-end: config → JWK → portofol + sesion → execute → passkey → prag", { skip: !available && "mungon solanaauth.so" }, async () => {
  const svm = new LiteSVM().withPrecompiles();
  const programId = new PublicKey(new Uint8Array(32).fill(9));
  svm.addProgramFromFile(A(programId), SO);
  const admin = Keypair.generate();
  const payer = Keypair.generate();
  for (const k of [admin, payer]) svm.airdrop(A(k.publicKey), 100_000_000_000n);
  // Upgrade authority = admin.
  const pd = svm.getAccount(A(sa.programDataAddress(programId)));
  const pdData = Uint8Array.from(pd.data);
  pdData[12] = 1;
  pdData.set(admin.publicKey.toBytes(), 13);
  svm.setAccount({ ...pd, data: pdData });
  setTime(svm, 1);

  const cfg = { admin: admin.publicKey, oracle: admin.publicKey, jwkTimelockSecs: 2, maxSessionSecs: 30 * 86400, recoveryDelaySecs: 172800, allowTestVk: false };
  let r = send(svm, [sa.initConfig(programId, admin.publicKey, cfg)], [admin]);
  assert.ok(r.ok, r.err);

  const inputs = sa.normalizeInputs(FX.inputs);
  const iss = sa.issFromBase64Details(inputs.issBase64Details);
  const modulus = sa.base64UrlDecode(FX.jwk.n);
  r = send(svm, [sa.proposeJwk(programId, admin.publicKey, admin.publicKey, { iss, kid: FX.jwk.kid, modulus, validFrom: 0, validUntil: 2n ** 62n })], [admin]);
  assert.ok(r.ok, r.err);
  setTime(svm, 3);
  const jwk = sa.jwkAddress(programId, iss, FX.jwk.kid);
  r = send(svm, [sa.applyJwk(programId, jwk)], [payer]);
  assert.ok(r.ok, r.err);

  // Hyrja e parë: portofol + sesion, me çelësin ephemeral të fixture-it.
  const eph = Keypair.fromSeed(sa.fromHex(FX.ephemeral_private_key_hex));
  const auth = new sa.SolanaAuth({ connection: null, programId, proverUrl: "", saltUrl: "" });
  const { identity, wallet, vault } = auth.walletFor(iss, inputs.addressSeed);
  const zk = sa.encodeZkBlock(inputs, FX.max_epoch);
  const policy = { expiresIn: 3600, label: "e2e", allowedPrograms: [sa.SYSTEM_PROGRAM_ID], limits: [sa.solLimit(5_000_000_000n, 3600)] };
  r = send(svm, [sa.createWallet(programId, payer.publicKey, { sessionKey: eph.publicKey, jwk, wallet }, zk, policy)], [payer, eph]);
  assert.ok(r.ok, r.err + "\n" + r.logs?.join("\n"));
  const w = sa.decodeWallet(data(svm, wallet));
  assert.deepEqual(w.zkIdentities[0].identity, identity);
  const session = sa.decodeSession(data(svm, sa.sessionAddress(programId, wallet, eph.publicKey)));
  assert.equal(session.label, "e2e");
  assert.equal(session.expiresAt, 10n);

  svm.airdrop(A(vault), 10_000_000_000n);
  const dest = Keypair.generate().publicKey;
  const transfer = (n) => SystemProgram.transfer({ fromPubkey: vault, toPubkey: dest, lamports: n });
  r = send(svm, [sa.execute(programId, eph.publicKey, wallet, [transfer(1_000_000_000)])], [payer, eph]);
  assert.ok(r.ok, r.err);
  assert.equal(balance(svm, dest), 1_000_000_000n);

  r = send(svm, [sa.execute(programId, eph.publicKey, wallet, [transfer(4_500_000_000)])], [payer, eph]);
  assert.equal(r.ok, false);
  assert.equal(sa.decodeError(r.err + r.logs.join("\n")), "SpendLimitExceeded");

  // Passkey: i pari me zk, pastaj pragu me passkey.
  const pk = sa.localPasskey(new Uint8Array(32).fill(11));
  r = send(svm, [sa.addPasskeyZk(programId, { sessionKey: eph.publicKey, jwk, wallet }, zk, 0, pk.publicKey)], [payer, eph]);
  assert.ok(r.ok, r.err);
  let nonce = sa.decodeWallet(data(svm, wallet)).nonce;
  r = send(svm, await sa.passkeyOps.setThreshold(programId, pk, wallet, nonce, 500_000_000n), [payer]);
  assert.ok(r.ok, r.err + "\n" + r.logs?.join("\n"));

  r = send(svm, [sa.execute(programId, eph.publicKey, wallet, [transfer(600_000_000)])], [payer, eph]);
  assert.equal(sa.decodeError(r.err + r.logs.join("\n")), "AboveThreshold");
  nonce = sa.decodeWallet(data(svm, wallet)).nonce;
  r = send(svm, await sa.passkeyOps.execute(programId, pk, nonce, eph.publicKey, wallet, [transfer(600_000_000)]), [payer, eph]);
  assert.ok(r.ok, r.err + "\n" + r.logs?.join("\n"));
  assert.equal(balance(svm, dest), 1_600_000_000n);

  // Revokimi nga vetë sesioni.
  r = send(svm, [sa.revokeSessionSelf(programId, eph.publicKey, wallet)], [payer, eph]);
  assert.ok(r.ok, r.err);
  r = send(svm, [sa.execute(programId, eph.publicKey, wallet, [transfer(1)])], [payer, eph]);
  assert.equal(sa.decodeError(r.err + r.logs.join("\n")), "SessionRevoked");
});
