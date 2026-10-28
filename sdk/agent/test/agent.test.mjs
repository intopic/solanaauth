// Agjenti → programi i vërtetë në LiteSVM, përmes një Connection-i të simuluar mbi LiteSVM.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Keypair, PublicKey, Transaction } from "@solana/web3.js";
import { LiteSVM, Clock, FailedTransactionMetadata } from "litesvm";
import { address, getTransactionDecoder } from "@solana/kit";
import * as sa from "@solanaauth/core";

import { AgentWallet, PolicyError, loginAgent } from "../dist/index.js";

const root = new URL("../../../", import.meta.url);
const SO = process.env.SOLANAAUTH_SO ?? new URL("programs/solanaauth/target/deploy/solanaauth.so", root).pathname;
const FX = JSON.parse(readFileSync(new URL("fixtures/proofs/google-mainnet-v1.json", root)));
const available = existsSync(SO);
if (!available && process.env.CI) throw new Error(`mungon ${SO}`);
const A = (pk) => address(pk.toBase58());

/** Connection minimal mbi LiteSVM (vetëm metodat që përdor SDK-ja). */
function svmConnection(svm) {
  return {
    async getLatestBlockhash() {
      svm.expireBlockhash();
      return { blockhash: svm.latestBlockhash(), lastValidBlockHeight: 1 };
    },
    async getAccountInfo(pk) {
      const a = svm.getAccount(A(pk));
      return a?.exists === false || !a?.data ? null : { data: Buffer.from(a.data), owner: new PublicKey(a.programAddress) };
    },
    async getBalance(pk) { return Number(svm.getBalance(A(pk)) ?? 0n); },
    async sendRawTransaction(raw) {
      const r = svm.sendTransaction(getTransactionDecoder().decode(raw));
      if (r instanceof FailedTransactionMetadata) {
        const e = new Error(r.toString());
        e.logs = r.meta().logs();
        throw e;
      }
      return "ok";
    },
    async confirmTransaction() { return { value: { err: null } }; },
  };
}

function setup() {
  const svm = new LiteSVM();
  const programId = new PublicKey(new Uint8Array(32).fill(9));
  svm.addProgramFromFile(A(programId), SO);
  const admin = Keypair.generate();
  svm.airdrop(A(admin.publicKey), 100_000_000_000n);
  const pd = svm.getAccount(A(sa.programDataAddress(programId)));
  const pdData = Uint8Array.from(pd.data);
  pdData[12] = 1;
  pdData.set(admin.publicKey.toBytes(), 13);
  svm.setAccount({ ...pd, data: pdData });
  const c = svm.getClock();
  svm.setClock(new Clock(c.slot, c.epochStartTimestamp, c.epoch, c.leaderScheduleEpoch, 1n));
  const connection = svmConnection(svm);
  const send = async (ixs, signers) => {
    const tx = new Transaction();
    tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
    tx.feePayer = signers[0].publicKey;
    tx.add(...ixs);
    tx.sign(...signers);
    return connection.sendRawTransaction(tx.serialize());
  };
  return { svm, programId, admin, connection, send };
}

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");

test("loginAgent (client-wallet approval) → transferSol brenda limitit → refuzim mbi limit", { skip: !available && "mungon solanaauth.so" }, async () => {
  const { svm, programId, admin, connection, send } = setup();
  await send([sa.initConfig(programId, admin.publicKey, {
    admin: admin.publicKey, oracle: admin.publicKey, jwkTimelockSecs: 0, maxSessionSecs: 86400, recoveryDelaySecs: 172800, allowTestVk: false,
  })], [admin]);
  const iss = "https://accounts.google.com";
  await send([sa.proposeJwk(programId, admin.publicKey, admin.publicKey, { iss, kid: FX.jwk.kid, modulus: sa.base64UrlDecode(FX.jwk.n), validFrom: 0, validUntil: 2n ** 62n })], [admin]);
  await send([sa.applyJwk(programId, sa.jwkAddress(programId, iss, FX.jwk.kid))], [admin]);

  const eph = Keypair.fromSeed(sa.fromHex(FX.ephemeral_private_key_hex));
  const config = { connection, programId, proverUrl: "", saltUrl: "" };
  const policy = { expiresIn: 3600, label: "agent", allowedPrograms: [sa.SYSTEM_PROGRAM_ID], limits: [sa.solLimit(1_000_000_000n, 3600)] };
  const owner = new sa.SolanaAuth(config);
  const pending = { ephemeralSecretKey: eph.secretKey, maxEpoch: FX.max_epoch, randomness: "1", nonce: "n" };
  const jwt = [b64({ alg: "RS256", kid: FX.jwk.kid }), b64({ iss, aud: "a", sub: "s" }), "x"].join(".");
  const result = await loginAgent({ config, policy, now: 1, authorize: async request => {
    assert.ok(!request.sessionKey.equals(eph.publicKey));
    const approved = await owner.buildDelegation(jwt, pending, sa.normalizeInputs(FX.inputs), request.policy, request.sessionKey, admin.publicKey);
    approved.transaction.partialSign(admin);
    const signature = await connection.sendRawTransaction(approved.transaction.serialize());
    svm.airdrop(A(request.sessionKey), 1_000_000_000n);
    return { wallet: approved.authorization.wallet, signature, created: approved.created };
  } });
  assert.equal(result.created, true);
  const wallet = result.wallet;

  const dir = mkdtempSync(join(tmpdir(), "agent-"));
  wallet.save(join(dir, "s.json"));
  assert.equal(statSync(join(dir, "s.json")).mode & 0o777, 0o600);
  const w = AgentWallet.load(new sa.SolanaAuth(config), join(dir, "s.json"));
  w.clock = () => 2n;

  svm.airdrop(A(w.vault), 5_000_000_000n);
  const dest = Keypair.generate().publicKey;
  await w.transferSol(dest, 400_000_000n);
  assert.equal(svm.getBalance(A(dest)), 400_000_000n);

  const st = await w.status(2n);
  assert.equal(st.label, "agent");
  assert.equal(st.allowances[0].remaining, 600_000_000n);

  // Kontrolli lokal ndalon para dërgimit; pa të, programi refuzon me të njëjtin kod.
  await assert.rejects(w.transferSol(dest, 700_000_000n, {}), (e) => e instanceof PolicyError && e.code === "SpendLimitExceeded");
  await assert.rejects(w.transferSol(dest, 700_000_000n, { precheck: false }), (e) => e instanceof PolicyError && e.code === "SpendLimitExceeded");
  await assert.rejects(
    w.transferToken(new PublicKey(new Uint8Array(32).fill(4)), dest, 1n, 6),
    (e) => e instanceof PolicyError && e.code === "ProgramNotAllowed",
  );
});
