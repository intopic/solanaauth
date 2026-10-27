// Mjedisi i përbashkët i testeve: programi i vërtetë në LiteSVM, config + JWK e Google.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { Keypair, PublicKey, Transaction } from "@solana/web3.js";
import { LiteSVM, Clock, FailedTransactionMetadata } from "litesvm";
import { address, getTransactionDecoder } from "@solana/kit";
import * as sa from "@solanaauth/core";

const root = new URL("../", import.meta.url);
export const SO = process.env.SOLANAAUTH_SO ?? new URL("programs/solanaauth/target/deploy/solanaauth.so", root).pathname;
export const FX = JSON.parse(readFileSync(new URL("fixtures/proofs/google-mainnet-v1.json", root)));
export const available = existsSync(SO);
if (!available && process.env.CI) throw new Error(`mungon ${SO}`);
export const A = (pk) => address(pk.toBase58());

export const GAME_SO = process.env.DEMO_GAME_SO ?? new URL("programs/demo-game/target/deploy/demo_game.so", root).pathname;
export const GAME_PROGRAM_ID = new PublicKey(new Uint8Array(32).fill(7));

/** LiteSVM me solanaauth (program ID = [9; 32]), config (timelock 0) dhe JWK-në e Google të fixture-it. */
export function world({ game = false } = {}) {
  const svm = new LiteSVM();
  if (game) svm.addProgramFromFile(A(GAME_PROGRAM_ID), GAME_SO);
  const programId = new PublicKey(new Uint8Array(32).fill(9));
  svm.addProgramFromFile(A(programId), SO);
  const admin = Keypair.generate();
  const feePayer = Keypair.generate();
  svm.airdrop(A(admin.publicKey), 100_000_000_000n);
  svm.airdrop(A(feePayer.publicKey), 10_000_000_000n);
  const pd = svm.getAccount(A(sa.programDataAddress(programId)));
  const pdData = Uint8Array.from(pd.data);
  pdData[12] = 1;
  pdData.set(admin.publicKey.toBytes(), 13);
  svm.setAccount({ ...pd, data: pdData });
  const c = svm.getClock();
  svm.setClock(new Clock(c.slot, c.epochStartTimestamp, c.epoch, c.leaderScheduleEpoch, 1n));
  const sendDirect = (ixs, signers) => {
    svm.expireBlockhash();
    const tx = new Transaction();
    tx.recentBlockhash = svm.latestBlockhash();
    tx.feePayer = signers[0].publicKey;
    tx.add(...ixs);
    tx.sign(...signers);
    const r = svm.sendTransaction(getTransactionDecoder().decode(tx.serialize()));
    assert.ok(!(r instanceof FailedTransactionMetadata), r.toString());
  };
  sendDirect([sa.initConfig(programId, admin.publicKey, {
    admin: admin.publicKey, oracle: admin.publicKey, jwkTimelockSecs: 0, maxSessionSecs: 86400, recoveryDelaySecs: 172800, allowTestVk: false,
  })], [admin]);
  const iss = "https://accounts.google.com";
  sendDirect([sa.proposeJwk(programId, admin.publicKey, admin.publicKey, { iss, kid: FX.jwk.kid, modulus: sa.base64UrlDecode(FX.jwk.n), validFrom: 0, validUntil: 2n ** 62n })], [admin]);
  sendDirect([sa.applyJwk(programId, sa.jwkAddress(programId, iss, FX.jwk.kid))], [admin]);

  const chain = {
    async simulate(tx, payer) {
      const before = Number(svm.getBalance(A(payer)));
      const r = svm.simulateTransaction(getTransactionDecoder().decode(tx.serialize()));
      if (r instanceof FailedTransactionMetadata) return { err: r.toString(), before, after: before, logs: r.meta().logs() };
      const post = r.postAccounts().find((a) => a.address === payer.toBase58());
      return { err: null, before, after: post ? Number(post.lamports) : before, logs: r.meta().logs() };
    },
    async send(raw) {
      const r = svm.sendTransaction(getTransactionDecoder().decode(raw));
      if (r instanceof FailedTransactionMetadata) throw new Error(r.toString());
      return Buffer.from(r.signature()).toString("hex");
    },
  };
  return { svm, programId, feePayer, chain, iss };
}


/** Connection minimal mbi LiteSVM (metodat që përdor SDK-ja). */
export function svmConnection(svm) {
  return {
    async getLatestBlockhash() {
      svm.expireBlockhash();
      return { blockhash: svm.latestBlockhash(), lastValidBlockHeight: 1 };
    },
    async getAccountInfo(pk) {
      const a = svm.getAccount(A(pk));
      return a?.exists === false || !a?.data ? null : { data: Buffer.from(a.data) };
    },
    async getBalance(pk) { return Number(svm.getBalance(A(pk)) ?? 0n); },
    async sendRawTransaction(raw) {
      const r = svm.sendTransaction(getTransactionDecoder().decode(raw));
      if (r instanceof FailedTransactionMetadata) throw Object.assign(new Error(r.toString()), { logs: r.meta().logs() });
      return Buffer.from(r.signature()).toString("hex");
    },
    async confirmTransaction() { return { value: { err: null } }; },
  };
}

/**
 * Hyrja me provën e fixture-it përmes SDK-së (`buildLogin`): krijon portofolin dhe sesionin.
 * `feePayer`: `FeePayer` (paymaster, server) ose `Keypair` që paguan; çelësi i sesionit s'ka SOL.
 */
export async function fixtureLogin(w, { policy, feePayer, connection = svmConnection(w.svm) }) {
  const client = new sa.SolanaAuth({ connection, programId: w.programId, proverUrl: "", saltUrl: "", feePayer: feePayer instanceof Keypair ? undefined : feePayer });
  const eph = Keypair.fromSeed(sa.fromHex(FX.ephemeral_private_key_hex));
  const pending = { ephemeralSecretKey: eph.secretKey, maxEpoch: FX.max_epoch, randomness: "1", nonce: "n" };
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const jwt = [b64({ alg: "RS256", kid: FX.jwk.kid }), b64({ iss: w.iss, aud: "a", sub: "s" }), "x"].join(".");
  const payerKey = feePayer instanceof Keypair ? feePayer.publicKey : undefined;
  const { transaction, session } = await client.buildLogin(jwt, pending, sa.normalizeInputs(FX.inputs), policy, payerKey);
  if (feePayer instanceof Keypair) {
    transaction.partialSign(feePayer);
    await connection.sendRawTransaction(transaction.serialize());
  } else {
    await feePayer.submit(transaction);
  }
  return { client, session, connection };
}
