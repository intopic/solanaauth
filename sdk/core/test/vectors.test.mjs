// Krahason SDK-në me klientin Rust të testeve (fixtures/sdk-vectors.json) dhe me @mysten/sui.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { PublicKey, SystemProgram } from "@solana/web3.js";
import { p256 } from "@noble/curves/p256";

import * as sa from "../dist/index.js";

const root = new URL("../../../", import.meta.url);
const V = JSON.parse(readFileSync(new URL("fixtures/sdk-vectors.json", root)));
const FX = JSON.parse(readFileSync(new URL(`fixtures/proofs/${V.fixture}.json`, root)));
const programId = new PublicKey(V.program_id);
const pk = (s) => new PublicKey(s);
const hex = (b) => sa.toHex(Uint8Array.from(b));

function same(name, ix) {
  const want = V.ix[name];
  assert.equal(ix.programId.toBase58(), want.program_id, `${name}: program`);
  assert.equal(hex(ix.data), want.data, `${name}: data`);
  assert.deepEqual(
    ix.keys.map((k) => ({ pubkey: k.pubkey.toBase58(), is_signer: k.isSigner, is_writable: k.isWritable })),
    want.accounts,
    `${name}: accounts`,
  );
}

const inputs = sa.normalizeInputs({ ...FX.inputs, address_seed: FX.inputs.address_seed });
const zk = sa.encodeZkBlock(inputs, FX.max_epoch, false);
const policy = {
  expiresIn: 3600,
  label: "demo",
  allowedPrograms: [sa.SYSTEM_PROGRAM_ID, sa.TOKEN_PROGRAM_ID],
  limits: [sa.solLimit(1_000_000_000n, 86_400)],
};
const iss = sa.issFromBase64Details(inputs.issBase64Details);
const sessionKey = pk(V.eph_pubkey);
const wallet = pk(V.wallet);
const jwk = sa.jwkAddress(programId, iss, FX.jwk.kid);

test("adresat dhe identiteti", () => {
  assert.equal(iss, "https://accounts.google.com");
  const id = sa.zkIdentity(iss, sa.toBigEndian(inputs.addressSeed));
  assert.equal(sa.toHex(id), V.identity);
  assert.equal(sa.walletAddress(programId, id).toBase58(), V.wallet);
  assert.equal(sa.vaultAddress(programId, wallet).toBase58(), V.vault);
  assert.equal(sa.sessionAddress(programId, wallet, sessionKey).toBase58(), V.session);
  assert.equal(sa.configAddress(programId).toBase58(), V.config);
  assert.equal(jwk.toBase58(), V.jwk);
});

test("blloku zk dhe politika", () => {
  assert.equal(sa.toHex(zk), V.zk_block);
  assert.equal(sa.toHex(sa.encodePolicy(policy)), V.policy);
});

test("instruksionet = klienti Rust", () => {
  const payer = pk(V.payer);
  const admin = pk(V.admin);
  const oracle = pk(V.oracle);
  same("init_config", sa.initConfig(programId, admin, {
    admin, oracle, jwkTimelockSecs: 2, maxSessionSecs: 30 * 24 * 3600, recoveryDelaySecs: 48 * 3600, allowTestVk: false,
  }));
  const modulus = sa.base64UrlDecode(FX.jwk.n);
  same("propose_jwk", sa.proposeJwk(programId, oracle, payer, {
    iss, kid: FX.jwk.kid, modulus, validFrom: 0, validUntil: 2n ** 63n - 1n,
  }));
  same("apply_jwk", sa.applyJwk(programId, jwk));
  const a = { sessionKey, jwk, wallet };
  same("create_wallet", sa.createWallet(programId, payer, a, zk, policy));
  same("open_session", sa.openSession(programId, payer, a, zk, policy));
  const vault = pk(V.vault);
  const dest = new PublicKey(new Uint8Array(32).fill(5));
  same("execute", sa.execute(programId, sessionKey, wallet, [
    SystemProgram.transfer({ fromPubkey: vault, toPubkey: dest, lamports: 1234 }),
  ]));
  same("revoke_self", sa.revokeSessionSelf(programId, sessionKey, wallet));
  same("close_session", sa.closeSession(programId, wallet, pk(V.session)));
});

test("genAddressSeed dhe generateNonce = @mysten/sui", async () => {
  const sui = await import("@mysten/sui/zklogin");
  const { Ed25519Keypair } = await import("@mysten/sui/keypairs/ed25519");
  const s = FX.address_seed_inputs;
  const ours = sa.genAddressSeed(s.user_salt, s.claim_name, s.claim_value, s.aud);
  assert.equal(ours, sui.genAddressSeed(BigInt(s.user_salt), s.claim_name, s.claim_value, s.aud));
  assert.equal(ours.toString(), inputs.addressSeed);

  const kp = Ed25519Keypair.generate();
  const pub = kp.getPublicKey().toRawBytes();
  for (const [maxEpoch, rnd] of [[10, "1234"], [1_800_000_000, sa.generateRandomness().toString()]]) {
    assert.equal(sa.generateNonce(pub, maxEpoch, rnd), sui.generateNonce(kp.getPublicKey(), maxEpoch, rnd));
  }
});

test("passkey: precompile, challenge, nënshkrimi", async () => {
  const priv = new Uint8Array(32).fill(7);
  const signer = sa.localPasskey(priv);
  const nonce = 3n;
  const [pre, ix] = await sa.passkeyOps.setThreshold(programId, signer, wallet, nonce, 1_000_000n);
  assert.equal(pre.programId.toBase58(), sa.SECP256R1_PROGRAM_ID.toBase58());
  const d = pre.data;
  const u16 = (i) => d[2 + 2 * i] | (d[3 + 2 * i] << 8);
  const pub = d.subarray(u16(2), u16(2) + 33);
  const sig = d.subarray(u16(0), u16(0) + 64);
  const msg = d.subarray(u16(4), u16(4) + u16(5));
  assert.deepEqual(Uint8Array.from(pub), signer.publicKey);
  const { sha256 } = await import("@noble/hashes/sha256");
  assert.ok(p256.verify(sig, sha256(msg), pub, { lowS: true }));
  // clientDataJSON brenda instruksionit dhe challenge-i i pritur
  const cdLen = ix.data[1] | (ix.data[2] << 8);
  const cd = JSON.parse(Buffer.from(ix.data.subarray(3, 3 + cdLen)).toString());
  const action = sa.actionHash(sa.Op.SetThreshold, new Uint8Array(0), new sa.Writer().u64(1_000_000n).finish(), ix.keys);
  const ch = sa.passkeyChallenge(wallet, nonce, action);
  assert.equal(cd.challenge, Buffer.from(ch).toString("base64url"));
  assert.equal(cd.type, "webauthn.get");
});

test("dekodimi i gabimeve", () => {
  assert.equal(sa.decodeError("custom program error: 0x21"), "SpendLimitExceeded");
  assert.equal(sa.decodeError({ InstructionError: [0, { Custom: 45 }] }), "AboveThreshold");
});
