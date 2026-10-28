import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Keypair, SystemProgram, Transaction } from '@solana/web3.js';
import { Clock } from 'litesvm';
import * as sa from '@solanaauth/core';
import * as kit from '@solanaauth/testkit';

const runnable = kit.available;
const options = { skip: !runnable && 'requires current SBF artifact' };
const transfer = (s, n, to) => SystemProgram.transfer({ fromPubkey: s.vault, toPubkey: to, lamports: n });
async function setup(policy) {
  const w = kit.world();
  const login = await kit.fixtureLogin(w, { policy, feePayer: w.feePayer });
  w.svm.airdrop(kit.A(login.session.vault), 100_000_000n);
  const execute = ixs => login.client.execute(login.session, ixs, { feePayer: w.feePayer });
  return { ...w, ...login, execute };
}
function advance(w, now) {
  const c = w.svm.getClock();
  w.svm.setClock(new Clock(c.slot, c.epochStartTimestamp, c.epoch, c.leaderScheduleEpoch, BigInt(now)));
}

test('V2 omitted restrictions allow programs/assets; explicit empty programs and zero caps reject', options, async () => {
  const to = Keypair.generate().publicKey;
  const free = await setup({ version: 2, expiresIn: 3600 });
  await free.execute([transfer(free.session, 1_000_000, to)]);
  const state = await sa.fetchSession(free.connection, free.session.session);
  assert.equal(state.version, 2);
  assert.equal(state.unrestrictedPrograms, true);
  assert.equal(state.unrestrictedAssets, true);
  assert.ok(!free.session.sessionKey.publicKey.equals(Keypair.fromSeed(sa.fromHex(kit.FX.ephemeral_private_key_hex)).publicKey));
  const blocked = await setup({ version: 2, expiresIn: 3600, allowedPrograms: [] });
  await assert.rejects(blocked.execute([transfer(blocked.session, 1, to)]), /0x20|Custom\(32\)/);
  const zero = await setup({ version: 2, expiresIn: 3600, limits: [{ mint: sa.SOL_MINT, maxPerExecute: 0n }] });
  await assert.rejects(zero.execute([transfer(zero.session, 1, to)]), /0x2f|Custom\(47\)/);
});

test('V2 per-execute and cumulative caps aggregate a batch; failures do not consume frequency', options, async () => {
  const w = await setup({ version: 2, expiresIn: 3600, limits: [{ mint: sa.SOL_MINT, amount: 10_000_000n, periodSecs: 3600, maxPerExecute: 6_000_000n }], frequency: { maxExecutions: 3, periodSecs: 3600 } });
  const to = Keypair.generate().publicKey;
  await assert.rejects(w.execute([transfer(w.session, 4_000_000, to), transfer(w.session, 3_000_000, to)]), /0x2f|Custom\(47\)/);
  assert.equal((await sa.fetchSession(w.connection, w.session.session)).frequency.executions, 0);
  assert.equal(w.svm.getBalance(kit.A(to)) ?? 0n, 0n);
  await w.execute([transfer(w.session, 6_000_000, to)]);
  await w.execute([transfer(w.session, 4_000_000, to)]);
  await assert.rejects(w.execute([transfer(w.session, 1, to)]), /0x21|Custom\(33\)/);
  const state = await sa.fetchSession(w.connection, w.session.session);
  assert.equal(state.frequency.executions, 2);
  assert.equal(state.limits[0].spent, 10_000_000n);
});

test('V2 execution frequency resets at its exact boundary and revocation blocks further use', options, async () => {
  const w = await setup({ version: 2, expiresIn: 3600, frequency: { maxExecutions: 1, periodSecs: 2 } });
  const to = Keypair.generate().publicKey;
  await w.execute([transfer(w.session, 1_000_000, to)]);
  await assert.rejects(w.execute([transfer(w.session, 1_000_000, to)]), /0x30|Custom\(48\)/);
  advance(w, 3);
  await w.execute([transfer(w.session, 1_000_000, to)]);
  await w.client.revoke(w.session, { feePayer: w.feePayer });
  await assert.rejects(w.execute([transfer(w.session, 1_000_000, to)]), /0x1f|Custom\(31\)/);
});

test('delegated key cannot reuse the public owner proof to reopen a broader session after revocation', options, async () => {
  const w = await setup({ version: 2, expiresIn: 3600, limits: [{ mint: sa.SOL_MINT, maxPerExecute: 0n }] });
  await w.client.revoke(w.session, { feePayer: w.feePayer });
  await w.client.send([sa.closeSession(w.programId, w.session.wallet, w.session.session)], w.session.sessionKey, w.feePayer);
  const zk = sa.encodeZkBlock(sa.normalizeInputs(kit.FX.inputs), kit.FX.max_epoch);
  const accounts = { wallet: w.session.wallet, sessionKey: w.session.sessionKey.publicKey, jwk: sa.jwkAddress(w.programId, w.iss, kit.FX.jwk.kid) };
  const legacy = { version: 1, expiresIn: 3600, allowedPrograms: [sa.SYSTEM_PROGRAM_ID], limits: [sa.solLimit(100_000_000n, 3600)] };
  await assert.rejects(w.client.send([sa.openSession(w.programId, w.feePayer.publicKey, accounts, zk, legacy)], w.session.sessionKey, w.feePayer), /0xa\b|Custom\(10\)/);
  const nextKey = Keypair.generate().publicKey;
  await assert.rejects(w.client.send([sa.openSession(w.programId, w.feePayer.publicKey, { ...accounts, delegatedKey: nextKey }, zk, { version: 2, expiresIn: 3600 })], w.session.sessionKey, w.feePayer), /0xa\b|Custom\(10\)/);
});
