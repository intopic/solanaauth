import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Keypair, SystemProgram, Transaction, TransactionInstruction } from '@solana/web3.js';
import { getTransactionDecoder } from '@solana/kit';
import * as sa from '@solanaauth/core';

const so = process.env.SOLANAAUTH_SO ?? fileURLToPath(new URL('../../../programs/solanaauth/target/deploy/solanaauth.so', import.meta.url));
if (process.env.CI && !existsSync(so)) throw new Error(`Missing SBF artifact: ${so}`);
const runnable = ['linux', 'darwin'].includes(process.platform) && existsSync(so);
test('new vault token accounts cannot retain a delegate; rollback protects future deposits', { skip: !runnable && 'requires current solanaauth.so and Linux/macOS LiteSVM' }, async () => {
  const kit = await import('@solanaauth/testkit');
  const w = kit.world();
  const policy = { expiresIn: 3600, allowedPrograms: [sa.SYSTEM_PROGRAM_ID, sa.TOKEN_PROGRAM_ID, kit.ATA], limits: [sa.solLimit(10_000_000n, 3600)] };
  const { client, session } = await kit.fixtureLogin(w, { policy, feePayer: w.feePayer });
  w.svm.airdrop(kit.A(session.vault), 100_000_000n);
  const mint = kit.createMint(w.svm, w.feePayer);
  const source = kit.ata(session.vault, mint);
  const delegate = Keypair.generate();
  const create = new TransactionInstruction({ programId: kit.ATA, data: Buffer.from([1]), keys: [
    { pubkey: session.vault, isSigner: true, isWritable: true },
    { pubkey: source, isSigner: false, isWritable: true },
    { pubkey: session.vault, isSigner: false, isWritable: false },
    { pubkey: mint, isSigner: false, isWritable: false },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    { pubkey: kit.TOKEN, isSigner: false, isWritable: false },
  ] });
  const data = Buffer.alloc(9);
  data[0] = 4; // SPL Token Approve.
  data.writeBigUInt64LE(2n ** 64n - 1n, 1);
  const approve = new TransactionInstruction({ programId: kit.TOKEN, data, keys: [
    { pubkey: source, isSigner: false, isWritable: true },
    { pubkey: delegate.publicKey, isSigner: false, isWritable: false },
    { pubkey: session.vault, isSigner: true, isWritable: false },
  ] });
  await assert.rejects(client.execute(session, [create, approve], { feePayer: w.feePayer }), /0x24|Custom\(36\)|TokenInvariant/);
  assert.ok(!w.svm.getAccount(kit.A(source))?.data?.length, 'failed execute rolls back ATA creation');
  const setAuthority = (kind) => new TransactionInstruction({ programId: kit.TOKEN,
    data: Buffer.concat([Buffer.from([6, kind, 1]), delegate.publicKey.toBuffer()]),
    keys: [
      { pubkey: source, isSigner: false, isWritable: true },
      { pubkey: session.vault, isSigner: true, isWritable: false },
    ],
  });
  for (const kind of [2, 3]) { // AccountOwner, CloseAccount.
    await assert.rejects(client.execute(session, [create, setAuthority(kind)], { feePayer: w.feePayer }), /0x24|Custom\(36\)|TokenInvariant/);
    assert.ok(!w.svm.getAccount(kit.A(source))?.data?.length);
  }
  await client.execute(session, [create], { feePayer: w.feePayer });
  const account = w.svm.getAccount(kit.A(source));
  assert.equal(Buffer.from(account.data).readUInt32LE(72), 0, 'valid new ATA has no delegate');
  kit.mintTo(w.svm, w.feePayer, mint, session.vault, 1_000_000n);
  await assert.rejects(client.execute(session, [approve], { feePayer: w.feePayer }), /0x24|Custom\(36\)|TokenInvariant/);
  assert.equal(kit.tokenBalance(w.svm, source), 1_000_000n);
});
