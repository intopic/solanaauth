// Adapter-i Wallet Standard kundër programit të vërtetë: një dApp i zakonshëm ndërton një transfer
// me vault-in si nënshkrues dhe fee payer; adapter-i e mbështjell në `execute`. signMessage (SAA-1271).
import { test } from "node:test";
import assert from "node:assert/strict";
import { Keypair, LAMPORTS_PER_SOL, PublicKey, SystemProgram, Transaction, TransactionMessage, VersionedTransaction } from "@solana/web3.js";
import * as sa from "@solanaauth/core";
import { A, available, fixtureLogin, svmConnection, world } from "@solanaauth/testkit";

import { SolanaAuthWallet } from "../dist/index.js";

test("Wallet Standard: connect, signAndSendTransaction (legacy + v0), signMessage", { skip: !available && "mungon solanaauth.so" }, async () => {
  const w = world();
  const payer = Keypair.generate();
  w.svm.airdrop(A(payer.publicKey), 1_000_000_000n);
  const policy = { expiresIn: 3600, label: "dapp", allowedPrograms: [sa.SYSTEM_PROGRAM_ID], limits: [sa.solLimit(BigInt(LAMPORTS_PER_SOL), 3600)] };
  const { session } = await fixtureLogin(w, { policy, feePayer: payer });
  w.svm.airdrop(A(session.vault), 2_000_000_000n);

  // Klienti i adapter-it: paguan serveri i aplikacionit (Keypair si FeePayer).
  const connection = svmConnection(w.svm);
  const feePayer = {
    publicKey: payer.publicKey,
    submit: async (tx) => { tx.partialSign(payer); return connection.sendRawTransaction(tx.serialize()); },
  };
  const auth = new sa.SolanaAuth({ connection, programId: w.programId, proverUrl: "", saltUrl: "", feePayer });
  const wallet = new SolanaAuthWallet(auth, async () => session);
  const changes = [];
  wallet.features["standard:events"].on("change", (e) => changes.push(e.accounts.length));
  const { accounts } = await wallet.features["standard:connect"].connect();
  assert.equal(accounts[0].address, session.vault.toBase58());
  assert.deepEqual(changes, [1]);
  const account = accounts[0];

  // dApp-i: tx legacy, vault-i = fee payer dhe nënshkrues.
  const dest = Keypair.generate().publicKey;
  const legacy = new Transaction({ feePayer: session.vault, blockhash: "11111111111111111111111111111111", lastValidBlockHeight: 1 })
    .add(SystemProgram.transfer({ fromPubkey: session.vault, toPubkey: dest, lamports: 10_000_000 }));
  const [r1] = await wallet.features["solana:signAndSendTransaction"].signAndSendTransaction({
    account, chain: "solana:devnet", transaction: legacy.serialize({ requireAllSignatures: false, verifySignatures: false }),
  });
  assert.equal(r1.signature.length, 64);
  assert.equal(w.svm.getBalance(A(dest)), 10_000_000n);

  // v0.
  const msg = new TransactionMessage({ payerKey: session.vault, recentBlockhash: "11111111111111111111111111111111", instructions: [SystemProgram.transfer({ fromPubkey: session.vault, toPubkey: dest, lamports: 5_000_000 })] }).compileToV0Message();
  await wallet.features["solana:signAndSendTransaction"].signAndSendTransaction({ account, chain: "solana:devnet", transaction: new VersionedTransaction(msg).serialize() });
  assert.equal(w.svm.getBalance(A(dest)), 15_000_000n);

  // Politika vlen edhe për dApp-et: mbi limit refuzohet on-chain.
  const big = new Transaction({ feePayer: session.vault, blockhash: "11111111111111111111111111111111", lastValidBlockHeight: 1 })
    .add(SystemProgram.transfer({ fromPubkey: session.vault, toPubkey: dest, lamports: 1_500_000_000 }));
  await assert.rejects(wallet.features["solana:signAndSendTransaction"].signAndSendTransaction({ account, chain: "solana:devnet", transaction: big.serialize({ requireAllSignatures: false, verifySignatures: false }) }), /0x21|Custom\(33\)/);
  // Nënshkrues tjetër përveç vault-it → refuzim para dërgimit.
  const other = Keypair.generate().publicKey;
  const foreign = new Transaction({ feePayer: session.vault, blockhash: "11111111111111111111111111111111", lastValidBlockHeight: 1 })
    .add(SystemProgram.transfer({ fromPubkey: other, toPubkey: dest, lamports: 1 }));
  await assert.rejects(wallet.features["solana:signAndSendTransaction"].signAndSendTransaction({ account, chain: "solana:devnet", transaction: foreign.serialize({ requireAllSignatures: false, verifySignatures: false }) }), /vetëm vault-i/);

  // signMessage: verifikim SAA-1271 me sesionin on-chain.
  const message = new TextEncoder().encode("Hyr në dApp: nonce 42");
  const [m] = await wallet.features["solana:signMessage"].signMessage({ account, message });
  const sig = { wallet: session.wallet, session: session.session, signature: m.signature };
  assert.deepEqual(await sa.verifySessionMessage(connection, w.programId, sig, message, 2), { valid: true });
  assert.equal((await sa.verifySessionMessage(connection, w.programId, sig, new TextEncoder().encode("tjetër"), 2)).valid, false);
  assert.match((await sa.verifySessionMessage(connection, w.programId, sig, message, 100)).reason, /skaduar/);
  assert.match((await sa.verifySessionMessage(connection, new PublicKey(new Uint8Array(32).fill(1)), sig, message, 2)).reason, /programit/);
  await auth.revoke(session);
  assert.match((await sa.verifySessionMessage(connection, w.programId, sig, message, 2)).reason, /revokuar/);

  await wallet.features["standard:disconnect"].disconnect();
  assert.equal(wallet.accounts.length, 0);
});
