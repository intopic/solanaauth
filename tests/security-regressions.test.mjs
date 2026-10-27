import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionMessage, VersionedTransaction, ComputeBudgetProgram } from '@solana/web3.js';
import * as sa from '@solanaauth/core';
import { BrowserLogin } from '@solanaauth/react';
import { loginAgent, transferChecked } from '@solanaauth/agent';
import { SolanaAuthWallet, instructionsOf } from '@solanaauth/wallet-standard';
import { MemoryStore, FileStore, Platform, Paymaster, SponsorError, loadPricing, effectivePlan, handleStripeEvent, rpcChain } from '../services/platform/dist/index.js';
import { planSync } from '../services/jwk-oracle/dist/index.js';
import { x402Handler } from '../examples/agent-x402/facilitator.mjs';
import { RateLimiter, requestIp } from '../services/prover/dist/rate-limit.js';

const now = 1_800_000_000;
const pricing = loadPricing(fileURLToPath(new URL('../config/pricing.json', import.meta.url)));
const key = () => Keypair.generate().publicKey;
test('patched RPC client retains the web3 HTTP JSON-RPC contract', async () => {
  const connection = new Connection('http://localhost:8899', { fetch: async (_url, init) => {
    const request = JSON.parse(init.body);
    assert.equal(request.jsonrpc, '2.0');
    assert.equal(request.method, 'getBalance');
    assert.equal(typeof request.id, 'string');
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: { context: { slot: 1 }, value: 42 } }));
  } });
  assert.equal(await connection.getBalance(key()), 42);
});
function setup({ balance = 6_000_000, daily = 100, lamports = 10000, store = new MemoryStore() } = {}) {
  const platform = new Platform({ store, pricing, network: 'mainnet', saltMasterSeed: new Uint8Array(32), now: () => now });
  const app = platform.createApp('owner', 'security');
  const { key: apiKey } = platform.createApiKey(app);
  platform.update(app, { paymaster: { enabled: true, globalDailyTx: daily, perUserDailyTx: daily, allowedPrograms: [SystemProgram.programId.toBase58()] } });
  store.addLedger({ appId: app.id, ts: now, kind: 'deposit', microUsd: balance, ref: 'initial' });
  const feePayer = Keypair.generate();
  const programId = key();
  let sent = 0;
  const chain = { simulate: async () => ({ err: null, before: 100_000_000, after: 100_000_000 - lamports, logs: [] }), send: async () => { await new Promise(r => setTimeout(r, 10)); return `signature-${++sent}`; } };
  const options = { store, pricing, chain, feePayer, programId, network: 'mainnet', price: { solUsd: async () => 100 }, now: () => now };
  const pm = new Paymaster(options);
  const raw = (wallet = key()) => {
    const eph = Keypair.generate();
    const tx = new Transaction({ feePayer: feePayer.publicKey, recentBlockhash: PublicKey.default.toBase58() });
    tx.add(sa.revokeSessionSelf(programId, eph.publicKey, wallet));
    tx.partialSign(eph);
    return tx.serialize({ requireAllSignatures: false });
  };
  return { store, platform, app, apiKey, pm, raw, options, chain, sent: () => sent };
}

test('parallel requests cannot exceed the daily quota or overdraw a deposit', async () => {
  for (const config of [{ daily: 1 }, { balance: 2_000_000, lamports: 20_000_000 }]) {
    const s = setup(config);
    const result = await Promise.allSettled([s.pm.sponsor(s.apiKey, s.raw()), s.pm.sponsor(s.apiKey, s.raw())]);
    assert.equal(result.filter(r => r.status === 'fulfilled').length, 1);
    assert.equal(result.filter(r => r.status === 'rejected').length, 1);
    assert.equal(s.sent(), 1);
    assert.ok(s.app.balanceMicroUsd >= 0);
    assert.equal(s.store.ledger(s.app.id).filter(e => e.kind === 'charge').length, 1);
  }
});

test('retries and concurrent identical requests settle once across paymaster instances', async () => {
  const s = setup();
  const other = new Paymaster(s.options);
  const raw = s.raw();
  const results = await Promise.all([s.pm.sponsor(s.apiKey, raw), other.sponsor(s.apiKey, raw)]);
  assert.deepEqual(results[0], results[1]);
  assert.deepEqual(await s.pm.sponsor(s.apiKey, raw), results[0]);
  assert.equal(s.sent(), 1);
  assert.equal(s.app.balanceMicroUsd, 5_999_000);
});

test('an ambiguous submission retains its reservation across restart and retries the exact signed bytes', async () => {
  const path = join(mkdtempSync(join(tmpdir(), 'solanaauth-')), 'store.json');
  const s = setup({ balance: 2_000_000, store: new FileStore(path) });
  let submitted;
  s.chain.send = async raw => { submitted = Buffer.from(raw); throw new Error('transport disconnected after submit'); };
  const raw = s.raw();
  await assert.rejects(s.pm.sponsor(s.apiKey, raw), /transport/);
  assert.equal(s.store.pending(s.app.id).length, 1);
  const restored = new FileStore(path);
  const options = { ...s.options, store: restored, chain: { ...s.chain, send: async bytes => { assert.deepEqual(Buffer.from(bytes), submitted); return 'recovered'; } } };
  const pm = new Paymaster(options);
  await assert.rejects(pm.sponsor(s.apiKey, s.raw()), e => e.code === 'DepositExhausted');
  const r = await pm.sponsor(s.apiKey, raw);
  assert.equal(r.signature, 'recovered');
  assert.equal(restored.pending(s.app.id).length, 0);
  assert.equal(restored.ledger(s.app.id).filter(e => e.kind === 'charge').length, 1);
});

test('confirmed failures release reservations without charging simulated rent', async () => {
  const s = setup();
  s.chain.send = async () => { throw new SponsorError('TransactionFailed', 'instruction error', 422); };
  await assert.rejects(s.pm.sponsor(s.apiKey, s.raw()), e => e.code === 'TransactionFailed');
  assert.equal(s.store.pending(s.app.id).length, 0);
  assert.equal(s.app.balanceMicroUsd, 6_000_000);
  const tx = Transaction.from(s.raw());
  tx.partialSign(s.options.feePayer);
  const chain = rpcChain({ getSignatureStatuses: async () => ({ value: [null] }), sendRawTransaction: async () => 'failed', confirmTransaction: async () => ({ value: { err: { InstructionError: [0, 'Custom'] } } }) });
  await assert.rejects(chain.send(tx.serialize()), e => e.code === 'TransactionFailed');
});

test('RPC retries find an already confirmed signature without rebroadcasting an expired transaction', async () => {
  const s = setup();
  const tx = Transaction.from(s.raw());
  tx.partialSign(s.options.feePayer);
  let lookedUp;
  const chain = rpcChain({
    getSignatureStatuses: async (signatures, options) => {
      assert.equal(options.searchTransactionHistory, true);
      lookedUp = signatures[0];
      return { value: [{ err: null, confirmationStatus: 'confirmed' }] };
    },
    sendRawTransaction: async () => assert.fail('must not rebroadcast'),
    confirmTransaction: async () => assert.fail('already confirmed'),
  });
  assert.equal(await chain.send(tx.serialize()), lookedUp);
  assert.equal(typeof lookedUp, 'string');
  assert.ok(lookedUp.length > 64);
});

test('compute budget rejects duplicate, malformed, deprecated and uncapped batch fees', () => {
  const valid = ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000_000n });
  assert.throws(() => sa.validateComputeBudget([valid, valid], 1_000_000n, 2_000_000n), /duplicate/);
  assert.throws(() => sa.validateComputeBudget([{ ...valid, data: Buffer.from([3]) }], 1_000_000n, 2_000_000n), /unsupported/);
  assert.throws(() => sa.validateComputeBudget([{ ...valid, data: Buffer.from([0,0,0,0,0]) }], 1_000_000n, 2_000_000n), /unsupported/);
  assert.throws(() => sa.validateComputeBudget([valid], 1_000_000n, 200_000n), /total priority fee/);
  sa.validateComputeBudget([ComputeBudgetProgram.setComputeUnitLimit({ units: 100_000 }), valid], 1_000_000n, 100_000n);
});

test('settlement uses confirmed cost and unused reservation is released', async () => {
  const s = setup();
  s.chain.spent = async () => 9000;
  const r = await s.pm.sponsor(s.apiKey, s.raw());
  assert.equal(r.chargedMicroUsd, 900);
  assert.equal(r.lamports, 9000);
  assert.equal(s.store.pending(s.app.id).length, 0);
});

test('paymaster rejects mixed wallets and counts every sponsored account operation', () => {
  const s = setup();
  const eph = Keypair.generate();
  const tx = new Transaction({ feePayer: s.options.feePayer.publicKey });
  for (const wallet of [key(), key()]) tx.add(sa.execute(s.options.programId, eph.publicKey, wallet, [SystemProgram.transfer({ fromPubkey: sa.vaultAddress(s.options.programId, wallet), toPubkey: key(), lamports: 1 })]));
  assert.throws(() => s.pm.inspect(s.app, tx), e => e.code === 'MixedWallets');
  const wallet = key();
  const same = new Transaction({ feePayer: s.options.feePayer.publicKey });
  for (let i = 0; i < 2; i++) same.add(sa.openSession(s.options.programId, s.options.feePayer.publicKey, { wallet, sessionKey: key(), jwk: key() }, new Uint8Array(), { expiresIn: 60, allowedPrograms: [], limits: [] }));
  assert.equal(s.pm.inspect(s.app, same).createsAccounts, 2);
  const revoke = new Transaction({ feePayer: s.options.feePayer.publicKey }).add(sa.revokeSessionSelf(s.options.programId, eph.publicKey, wallet));
  assert.equal(s.pm.inspect(s.app, revoke).subject, wallet.toBase58());
});

test('x402 rejects attacker-chosen priority fees before signing; ordinary payments still pass', async () => {
  const feePayer = Keypair.generate();
  const eph = Keypair.generate();
  const wallet = key();
  const programId = key();
  const mint = key();
  const payTo = key();
  const ataProgram = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
  const ata = owner => PublicKey.findProgramAddressSync([owner.toBuffer(), sa.TOKEN_PROGRAM_ID.toBuffer(), mint.toBuffer()], ataProgram)[0];
  const vault = sa.vaultAddress(programId, wallet);
  let sent = 0;
  const handler = x402Handler({ programId, feePayer, mint, payTo, price: 1n, decimals: 6, network: 'solana-devnet', chain: { send: async raw => { assert.ok(Transaction.from(raw).verifySignatures()); sent++; return 'sig'; } }, serve: async () => ({ ok: true }) });
  for (const malicious of [true, false]) {
    const tx = new Transaction({ feePayer: feePayer.publicKey, recentBlockhash: PublicKey.default.toBase58() });
    if (malicious) tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }), ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000_000_000n }));
    tx.add(sa.execute(programId, eph.publicKey, wallet, [transferChecked(ata(vault), mint, ata(payTo), vault, 1n, 6)]));
    tx.partialSign(eph);
    const header = Buffer.from(JSON.stringify({ x402Version: 1, scheme: 'exact', network: 'solana-devnet', payload: { transaction: tx.serialize({ requireAllSignatures: false }).toString('base64') } })).toString('base64');
    let status;
    const res = { writeHead(s) { status = s; return this; }, end() {} };
    await handler({ url: '/resource', headers: { 'x-payment': header } }, res);
    assert.equal(status, malicious ? 402 : 200);
  }
  assert.equal(sent, 1);
});

test('Apple uses its supported browser flow and is rejected before starting an unsupported loopback flow', async () => {
  const url = new URL(sa.SolanaAuth.oauthUrl({ provider: 'apple', clientId: 'app', redirectUri: 'https://example.com', nonce: 'n' }));
  assert.equal(url.searchParams.get('response_type'), 'code id_token');
  assert.equal(url.searchParams.has('scope'), false);
  assert.equal(url.searchParams.get('response_mode'), 'fragment');
  await assert.rejects(loginAgent({ provider: 'apple' }), /HTTPS/);
});

test('expired paid plans fall back to free quotas and pricing at the exact boundary', () => {
  const s = setup();
  handleStripeEvent(s.store, { type: 'checkout.session.completed', data: { object: { id: 'checkout', payment_status: 'paid', amount_total: 4900, metadata: { appId: s.app.id, kind: 'plan', plan: 'starter' } } } }, now);
  assert.equal(effectivePlan(s.app, s.app.paidUntil - 1), 'starter');
  assert.equal(effectivePlan(s.app, s.app.paidUntil), 'free');
  assert.equal(effectivePlan(s.app, s.app.paidUntil + 1), 'free');
});

test('numeric writers reject negative, overflowing, and unsafe policy values', () => {
  for (const n of [-1n, 2n ** 64n, Number.MAX_SAFE_INTEGER + 1]) assert.throws(() => new sa.Writer().u64(n), RangeError);
  for (const n of [-1, 2 ** 32, 1.5]) assert.throws(() => new sa.Writer().u32(n), RangeError);
  for (const n of [-(2n ** 63n) - 1n, 2n ** 63n]) assert.throws(() => new sa.Writer().i64(n), RangeError);
  assert.throws(() => sa.encodePolicy({ expiresIn: 60, allowedPrograms: [], limits: [sa.solLimit(-1n, 60)] }), RangeError);
  assert.equal(Buffer.from(new sa.Writer().u64(2n ** 64n - 1n).finish()).readBigUInt64LE(), 2n ** 64n - 1n);
});

test('expired JWKs are renewed and mismatching pending keys are never silently applied', async () => {
  const d = new Uint8Array(192);
  d[0] = 2;
  d[72] = 1;
  const view = new DataView(d.buffer);
  view.setBigInt64(112, 1n, true);
  view.setBigInt64(120, 2n, true);
  const chain = { now: async () => now, getAccountData: async () => d };
  const options = { programId: key(), oracle: key(), payer: key(), validitySecs: 3600 };
  const jwks = [{ kty: 'RSA', kid: 'k', n: 'AQ', e: 'AQAB' }];
  assert.equal((await planSync(chain, 'https://accounts.google.com', jwks, options))[0].kind, 'propose');
  d[3] = 1;
  assert.equal((await planSync(chain, 'https://accounts.google.com', jwks, options))[0].kind, 'propose');
  d[4] = 1;
  assert.equal((await planSync(chain, 'https://accounts.google.com', jwks, options))[0].kind, 'skip');
});

test('pricing uses a filesystem path on Windows and logout retains retry credentials after failure', async () => {
  assert.ok(loadPricing().plans.free);
  const data = new Map();
  const session = { wallet: key(), vault: key(), session: key(), sessionKey: Keypair.generate(), expiresAt: 9_000_000_000, identity: new Uint8Array(32) };
  data.set('solanaauth:session', sa.serializeSession(session));
  const storage = { getItem: k => data.get(k) ?? null, setItem: (k,v) => data.set(k,v), removeItem: k => data.delete(k) };
  const auth = { revoke: async () => { throw new Error('RPC unavailable'); } };
  const login = new BrowserLogin(auth, { storage });
  await assert.rejects(login.logout(true), /RPC unavailable/);
  assert.ok(data.has('solanaauth:session'));
  auth.revoke = async () => 'confirmed';
  assert.equal(await login.logout(true), 'confirmed');
  assert.equal(data.has('solanaauth:session'), false);
});

test('wallet amounts are lossless and attaching a passkey preserves OAuth credentials', async () => {
  const ts = await import('typescript');
  const dir = mkdtempSync(fileURLToPath(new URL('../apps/wallet/src/.security-test-', import.meta.url)));
  const oldWindow = globalThis.window;
  globalThis.window = { location: { hostname: 'localhost' } };
  try {
    const source = readFileSync(new URL('../apps/wallet/src/wallet.ts', import.meta.url), 'utf8')
      .replace('import.meta.env', '{}').replace('from "@solanaauth/core";', 'from "./core.mjs";');
    writeFileSync(join(dir, 'core.mjs'), 'export * from "@solanaauth/core"; export const discoverBrowserPasskey = async () => globalThis.__testPasskey;');
    writeFileSync(join(dir, 'wallet.mjs'), ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText);
    const wallet = await import(pathToFileURL(join(dir, 'wallet.mjs')).href);
    assert.equal(wallet.fmt(10n, 0), '10');
    assert.equal(wallet.fmt(100n, 2), '1');
    assert.equal(wallet.parseAmount('1.25', 2), 125n);
    for (const text of ['1.2.3', '-1', '1e9', '18446744073709551616']) assert.throws(() => wallet.parseAmount(text, 0));
    const state = { wallet: key(), zk: { block: new Uint8Array([1]) }, zkKey: Keypair.generate(), session: { proof: 'preserved' }, passkey: null };
    wallet.connection.getAccountInfo = async () => null;
    const signer = { credential: 'stubbed WebAuthn assertion' };
    globalThis.__testPasskey = { wallet: state.wallet, signer };
    const attached = await wallet.attachPasskey(state);
    assert.equal(attached.zk, state.zk);
    assert.equal(attached.zkKey, state.zkKey);
    assert.equal(attached.session, state.session);
    assert.equal(attached.passkey, signer);
    globalThis.__testPasskey = { wallet: key(), signer };
    await assert.rejects(wallet.attachPasskey(state), /portofoli tjetër/);
  } finally {
    globalThis.window = oldWindow;
    delete globalThis.__testPasskey;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Wallet Standard v0 decoding works without Node globals and SAA signatures use their own feature', async () => {
  const session = { wallet: key(), vault: key(), session: key(), sessionKey: Keypair.generate(), expiresAt: now + 60, identity: new Uint8Array(32) };
  const wallet = new SolanaAuthWallet({ programId: key() }, async () => session, session);
  assert.equal(wallet.features['solana:signMessage'], undefined);
  const [r] = await wallet.features['solanaauth:session'].signMessage({ account: wallet.accounts[0], message: new Uint8Array([1]) });
  assert.equal(r.signatureType, sa.SIGNATURE_TYPE);
  await assert.rejects(wallet.features['solanaauth:session'].signMessage({ account: { address: key().toBase58() }, message: new Uint8Array() }), /panjohur/);
  const payer = key();
  const message = new TransactionMessage({ payerKey: payer, recentBlockhash: PublicKey.default.toBase58(), instructions: [SystemProgram.transfer({ fromPubkey: payer, toPubkey: key(), lamports: 1 })] }).compileToV0Message();
  const bytes = new VersionedTransaction(message).serialize();
  const saved = globalThis.Buffer;
  try { delete globalThis.Buffer; assert.equal(instructionsOf(bytes).instructions.length, 1); }
  finally { globalThis.Buffer = saved; }
});

test('rate limits ignore spoofed forwarding headers, expire entries and fail closed at capacity', () => {
  const req = { socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-for': '8.8.8.8' } };
  assert.equal(requestIp(req), '127.0.0.1');
  assert.equal(requestIp(req, ['127.0.0.1']), '8.8.8.8');
  let clock = 0;
  const limit = new RateLimiter(1, 2, () => clock);
  assert.equal(limit.allow('a'), true);
  assert.equal(limit.allow('a'), false);
  assert.equal(limit.allow('b'), true);
  assert.equal(limit.allow('c'), false);
  clock = 60000;
  assert.equal(limit.allow('c'), true);
});

test('real salt/prover HTTP servers enforce the limit despite changing X-Forwarded-For', async () => {
  for (const service of ['salt', 'prover']) {
    const child = spawn(process.execPath, [fileURLToPath(new URL(`../services/${service}/dist/server.js`, import.meta.url))], { env: { ...process.env, PORT: '0', ALLOWED_AUDIENCES: 'app', RATE_LIMIT_PER_MIN: '1', SALT_MASTER_SEED: '11'.repeat(32), TRUSTED_PROXIES: '' }, stdio: ['ignore','pipe','pipe'] });
    try {
      const port = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('server startup timeout')), 10000);
        let output = '';
        child.on('error', reject);
        child.stdout.on('data', c => { output += c; const match = /port=(\d+)/.exec(output); if (match) { clearTimeout(timer); resolve(Number(match[1])); } });
        child.on('exit', code => { clearTimeout(timer); reject(new Error(`server exited: ${code}`)); });
      });
      const url = `http://127.0.0.1:${port}/${service === 'salt' ? 'salt' : 'v1'}`;
      for (let i = 0; i < 3; i++) {
        const r = await fetch(url, { method: 'POST', headers: { 'x-forwarded-for': `10.0.0.${i + 1}` }, body: '{}' });
        assert.equal(r.status, i === 0 ? 400 : 429);
        await r.text();
      }
    } finally { const exited = once(child, 'exit'); child.kill(); await exited; }
  }
});
