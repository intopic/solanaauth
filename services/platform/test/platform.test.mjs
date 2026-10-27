import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { createServer } from "node:http";
import { Keypair } from "@solana/web3.js";
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from "jose";

import {
  MemoryStore, OwnerAuth, Platform, USDC_MINT, createHandler, creditDeposits, handleStripeEvent, invoice, loadPricing, monthRange, verifyStripeSignature,
} from "../dist/index.js";

const root = new URL("../../../", import.meta.url);
const pricing = loadPricing(new URL("config/pricing.json", root).pathname);
const ISS = "https://accounts.google.com";

async function issuer() {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256" };
  const keys = createLocalJWKSet({ keys: [jwk] });
  const sign = (claims, aud = "web-client") =>
    new SignJWT({ nonce: "n", ...claims }).setProtectedHeader({ alg: "RS256", kid: "k1" }).setIssuer(ISS).setAudience(aud)
      .setIssuedAt().setExpirationTime("1h").sign(privateKey);
  return { keys, sign };
}

test("salt përmes aplikacionit: aud nga dashboard-i, MAU, kuota e planit Falas", async () => {
  const { keys, sign } = await issuer();
  const store = new MemoryStore();
  const now = Math.floor(Date.now() / 1000);
  const small = structuredClone(pricing);
  small.plans.free.includedMau = 2;
  const p = new Platform({ store, pricing: small, network: "mainnet", saltMasterSeed: new Uint8Array(32).fill(3), keys: { [ISS]: keys }, now: () => now });
  const app = p.createApp("o@x.com", "A");
  const { key } = p.createApiKey(app);
  await assert.rejects(p.salt(key, await sign({ sub: "u1" })), /client ID/);
  p.update(app, { oauth: { google: ["web-client"], apple: [] } });
  const a = await p.salt(key, await sign({ sub: "u1" }));
  assert.equal(a.salt, (await p.salt(key, await sign({ sub: "u1" }))).salt);
  await assert.rejects(p.salt(key, await sign({ sub: "u1" }, "tjetër")), (e) => e.status === 401);
  await assert.rejects(p.salt("sa_live_gabim", await sign({ sub: "u1" })), (e) => e.status === 401);
  await p.salt(key, await sign({ sub: "u2" }), "agent");
  await assert.rejects(p.salt(key, await sign({ sub: "u3" })), (e) => e.status === 402);
  await p.salt(key, await sign({ sub: "u1" })); // përdorues ekzistues: lejohet
  const [from, to] = monthRange(new Date(now * 1000).toISOString().slice(0, 7));
  const inv = invoice(small, "free", "m", store.usage(app.id, from, to));
  assert.deepEqual([inv.usage.mau, inv.usage.agents, inv.totalUsd], [2, 1, 0]);
  // Çelësi i revokuar s'punon më.
  p.revokeApiKey(app, app.apiKeys[0].id);
  await assert.rejects(p.salt(key, await sign({ sub: "u1" })), (e) => e.status === 401);
});

test("fatura nga konfigurimi i çmimeve", () => {
  const ev = (kind, n, net = "mainnet") => Array.from({ length: n }, (_, i) => ({ appId: "a", ts: 0, kind, subject: `${kind}${i}`, network: net }));
  const usage = [...ev("login", 6000), ...ev("agent", 60), ...ev("login", 999, "devnet")];
  const s = invoice(pricing, "starter", "2026-10", usage);
  assert.deepEqual(s.lines.map((l) => [l.quantity, l.amountUsd]), [[1, 49], [1000, 30], [10, 1]]);
  assert.equal(s.totalUsd, 80);
  const g = invoice(pricing, "growth", "2026-10", usage);
  assert.equal(g.totalUsd, 199);
  const f = invoice(pricing, "free", "2026-10", usage);
  assert.equal(f.totalUsd, 0);
  assert.equal(f.overQuota, true);
  assert.equal(invoice(pricing, "enterprise", "2026-10", usage).contract, true);
});

test("Stripe: nënshkrimi i webhook-ut dhe idempotenca", () => {
  const secret = "whsec_test";
  const payload = JSON.stringify({ x: 1 });
  const t = 1_800_000_000;
  const sig = createHmac("sha256", secret).update(`${t}.${payload}`).digest("hex");
  assert.ok(verifyStripeSignature(payload, `t=${t},v1=${sig}`, secret, t + 10));
  assert.ok(!verifyStripeSignature(payload, `t=${t},v1=${sig}`, secret, t + 1000));
  assert.ok(!verifyStripeSignature(payload + " ", `t=${t},v1=${sig}`, secret, t));
  assert.ok(!verifyStripeSignature(payload, `t=${t},v1=${sig}`, "tjetër", t));

  const store = new MemoryStore();
  const p = new Platform({ store, pricing, network: "mainnet", saltMasterSeed: new Uint8Array(32) });
  const app = p.createApp("o", "A");
  const ev = (id, kind, amount, plan) => ({ type: "checkout.session.completed", data: { object: { id, payment_status: "paid", amount_total: amount, metadata: { appId: app.id, kind, ...(plan ? { plan } : {}) } } } });
  assert.equal(handleStripeEvent(store, ev("cs_1", "deposit", 2500)), "deposit");
  assert.equal(handleStripeEvent(store, ev("cs_1", "deposit", 2500)), "duplicate");
  assert.equal(app.balanceMicroUsd, 25_000_000);
  assert.equal(handleStripeEvent(store, ev("cs_2", "plan", 4900, "starter"), 100), "plan");
  assert.equal(app.plan, "starter");
  assert.equal(app.paidUntil, 100 + 30 * 86400);
  assert.equal(handleStripeEvent(store, ev("cs_2", "plan", 4900, "starter"), 100), "duplicate");
  assert.equal(app.paidUntil, 100 + 30 * 86400);
});

test("depozitat USDC/SOL në Solana: kreditim një herë për nënshkrim", async () => {
  const store = new MemoryStore();
  const p = new Platform({ store, pricing, network: "mainnet", saltMasterSeed: new Uint8Array(32) });
  const app = p.createApp("o", "A");
  const treasury = Keypair.generate().publicKey;
  const reference = Keypair.generate().publicKey;
  const mint = USDC_MINT.mainnet;
  const chain = {
    signaturesFor: async () => ["s1", "s2", "s3"],
    credited: async (sig) => ({
      s1: { lamports: 0, tokens: { [mint.toBase58()]: 12_500_000n }, ok: true },
      s2: { lamports: 100_000_000, tokens: {}, ok: true },
      s3: { lamports: 0, tokens: { [mint.toBase58()]: 1n }, ok: false },
    })[sig],
  };
  const price = { solUsd: async () => 150 };
  const o = { appId: app.id, reference, treasury, usdcMint: mint };
  assert.equal(await creditDeposits(store, chain, price, o), 12_500_000 + 15_000_000);
  assert.equal(await creditDeposits(store, chain, price, o), 0);
  assert.equal(app.balanceMicroUsd, 27_500_000);
});

test("HTTP: hyrja në dashboard, aplikacioni, çelësat, përdorimi", async () => {
  const { keys, sign } = await issuer();
  const store = new MemoryStore();
  const platform = new Platform({ store, pricing, network: "devnet", saltMasterSeed: new Uint8Array(32), keys: { [ISS]: keys } });
  const auth = new OwnerAuth({ secret: new Uint8Array(32).fill(5), googleClientId: "dash", keys });
  const server = createServer(createHandler({ platform, auth }));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body, headers = {}) => {
    const r = await fetch(base + path, { method, headers: { "content-type": "application/json", ...headers }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, body: await r.json() };
  };
  try {
    assert.equal((await call("GET", "/apps")).status, 401);
    assert.equal((await call("POST", "/auth/google", { id_token: await sign({ sub: "o", email: "Dev@X.com", email_verified: true }) })).status, 401, "aud tjetër");
    const login = await call("POST", "/auth/google", { id_token: await sign({ sub: "o", email: "Dev@X.com", email_verified: true }, "dash") });
    assert.equal(login.body.owner, "dev@x.com");
    const H = { authorization: `Bearer ${login.body.token}` };
    const created = await call("POST", "/apps", { name: "Loja" }, H);
    assert.equal(created.status, 201);
    const id = created.body.id;
    const k = await call("POST", `/apps/${id}/keys`, {}, H);
    assert.match(k.body.key, /^sa_test_/);
    assert.equal(k.body.hash, undefined);
    const patched = await call("PATCH", `/apps/${id}`, { oauth: { google: ["web-client"] }, paymaster: { enabled: true, allowedPrograms: ["11111111111111111111111111111111"] } }, H);
    assert.equal(patched.body.paymaster.enabled, true);
    assert.equal((await call("GET", `/apps/${id}`, null, H)).body.apiKeys[0].hash, undefined);
    // Aplikacioni i një pronari tjetër s'shihet.
    const other = auth.sign("tjeter@x.com", Math.floor(Date.now() / 1000) + 60);
    assert.equal((await call("GET", `/apps/${id}`, null, { authorization: `Bearer ${other}` })).status, 404);
    // API publike me çelësin.
    const salt = await call("POST", "/v1/salt", { jwt: await sign({ sub: "u1" }) }, { "x-api-key": k.body.key });
    assert.equal(salt.status, 200);
    assert.equal((await call("GET", "/v1/paymaster", null, { "x-api-key": k.body.key })).body.enabled, false, "pa paymaster të konfiguruar");
    assert.equal((await call("GET", "/v1/templates")).body.length, 4);
    const usage = await call("GET", `/apps/${id}/usage`, null, H);
    assert.equal(usage.body.usage.mau, 0, "devnet nuk numërohet");
    assert.equal((await call("POST", `/apps/${id}/checkout`, { kind: "deposit", amountUsd: 10 }, H)).status, 503);
    await call("DELETE", `/apps/${id}/keys/${k.body.id}`, null, H);
    assert.equal((await call("POST", "/v1/salt", { jwt: await sign({ sub: "u1" }) }, { "x-api-key": k.body.key })).status, 401);
  } finally {
    server.close();
  }
});
