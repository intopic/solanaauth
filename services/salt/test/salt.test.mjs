import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from "jose";

import { createSaltService, deriveSalt } from "../dist/index.js";

const ISS = "https://accounts.google.com";
const AUD = "123-app.apps.googleusercontent.com";
const seed = new Uint8Array(32).fill(1);

async function setup() {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256" };
  const salt = createSaltService({ masterSeed: seed, allowedAudiences: [AUD], keys: { [ISS]: createLocalJWKSet({ keys: [jwk] }) } });
  const sign = (claims, opts = {}) =>
    new SignJWT({ nonce: "n", ...claims })
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(opts.iss ?? ISS)
      .setAudience(opts.aud ?? AUD)
      .setSubject(opts.sub ?? "user-1")
      .setIssuedAt()
      .setExpirationTime(opts.exp ?? "1h")
      .sign(opts.key ?? privateKey);
  return { salt, sign };
}

test("salt deterministik, i ndryshëm për përdorues të ndryshëm, < 2^128", async () => {
  const { salt, sign } = await setup();
  const a = await salt(await sign({}));
  const b = await salt(await sign({}));
  const c = await salt(await sign({}, { sub: "user-2" }));
  assert.equal(a.salt, b.salt);
  assert.notEqual(a.salt, c.salt);
  assert.ok(BigInt(a.salt) < 2n ** 128n);
  assert.equal(a.salt, deriveSalt(seed, ISS, AUD, "user-1").toString());
});

test("refuzon JWT të pavlefshme", async () => {
  const { salt, sign } = await setup();
  const other = (await generateKeyPair("RS256")).privateKey;
  await assert.rejects(salt(await sign({}, { key: other })), (e) => e.status === 401);
  await assert.rejects(salt(await sign({}, { aud: "tjetër" })), (e) => e.status === 401);
  await assert.rejects(salt(await sign({}, { exp: Math.floor(Date.now() / 1000) - 3600 })), (e) => e.status === 401);
  await assert.rejects(salt(await sign({}, { iss: "https://evil.example" })), (e) => e.status === 400);
  await assert.rejects(salt("jo.jwt"), (e) => e.status === 400);
});
