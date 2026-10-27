import { test } from "node:test";
import assert from "node:assert/strict";

import { checkRequest } from "../dist/index.js";

const now = 1_800_000_000;
const jwt = (claims) => ["e30", Buffer.from(JSON.stringify(claims)).toString("base64url"), "sig"].join(".");
const limits = { allowedAudiences: ["app"], maxSessionSecs: 86400 };
const req = (o = {}) => ({
  jwt: jwt({ aud: "app", exp: now + 100 }),
  extendedEphemeralPublicKey: "AA==",
  maxEpoch: String(now + 3600),
  jwtRandomness: "1",
  salt: "2",
  keyClaimName: "sub",
  ...o,
});

test("pranon kërkesën e rregullt", () => {
  assert.equal(checkRequest(req(), limits, now).maxEpoch, String(now + 3600));
});

test("refuzon", () => {
  const status = (r) => { try { checkRequest(r, limits, now); return 200; } catch (e) { return e.status; } };
  assert.equal(status(req({ jwt: jwt({ aud: "tjetër" }) })), 403);
  assert.equal(status(req({ jwt: jwt({ aud: "app", exp: now - 3600 }) })), 400);
  assert.equal(status(req({ maxEpoch: String(now - 1) })), 400);
  assert.equal(status(req({ maxEpoch: String(now + 2 * 86400) })), 400);
  assert.equal(status(req({ keyClaimName: "email" })), 400);
  assert.equal(status(req({ salt: undefined })), 400);
  assert.equal(status({}), 400);
});
