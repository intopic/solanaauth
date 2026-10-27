// Rrjedha e hyrjes në shfletues me salt/prover të simuluar dhe provën e fixture-it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { PublicKey } from "@solana/web3.js";
import * as sa from "@solanaauth/core";
import { createElement } from "react";
import { renderToString } from "react-dom/server";

import { BrowserLogin, SolanaAuthProvider, useSolanaAuth } from "../dist/index.js";

const root = new URL("../../../", import.meta.url);
const FX = JSON.parse(readFileSync(new URL("fixtures/proofs/google-mainnet-v1.json", root)));
const programId = new PublicKey(new Uint8Array(32).fill(9));

class Mem {
  m = new Map();
  getItem(k) { return this.m.get(k) ?? null; }
  setItem(k, v) { this.m.set(k, v); }
  removeItem(k) { this.m.delete(k); }
}

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");

test("start → finish: salt, provë, create_wallet, sesioni ruhet", async () => {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body) });
    if (url === "https://salt.test") return new Response(JSON.stringify({ salt: FX.address_seed_inputs.user_salt }));
    return new Response(JSON.stringify({ ...FX.inputs, addressSeed: FX.inputs.address_seed }));
  };
  const sent = [];
  const connection = {
    getAccountInfo: async () => null,
    getLatestBlockhash: async () => ({ blockhash: "11111111111111111111111111111111", lastValidBlockHeight: 1 }),
  };
  const auth = new sa.SolanaAuth({ connection, programId, proverUrl: "https://prover.test", saltUrl: "https://salt.test", fetch });
  const storage = new Mem();
  const policy = { expiresIn: 3600, label: "web", allowedPrograms: [sa.SYSTEM_PROGRAM_ID], limits: [sa.solLimit(1_000_000_000n, 86400)] };
  const login = new BrowserLogin(auth, {
    clientIds: { google: FX.address_seed_inputs.aud }, redirectUri: "https://app.test/cb", policy, storage,
    submit: async (tx) => { sent.push(tx); return "sig"; },
  });

  const url = new URL(login.start("google"));
  assert.equal(url.origin + url.pathname, "https://accounts.google.com/o/oauth2/v2/auth");
  const nonce = url.searchParams.get("nonce");
  const state = url.searchParams.get("state");

  const jwt = [b64({ alg: "RS256", kid: FX.jwk.kid }), b64({ iss: "https://accounts.google.com", aud: FX.address_seed_inputs.aud, sub: FX.address_seed_inputs.claim_value, nonce }), "x"].join(".");
  await assert.rejects(login.finish(`https://app.test/cb#id_token=${jwt}&state=tjetër`), /state/);
  const r = await login.finish(`https://app.test/cb#id_token=${jwt}&state=${state}`);
  assert.equal(r.created, true);
  assert.equal(r.signature, "sig");
  assert.equal(calls[1].body.keyClaimName, "sub");
  assert.equal(calls[1].body.jwtRandomness.length > 0, true);

  const { wallet } = auth.walletFor("https://accounts.google.com", FX.inputs.address_seed);
  assert.ok(r.session.wallet.equals(wallet));
  const ix = sent[0].instructions[0];
  assert.equal(ix.data[0], sa.Op.CreateWallet);
  assert.ok(login.current().wallet.equals(wallet));
  // E kaluar kohe → sesioni hiqet.
  assert.equal(login.current(r.session.expiresAt + 1), null);
  // Pa pending → finish refuzon (s'mund të ripërdoret fragmenti).
  await assert.rejects(login.finish(`https://app.test/cb#id_token=${jwt}&state=${state}`), /pritje/);
});

test("SolanaAuthProvider renderohet në server", () => {
  const Child = () => createElement("span", null, useSolanaAuth().status);
  const html = renderToString(
    createElement(SolanaAuthProvider, {
      config: { connection: null, programId, proverUrl: "", saltUrl: "" },
      clientIds: {}, redirectUri: "", policy: { expiresIn: 1, label: "", allowedPrograms: [], limits: [] },
    }, createElement(Child)),
  );
  assert.equal(html, "<span>idle</span>");
});
