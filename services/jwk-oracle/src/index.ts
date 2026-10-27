/**
 * Sinkronizimi i JWKS → regjistri on-chain.
 *
 * Për çdo çelës RSA të lëshuesit:
 * - nëse llogaria `["jwk", sha256(iss), sha256(kid)]` nuk ekziston → `propose_jwk`;
 * - nëse ka një propozim në pritje dhe timelock-u ka kaluar → `apply_jwk` (kushdo mund ta bëjë).
 *
 * Oracle nuk revokon: një `kid` që zhduket nga JWKS mbetet aktiv deri në `valid_until` ose deri sa
 * admini ta revokojë (`revoke_jwk`). Kjo e mban oracle-in pa fuqi për të bllokuar hyrjet; një
 * oracle i komprometuar mund vetëm të propozojë, dhe çdo propozim duket on-chain gjatë timelock-ut.
 */
import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import { applyJwk, base64UrlDecode, decodeJwk, jwkAddress, proposeJwk } from "@solanaauth/core";

export const PROVIDERS: Record<string, { iss: string; jwksUrl: string }> = {
  google: { iss: "https://accounts.google.com", jwksUrl: "https://www.googleapis.com/oauth2/v3/certs" },
  apple: { iss: "https://appleid.apple.com", jwksUrl: "https://appleid.apple.com/auth/keys" },
};

export interface Jwk {
  kty: string;
  kid: string;
  n?: string;
  e?: string;
  alg?: string;
  use?: string;
}

/** Leximi minimal i zinxhirit, që oracle të testohet edhe në LiteSVM. */
export interface Chain {
  getAccountData(address: PublicKey): Promise<Uint8Array | null>;
  now(): Promise<number>;
}

export type Action =
  | { kind: "propose"; iss: string; kid: string; instruction: TransactionInstruction }
  | { kind: "apply"; iss: string; kid: string; instruction: TransactionInstruction }
  | { kind: "wait"; iss: string; kid: string; eta: bigint }
  | { kind: "ok"; iss: string; kid: string }
  | { kind: "skip"; iss: string; kid: string; reason: string };

export interface SyncOptions {
  programId: PublicKey;
  oracle: PublicKey;
  payer: PublicKey;
  /** Sa sekonda pas tani mbetet i vlefshëm një çelës i ri (parazgjedhja: 2^62, pa skadim). */
  validitySecs?: number;
}

export async function planSync(chain: Chain, iss: string, keys: Jwk[], o: SyncOptions): Promise<Action[]> {
  const now = await chain.now();
  const out: Action[] = [];
  for (const k of keys) {
    if (k.kty !== "RSA" || !k.n || (k.alg && k.alg !== "RS256") || (k.use && k.use !== "sig")) {
      out.push({ kind: "skip", iss, kid: k.kid, reason: "jo RSA/RS256/sig" });
      continue;
    }
    if (k.e && k.e !== "AQAB") {
      // Qarku zkLogin pranon vetëm e = 65537.
      out.push({ kind: "skip", iss, kid: k.kid, reason: `eksponent ${k.e}` });
      continue;
    }
    const addr = jwkAddress(o.programId, iss, k.kid);
    const data = await chain.getAccountData(addr);
    if (!data) {
      const validUntil = o.validitySecs ? BigInt(now + o.validitySecs) : 2n ** 62n;
      out.push({
        kind: "propose",
        iss,
        kid: k.kid,
        instruction: proposeJwk(o.programId, o.oracle, o.payer, {
          iss,
          kid: k.kid,
          modulus: base64UrlDecode(k.n),
          validFrom: 0,
          validUntil,
        }),
      });
      continue;
    }
    const acc = decodeJwk(data);
    if (acc.pending) {
      if (BigInt(now) >= acc.pending.eta) out.push({ kind: "apply", iss, kid: k.kid, instruction: applyJwk(o.programId, addr) });
      else out.push({ kind: "wait", iss, kid: k.kid, eta: acc.pending.eta });
    } else if (acc.revoked) {
      out.push({ kind: "skip", iss, kid: k.kid, reason: "i revokuar nga admini" });
    } else {
      out.push({ kind: "ok", iss, kid: k.kid });
    }
  }
  return out;
}

export async function fetchJwks(url: string, f: typeof fetch = fetch): Promise<Jwk[]> {
  const res = await f(url);
  if (!res.ok) throw new Error(`${url}: ${res.status}`);
  const body = await res.json();
  if (!Array.isArray(body.keys)) throw new Error(`${url}: pa "keys"`);
  return body.keys;
}
