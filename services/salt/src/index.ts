/**
 * Salt-i i zkLogin: `salt = HKDF-SHA256(ikm = master_seed, salt = "", info = "solanaauth:salt:v1" || iss || 0 || aud || 0 || sub, 16 bytes)`.
 *
 * - Salt-i nuk është çelës: pa një JWT të vlefshme të përdoruesit nuk jep akses, dhe prova zk
 *   nuk e zbulon on-chain. Por i njëjti salt duhet të kthehet gjithmonë për të njëjtin përdorues,
 *   përndryshe adresa e portofolit ndryshon; prandaj `master_seed` duhet ruajtur dhe kopjuar (backup).
 * - Shërbimi verifikon nënshkrimin e JWT-së me JWKS e lëshuesit, `exp`, dhe që `aud` është në
 *   listën e aplikacioneve të lejuara.
 */
import { hkdfSync, timingSafeEqual } from "node:crypto";
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";

export const ISSUERS: Record<string, string> = {
  "https://accounts.google.com": "https://www.googleapis.com/oauth2/v3/certs",
  "accounts.google.com": "https://www.googleapis.com/oauth2/v3/certs",
  "https://appleid.apple.com": "https://appleid.apple.com/auth/keys",
};

export interface SaltServiceOptions {
  /** 32 bytes. Kurrë në repo; nga një secret manager. */
  masterSeed: Uint8Array;
  /** Client ID-të e lejuara (`aud`). */
  allowedAudiences: string[];
  /** iss → burimi i çelësave (për teste mund të jetë një JWKS lokal). */
  keys?: Record<string, JWTVerifyGetKey>;
  /** Toleranca e orës në sekonda. */
  clockToleranceSecs?: number;
}

export class SaltError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export function deriveSalt(masterSeed: Uint8Array, iss: string, aud: string, sub: string): bigint {
  const info = Buffer.concat([Buffer.from("solanaauth:salt:v1"), Buffer.from(iss), Buffer.of(0), Buffer.from(aud), Buffer.of(0), Buffer.from(sub)]);
  const okm = new Uint8Array(hkdfSync("sha256", masterSeed, new Uint8Array(0), info, 16));
  let n = 0n;
  for (const b of okm) n = (n << 8n) | BigInt(b);
  return n;
}

export function createSaltService(opts: SaltServiceOptions) {
  if (opts.masterSeed.length !== 32) throw new Error("masterSeed duhet të jetë 32 bytes");
  const keys: Record<string, JWTVerifyGetKey> = { ...opts.keys };
  for (const [iss, url] of Object.entries(ISSUERS)) {
    keys[iss] ??= createRemoteJWKSet(new URL(url));
  }

  return async function salt(jwt: string): Promise<{ salt: string; iss: string; aud: string; sub: string }> {
    if (typeof jwt !== "string" || jwt.split(".").length !== 3) throw new SaltError(400, "JWT i pavlefshëm");
    let iss: string;
    try {
      iss = JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString()).iss;
    } catch {
      throw new SaltError(400, "JWT i pavlefshëm");
    }
    const getKey = keys[iss];
    if (!getKey) throw new SaltError(400, `lëshues i panjohur: ${iss}`);
    let payload;
    try {
      ({ payload } = await jwtVerify(jwt, getKey, {
        issuer: iss,
        audience: opts.allowedAudiences,
        algorithms: ["RS256"],
        clockTolerance: opts.clockToleranceSecs ?? 30,
      }));
    } catch (e) {
      throw new SaltError(401, `JWT nuk u verifikua: ${(e as Error).message}`);
    }
    const aud = Array.isArray(payload.aud) ? payload.aud[0] : payload.aud!;
    const sub = payload.sub;
    if (!sub) throw new SaltError(400, "JWT pa sub");
    // Google përdor dy forma të iss; salt-i lidhet me formën kanonike.
    const canonIss = iss === "accounts.google.com" ? "https://accounts.google.com" : iss;
    return { salt: deriveSalt(opts.masterSeed, canonIss, aud, sub).toString(), iss: canonIss, aud, sub };
  };
}

export function constantTimeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
