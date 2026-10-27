/**
 * Kontrollet e proxy-t para se një kërkesë të arrijë prover-in (i shtrenjtë: ~3 s CPU për provë).
 * Nënshkrimi i JWT-së nuk kontrollohet këtu: qarku e verifikon vetë dhe një JWT e falsifikuar nuk
 * jep provë të vlefshme. Proxy-i vetëm mbron kapacitetin.
 */
export interface ProveRequest {
  jwt: string;
  extendedEphemeralPublicKey: string;
  maxEpoch: string;
  jwtRandomness: string;
  salt: string;
  keyClaimName: string;
}

export interface Limits {
  allowedAudiences: string[];
  /** `maxEpoch` (në solanaauth = unix timestamp) nuk mund të jetë më larg se kaq nga tani. */
  maxSessionSecs: number;
}

export class RejectError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export function checkRequest(body: unknown, limits: Limits, now = Math.floor(Date.now() / 1000)): ProveRequest {
  const b = body as Partial<ProveRequest>;
  for (const k of ["jwt", "extendedEphemeralPublicKey", "maxEpoch", "jwtRandomness", "salt", "keyClaimName"] as const) {
    if (typeof b?.[k] !== "string") throw new RejectError(400, `mungon ${k}`);
  }
  const parts = b.jwt!.split(".");
  if (parts.length !== 3) throw new RejectError(400, "JWT i pavlefshëm");
  let claims: { aud?: string | string[]; exp?: number };
  try {
    claims = JSON.parse(Buffer.from(parts[1], "base64url").toString());
  } catch {
    throw new RejectError(400, "JWT i pavlefshëm");
  }
  const aud = Array.isArray(claims.aud) ? claims.aud[0] : claims.aud;
  if (!aud || !limits.allowedAudiences.includes(aud)) throw new RejectError(403, "aplikacion i palejuar");
  if (typeof claims.exp === "number" && claims.exp + 60 < now) throw new RejectError(400, "JWT ka skaduar");
  if (b.keyClaimName !== "sub") throw new RejectError(400, "vetëm keyClaimName=sub");
  if (!/^\d{1,20}$/.test(b.maxEpoch!)) throw new RejectError(400, "maxEpoch i pavlefshëm");
  const maxEpoch = Number(b.maxEpoch);
  if (maxEpoch <= now) throw new RejectError(400, "maxEpoch në të kaluarën");
  if (maxEpoch > now + limits.maxSessionSecs) throw new RejectError(400, "maxEpoch shumë larg");
  return b as ProveRequest;
}
