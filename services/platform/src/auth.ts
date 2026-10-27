/**
 * Hyrja në dashboard: pronari hyn me Google (id_token i verifikuar), dhe merr një token sesioni
 * të nënshkruar me HMAC (pa gjendje në server). Sekreti nga `DASHBOARD_SESSION_SECRET`.
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";

const GOOGLE_JWKS = createRemoteJWKSet(new URL("https://www.googleapis.com/oauth2/v3/certs"));

export interface OwnerAuthOptions {
  secret: Uint8Array;
  googleClientId: string;
  keys?: JWTVerifyGetKey;
  ttlSecs?: number;
}

export class OwnerAuth {
  constructor(private o: OwnerAuthOptions) {}

  async login(idToken: string, now = Math.floor(Date.now() / 1000)): Promise<{ token: string; owner: string }> {
    const { payload } = await jwtVerify(idToken, this.o.keys ?? GOOGLE_JWKS, {
      issuer: ["https://accounts.google.com", "accounts.google.com"],
      audience: this.o.googleClientId,
      algorithms: ["RS256"],
    });
    if (payload.email_verified !== true || typeof payload.email !== "string") throw new Error("email i paverifikuar");
    const owner = payload.email.toLowerCase();
    return { token: this.sign(owner, now + (this.o.ttlSecs ?? 12 * 3600)), owner };
  }

  sign(owner: string, exp: number): string {
    const body = Buffer.from(JSON.stringify({ owner, exp })).toString("base64url");
    return `${body}.${createHmac("sha256", this.o.secret).update(body).digest("base64url")}`;
  }

  verify(token: string | undefined, now = Math.floor(Date.now() / 1000)): string | null {
    if (!token) return null;
    const [body, mac] = token.split(".");
    if (!body || !mac) return null;
    const want = createHmac("sha256", this.o.secret).update(body).digest();
    const got = Buffer.from(mac, "base64url");
    if (got.length !== want.length || !timingSafeEqual(got, want)) return null;
    const { owner, exp } = JSON.parse(Buffer.from(body, "base64url").toString());
    return exp > now ? owner : null;
  }
}
