/**
 * `signMessage` për portofolin PDA (SAA-1271, `docs/SIGN-MESSAGE.md`). Një PDA s'ka çelës, prandaj
 * nënshkruan sesioni dhe verifikuesi kontrollon që sesioni është i portofolit, aktiv dhe i paskaduar:
 *
 *   msg = "solanaauth signed message v1\n" || wallet (32) || session (32) || sha256(message)
 *   sig = Ed25519(session_key, msg)
 */
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";

import { decodeSession } from "./accounts.js";
import { sessionAddress } from "./pda.js";
import { concat, utf8 } from "./bytes.js";

export const SIGN_MESSAGE_PREFIX = "solanaauth signed message v1\n";
export const SIGNATURE_TYPE = "solanaauth-session-v1";

export interface SessionSignature {
  signatureType: typeof SIGNATURE_TYPE;
  wallet: PublicKey;
  session: PublicKey;
  signature: Uint8Array;
}

export function signedMessageBytes(wallet: PublicKey, session: PublicKey, message: Uint8Array): Uint8Array {
  return concat(utf8(SIGN_MESSAGE_PREFIX), wallet.toBytes(), session.toBytes(), sha256(message));
}

export function signMessage(s: { wallet: PublicKey; session: PublicKey; sessionKey: Keypair }, message: Uint8Array): SessionSignature {
  const signature = ed25519.sign(signedMessageBytes(s.wallet, s.session, message), s.sessionKey.secretKey.subarray(0, 32));
  return { signatureType: SIGNATURE_TYPE, wallet: s.wallet, session: s.session, signature };
}

/**
 * Verifikimi off-chain: lexon `Session` nga zinxhiri. Kthen arsyen kur dështon.
 * `now` në sekonda (ora e zinxhirit kur ka rëndësi).
 */
export async function verifySessionMessage(
  connection: Connection,
  programId: PublicKey,
  sig: Omit<SessionSignature, "signatureType">,
  message: Uint8Array,
  now = Math.floor(Date.now() / 1000),
): Promise<{ valid: true } | { valid: false; reason: string }> {
  const acc = await connection.getAccountInfo(sig.session);
  if (!acc) return { valid: false, reason: "sesioni nuk ekziston" };
  // Vetëm programi krijon llogari `Session` në PDA-në e saktë: pronari dhe adresa e vërtetojnë.
  if (!acc.owner.equals(programId)) return { valid: false, reason: "llogaria s'është e programit" };
  const s = decodeSession(acc.data);
  if (!sessionAddress(programId, sig.wallet, s.sessionKey).equals(sig.session)) return { valid: false, reason: "adresë sesioni e pavlefshme" };
  if (!s.wallet.equals(sig.wallet)) return { valid: false, reason: "sesioni s'është i këtij portofoli" };
  if (s.revoked) return { valid: false, reason: "sesioni është revokuar" };
  if (BigInt(now) >= s.expiresAt) return { valid: false, reason: "sesioni ka skaduar" };
  const ok = ed25519.verify(sig.signature, signedMessageBytes(sig.wallet, sig.session, message), s.sessionKey.toBytes());
  return ok ? { valid: true } : { valid: false, reason: "nënshkrim i pavlefshëm" };
}
