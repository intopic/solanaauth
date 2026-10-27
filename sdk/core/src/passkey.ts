import { Buffer } from "buffer";
/**
 * Passkey (WebAuthn, P-256) për veprimet mbi prag, rikuperimin dhe revokimin.
 *
 * Programi pret instruksionin e precompile-it secp256r1 menjëherë para instruksionit të vet, me
 * mesazhin `authenticatorData || sha256(clientDataJSON)`, dhe `challenge` në `clientDataJSON` =
 * `sha256("solanaauth:passkey:v1" || wallet || nonce || action_hash)` (shih `passkey.rs`).
 */
import { AccountMeta, PublicKey, TransactionInstruction } from "@solana/web3.js";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";

import { Writer, base64UrlEncode, concat, utf8 } from "./bytes.js";
import { DOMAIN, INSTRUCTIONS_SYSVAR_ID, Op, SECP256R1_PROGRAM_ID } from "./constants.js";
import { executeParts, rawInstruction, readonlyMeta, writableMeta, zkMetas, ZkAccounts } from "./instructions.js";

export interface PasskeyAssertion {
  /** secp256r1 i ngjeshur (33 bytes). */
  publicKey: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  /** `r || s` (64 bytes) me s të ulët, ose DER (konvertohet). */
  signature: Uint8Array;
}

export interface PasskeySigner {
  publicKey: Uint8Array;
  sign(challenge: Uint8Array): Promise<PasskeyAssertion>;
}

export function actionHash(op: number, prefix: Uint8Array, payload: Uint8Array, keys: AccountMeta[]): Uint8Array {
  const parts = [Uint8Array.of(op), prefix, payload];
  for (const k of keys) if (!k.pubkey.equals(INSTRUCTIONS_SYSVAR_ID)) parts.push(k.pubkey.toBytes());
  return sha256(concat(...parts));
}

export function passkeyChallenge(wallet: PublicKey, nonce: bigint, action: Uint8Array): Uint8Array {
  return sha256(concat(utf8(DOMAIN.passkey), wallet.toBytes(), new Writer().u64(nonce).finish(), action));
}

/** Nënshkrimi `r || s` me s ≤ n/2 (kërkesë e precompile-it). */
export function normalizeSignature(sig: Uint8Array): Uint8Array {
  const s = sig.length === 64 ? p256.Signature.fromCompact(sig) : p256.Signature.fromDER(sig);
  return s.normalizeS().toCompactRawBytes();
}

export function secp256r1Instruction(a: PasskeyAssertion): TransactionInstruction {
  const msg = concat(a.authenticatorData, sha256(a.clientDataJSON));
  const sig = normalizeSignature(a.signature);
  const pkOff = 16;
  const sigOff = pkOff + 33;
  const msgOff = sigOff + 64;
  const d = new Writer().u8(1).u8(0);
  for (const v of [sigOff, 0xffff, pkOff, 0xffff, msgOff, msg.length, 0xffff]) d.u16(v);
  d.bytes(a.publicKey).bytes(sig).bytes(msg);
  return new TransactionInstruction({ programId: SECP256R1_PROGRAM_ID, keys: [], data: Buffer.from(d.finish()) });
}

/**
 * Ndërton `[precompile, instruksioni]`: blloku passkey vendoset midis `prefix` dhe `payload`.
 * `nonce` është `wallet.nonce` aktual (shih `fetchWallet`).
 */
export async function withPasskey(
  programId: PublicKey,
  signer: PasskeySigner,
  wallet: PublicKey,
  nonce: bigint,
  op: number,
  prefix: Uint8Array,
  payload: Uint8Array,
  keys: AccountMeta[],
): Promise<TransactionInstruction[]> {
  const challenge = passkeyChallenge(wallet, nonce, actionHash(op, prefix, payload, keys));
  const a = await signer.sign(challenge);
  const data = new Writer().u8(op).bytes(prefix).vec16(a.clientDataJSON).bytes(payload).finish();
  return [secp256r1Instruction(a), rawInstruction(programId, data, keys)];
}

const sysvarWallet = (wallet: PublicKey) => [readonlyMeta(INSTRUCTIONS_SYSVAR_ID), writableMeta(wallet)];

export const passkeyOps = {
  addPasskey: (programId: PublicKey, s: PasskeySigner, wallet: PublicKey, nonce: bigint, slot: number, pubkey: Uint8Array) =>
    withPasskey(programId, s, wallet, nonce, Op.AddPasskey, Uint8Array.of(1), concat(Uint8Array.of(slot), pubkey), sysvarWallet(wallet)),

  removePasskey: (programId: PublicKey, s: PasskeySigner, wallet: PublicKey, nonce: bigint, slot: number) =>
    withPasskey(programId, s, wallet, nonce, Op.RemovePasskey, new Uint8Array(0), Uint8Array.of(slot), sysvarWallet(wallet)),

  setThreshold: (programId: PublicKey, s: PasskeySigner, wallet: PublicKey, nonce: bigint, lamports: bigint) =>
    withPasskey(programId, s, wallet, nonce, Op.SetThreshold, new Uint8Array(0), new Writer().u64(lamports).finish(), sysvarWallet(wallet)),

  cancelRecovery: (programId: PublicKey, s: PasskeySigner, wallet: PublicKey, nonce: bigint) =>
    withPasskey(programId, s, wallet, nonce, Op.CancelRecovery, Uint8Array.of(1), new Uint8Array(0), sysvarWallet(wallet)),

  revokeSession: (programId: PublicKey, s: PasskeySigner, wallet: PublicKey, nonce: bigint, session: PublicKey) =>
    withPasskey(programId, s, wallet, nonce, Op.RevokeSession, Uint8Array.of(2), new Uint8Array(0), [
      readonlyMeta(INSTRUCTIONS_SYSVAR_ID),
      writableMeta(wallet),
      writableMeta(session),
    ]),

  /** Rikuperim: shton identitetin zk të provës së re në `slot` pas timelock-ut. */
  beginRecoveryAddZk: (
    programId: PublicKey,
    s: PasskeySigner,
    nonce: bigint,
    a: ZkAccounts,
    newZkBlock: Uint8Array,
    slot: number,
  ) =>
    withPasskey(programId, s, a.wallet, nonce, Op.BeginRecovery, Uint8Array.of(2), concat(newZkBlock, Uint8Array.of(slot)), [
      ...zkMetas(programId, a),
      readonlyMeta(INSTRUCTIONS_SYSVAR_ID),
    ]),

  /** `execute` i miratuar me passkey (kalon pragun ditor). */
  execute: async (
    programId: PublicKey,
    s: PasskeySigner,
    nonce: bigint,
    sessionKey: PublicKey,
    wallet: PublicKey,
    inner: TransactionInstruction[],
  ) => {
    const { keys, rest } = executeParts(programId, sessionKey, wallet, inner);
    keys.push(readonlyMeta(INSTRUCTIONS_SYSVAR_ID));
    return withPasskey(programId, s, wallet, nonce, Op.Execute, Uint8Array.of(1), rest, keys);
  },
};

/** `clientDataJSON` minimal (për nënshkrues jashtë shfletuesit). */
export function clientDataFor(challenge: Uint8Array, origin: string): Uint8Array {
  const b64 = base64UrlEncode(challenge);
  return utf8(JSON.stringify({ type: "webauthn.get", challenge: b64, origin, crossOrigin: false }));
}

/**
 * Nënshkrues P-256 lokal (agjent, CLI, teste). Prodhon të njëjtin format si WebAuthn.
 * Çelësi privat mbetet te ai që e thërret: SDK-ja nuk e dërgon askund.
 */
export function localPasskey(privateKey: Uint8Array, rpId = "solanaauth.dev"): PasskeySigner {
  const publicKey = p256.getPublicKey(privateKey, true);
  return {
    publicKey,
    async sign(challenge) {
      const clientDataJSON = clientDataFor(challenge, `https://${rpId}`);
      const authenticatorData = concat(sha256(utf8(rpId)), Uint8Array.of(0x05), Uint8Array.of(0, 0, 0, 1));
      const msg = concat(authenticatorData, sha256(clientDataJSON));
      const signature = p256.sign(sha256(msg), privateKey, { lowS: true }).toCompactRawBytes();
      return { publicKey, authenticatorData, clientDataJSON, signature };
    },
  };
}

/** Çelësi publik i ngjeshur nga SPKI (`AuthenticatorAttestationResponse.getPublicKey()`). */
export function compressSpkiP256(spki: Uint8Array): Uint8Array {
  const raw = spki.slice(spki.length - 65);
  if (raw[0] !== 4) throw new Error("çelës P-256 i pavlefshëm");
  return p256.ProjectivePoint.fromHex(raw).toRawBytes(true);
}

/** Krijon një passkey në shfletues (WebAuthn) dhe kthen ID-në dhe çelësin publik të ngjeshur. */
export async function createBrowserPasskey(opts: {
  rpId: string;
  rpName: string;
  userName: string;
  userId?: Uint8Array;
}): Promise<{ credentialId: Uint8Array; publicKey: Uint8Array }> {
  const userId = opts.userId ?? globalThis.crypto.getRandomValues(new Uint8Array(16));
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { id: opts.rpId, name: opts.rpName },
      user: { id: userId as BufferSource, name: opts.userName, displayName: opts.userName },
      challenge: globalThis.crypto.getRandomValues(new Uint8Array(32)) as BufferSource,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("passkey-i nuk u krijua");
  const resp = cred.response as AuthenticatorAttestationResponse;
  const spki = resp.getPublicKey();
  if (!spki) throw new Error("shfletuesi nuk dha çelësin publik");
  return { credentialId: new Uint8Array(cred.rawId), publicKey: compressSpkiP256(new Uint8Array(spki)) };
}

/** Nënshkrues WebAuthn në shfletues për një passkey ekzistues. */
export function browserPasskey(credentialId: Uint8Array, publicKey: Uint8Array, rpId?: string): PasskeySigner {
  return {
    publicKey,
    async sign(challenge) {
      const cred = (await navigator.credentials.get({
        publicKey: {
          challenge: challenge as BufferSource,
          rpId,
          allowCredentials: [{ type: "public-key", id: credentialId as BufferSource }],
          userVerification: "required",
        },
      })) as PublicKeyCredential | null;
      if (!cred) throw new Error("nënshkrimi me passkey u anulua");
      const resp = cred.response as AuthenticatorAssertionResponse;
      return {
        publicKey,
        authenticatorData: new Uint8Array(resp.authenticatorData),
        clientDataJSON: new Uint8Array(resp.clientDataJSON),
        signature: new Uint8Array(resp.signature),
      };
    },
  };
}

/**
 * Hyrja vetëm me passkey (pa Google): passkey-t që krijon faqja e portofolit kanë `user.id` =
 * adresa e portofolit, prandaj një passkey "discoverable" tregon portofolin. Çelësi publik gjendet
 * duke verifikuar nënshkrimin kundër passkey-ve të regjistruar në portofol.
 */
export async function discoverBrowserPasskey(
  rpId: string,
  passkeysOf: (wallet: PublicKey) => Promise<Uint8Array[]>,
): Promise<{ wallet: PublicKey; signer: PasskeySigner; credentialId: Uint8Array }> {
  const challenge = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const cred = (await navigator.credentials.get({
    publicKey: { challenge: challenge as BufferSource, rpId, userVerification: "required" },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("hyrja me passkey u anulua");
  const resp = cred.response as AuthenticatorAssertionResponse;
  if (!resp.userHandle || resp.userHandle.byteLength !== 32) throw new Error("ky passkey s'është krijuar nga faqja e portofolit");
  const wallet = new PublicKey(new Uint8Array(resp.userHandle));
  const msg = sha256(concat(new Uint8Array(resp.authenticatorData), sha256(new Uint8Array(resp.clientDataJSON))));
  const sig = normalizeSignature(new Uint8Array(resp.signature));
  const publicKey = (await passkeysOf(wallet)).find((pk) => p256.verify(sig, msg, pk, { lowS: true, prehash: false }));
  if (!publicKey) throw new Error("passkey-i nuk është (më) i regjistruar në portofol");
  const credentialId = new Uint8Array(cred.rawId);
  return { wallet, signer: browserPasskey(credentialId, publicKey, rpId), credentialId };
}
