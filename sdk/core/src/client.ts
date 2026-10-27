/**
 * Rrjedha e plotë e hyrjes: çelës ephemeral → nonce → OAuth (Google/Apple) → salt → provë →
 * `create_wallet` ose `open_session`. SDK-ja nuk mban kurrë çelësa privatë të përdoruesit: çelësi
 * i sesionit krijohet dhe ruhet te klienti, dhe fuqitë e tij i kufizon politika on-chain.
 */
import {
  Commitment,
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";

import { fetchWallet } from "./accounts.js";
import { toBigEndian } from "./bytes.js";
import * as ixs from "./instructions.js";
import { Policy } from "./instructions.js";
import { jwkAddress, sessionAddress, vaultAddress, walletAddress, zkIdentity } from "./pda.js";
import {
  ZkLoginInputs,
  decodeJwt,
  decodeJwtHeader,
  encodeZkBlock,
  genAddressSeed,
  generateNonce,
  generateRandomness,
  normalizeInputs,
} from "./zklogin.js";

export interface SolanaAuthOptions {
  connection: Connection;
  programId: PublicKey;
  /** URL e prover-it (API e Mysten: `POST { jwt, extendedEphemeralPublicKey, ... }`). */
  proverUrl: string;
  /** URL e shërbimit të salt-it (`POST { jwt }` → `{ salt }`). */
  saltUrl: string;
  /** Prova nga prover-i dev (verifying key test). Vetëm devnet. */
  vkTest?: boolean;
  commitment?: Commitment;
  fetch?: typeof fetch;
}

/** Gjendja midis hapit të parë (redirect te OAuth) dhe kthimit me JWT. Ruhet te klienti. */
export interface PendingLogin {
  ephemeralSecretKey: Uint8Array;
  maxEpoch: number;
  randomness: string;
  nonce: string;
}

export interface Session {
  wallet: PublicKey;
  vault: PublicKey;
  session: PublicKey;
  sessionKey: Keypair;
  expiresAt: number;
  identity: Uint8Array;
}

export const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
export const APPLE_AUTH_URL = "https://appleid.apple.com/auth/authorize";

export class SolanaAuth {
  readonly connection: Connection;
  readonly programId: PublicKey;
  private opts: SolanaAuthOptions;

  constructor(opts: SolanaAuthOptions) {
    this.opts = opts;
    this.connection = opts.connection;
    this.programId = opts.programId;
  }

  private get fetch() {
    return this.opts.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** Hapi 1: çelësi ephemeral dhe nonce-i. `sessionSecs` ≤ `config.max_session_secs`. */
  beginLogin(sessionSecs = 24 * 3600, now = Math.floor(Date.now() / 1000)): PendingLogin {
    const kp = Keypair.generate();
    const maxEpoch = now + sessionSecs;
    const randomness = generateRandomness().toString();
    return {
      ephemeralSecretKey: kp.secretKey,
      maxEpoch,
      randomness,
      nonce: generateNonce(kp.publicKey.toBytes(), maxEpoch, randomness),
    };
  }

  /** URL-ja e OAuth (implicit flow me `id_token`). */
  static oauthUrl(p: { provider: "google" | "apple"; clientId: string; redirectUri: string; nonce: string; state?: string }): string {
    const base = p.provider === "google" ? GOOGLE_AUTH_URL : APPLE_AUTH_URL;
    const q = new URLSearchParams({
      client_id: p.clientId,
      redirect_uri: p.redirectUri,
      response_type: "id_token",
      scope: "openid",
      nonce: p.nonce,
      ...(p.provider === "apple" ? { response_mode: "fragment" } : {}),
      ...(p.state ? { state: p.state } : {}),
    });
    return `${base}?${q}`;
  }

  async fetchSalt(jwt: string): Promise<bigint> {
    const res = await this.fetch(this.opts.saltUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jwt }),
    });
    if (!res.ok) throw new Error(`salt service: ${res.status} ${await res.text()}`);
    return BigInt((await res.json()).salt);
  }

  async prove(jwt: string, pending: PendingLogin, salt: bigint): Promise<ZkLoginInputs> {
    const kp = Keypair.fromSecretKey(pending.ephemeralSecretKey);
    const ext = new Uint8Array(33);
    ext.set(kp.publicKey.toBytes(), 1);
    const res = await this.fetch(this.opts.proverUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jwt,
        extendedEphemeralPublicKey: Buffer.from(ext).toString("base64"),
        maxEpoch: String(pending.maxEpoch),
        jwtRandomness: pending.randomness,
        salt: salt.toString(),
        keyClaimName: "sub",
      }),
    });
    if (!res.ok) throw new Error(`prover: ${res.status} ${await res.text()}`);
    const claims = decodeJwt(jwt);
    const raw = await res.json();
    const addressSeed = raw.addressSeed ?? raw.address_seed ?? genAddressSeed(salt, "sub", claims.sub, claims.aud).toString();
    return normalizeInputs({ ...raw, addressSeed });
  }

  /** Portofoli i një përdoruesi (iss + address_seed), pa transaksion. */
  walletFor(iss: string, addressSeed: string | bigint) {
    const identity = zkIdentity(iss, toBigEndian(addressSeed));
    const wallet = walletAddress(this.programId, identity);
    return { identity, wallet, vault: vaultAddress(this.programId, wallet) };
  }

  /**
   * Hapi 2: nga JWT-ja te transaksioni. Krijon portofolin (hyrja e parë) ose hap sesion të ri.
   * `payer` paguan rent-in dhe tarifën; parazgjedhja është vetë çelësi i sesionit (duhet SOL).
   */
  async completeLogin(
    jwt: string,
    pending: PendingLogin,
    policy: Policy,
    payer?: PublicKey,
  ): Promise<{ transaction: Transaction; session: Session; created: boolean }> {
    if (decodeJwt(jwt).nonce !== pending.nonce) throw new Error("nonce-i i JWT-së nuk përputhet");
    const salt = await this.fetchSalt(jwt);
    const inputs = await this.prove(jwt, pending, salt);
    return this.buildLogin(jwt, pending, inputs, policy, payer);
  }

  /** Si `completeLogin`, me provën të marrë tashmë. */
  async buildLogin(jwt: string, pending: PendingLogin, inputs: ZkLoginInputs, policy: Policy, payer?: PublicKey) {
    const claims = decodeJwt(jwt);
    const { kid } = decodeJwtHeader(jwt);
    const sessionKey = Keypair.fromSecretKey(pending.ephemeralSecretKey);
    const { identity, wallet, vault } = this.walletFor(claims.iss, inputs.addressSeed);
    const zk = encodeZkBlock(inputs, pending.maxEpoch, this.opts.vkTest);
    const accounts = { sessionKey: sessionKey.publicKey, jwk: jwkAddress(this.programId, claims.iss, kid), wallet };
    const exists = (await fetchWallet(this.connection, wallet)) !== null;
    const feePayer = payer ?? sessionKey.publicKey;
    const ix = exists
      ? ixs.openSession(this.programId, feePayer, accounts, zk, policy)
      : ixs.createWallet(this.programId, feePayer, accounts, zk, policy);
    const transaction = await this.transaction([ix], feePayer);
    transaction.partialSign(sessionKey);
    const now = Math.floor(Date.now() / 1000);
    return {
      transaction,
      created: !exists,
      session: {
        wallet,
        vault,
        session: sessionAddress(this.programId, wallet, sessionKey.publicKey),
        sessionKey,
        expiresAt: Math.min(pending.maxEpoch, now + policy.expiresIn),
        identity,
      },
    };
  }

  async transaction(instructions: TransactionInstruction[], feePayer: PublicKey): Promise<Transaction> {
    const { blockhash, lastValidBlockHeight } = await this.connection.getLatestBlockhash(this.opts.commitment);
    const tx = new Transaction({ feePayer, blockhash, lastValidBlockHeight });
    tx.add(...instructions);
    return tx;
  }

  /** `execute`: instruksionet ekzekutohen me vault-in si nënshkrues, brenda politikës. */
  async execute(session: Session, inner: TransactionInstruction[], feePayer?: Keypair): Promise<string> {
    const ix = ixs.execute(this.programId, session.sessionKey.publicKey, session.wallet, inner);
    const payer = feePayer ?? session.sessionKey;
    const tx = await this.transaction([ix], payer.publicKey);
    const signers = payer === session.sessionKey ? [payer] : [payer, session.sessionKey];
    tx.sign(...signers);
    return this.connection.sendRawTransaction(tx.serialize());
  }

  async revoke(session: Session): Promise<string> {
    const ix = ixs.revokeSessionSelf(this.programId, session.sessionKey.publicKey, session.wallet);
    const tx = await this.transaction([ix], session.sessionKey.publicKey);
    tx.sign(session.sessionKey);
    return this.connection.sendRawTransaction(tx.serialize());
  }
}

/** Ruajtja e sesionit si JSON (p.sh. në `localStorage` ose skedar i agjentit). */
export function serializeSession(s: Session): string {
  return JSON.stringify({
    wallet: s.wallet.toBase58(),
    vault: s.vault.toBase58(),
    session: s.session.toBase58(),
    sessionKey: Array.from(s.sessionKey.secretKey),
    expiresAt: s.expiresAt,
    identity: Array.from(s.identity),
  });
}

export function deserializeSession(json: string): Session {
  const o = JSON.parse(json);
  return {
    wallet: new PublicKey(o.wallet),
    vault: new PublicKey(o.vault),
    session: new PublicKey(o.session),
    sessionKey: Keypair.fromSecretKey(Uint8Array.from(o.sessionKey)),
    expiresAt: o.expiresAt,
    identity: Uint8Array.from(o.identity),
  };
}
