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

import { fetchWallet, findWalletsByIdentity } from "./accounts.js";
import { base64Encode, toBigEndian } from "./bytes.js";
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
  /** API key i platformës (dërgohet si `x-api-key` te salt-i dhe prover-i i hostuar). */
  apiKey?: string;
  /** `"agent"` kur hyn një agjent (numërohet si agjent aktiv në platformë). */
  client?: "app" | "agent";
  /** Kush paguan tarifat dhe rent-in kur s'jepet ndryshe: përdoruesi (çelësi i sesionit), aplikacioni, Kora ose paymaster-i. */
  feePayer?: FeePayer;
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

/**
 * Paguesi i tarifave. `publicKey` vendoset si fee payer para nënshkrimit të çelësit të sesionit;
 * `submit` merr tx-in e nënshkruar pjesërisht, e nënshkruan dhe e dërgon.
 */
export interface FeePayer {
  publicKey: PublicKey;
  submit(tx: Transaction): Promise<string>;
}

const b64 = (tx: Transaction) => {
  const raw = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
  let s = "";
  for (const b of raw) s += String.fromCharCode(b);
  return btoa(s);
};

/** Paymaster-i i platformës (opsional; aplikacioni e aktivizon nga dashboard-i). */
export async function paymasterFeePayer(platformUrl: string, apiKey: string, f: typeof fetch = fetch): Promise<FeePayer> {
  const res = await f(`${platformUrl}/v1/paymaster`, { headers: { "x-api-key": apiKey } });
  const info = await res.json();
  if (!res.ok || !info.enabled || !info.feePayer) throw new Error("paymaster-i s'është aktiv për këtë aplikacion");
  return {
    publicKey: new PublicKey(info.feePayer),
    async submit(tx) {
      const r = await f(`${platformUrl}/v1/sponsor`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": apiKey },
        body: JSON.stringify({ transaction: b64(tx) }),
      });
      const body = await r.json();
      if (!r.ok) throw Object.assign(new Error(`paymaster: ${body.code ?? r.status} ${body.error ?? ""}`), { code: body.code });
      return body.signature;
    },
  };
}

/** Serveri i aplikacionit si fee payer: i njëjti protokoll si paymaster-i (`POST { transaction }` → `{ signature }`). */
export function appServerFeePayer(url: string, publicKey: PublicKey, headers: Record<string, string> = {}, f: typeof fetch = fetch): FeePayer {
  return {
    publicKey,
    async submit(tx) {
      const r = await f(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ transaction: b64(tx) }) });
      const body = await r.json();
      if (!r.ok) throw new Error(`fee payer: ${body.error ?? r.status}`);
      return body.signature;
    },
  };
}

/** Kora (JSON-RPC): `getPayerSigner` dhe `signAndSendTransaction`. */
export async function koraFeePayer(rpcUrl: string, f: typeof fetch = fetch): Promise<FeePayer> {
  const rpc = async (method: string, params: unknown) => {
    const r = await f(rpcUrl, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    const body = await r.json();
    if (body.error) throw new Error(`kora ${method}: ${body.error.message}`);
    return body.result;
  };
  const signer = await rpc("getPayerSigner", {});
  return {
    publicKey: new PublicKey(signer.signer_address ?? signer.payment_address),
    async submit(tx) {
      const r = await rpc("signAndSendTransaction", { transaction: b64(tx) });
      return r.signature;
    },
  };
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

  private headers(): Record<string, string> {
    return {
      "content-type": "application/json",
      ...(this.opts.apiKey ? { "x-api-key": this.opts.apiKey } : {}),
      ...(this.opts.client ? { "x-solanaauth-client": this.opts.client } : {}),
    };
  }

  get feePayer(): FeePayer | undefined {
    return this.opts.feePayer;
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
      headers: this.headers(),
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
      headers: this.headers(),
      body: JSON.stringify({
        jwt,
        extendedEphemeralPublicKey: base64Encode(ext),
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
   * Portofoli ku identiteti është autoritet: adresa e derivuar (identiteti fillestar), ose, pas një
   * rikuperimi që shtoi këtë identitet në një portofol tjetër, ai portofol (kërkim on-chain).
   */
  async resolveWallet(identity: Uint8Array): Promise<{ wallet: PublicKey; exists: boolean }> {
    const derived = walletAddress(this.programId, identity);
    if (await fetchWallet(this.connection, derived)) return { wallet: derived, exists: true };
    const found = await findWalletsByIdentity(this.connection, this.programId, identity);
    return found.length ? { wallet: found[0], exists: true } : { wallet: derived, exists: false };
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
    const { identity } = this.walletFor(claims.iss, inputs.addressSeed);
    const { wallet, exists } = await this.resolveWallet(identity);
    const vault = vaultAddress(this.programId, wallet);
    const zk = encodeZkBlock(inputs, pending.maxEpoch, this.opts.vkTest);
    const accounts = { sessionKey: sessionKey.publicKey, jwk: jwkAddress(this.programId, claims.iss, kid), wallet };
    const feePayer = payer ?? this.opts.feePayer?.publicKey ?? sessionKey.publicKey;
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

  /**
   * `execute`: instruksionet ekzekutohen me vault-in si nënshkrues, brenda politikës.
   * `feePayer`: një `Keypair` (p.sh. serveri i aplikacionit në Node), një `FeePayer` (paymaster,
   * Kora, serveri i aplikacionit), ose parazgjedhja e klientit; përndryshe paguan çelësi i sesionit.
   */
  async execute(session: Session, inner: TransactionInstruction[], opts: { feePayer?: Keypair | FeePayer } = {}): Promise<string> {
    const ix = ixs.execute(this.programId, session.sessionKey.publicKey, session.wallet, inner);
    return this.send([ix], session.sessionKey, opts.feePayer ?? this.opts.feePayer);
  }

  /** Instruksioni `execute` për sesionin (për adapter-ë që dërgojnë vetë). */
  wrapExecute(session: Session, inner: TransactionInstruction[]): TransactionInstruction {
    return ixs.execute(this.programId, session.sessionKey.publicKey, session.wallet, inner);
  }

  async revoke(session: Session, opts: { feePayer?: Keypair | FeePayer } = {}): Promise<string> {
    const ix = ixs.revokeSessionSelf(this.programId, session.sessionKey.publicKey, session.wallet);
    return this.send([ix], session.sessionKey, opts.feePayer ?? this.opts.feePayer);
  }

  /** Nënshkruan me çelësin e sesionit dhe dërgon me paguesin e zgjedhur. */
  async send(instructions: TransactionInstruction[], sessionKey: Keypair, payer: Keypair | FeePayer | undefined = this.opts.feePayer): Promise<string> {
    if (payer && !(payer instanceof Keypair)) {
      const tx = await this.transaction(instructions, payer.publicKey);
      tx.partialSign(sessionKey);
      return payer.submit(tx);
    }
    const p = payer ?? sessionKey;
    const tx = await this.transaction(instructions, p.publicKey);
    tx.sign(...(p === sessionKey ? [p] : [p, sessionKey]));
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
