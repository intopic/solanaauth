/**
 * Rrjedha e hyrjes në shfletues, pa React: redirect te OAuth, kthimi me `id_token` në fragment,
 * salt + provë, dhe transaksioni `create_wallet`/`open_session`.
 *
 * Çelësi i sesionit ruhet në `storage` (parazgjedhja `localStorage`). Kush lexon storage-in (p.sh.
 * një XSS) merr sesionin, por vetëm brenda politikës on-chain: programet e lejuara, limitet dhe
 * skadimi. Çelësi i përdoruesit (Google/Apple) nuk prek kurrë faqen.
 */
import { Connection, PublicKey, Transaction } from "@solana/web3.js";
import {
  PendingLogin,
  Policy,
  Session,
  SolanaAuth,
  deserializeSession,
  serializeSession,
} from "@solanaauth/core";

export interface KeyValueStorage {
  getItem(k: string): string | null;
  setItem(k: string, v: string): void;
  removeItem(k: string): void;
}

export type Provider = "google" | "apple";

export interface BrowserLoginOptions {
  clientIds: Partial<Record<Provider, string>>;
  redirectUri: string;
  policy: Policy;
  /** Kohëzgjatja e provës (≤ `config.max_session_secs`). Parazgjedhja: `policy.expiresIn`. */
  sessionSecs?: number;
  storage?: KeyValueStorage;
  /**
   * Dërgimi i transaksionit të hyrjes. Parazgjedhja: `feePayer` i klientit (paymaster, Kora,
   * serveri i aplikacionit) nëse është dhënë, përndryshe vetë çelësi i sesionit (duhet SOL).
   */
  submit?: (tx: Transaction, connection: Connection) => Promise<string>;
  /** Thirret para dërgimit kur paguan çelësi i sesionit (p.sh. airdrop në devnet). */
  fundSessionKey?: (sessionKey: PublicKey, connection: Connection) => Promise<void>;
  storageKey?: string;
}

const PENDING = "solanaauth:pending";

interface StoredPending extends Omit<PendingLogin, "ephemeralSecretKey"> {
  ephemeralSecretKey: number[];
  state: string;
  provider: Provider;
}

export class BrowserLogin {
  private storage: KeyValueStorage;
  private key: string;

  constructor(readonly auth: SolanaAuth, readonly opts: BrowserLoginOptions) {
    this.storage = opts.storage ?? globalThis.localStorage;
    this.key = opts.storageKey ?? "solanaauth:session";
  }

  /** Hapi 1: URL-ja e OAuth. Gjendja ruhet derisa përdoruesi të kthehet. */
  start(provider: Provider, now?: number): string {
    const clientId = this.opts.clientIds[provider];
    if (!clientId) throw new Error(`mungon client ID për ${provider}`);
    const p = this.auth.beginLogin(this.opts.sessionSecs ?? this.opts.policy.expiresIn, now);
    const state = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
    const stored: StoredPending = { ...p, ephemeralSecretKey: Array.from(p.ephemeralSecretKey), state, provider };
    this.storage.setItem(PENDING, JSON.stringify(stored));
    return SolanaAuth.oauthUrl({ provider, clientId, redirectUri: this.opts.redirectUri, nonce: p.nonce, state });
  }

  /** A ka një përgjigje OAuth në këtë URL (fragment ose query për Apple form_post)? */
  static hasCallback(url: string): boolean {
    const u = new URL(url);
    return new URLSearchParams(u.hash.slice(1)).has("id_token") || u.searchParams.has("id_token");
  }

  /** Hapi 2: nga URL-ja e kthimit te sesioni (transaksioni dërgohet me `submit`). */
  async finish(url: string): Promise<{ session: Session; created: boolean; signature: string }> {
    const u = new URL(url);
    const params = new URLSearchParams(u.hash.slice(1));
    for (const [k, v] of u.searchParams) if (!params.has(k)) params.set(k, v);
    const jwt = params.get("id_token");
    const err = params.get("error");
    if (err) throw new Error(`OAuth: ${err}`);
    if (!jwt) throw new Error("mungon id_token");
    const raw = this.storage.getItem(PENDING);
    if (!raw) throw new Error("nuk ka hyrje në pritje");
    const stored: StoredPending = JSON.parse(raw);
    if (params.get("state") !== stored.state) throw new Error("state nuk përputhet");
    this.storage.removeItem(PENDING);
    const pending: PendingLogin = { ...stored, ephemeralSecretKey: Uint8Array.from(stored.ephemeralSecretKey) };
    const { transaction, session, created } = await this.auth.completeLogin(jwt, pending, this.opts.policy);
    const signature = this.opts.submit
      ? await this.opts.submit(transaction, this.auth.connection)
      : this.auth.feePayer
        ? await this.auth.feePayer.submit(transaction)
        : await this.sendAsSessionKey(transaction, session);
    this.storage.setItem(this.key, serializeSession(session));
    return { session, created, signature };
  }

  private async sendAsSessionKey(tx: Transaction, session: Session) {
    if (!tx.feePayer?.equals(session.sessionKey.publicKey)) throw new Error("jep `submit` kur paguesi s'është çelësi i sesionit");
    await this.opts.fundSessionKey?.(session.sessionKey.publicKey, this.auth.connection);
    if (this.opts.fundSessionKey) {
      // Airdrop-i mund të marrë kohë; blockhash-i rifreskohet.
      tx.recentBlockhash = (await this.auth.connection.getLatestBlockhash()).blockhash;
    }
    tx.sign(session.sessionKey);
    const sig = await this.auth.connection.sendRawTransaction(tx.serialize());
    await this.auth.connection.confirmTransaction(sig, "confirmed");
    return sig;
  }

  /** Sesioni i ruajtur, nëse s'ka skaduar. */
  current(now = Math.floor(Date.now() / 1000)): Session | null {
    const raw = this.storage.getItem(this.key);
    if (!raw) return null;
    const s = deserializeSession(raw);
    if (s.expiresAt <= now) {
      this.storage.removeItem(this.key);
      return null;
    }
    return s;
  }

  /** Revokon sesionin on-chain (nëse `onChain`) dhe e fshin lokalisht. */
  async logout(onChain = true): Promise<string | null> {
    const s = this.current();
    this.storage.removeItem(this.key);
    return s && onChain ? this.auth.revoke(s) : null;
  }
}
