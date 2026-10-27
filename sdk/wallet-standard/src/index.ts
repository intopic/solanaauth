/**
 * Portofoli solanaauth si Wallet Standard. Llogaria që sheh dApp-i është vault-i (PDA). Një PDA
 * s'nënshkruan dot tx-in vetë, prandaj:
 *
 * - `solana:signAndSendTransaction`: instruksionet e dApp-it (ku vault-i është nënshkrues dhe/ose
 *   fee payer) mbështillen në `execute`; politika e sesionit vendos on-chain. Fee payer-i bëhet
 *   paguesi i klientit (paymaster, server, Kora) ose çelësi i sesionit.
 * - `solanaauth:session.signMessage`: nënshkrim SAA-1271 nga sesioni (`docs/SIGN-MESSAGE.md`).
 * - `solana:signTransaction` nuk ofrohet: një tx i nënshkruar nga vault-i jashtë programit s'ekziston.
 */
import { Buffer } from "buffer";
import type { SolanaSignAndSendTransactionFeature, SolanaSignAndSendTransactionMethod } from "@solana/wallet-standard-features";
import { PublicKey, Transaction, TransactionInstruction, VersionedTransaction } from "@solana/web3.js";
import { SIGNATURE_TYPE, Session, SessionSignature, SolanaAuth, signMessage } from "@solanaauth/core";
import type { Wallet, WalletAccount, WalletIcon } from "@wallet-standard/base";
import type { StandardConnectFeature, StandardConnectMethod, StandardDisconnectFeature, StandardEventsFeature, StandardEventsListeners, StandardEventsOnMethod } from "@wallet-standard/features";
import { registerWallet } from "@wallet-standard/wallet";

export const SOLANA_CHAINS = ["solana:mainnet", "solana:devnet", "solana:testnet"] as const;
const ICON = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iOCIgZmlsbD0iIzRmNDZlNSIvPjx0ZXh0IHg9IjE2IiB5PSIyMiIgZm9udC1zaXplPSIxNiIgZm9udC1mYW1pbHk9InNhbnMtc2VyaWYiIGZpbGw9IiNmZmYiIHRleHQtYW5jaG9yPSJtaWRkbGUiPnNhPC90ZXh0Pjwvc3ZnPg==" as WalletIcon;

class Account implements WalletAccount {
  readonly chains = SOLANA_CHAINS;
  readonly features = ["solana:signAndSendTransaction"] as const;
  constructor(readonly vault: PublicKey) {}
  get address() {
    return this.vault.toBase58();
  }
  get publicKey() {
    return this.vault.toBytes();
  }
}

/** Instruksionet e një tx-i legacy ose v0 (pa address lookup tables). */
export function instructionsOf(bytes: Uint8Array): { instructions: TransactionInstruction[]; feePayer: PublicKey } {
  const versioned = VersionedTransaction.deserialize(bytes);
  if (versioned.version === "legacy") {
    const t = Transaction.from(bytes);
    return { instructions: t.instructions, feePayer: t.feePayer! };
  }
  const m = versioned.message;
  if (m.addressTableLookups.length) throw new Error("tx-at me address lookup tables s'mbështeten ende");
  const keys = m.staticAccountKeys;
  const instructions = m.compiledInstructions.map(
    (ix) =>
      new TransactionInstruction({
        programId: keys[ix.programIdIndex],
        data: Buffer.from(ix.data),
        keys: ix.accountKeyIndexes.map((i) => ({ pubkey: keys[i], isSigner: m.isAccountSigner(i), isWritable: m.isAccountWritable(i) })),
      }),
  );
  return { instructions, feePayer: keys[0] };
}

/**
 * Veçori shtesë: adresat që i duhen verifikuesit të `signMessage` (SAA-1271). Vault-i që sheh dApp-i
 * s'mjafton, sepse nënshkruan sesioni i portofolit.
 */
export const SESSION_FEATURE = "solanaauth:session" as const;
export type SolanaAuthSessionFeature = {
  [SESSION_FEATURE]: {
    version: "1.0.0";
    signatureType: typeof SIGNATURE_TYPE;
    programId: string;
    getSession(): { wallet: string; session: string; vault: string; expiresAt: number } | null;
    signMessage(...inputs: { account: WalletAccount; message: Uint8Array }[]): Promise<(SessionSignature & { signedMessage: Uint8Array })[]>;
  };
};

const COMPUTE_BUDGET = new PublicKey("ComputeBudget111111111111111111111111111111");

export class SolanaAuthWallet implements Wallet {
  readonly version = "1.0.0" as const;
  readonly name = "solanaauth";
  readonly icon = ICON;
  readonly chains = SOLANA_CHAINS;
  #listeners: { [E in keyof StandardEventsListeners]?: StandardEventsListeners[E][] } = {};
  #session: Session | null;

  /**
   * @param getSession thirret në `connect`: kthen sesionin (p.sh. nga `BrowserLogin.current()` ose
   *   pas një hyrjeje të re).
   */
  constructor(readonly auth: SolanaAuth, private getSession: () => Promise<Session | null>, session: Session | null = null) {
    this.#session = session;
  }

  get accounts(): Account[] {
    return this.#session ? [new Account(this.#session.vault)] : [];
  }

  get features(): StandardConnectFeature & StandardDisconnectFeature & StandardEventsFeature & SolanaSignAndSendTransactionFeature & SolanaAuthSessionFeature {
    return {
      "standard:connect": { version: "1.0.0", connect: this.#connect },
      "standard:disconnect": { version: "1.0.0", disconnect: async () => this.#set(null) },
      "standard:events": { version: "1.0.0", on: this.#on },
      "solana:signAndSendTransaction": { version: "1.0.0", supportedTransactionVersions: ["legacy", 0], signAndSendTransaction: this.#signAndSend },
      [SESSION_FEATURE]: {
        version: "1.0.0",
        signatureType: SIGNATURE_TYPE,
        programId: this.auth.programId.toBase58(),
        signMessage: this.#signMessage,
        getSession: () => {
          const s = this.#session;
          return s && { wallet: s.wallet.toBase58(), session: s.session.toBase58(), vault: s.vault.toBase58(), expiresAt: s.expiresAt };
        },
      },
    };
  }

  #set(s: Session | null) {
    this.#session = s;
    for (const l of this.#listeners.change ?? []) l({ accounts: this.accounts });
  }

  #connect: StandardConnectMethod = async () => {
    if (!this.#session) this.#set(await this.getSession());
    return { accounts: this.accounts };
  };

  #on: StandardEventsOnMethod = (event, listener) => {
    (this.#listeners[event] ??= []).push(listener as never);
    return () => {
      this.#listeners[event] = this.#listeners[event]?.filter((l) => l !== listener) as never;
    };
  };

  /** Mbështjell instruksionet e dApp-it në `execute`. */
  wrap(bytes: Uint8Array): TransactionInstruction[] {
    const s = this.#session;
    if (!s) throw new Error("s'është lidhur");
    const { instructions } = instructionsOf(bytes);
    // ComputeBudget i dApp-it mbetet në nivelin e parë; pjesa tjetër ekzekutohet nga vault-i.
    const inner = instructions.filter((ix) => !ix.programId.equals(COMPUTE_BUDGET));
    for (const ix of inner) {
      for (const k of ix.keys) {
        if (k.isSigner && !k.pubkey.equals(s.vault)) throw new Error(`tx-i kërkon nënshkruesin ${k.pubkey.toBase58()}: vetëm vault-i nënshkruan`);
      }
    }
    return [...instructions.filter((ix) => ix.programId.equals(COMPUTE_BUDGET)), this.auth.wrapExecute(s, inner)];
  }

  #signAndSend: SolanaSignAndSendTransactionMethod = async (...inputs) => {
    const s = this.#session;
    if (!s) throw new Error("s'është lidhur");
    const out = [];
    for (const input of inputs) {
      if (input.account.address !== s.vault.toBase58()) throw new Error("llogari e panjohur");
      const sig = await this.auth.send(this.wrap(input.transaction), s.sessionKey);
      out.push({ signature: bs58decode(sig) });
    }
    return out;
  };

  #signMessage = async (...inputs: { account: WalletAccount; message: Uint8Array }[]) => {
    const s = this.#session;
    if (!s) throw new Error("s'është lidhur");
    return inputs.map((input) => {
      if (input.account.address !== s.vault.toBase58()) throw new Error("llogari e panjohur");
      const r = signMessage(s, input.message);
      return { ...r, signedMessage: input.message };
    });
  };
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function bs58decode(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) n = n * 58n + BigInt(B58.indexOf(c));
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 255n));
    n >>= 8n;
  }
  for (const c of s) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

/** Regjistron portofolin te dApp-et (Wallet Standard). */
export function registerSolanaAuthWallet(wallet: SolanaAuthWallet) {
  registerWallet(wallet);
  return wallet;
}
