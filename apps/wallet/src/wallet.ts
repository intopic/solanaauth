/**
 * Logjika e faqes së portofolit. Faqja s'ka server dhe s'mban çelësa: hyn me Google/Apple (provë
 * zk) ose me passkey, dhe çdo veprim është një instruksion i programit. Funksionon edhe kur
 * aplikacioni që krijoi portofolin s'ekziston më (pa lock-in).
 */
import { Buffer } from "buffer";
import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import {
  FeePayer, PasskeySigner, Policy, SOL_MINT, SYSTEM_PROGRAM_ID, Session, SolanaAuth, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID,
  WalletAccount, ZkAccounts, addPasskeyZk, beginRecoveryAddPasskey, browserPasskey, cancelRecoveryZk, createBrowserPasskey,
  decodeJwt, decodeJwtHeader, decodeWallet, discoverBrowserPasskey, encodeZkBlock, fetchSessions, finishRecovery, genAddressSeed,
  jwkAddress, passkeyOps, paymasterFeePayer, revokeSessionZk, vaultAddress, zkIdentity, toBigEndian, PendingLogin,
  confirmTransaction,
  openSession, policyFromJson, policyHash, toHex,
} from "@solanaauth/core";

const env = import.meta.env;
export const connection = new Connection(env.VITE_RPC_URL ?? "https://api.devnet.solana.com", "confirmed");
export const programId = new PublicKey(env.VITE_PROGRAM_ID || "11111111111111111111111111111111");
const platform = env.VITE_PLATFORM_URL as string | undefined;
export const auth = new SolanaAuth({
  connection,
  programId,
  saltUrl: env.VITE_SALT_URL || `${platform}/v1/salt`,
  proverUrl: env.VITE_PROVER_URL || `${platform}/v1/prove`,
  apiKey: env.VITE_API_KEY || undefined,
});
export const ATA_PROGRAM_ID = new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const RP_ID = window.location.hostname;
const U64_MAX = 2n ** 64n - 1n;

/** Kush paguan tarifat: paymaster-i (nëse aktivizohet) ose një çelës i përkohshëm me airdrop (devnet). */
export async function feePayer(): Promise<FeePayer | Keypair> {
  if (env.VITE_USE_PAYMASTER === "true" && platform && env.VITE_API_KEY) return paymasterFeePayer(platform, env.VITE_API_KEY);
  const kp = Keypair.generate();
  await airdrop(kp.publicKey);
  return kp;
}

export async function airdrop(to: PublicKey) {
  if ((await connection.getBalance(to)) >= 0.01 * LAMPORTS_PER_SOL) return;
  const sig = await connection.requestAirdrop(to, 0.05 * LAMPORTS_PER_SOL);
  await confirmTransaction(connection, sig);
}

export interface ZkAuth {
  block: Uint8Array;
  accounts: ZkAccounts;
  identity: Uint8Array;
  /** Identiteti nuk është (ende) autoritet i portofolit: vetëm rikuperim (kind 2). */
  foreign: boolean;
}

export interface State {
  wallet: PublicKey;
  vault: PublicKey;
  account: WalletAccount | null;
  session: Session | null;
  zk: ZkAuth | null;
  passkey: PasskeySigner | null;
  /** Çelësi ephemeral i provës zk (nënshkruan instruksionet me provë). */
  zkKey: Keypair | null;
}

// ------------------------------------------------------------------ hyrja

export function startLogin(provider: "google" | "apple", target?: PublicKey) {
  const p = auth.beginLogin(3600);
  const state = crypto.randomUUID();
  sessionStorage.setItem("wallet:pending", JSON.stringify({ ...p, ephemeralSecretKey: Array.from(p.ephemeralSecretKey), state, target: target?.toBase58() }));
  const clientId = provider === "google" ? env.VITE_GOOGLE_CLIENT_ID : env.VITE_APPLE_CLIENT_ID;
  window.location.assign(SolanaAuth.oauthUrl({ provider, clientId, redirectUri: window.location.origin, nonce: p.nonce, state }));
}

/** Politika e sesionit të faqes: SOL (pragu ditor me passkey e mbron) dhe token-at që ka vault-i. */
async function walletPolicy(vault: PublicKey): Promise<Policy> {
  const tokens = await connection.getParsedTokenAccountsByOwner(vault, { programId: TOKEN_PROGRAM_ID });
  const limits = [{ mint: SOL_MINT, amount: U64_MAX, periodSecs: 86400 }];
  for (const t of tokens.value
    .map((a) => a.account.data.parsed.info)
    .filter((i) => BigInt(i.tokenAmount.amount) > 0n)
    .sort((a, b) => (BigInt(b.tokenAmount.amount) > BigInt(a.tokenAmount.amount) ? 1 : -1))
    .slice(0, 3)) {
    limits.push({ mint: new PublicKey(t.mint), amount: BigInt(t.tokenAmount.amount), periodSecs: 86400 });
  }
  return { expiresIn: 3600, label: "wallet-page", allowedPrograms: [SYSTEM_PROGRAM_ID, TOKEN_PROGRAM_ID, ATA_PROGRAM_ID], limits };
}

export async function finishLogin(): Promise<State | null> {
  const params = new URLSearchParams(window.location.hash.slice(1));
  const jwt = params.get("id_token");
  if (!jwt) return null;
  history.replaceState(null, "", window.location.pathname);
  const raw = sessionStorage.getItem("wallet:pending");
  if (!raw) throw new Error("nuk ka hyrje në pritje");
  const stored = JSON.parse(raw);
  sessionStorage.removeItem("wallet:pending");
  if (params.get("state") !== stored.state) throw new Error("state nuk përputhet");
  const pending: PendingLogin = { ...stored, ephemeralSecretKey: Uint8Array.from(stored.ephemeralSecretKey) };
  if (decodeJwt(jwt).nonce !== pending.nonce) throw new Error("nonce nuk përputhet");

  const claims = decodeJwt(jwt);
  const salt = await auth.fetchSalt(jwt);
  const seed = genAddressSeed(salt, "sub", claims.sub, claims.aud);
  const identity = zkIdentity(claims.iss, toBigEndian(seed));
  const sessionKey = Keypair.fromSecretKey(pending.ephemeralSecretKey);
  const target = stored.target ? new PublicKey(stored.target) : null;
  const resolved = await auth.resolveWallet(identity);
  const inputs = await auth.prove(jwt, pending, salt);
  const jwk = jwkAddress(programId, claims.iss, decodeJwtHeader(jwt).kid);
  const block = encodeZkBlock(inputs, pending.maxEpoch);

  // Rikuperim (kind 2): identiteti i ri për një portofol të hapur me passkey.
  if (target && !(resolved.exists && resolved.wallet.equals(target))) {
    const wallet = target;
    return {
      wallet, vault: vaultAddress(programId, wallet), account: await loadWallet(wallet), session: null, passkey: null,
      zk: { block, identity, accounts: { sessionKey: sessionKey.publicKey, jwk, wallet }, foreign: true }, zkKey: sessionKey,
    };
  }

  const wallet = resolved.wallet;
  const policy = await walletPolicy(vaultAddress(programId, wallet));
  const { transaction, session } = await auth.buildLogin(jwt, pending, inputs, policy, sessionKey.publicKey);
  await airdrop(sessionKey.publicKey);
  const latest = await connection.getLatestBlockhash();
  transaction.recentBlockhash = latest.blockhash;
  transaction.lastValidBlockHeight = latest.lastValidBlockHeight;
  transaction.sign(sessionKey);
  const sig = await connection.sendRawTransaction(transaction.serialize());
  await confirmTransaction(connection, sig);
  return {
    wallet, vault: session.vault, account: await loadWallet(wallet), session, passkey: null,
    zk: { block, identity, accounts: { sessionKey: sessionKey.publicKey, jwk, wallet }, foreign: false }, zkKey: sessionKey,
  };
}

export async function passkeyLogin(): Promise<State> {
  const { wallet, signer } = await discoverBrowserPasskey(RP_ID, async (w) => (await loadWallet(w))?.passkeys.map((p) => p.publicKey) ?? []);
  return { wallet, vault: vaultAddress(programId, wallet), account: await loadWallet(wallet), session: null, zk: null, passkey: signer, zkKey: null };
}

/** Attach an existing passkey without discarding an active OAuth session. */
export async function attachPasskey(s: State): Promise<State> {
  const selected = await passkeyLogin();
  if (!selected.wallet.equals(s.wallet)) throw new Error("passkey-i i përket një portofoli tjetër");
  return { ...s, passkey: selected.passkey };
}

export function agentRequest(text: string) {
  if (text.length > 16384) throw new Error("kërkesë shumë e madhe");
  const r = JSON.parse(text);
  if (r.version !== 1 || r.programId !== programId.toBase58()) throw new Error("programi i kërkesës nuk përputhet me këtë wallet");
  return { sessionKey: new PublicKey(r.sessionKey), policy: policyFromJson(r.policy) };
}

/** Runs in the owner's wallet; only the public delegation receipt goes back to the agent. */
export async function approveAgent(s: State, text: string) {
  if (!s.zk || s.zk.foreign || !s.zkKey) throw new Error("autorizo me Google/Apple të pronarit");
  const request = agentRequest(text);
  const instruction = openSession(programId, s.zkKey.publicKey, { ...s.zk.accounts, delegatedKey: request.sessionKey }, s.zk.block, request.policy);
  const signature = await sendZk(s, [instruction]);
  return JSON.stringify({ wallet: s.wallet.toBase58(), signature, created: false, policyHash: toHex(policyHash(request.policy)) }, null, 2);
}

export async function loadWallet(wallet: PublicKey): Promise<WalletAccount | null> {
  const a = await connection.getAccountInfo(wallet);
  return a ? decodeWallet(a.data) : null;
}

// ------------------------------------------------------------------ asetet

export interface Asset {
  mint: PublicKey | null;
  symbol: string;
  amount: bigint;
  decimals: number;
  tokenAccount?: PublicKey;
  programId?: PublicKey;
}

export async function assets(vault: PublicKey): Promise<Asset[]> {
  const out: Asset[] = [{ mint: null, symbol: "SOL", amount: BigInt(await connection.getBalance(vault)), decimals: 9 }];
  for (const programId of [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID]) {
    const r = await connection.getParsedTokenAccountsByOwner(vault, { programId });
    for (const a of r.value) {
      const i = a.account.data.parsed.info;
      out.push({ mint: new PublicKey(i.mint), symbol: `${i.mint.slice(0, 4)}…`, amount: BigInt(i.tokenAmount.amount), decimals: i.tokenAmount.decimals, tokenAccount: a.pubkey, programId });
    }
  }
  return out;
}

export const fmt = (amount: bigint, decimals: number) => {
  if (decimals === 0) return amount.toString();
  const s = amount.toString().padStart(decimals + 1, "0");
  return `${s.slice(0, -decimals) || "0"}.${s.slice(-decimals)}`.replace(/\.?0+$/, "");
};

export function parseAmount(s: string, decimals: number): bigint {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255 || !/^\d+(?:\.\d*)?$/.test(s.trim())) throw new Error("shumë e pavlefshme");
  const [a, b = ""] = s.trim().split(".");
  if (!/^\d+$/.test(a) || !/^\d*$/.test(b) || b.length > decimals) throw new Error("shumë e pavlefshme");
  const amount = BigInt(a + b.padEnd(decimals, "0"));
  if (amount > U64_MAX) throw new Error("shuma tejkalon u64");
  return amount;
}

function ata(owner: PublicKey, mint: PublicKey, tokenProgram: PublicKey) {
  return PublicKey.findProgramAddressSync([owner.toBuffer(), tokenProgram.toBuffer(), mint.toBuffer()], ATA_PROGRAM_ID)[0];
}

/** Instruksionet e tërheqjes (vault-i nënshkruan nga programi). */
export function withdrawIxs(vault: PublicKey, asset: Asset, to: PublicKey, amount: bigint): TransactionInstruction[] {
  if (!asset.mint) return [SystemProgram.transfer({ fromPubkey: vault, toPubkey: to, lamports: amount })];
  const tp = asset.programId!;
  const dest = ata(to, asset.mint, tp);
  // CreateIdempotent (1): vault-i paguan rent-in e ATA-së së marrësit nëse s'ekziston.
  const create = new TransactionInstruction({
    programId: ATA_PROGRAM_ID,
    data: Buffer.from([1]),
    keys: [
      { pubkey: vault, isSigner: true, isWritable: true },
      { pubkey: dest, isSigner: false, isWritable: true },
      { pubkey: to, isSigner: false, isWritable: false },
      { pubkey: asset.mint, isSigner: false, isWritable: false },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: tp, isSigner: false, isWritable: false },
    ],
  });
  const data = Buffer.alloc(10);
  data[0] = 12;
  new DataView(data.buffer, data.byteOffset).setBigUint64(1, amount, true);
  data[9] = asset.decimals;
  const transfer = new TransactionInstruction({
    programId: tp,
    data,
    keys: [
      { pubkey: asset.tokenAccount!, isSigner: false, isWritable: true },
      { pubkey: asset.mint, isSigner: false, isWritable: false },
      { pubkey: dest, isSigner: false, isWritable: true },
      { pubkey: vault, isSigner: true, isWritable: false },
    ],
  });
  return [create, transfer];
}

// ------------------------------------------------------------------ veprimet

async function nonce(wallet: PublicKey) {
  return (await loadWallet(wallet))!.nonce;
}

/** Tërheqje: me passkey kur portofoli ka (kalon pragun ditor), përndryshe me sesionin. */
export async function withdraw(s: State, asset: Asset, to: PublicKey, amount: bigint) {
  if (!s.session) throw new Error("tërheqja kërkon hyrje me Google/Apple (sesion)");
  const ixs = withdrawIxs(s.vault, asset, to, amount);
  if (s.passkey) {
    const pair = await passkeyOps.execute(programId, s.passkey, await nonce(s.wallet), s.session.sessionKey.publicKey, s.wallet, ixs);
    return auth.send(pair, s.session.sessionKey);
  }
  return auth.execute(s.session, ixs);
}

export const sessions = (wallet: PublicKey) => fetchSessions(connection, programId, wallet);

async function sendPasskeyOp(ixs: TransactionInstruction[]) {
  const payer = await feePayer();
  if (payer instanceof Keypair) {
    const tx = await auth.transaction(ixs, payer.publicKey);
    tx.sign(payer);
    const sig = await connection.sendRawTransaction(tx.serialize());
    await confirmTransaction(connection, sig);
    return sig;
  }
  const tx = await auth.transaction(ixs, payer.publicKey);
  return payer.submit(tx);
}

/** Tx i nënshkruar nga çelësi ephemeral i provës zk (dhe paguesi). */
async function sendZk(s: State, ixs: TransactionInstruction[]) {
  const key = s.zkKey;
  if (!key) throw new Error("kërkon hyrje me Google/Apple");
  await airdrop(key.publicKey);
  const tx = await auth.transaction(ixs, key.publicKey);
  tx.sign(key);
  const sig = await connection.sendRawTransaction(tx.serialize());
  await confirmTransaction(connection, sig);
  return sig;
}

export async function revokeSession(s: State, session: PublicKey) {
  if (s.passkey) return sendPasskeyOp(await passkeyOps.revokeSession(programId, s.passkey, s.wallet, await nonce(s.wallet), session));
  if (s.zk && !s.zk.foreign) return sendZk(s, [revokeSessionZk(programId, s.zk.accounts, session, s.zk.block)]);
  throw new Error("revokimi kërkon Google/Apple ose passkey");
}

const freeSlot = (used: number[], n: number) => {
  for (let i = 0; i < n; i++) if (!used.includes(i)) return i;
  throw new Error("të gjitha slot-et janë të zëna");
};

export function rememberPasskey(wallet: PublicKey, credentialId: Uint8Array, publicKey: Uint8Array) {
  const k = `wallet:passkeys:${wallet.toBase58()}`;
  const all = JSON.parse(localStorage.getItem(k) ?? "[]");
  all.push({ credentialId: Array.from(credentialId), publicKey: Array.from(publicKey) });
  localStorage.setItem(k, JSON.stringify(all));
}

/** Passkey i ri, me `user.id` = portofoli (që hyrja me passkey ta gjejë portofolin). */
export async function newPasskey(wallet: PublicKey) {
  const p = await createBrowserPasskey({ rpId: RP_ID, rpName: "solanaauth", userName: `portofoli ${wallet.toBase58().slice(0, 6)}`, userId: wallet.toBytes() });
  rememberPasskey(wallet, p.credentialId, p.publicKey);
  return p;
}

export async function addPasskey(s: State) {
  const acc = (await loadWallet(s.wallet))!;
  const slot = freeSlot(acc.passkeys.map((p) => p.slot), 4);
  const p = await newPasskey(s.wallet);
  let sig: string;
  if (acc.passkeys.length === 0) {
    if (!s.zk || s.zk.foreign) throw new Error("passkey-i i parë shtohet pas hyrjes me Google/Apple");
    sig = await sendZk(s, [addPasskeyZk(programId, s.zk.accounts, s.zk.block, slot, p.publicKey)]);
  } else {
    if (!s.passkey) throw new Error("hyr me një passkey ekzistues, ose përdor rikuperimin (48 orë) nëse e ke humbur");
    sig = await sendPasskeyOp(await passkeyOps.addPasskey(programId, s.passkey, s.wallet, acc.nonce, slot, p.publicKey));
  }
  return { sig, signer: browserPasskey(p.credentialId, p.publicKey, RP_ID) };
}

export async function removePasskey(s: State, slot: number) {
  if (!s.passkey) throw new Error("heqja kërkon passkey");
  return sendPasskeyOp(await passkeyOps.removePasskey(programId, s.passkey, s.wallet, await nonce(s.wallet), slot));
}

export async function setThreshold(s: State, lamports: bigint) {
  if (!s.passkey) throw new Error("pragu ndryshohet me passkey");
  return sendPasskeyOp(await passkeyOps.setThreshold(programId, s.passkey, s.wallet, await nonce(s.wallet), lamports));
}

/** Humbi passkey-n: Google/Apple fillon shtimin e një passkey të ri pas timelock-ut. */
export async function recoverPasskey(s: State) {
  if (!s.zk || s.zk.foreign) throw new Error("kërkon hyrje me Google/Apple");
  const acc = (await loadWallet(s.wallet))!;
  const slot = acc.passkeys.length < 4 ? freeSlot(acc.passkeys.map((p) => p.slot), 4) : 0;
  const p = await newPasskey(s.wallet);
  return sendZk(s, [beginRecoveryAddPasskey(programId, s.zk.accounts, s.zk.block, slot, p.publicKey)]);
}

/** Humbi Google/salt-in: passkey-i fillon shtimin e identitetit të ri pas timelock-ut. */
export async function recoverZk(s: State) {
  if (!s.passkey || !s.zk?.foreign) throw new Error("kërkon passkey dhe hyrje me llogarinë e re Google/Apple");
  const acc = (await loadWallet(s.wallet))!;
  const slot = acc.zkIdentities.length < 2 ? freeSlot(acc.zkIdentities.map((z) => z.slot), 2) : 0;
  const pair = await passkeyOps.beginRecoveryAddZk(programId, s.passkey, acc.nonce, s.zk.accounts, s.zk.block, slot);
  return sendZk(s, pair);
}

export async function cancelRecovery(s: State) {
  if (s.passkey) return sendPasskeyOp(await passkeyOps.cancelRecovery(programId, s.passkey, s.wallet, await nonce(s.wallet)));
  if (s.zk && !s.zk.foreign) return sendZk(s, [cancelRecoveryZk(programId, s.zk.accounts, s.zk.block)]);
  throw new Error("anulimi kërkon një autoritet ekzistues");
}

export const completeRecovery = (wallet: PublicKey) => sendPasskeyOp([finishRecovery(programId, wallet)]);
