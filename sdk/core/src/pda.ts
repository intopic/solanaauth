import { PublicKey } from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha256";

import { BPF_LOADER_UPGRADEABLE_ID, DOMAIN, SEED } from "./constants.js";
import { concat, utf8 } from "./bytes.js";

const pda = (seeds: Uint8Array[], programId: PublicKey) =>
  PublicKey.findProgramAddressSync(seeds, programId)[0];

export function configAddress(programId: PublicKey): PublicKey {
  return pda([utf8(SEED.config)], programId);
}

export function jwkAddress(programId: PublicKey, iss: string, kid: string): PublicKey {
  return pda([utf8(SEED.jwk), sha256(utf8(iss)), sha256(utf8(kid))], programId);
}

/** `sha256(DOMAIN_ZK || iss || address_seed)`. */
export function zkIdentity(iss: string, addressSeed: Uint8Array): Uint8Array {
  return sha256(concat(utf8(DOMAIN.zk), utf8(iss), addressSeed));
}

export function walletId(identity: Uint8Array): Uint8Array {
  return sha256(concat(utf8(DOMAIN.wallet), identity));
}

/** Adresa e `Wallet` nga identiteti fillestar zk. Nuk ndryshon kurrë. */
export function walletAddress(programId: PublicKey, identity: Uint8Array): PublicKey {
  return pda([utf8(SEED.wallet), walletId(identity)], programId);
}

/** Adresa ku përdoruesi merr fondet (PDA pa të dhëna, e System Program). */
export function vaultAddress(programId: PublicKey, wallet: PublicKey): PublicKey {
  return pda([utf8(SEED.vault), wallet.toBytes()], programId);
}

export function sessionAddress(programId: PublicKey, wallet: PublicKey, sessionKey: PublicKey): PublicKey {
  return pda([utf8(SEED.session), wallet.toBytes(), sessionKey.toBytes()], programId);
}

export function programDataAddress(programId: PublicKey): PublicKey {
  return pda([programId.toBytes()], BPF_LOADER_UPGRADEABLE_ID);
}
