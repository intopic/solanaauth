import { PublicKey } from "@solana/web3.js";

export const SYSTEM_PROGRAM_ID = new PublicKey("11111111111111111111111111111111");
export const TOKEN_PROGRAM_ID = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export const TOKEN_2022_PROGRAM_ID = new PublicKey("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
export const BPF_LOADER_UPGRADEABLE_ID = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");
export const INSTRUCTIONS_SYSVAR_ID = new PublicKey("Sysvar1nstructions1111111111111111111111111");
export const SECP256R1_PROGRAM_ID = new PublicKey("Secp256r1SigVerify1111111111111111111111111");

/** Mint-i "zero" në limitet e politikës = SOL (lamports e vault-it). */
export const SOL_MINT = new PublicKey(new Uint8Array(32));

export const Op = {
  InitConfig: 0,
  UpdateConfig: 1,
  ProposeJwk: 2,
  ApplyJwk: 3,
  RevokeJwk: 4,
  CreateWallet: 5,
  OpenSession: 6,
  Execute: 7,
  RevokeSession: 8,
  CloseSession: 10,
  AddPasskey: 11,
  RemovePasskey: 12,
  SetThreshold: 13,
  BeginRecovery: 14,
  CancelRecovery: 15,
  FinishRecovery: 16,
} as const;

export const SEED = {
  config: "config",
  jwk: "jwk",
  wallet: "wallet",
  vault: "vault",
  session: "session",
} as const;

export const DOMAIN = {
  zk: "solanaauth:zk:v1",
  wallet: "solanaauth:wallet:v1",
  passkey: "solanaauth:passkey:v1",
} as const;

export const MAX_PROGRAMS = 8;
export const MAX_LIMITS = 4;
export const MAX_PASSKEYS = 4;
export const MAX_ZK = 2;

/** Kodet e gabimeve të programit (`ProgramError::Custom`). */
export const ERRORS: Record<number, string> = {
  1: "InvalidInstruction",
  2: "InvalidAccount",
  3: "MissingSignature",
  4: "Unauthorized",
  5: "AlreadyInitialized",
  10: "ProofRejected",
  11: "JwkNotActive",
  12: "IssMismatch",
  13: "InvalidIss",
  14: "ProofExpired",
  15: "ProofTooLong",
  16: "TestVkNotAllowed",
  17: "InvalidPublicInputs",
  18: "UnknownIdentity",
  20: "TimelockNotElapsed",
  21: "NothingPending",
  22: "InvalidJwkWindow",
  30: "SessionExpired",
  31: "SessionRevoked",
  32: "ProgramNotAllowed",
  33: "SpendLimitExceeded",
  34: "AssetNotAllowed",
  35: "VaultInvariant",
  36: "TokenInvariant",
  37: "ForbiddenProgram",
  38: "TooManyEntries",
  39: "SessionStillActive",
  40: "InvalidPolicy",
  41: "PasskeyRequired",
  42: "InvalidPasskeySignature",
  43: "RecoveryPending",
  44: "NoRecovery",
  45: "AboveThreshold",
  46: "SlotOccupied",
};

/** Emri i gabimit nga një mesazh/objekt gabimi i web3.js (`custom program error: 0x21`). */
export function decodeError(err: unknown): string | undefined {
  const s =
    typeof err === "string"
      ? err
      : err instanceof Error
        ? `${err.message} ${JSON.stringify((err as any).logs ?? "")}`
        : JSON.stringify(err);
  const hex = /custom program error: 0x([0-9a-f]+)/i.exec(s);
  if (hex) return ERRORS[parseInt(hex[1], 16)];
  const dec = /"Custom":\s*(\d+)/.exec(s);
  if (dec) return ERRORS[Number(dec[1])];
  return undefined;
}
