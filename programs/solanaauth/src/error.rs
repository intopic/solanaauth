//! Kodet e gabimeve (`ProgramError::Custom`). Numrat janë pjesë e API-së: mos i rinumëro.

use pinocchio::error::ProgramError;
use zklogin_verifier::inputs::InputError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthError {
    InvalidInstruction = 1,
    InvalidAccount = 2,
    MissingSignature = 3,
    Unauthorized = 4,
    AlreadyInitialized = 5,
    // zkLogin
    ProofRejected = 10,
    JwkNotActive = 11,
    IssMismatch = 12,
    InvalidIss = 13,
    ProofExpired = 14,
    ProofTooLong = 15,
    TestVkNotAllowed = 16,
    InvalidPublicInputs = 17,
    UnknownIdentity = 18,
    // JWK registry
    TimelockNotElapsed = 20,
    NothingPending = 21,
    InvalidJwkWindow = 22,
    // Sesionet dhe politikat
    SessionExpired = 30,
    SessionRevoked = 31,
    ProgramNotAllowed = 32,
    SpendLimitExceeded = 33,
    AssetNotAllowed = 34,
    VaultInvariant = 35,
    TokenInvariant = 36,
    ForbiddenProgram = 37,
    TooManyEntries = 38,
    SessionStillActive = 39,
    InvalidPolicy = 40,
    // Passkey, rikuperimi, pragu (M3)
    PasskeyRequired = 41,
    InvalidPasskeySignature = 42,
    RecoveryPending = 43,
    NoRecovery = 44,
    AboveThreshold = 45,
    SlotOccupied = 46,
}

impl From<AuthError> for ProgramError {
    fn from(e: AuthError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

impl From<InputError> for AuthError {
    fn from(_: InputError) -> Self {
        AuthError::InvalidPublicInputs
    }
}

pub type Result<T> = core::result::Result<T, ProgramError>;
