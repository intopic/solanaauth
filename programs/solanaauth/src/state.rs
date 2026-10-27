//! Formati i llogarive (zero-copy, alignment 1). Byte-i i parë është diskriminuesi.
//! Madhësitë janë fikse; fushat e rezervuara mbushen me zero.

use crate::util::{Account, PodI64, PodU16, PodU32, PodU64};

pub const VERSION: u8 = 1;

pub const SEED_CONFIG: &[u8] = b"config";
pub const SEED_JWK: &[u8] = b"jwk";
pub const SEED_WALLET: &[u8] = b"wallet";
pub const SEED_VAULT: &[u8] = b"vault";
pub const SEED_SESSION: &[u8] = b"session";

pub const DOMAIN_ZK: &[u8] = b"solanaauth:zk:v1";
pub const DOMAIN_WALLET: &[u8] = b"solanaauth:wallet:v1";

pub const MAX_ZK: usize = 2;
pub const MAX_PASSKEYS: usize = 4;
pub const MAX_PROGRAMS: usize = 8;
pub const MAX_LIMITS: usize = 4;

/// `["config"]`: parametrat globalë.
#[repr(C)]
pub struct Config {
    pub disc: u8,
    pub version: u8,
    pub bump: u8,
    /// 1 → pranohet edhe verifying key-i `zkLogin-test` (vetëm build-i jo-mainnet).
    pub allow_test_vk: u8,
    pub _pad: [u8; 4],
    pub admin: [u8; 32],
    pub oracle: [u8; 32],
    /// Sekonda midis `propose_jwk` dhe `apply_jwk`.
    pub jwk_timelock: PodI64,
    /// `max_epoch` mund të jetë më së shumti `now + max_session_secs`.
    pub max_session_secs: PodI64,
    /// Timelock-u i rikuperimit (M3).
    pub recovery_delay: PodI64,
}

impl Account for Config {
    const LEN: usize = 96;
    const DISC: u8 = 1;
}

/// Një çelës RSA i lëshuesit (aktiv + një ndryshim në pritje).
#[repr(C)]
pub struct JwkKey {
    pub modulus_hash: [u8; 32],
    pub modulus_bits: PodU16,
    pub _pad: [u8; 6],
    pub valid_from: PodI64,
    pub valid_until: PodI64,
}

/// `["jwk", sha256(iss), sha256(kid)]`.
#[repr(C)]
pub struct Jwk {
    pub disc: u8,
    pub version: u8,
    pub bump: u8,
    pub has_pending: u8,
    pub revoked: u8,
    pub _pad: [u8; 3],
    pub iss_hash: [u8; 32],
    pub kid_hash: [u8; 32],
    pub active: JwkKey,
    pub pending: JwkKey,
    pub pending_eta: PodI64,
}

impl Account for Jwk {
    const LEN: usize = 192;
    const DISC: u8 = 2;
}

impl Jwk {
    pub fn is_active(&self, now: i64) -> bool {
        self.revoked == 0
            && self.active.valid_from.get() <= now
            && now < self.active.valid_until.get()
    }
}

#[repr(C)]
pub struct ZkAuthority {
    /// `sha256(DOMAIN_ZK || iss || address_seed)`; zero → vend bosh.
    pub identity: [u8; 32],
    pub added_at: PodI64,
}

#[repr(C)]
pub struct Passkey {
    /// secp256r1 i ngjeshur (33 bytes); zero → vend bosh.
    pub pubkey: [u8; 33],
    pub _pad: [u8; 7],
    pub added_at: PodI64,
}

#[repr(C)]
pub struct Recovery {
    /// 0 asnjë, 1 shto passkey, 2 shto identitet zk (M3).
    pub kind: u8,
    pub _pad: [u8; 7],
    pub eta: PodI64,
    pub data: [u8; 40],
}

/// `["wallet", wallet_id]`.
#[repr(C)]
pub struct Wallet {
    pub disc: u8,
    pub version: u8,
    pub bump: u8,
    pub vault_bump: u8,
    pub _pad: [u8; 4],
    pub wallet_id: [u8; 32],
    pub created_at: PodI64,
    /// Rritet pas çdo veprimi me passkey (M3).
    pub nonce: PodU64,
    pub zk: [ZkAuthority; MAX_ZK],
    pub passkeys: [Passkey; MAX_PASSKEYS],
    pub threshold_lamports: PodU64,
    pub recovery: Recovery,
    pub sessions_opened: PodU32,
    pub _pad2: [u8; 4],
}

impl Account for Wallet {
    const LEN: usize = 400;
    const DISC: u8 = 3;
}

impl Wallet {
    pub fn has_identity(&self, identity: &[u8; 32]) -> bool {
        *identity != [0u8; 32] && self.zk.iter().any(|z| &z.identity == identity)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SpendLimit {
    /// Mint-i i token-it; zero = SOL (lamports e vault-it).
    pub mint: [u8; 32],
    pub amount: PodU64,
    pub period_secs: PodU32,
    pub _pad: [u8; 4],
    pub window_start: PodI64,
    pub spent: PodU64,
}

/// `["session", wallet, session_key]`.
#[repr(C)]
pub struct Session {
    pub disc: u8,
    pub version: u8,
    pub bump: u8,
    pub revoked: u8,
    pub n_programs: u8,
    pub n_limits: u8,
    pub _pad: [u8; 2],
    pub wallet: [u8; 32],
    pub session_key: [u8; 32],
    pub created_at: PodI64,
    pub expires_at: PodI64,
    pub label: [u8; 32],
    /// I rezervuar për pagesën e tarifave nga vault-i (paymaster, M5); 0 në M2.
    pub max_fee: PodU64,
    pub allowed_programs: [[u8; 32]; MAX_PROGRAMS],
    pub limits: [SpendLimit; MAX_LIMITS],
}

impl Account for Session {
    const LEN: usize = 640;
    const DISC: u8 = 4;
}

impl Session {
    pub fn programs(&self) -> &[[u8; 32]] {
        &self.allowed_programs[..self.n_programs as usize]
    }

    pub fn limits_mut(&mut self) -> &mut [SpendLimit] {
        &mut self.limits[..self.n_limits as usize]
    }

    pub fn is_usable(&self, now: i64) -> bool {
        self.revoked == 0 && now < self.expires_at.get()
    }
}

const _: () = {
    assert!(core::mem::size_of::<Config>() == Config::LEN);
    assert!(core::mem::size_of::<Jwk>() == Jwk::LEN);
    assert!(core::mem::size_of::<Wallet>() == Wallet::LEN);
    assert!(core::mem::size_of::<Session>() == Session::LEN);
    assert!(core::mem::align_of::<Config>() == 1);
    assert!(core::mem::align_of::<Jwk>() == 1);
    assert!(core::mem::align_of::<Wallet>() == 1);
    assert!(core::mem::align_of::<Session>() == 1);
};
