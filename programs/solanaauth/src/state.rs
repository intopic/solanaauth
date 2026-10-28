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
pub const DOMAIN_PASSKEY: &[u8] = b"solanaauth:passkey:v1";

/// Dritarja e pragut ditor (D14).
pub const THRESHOLD_WINDOW_SECS: i64 = 24 * 3600;

pub const RECOVERY_NONE: u8 = 0;
pub const RECOVERY_ADD_PASSKEY: u8 = 1;
pub const RECOVERY_ADD_ZK: u8 = 2;

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
    /// `RECOVERY_*`.
    pub kind: u8,
    /// Vendi (slot) që zëvendësohet.
    pub slot: u8,
    pub _pad: [u8; 6],
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
    /// Daljet e SOL mbi këtë shumë brenda 24 orëve kërkojnë passkey (0 = pa prag).
    pub threshold_lamports: PodU64,
    pub recovery: Recovery,
    pub sessions_opened: PodU32,
    pub _pad2: [u8; 4],
    pub threshold_window_start: PodI64,
    pub threshold_spent: PodU64,
}

impl Account for Wallet {
    const LEN: usize = 416;
    const DISC: u8 = 3;
}

impl Wallet {
    pub fn has_identity(&self, identity: &[u8; 32]) -> bool {
        *identity != [0u8; 32] && self.zk.iter().any(|z| &z.identity == identity)
    }

    pub fn passkey_slot(&self, pubkey: &[u8; 33]) -> Option<usize> {
        if *pubkey == [0u8; 33] {
            return None;
        }
        self.passkeys.iter().position(|p| &p.pubkey == pubkey)
    }

    pub fn has_passkey(&self) -> bool {
        self.passkeys.iter().any(|p| p.pubkey != [0u8; 33])
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

    fn check(
        view: &pinocchio::AccountView,
        program_id: &pinocchio::Address,
    ) -> crate::error::Result<()> {
        if !view.owned_by(program_id) {
            return Err(crate::error::AuthError::InvalidAccount.into());
        }
        Self::from_bytes(&view.try_borrow()?)?;
        Ok(())
    }

    fn from_bytes(data: &[u8]) -> crate::error::Result<&Self> {
        if !Self::valid_layout(data) {
            return Err(crate::error::AuthError::InvalidAccount.into());
        }
        // SAFETY: validated full layout; Session is the 640-byte, alignment-one prefix.
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    fn from_bytes_mut(data: &mut [u8]) -> crate::error::Result<&mut Self> {
        if !Self::valid_layout(data) {
            return Err(crate::error::AuthError::InvalidAccount.into());
        }
        // SAFETY: validated layout and unique borrow; all fields are bytes/Pod integers.
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    fn init_bytes(data: &mut [u8]) -> crate::error::Result<&mut Self> {
        if ![Self::LEN, Self::V2_LEN].contains(&data.len()) || data[0] != 0 {
            return Err(crate::error::AuthError::AlreadyInitialized.into());
        }
        data[0] = Self::DISC;
        data[1] = if data.len() == Self::LEN { 1 } else { 2 };
        Self::from_bytes_mut(data)
    }
}

impl Session {
    pub const V2_LEN: usize = Self::LEN + core::mem::size_of::<SessionRules>();
    fn valid_layout(data: &[u8]) -> bool {
        data.len() >= Self::LEN
            && data[0] == Self::DISC
            && ((data.len() == Self::LEN && data[1] == 1)
                || (data.len() == Self::V2_LEN && data[1] == 2))
            && data[4] as usize <= MAX_PROGRAMS
            && data[5] as usize <= MAX_LIMITS
            && (data[1] != 2 || (data[6] & !7 == 0 && data[7] == 0))
    }
    pub fn unrestricted_programs(&self) -> bool {
        self.version == 2 && self._pad[0] & 1 != 0
    }
    pub fn unrestricted_assets(&self) -> bool {
        self.version == 2 && self._pad[0] & 2 != 0
    }
    pub fn programs(&self) -> &[[u8; 32]] {
        &self.allowed_programs[..self.n_programs as usize]
    }

    pub fn limits_mut(&mut self) -> &mut [SpendLimit] {
        &mut self.limits[..self.n_limits as usize]
    }
    pub fn limits(&self) -> &[SpendLimit] {
        &self.limits[..self.n_limits as usize]
    }

    pub fn is_usable(&self, now: i64) -> bool {
        self.revoked == 0 && now < self.expires_at.get()
    }
}

/// V2 extension, preserving the V1 account prefix and address derivation.
#[repr(C)]
pub struct SessionRules {
    pub per_execute: [PodU64; MAX_LIMITS],
    pub max_executions: PodU32,
    pub period_secs: PodU32,
    pub executions: PodU32,
    pub _pad: [u8; 4],
    pub window_start: PodI64,
    pub policy_hash: [u8; 32],
}

impl SessionRules {
    pub fn from_bytes(data: &[u8]) -> crate::error::Result<&Self> {
        Session::from_bytes(data)?;
        if data.len() != Session::V2_LEN {
            return Err(crate::error::AuthError::InvalidAccount.into());
        }
        // SAFETY: complete V2 layout checked, extension has alignment one and byte-only fields.
        Ok(unsafe { &*(data.as_ptr().add(Session::LEN) as *const Self) })
    }
    pub fn from_bytes_mut(data: &mut [u8]) -> crate::error::Result<&mut Self> {
        Self::from_bytes(data)?;
        // SAFETY: checked V2 extension with an exclusive data borrow.
        Ok(unsafe { &mut *(data.as_mut_ptr().add(Session::LEN) as *mut Self) })
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
    assert!(core::mem::align_of::<SessionRules>() == 1);
    assert!(Session::V2_LEN == 728);
};
