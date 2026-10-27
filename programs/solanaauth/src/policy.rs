//! Blloku i politikës së sesionit dhe kontrollet statike të tij.
//!
//! Formati: `expires_in u32, max_fee u64, label [32], n_programs u8, programs [32 * n],
//! n_limits u8, (mint [32], amount u64, period_secs u32) * n`.

use pinocchio::Address;

use crate::error::{AuthError, Result};
use crate::state::{Session, SpendLimit, MAX_LIMITS, MAX_PROGRAMS};
use crate::util::{PodI64, PodU32, PodU64, Reader};

/// Programet ku sesioni nuk mund të bëjë kurrë CPI, edhe po të jenë në listë.
pub const FORBIDDEN_PROGRAMS: [Address; 5] = [
    // BPF loaders (upgrade/close të programeve) dhe Native Loader.
    Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111"),
    Address::from_str_const("BPFLoader2111111111111111111111111111111111"),
    Address::from_str_const("BPFLoader1111111111111111111111111111111111"),
    Address::from_str_const("LoaderV411111111111111111111111111111111111"),
    Address::from_str_const("NativeLoader1111111111111111111111111111111"),
];

pub fn is_forbidden(program: &Address, self_id: &Address) -> bool {
    program == self_id || FORBIDDEN_PROGRAMS.iter().any(|p| p == program)
}

pub struct Policy<'a> {
    pub expires_in: u32,
    pub max_fee: u64,
    pub label: &'a [u8; 32],
    pub programs: &'a [u8],
    pub limits: &'a [u8],
}

const LIMIT_LEN: usize = 32 + 8 + 4;

impl<'a> Policy<'a> {
    pub fn read(r: &mut Reader<'a>) -> Result<Self> {
        let expires_in = r.u32()?;
        let max_fee = r.u64()?;
        let label = r.array()?;
        let n_programs = r.u8()? as usize;
        if n_programs > MAX_PROGRAMS {
            return Err(AuthError::TooManyEntries.into());
        }
        let programs = r.take(32 * n_programs)?;
        let n_limits = r.u8()? as usize;
        if n_limits > MAX_LIMITS {
            return Err(AuthError::TooManyEntries.into());
        }
        let limits = r.take(LIMIT_LEN * n_limits)?;
        Ok(Policy {
            expires_in,
            max_fee,
            label,
            programs,
            limits,
        })
    }

    /// Shkruan politikën te `session` pasi kontrollon që është e vlefshme.
    pub fn apply(&self, session: &mut Session, now: i64, self_id: &Address) -> Result<()> {
        if self.expires_in == 0 {
            return Err(AuthError::InvalidPolicy.into());
        }
        if self.max_fee != 0 {
            // Pagesa e tarifave nga vault-i vjen me paymaster-in (M5).
            return Err(AuthError::InvalidPolicy.into());
        }
        session.label = *self.label;
        session.max_fee = PodU64::default();

        let n_programs = self.programs.len() / 32;
        for (i, chunk) in self.programs.chunks_exact(32).enumerate() {
            let p: [u8; 32] = chunk.try_into().unwrap();
            if is_forbidden(&Address::new_from_array(p), self_id)
                || session.allowed_programs[..i].contains(&p)
            {
                return Err(AuthError::InvalidPolicy.into());
            }
            session.allowed_programs[i] = p;
        }
        session.n_programs = n_programs as u8;

        let n_limits = self.limits.len() / LIMIT_LEN;
        for (i, chunk) in self.limits.chunks_exact(LIMIT_LEN).enumerate() {
            let mint: [u8; 32] = chunk[..32].try_into().unwrap();
            let amount = u64::from_le_bytes(chunk[32..40].try_into().unwrap());
            let period = u32::from_le_bytes(chunk[40..44].try_into().unwrap());
            if period == 0 || session.limits[..i].iter().any(|l| l.mint == mint) {
                return Err(AuthError::InvalidPolicy.into());
            }
            session.limits[i] = SpendLimit {
                mint,
                amount: PodU64(amount.to_le_bytes()),
                period_secs: PodU32(period.to_le_bytes()),
                _pad: [0; 4],
                window_start: PodI64(now.to_le_bytes()),
                spent: PodU64::default(),
            };
        }
        session.n_limits = n_limits as u8;
        Ok(())
    }
}

/// Zbret `amount` nga limiti i `mint` (dritarja rifillon kur kalon `period_secs`).
/// Asetet pa limit nuk mund të zbresin (D5).
pub fn charge(session: &mut Session, mint: &[u8; 32], amount: u64, now: i64) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let limit = session
        .limits_mut()
        .iter_mut()
        .find(|l| &l.mint == mint)
        .ok_or(AuthError::AssetNotAllowed)?;
    let start = limit.window_start.get();
    if now >= start.saturating_add(limit.period_secs.get() as i64) {
        limit.window_start.set(now);
        limit.spent.set(0);
    }
    let spent = limit
        .spent
        .get()
        .checked_add(amount)
        .ok_or(AuthError::SpendLimitExceeded)?;
    if spent > limit.amount.get() {
        return Err(AuthError::SpendLimitExceeded.into());
    }
    limit.spent.set(spent);
    Ok(())
}
