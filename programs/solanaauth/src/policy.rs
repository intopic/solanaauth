//! Blloku i politikës së sesionit dhe kontrollet statike të tij.
//!
//! Formati: `expires_in u32, max_fee u64, label [32], n_programs u8, programs [32 * n],
//! n_limits u8, (mint [32], amount u64, period_secs u32) * n`.

use pinocchio::Address;

use crate::error::{AuthError, Result};
use crate::state::{Session, SessionRules, SpendLimit, MAX_LIMITS, MAX_PROGRAMS};
use crate::util::{sha256, Account, PodI64, PodU32, PodU64, Reader};

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
    pub v2: bool,
    pub flags: u8,
    pub expires_in: u32,
    pub max_fee: u64,
    pub label: &'a [u8; 32],
    pub programs: &'a [u8],
    pub limits: &'a [u8],
    pub max_executions: u32,
    pub execution_period: u32,
    pub hash: [u8; 32],
}

const LIMIT_LEN: usize = 32 + 8 + 4;

impl<'a> Policy<'a> {
    pub fn read(r: &mut Reader<'a>) -> Result<Self> {
        let original = r.data;
        let first = r.u32()?;
        let v2 = first == 0;
        let flags = if v2 {
            if r.u8()? != 2 {
                return Err(AuthError::InvalidPolicy.into());
            }
            let f = r.u8()?;
            if f & !7 != 0 {
                return Err(AuthError::InvalidPolicy.into());
            }
            f
        } else {
            0
        };
        let expires_in = if v2 { r.u32()? } else { first };
        let max_fee = if v2 { 0 } else { r.u64()? };
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
        let limits = r.take((if v2 { 53 } else { LIMIT_LEN }) * n_limits)?;
        let (max_executions, execution_period) = if flags & 4 != 0 {
            (r.u32()?, r.u32()?)
        } else {
            (0, 0)
        };
        if flags & 4 != 0 && execution_period == 0 {
            return Err(AuthError::InvalidPolicy.into());
        }
        let hash = sha256(&[&original[..original.len() - r.data.len()]]);
        Ok(Policy {
            v2,
            flags,
            expires_in,
            max_fee,
            label,
            programs,
            limits,
            max_executions,
            execution_period,
            hash,
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
        session._pad = [self.flags, 0];

        let n_programs = self.programs.len() / 32;
        if self.flags & 1 != 0 && n_programs != 0 {
            return Err(AuthError::InvalidPolicy.into());
        }
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

        let stride = if self.v2 { 53 } else { LIMIT_LEN };
        let n_limits = self.limits.len() / stride;
        for (i, chunk) in self.limits.chunks_exact(stride).enumerate() {
            let mint: [u8; 32] = chunk[..32].try_into().unwrap();
            let f = if self.v2 { chunk[32] } else { 1 };
            let offset = if self.v2 { 33 } else { 32 };
            let amount = u64::from_le_bytes(chunk[offset..offset + 8].try_into().unwrap());
            let period = u32::from_le_bytes(chunk[offset + 8..offset + 12].try_into().unwrap());
            if f & !3 != 0
                || (f & 1 != 0 && period == 0)
                || (f & 1 == 0 && (period != 0 || amount != 0))
                || session.limits[..i].iter().any(|l| l.mint == mint)
            {
                return Err(AuthError::InvalidPolicy.into());
            }
            session.limits[i] = SpendLimit {
                mint,
                amount: PodU64(amount.to_le_bytes()),
                period_secs: PodU32(period.to_le_bytes()),
                _pad: [if self.v2 { f } else { 0 }, 0, 0, 0],
                window_start: PodI64(now.to_le_bytes()),
                spent: PodU64::default(),
            };
        }
        session.n_limits = n_limits as u8;
        Ok(())
    }

    pub fn apply_rules(&self, data: &mut [u8], now: i64) -> Result<()> {
        if self.v2 {
            let rules = SessionRules::from_bytes_mut(data)?;
            for (i, chunk) in self.limits.chunks_exact(53).enumerate() {
                rules.per_execute[i].set(u64::from_le_bytes(chunk[45..53].try_into().unwrap()));
                if chunk[32] & 2 == 0 && rules.per_execute[i].get() != 0 {
                    return Err(AuthError::InvalidPolicy.into());
                }
            }
            rules.max_executions.set(self.max_executions);
            rules.period_secs.set(self.execution_period);
            rules.window_start.set(now);
            rules.policy_hash = self.hash;
        }
        Ok(())
    }
}

/// Zbret `amount` nga limiti i `mint` (dritarja rifillon kur kalon `period_secs`).
/// Asetet pa limit nuk mund të zbresin (D5).
pub fn charge(session: &mut Session, mint: &[u8; 32], amount: u64, now: i64) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let unrestricted = session.unrestricted_assets();
    let v2 = session.version == 2;
    let found = session.limits_mut().iter_mut().find(|l| &l.mint == mint);
    let limit = match found {
        Some(l) => l,
        None if unrestricted => return Ok(()),
        None => return Err(AuthError::AssetNotAllowed.into()),
    };
    if v2 && limit._pad[0] & 1 == 0 {
        return Ok(());
    }
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

/// Per-execute and periodic caps use the same aggregate net debit for each mint.
pub fn charge_execution(data: &mut [u8], mint: &[u8; 32], amount: u64, now: i64) -> Result<()> {
    let s = Session::from_bytes(data)?;
    if amount > 0 && s.version == 2 {
        if let Some((i, l)) = s.limits().iter().enumerate().find(|(_, l)| &l.mint == mint) {
            if l._pad[0] & 2 != 0 && amount > SessionRules::from_bytes(data)?.per_execute[i].get() {
                return Err(AuthError::PerExecuteLimitExceeded.into());
            }
        }
    }
    charge(Session::from_bytes_mut(data)?, mint, amount, now)
}

/// Counts successful execute calls; a later instruction failure rolls this state back atomically.
pub fn record_execution(data: &mut [u8], now: i64) -> Result<()> {
    let s = Session::from_bytes(data)?;
    if s.version != 2 || s._pad[0] & 4 == 0 {
        return Ok(());
    }
    let r = SessionRules::from_bytes_mut(data)?;
    if now
        >= r.window_start
            .get()
            .saturating_add(r.period_secs.get() as i64)
    {
        r.window_start.set(now);
        r.executions.set(0);
    }
    if r.executions.get() >= r.max_executions.get() {
        return Err(AuthError::FrequencyExceeded.into());
    }
    r.executions.set(
        r.executions
            .get()
            .checked_add(1)
            .ok_or(AuthError::FrequencyExceeded)?,
    );
    Ok(())
}
