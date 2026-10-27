//! M3: autoritetet e portofolit (passkey, identitetet zk), pragu dhe rikuperimi me timelock.
//!
//! | op | instruksioni      | llogaritë | data |
//! |----|-------------------|-----------|------|
//! | 11 | `add_passkey`     | mode 0: session_key (s), config, jwk, wallet (w) | `0, zk_block, slot u8, pubkey [33]` (vetëm kur portofoli s'ka passkey) |
//! |    |                   | mode 1: instructions_sysvar, wallet (w) | `1, passkey_block, slot u8, pubkey [33]` |
//! | 12 | `remove_passkey`  | instructions_sysvar, wallet (w) | `passkey_block, slot u8` |
//! | 13 | `set_threshold`   | instructions_sysvar, wallet (w) | `passkey_block, threshold_lamports u64` |
//! | 14 | `begin_recovery`  | kind 1: session_key (s), config, jwk, wallet (w) | `1, zk_block, slot u8, pubkey [33]` |
//! |    |                   | kind 2: session_key (s), config, jwk, wallet (w), instructions_sysvar | `2, passkey_block, zk_block (identiteti i ri), slot u8` |
//! | 15 | `cancel_recovery` | mode 0: session_key (s), config, jwk, wallet (w) | `0, zk_block` |
//! |    |                   | mode 1: instructions_sysvar, wallet (w) | `1, passkey_block` |
//! | 16 | `finish_recovery` | config, wallet (w) | — (kushdo, pas `eta`) |
//!
//! Rikuperimi (DIZAJNI.md 7, D7): një faktor i vetëm mund të shtojë faktorin tjetër vetëm pas
//! `config.recovery_delay`; çdo autoritet ekzistues (zk ose passkey) mund ta anulojë.

use pinocchio::{AccountView, Address, ProgramResult};

use crate::error::{AuthError, Result};
use crate::passkey;
use crate::processor::{load_config, verify_zk};
use crate::state::*;
use crate::util::*;
use crate::zk::ZkBlock;

/// Verifikon passkey-n për këtë instruksion dhe rrit nonce-in e portofolit.
/// `hashed` janë llogaritë që hyjnë në `action_hash` (të gjitha përveç sysvar-it).
#[allow(clippy::too_many_arguments)]
pub fn authorize_passkey(
    op: u8,
    prefix: &[u8],
    client_data: &[u8],
    payload: &[u8],
    sysvar: &AccountView,
    wallet_view: &AccountView,
    hashed: &[AccountView],
    program_id: &Address,
) -> Result<usize> {
    Wallet::check(wallet_view, program_id)?;
    require_writable(wallet_view)?;
    let action = passkey::action_hash(op, prefix, payload, hashed)?;
    let mut d = wallet_view.try_borrow_mut()?;
    let w = Wallet::from_bytes_mut(&mut d)?;
    let slot = passkey::verify(sysvar, w, wallet_view.address(), client_data, &action)?;
    w.nonce.set(w.nonce.get().wrapping_add(1));
    Ok(slot)
}

fn zk_identity_of_wallet(
    zkb: &ZkBlock<'_>,
    session_key: &AccountView,
    config: &AccountView,
    jwk: &AccountView,
    wallet_view: &AccountView,
    program_id: &Address,
) -> ProgramResult {
    Wallet::check(wallet_view, program_id)?;
    require_writable(wallet_view)?;
    let v = verify_zk(zkb, session_key, config, jwk, now()?, program_id)?;
    let d = wallet_view.try_borrow()?;
    if !Wallet::from_bytes(&d)?.has_identity(&v.identity) {
        return Err(AuthError::UnknownIdentity.into());
    }
    Ok(())
}

fn read_pubkey<'a>(r: &mut Reader<'a>) -> Result<&'a [u8; 33]> {
    let pk: &[u8; 33] = r.array()?;
    if pk[0] != 2 && pk[0] != 3 {
        return Err(AuthError::InvalidInstruction.into());
    }
    Ok(pk)
}

fn read_slot(r: &mut Reader<'_>, max: usize) -> Result<usize> {
    let s = r.u8()? as usize;
    if s >= max {
        return Err(AuthError::InvalidInstruction.into());
    }
    Ok(s)
}

/// 11. `add_passkey`.
pub fn add_passkey(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let mut r = Reader::new(data);
    let mode = r.u8()?;
    let wallet_view = match mode {
        0 => {
            let [session_key, config, jwk, wallet_view, ..] = accounts else {
                return Err(AuthError::InvalidAccount.into());
            };
            let zkb = ZkBlock::read(&mut r)?;
            zk_identity_of_wallet(&zkb, session_key, config, jwk, wallet_view, program_id)?;
            let d = wallet_view.try_borrow()?;
            if Wallet::from_bytes(&d)?.has_passkey() {
                // Me passkey ekzistues, faktori zk shton passkey vetëm me rikuperim (timelock).
                return Err(AuthError::PasskeyRequired.into());
            }
            wallet_view
        }
        1 => {
            let [sysvar, wallet_view, ..] = accounts else {
                return Err(AuthError::InvalidAccount.into());
            };
            let client_data = passkey::read_block(&mut r)?;
            authorize_passkey(
                crate::OP_ADD_PASSKEY,
                &[mode],
                client_data,
                r.data,
                sysvar,
                wallet_view,
                &accounts[1..2],
                program_id,
            )?;
            wallet_view
        }
        _ => return Err(AuthError::InvalidInstruction.into()),
    };
    let slot = read_slot(&mut r, MAX_PASSKEYS)?;
    let pubkey = read_pubkey(&mut r)?;
    r.finish()?;
    let now = now()?;
    let mut d = wallet_view.try_borrow_mut()?;
    let w = Wallet::from_bytes_mut(&mut d)?;
    if w.passkeys[slot].pubkey != [0u8; 33] {
        return Err(AuthError::SlotOccupied.into());
    }
    if w.passkey_slot(pubkey).is_some() {
        return Err(AuthError::InvalidInstruction.into());
    }
    w.passkeys[slot].pubkey = *pubkey;
    w.passkeys[slot].added_at.set(now);
    Ok(())
}

/// 12. `remove_passkey`.
pub fn remove_passkey(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [sysvar, wallet_view, ..] = accounts else {
        return Err(AuthError::InvalidAccount.into());
    };
    let mut r = Reader::new(data);
    let client_data = passkey::read_block(&mut r)?;
    let payload = r.data;
    let slot = read_slot(&mut r, MAX_PASSKEYS)?;
    r.finish()?;
    authorize_passkey(
        crate::OP_REMOVE_PASSKEY,
        &[],
        client_data,
        payload,
        sysvar,
        wallet_view,
        &accounts[1..2],
        program_id,
    )?;
    let mut d = wallet_view.try_borrow_mut()?;
    let w = Wallet::from_bytes_mut(&mut d)?;
    if w.passkeys[slot].pubkey == [0u8; 33] {
        return Err(AuthError::InvalidInstruction.into());
    }
    w.passkeys[slot] = Passkey {
        pubkey: [0; 33],
        _pad: [0; 7],
        added_at: PodI64::default(),
    };
    Ok(())
}

/// 13. `set_threshold`.
pub fn set_threshold(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [sysvar, wallet_view, ..] = accounts else {
        return Err(AuthError::InvalidAccount.into());
    };
    let mut r = Reader::new(data);
    let client_data = passkey::read_block(&mut r)?;
    let payload = r.data;
    let threshold = r.u64()?;
    r.finish()?;
    authorize_passkey(
        crate::OP_SET_THRESHOLD,
        &[],
        client_data,
        payload,
        sysvar,
        wallet_view,
        &accounts[1..2],
        program_id,
    )?;
    let mut d = wallet_view.try_borrow_mut()?;
    let w = Wallet::from_bytes_mut(&mut d)?;
    w.threshold_lamports.set(threshold);
    w.threshold_window_start.set(now()?);
    w.threshold_spent.set(0);
    Ok(())
}

/// 14. `begin_recovery`.
pub fn begin_recovery(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [session_key, config, jwk, wallet_view, rest @ ..] = accounts else {
        return Err(AuthError::InvalidAccount.into());
    };
    let delay = {
        let d = load_config(config, program_id)?;
        Config::from_bytes(&d)?.recovery_delay.get()
    };
    let mut r = Reader::new(data);
    let kind = r.u8()?;
    let mut payload = [0u8; 40];
    let slot;
    match kind {
        RECOVERY_ADD_PASSKEY => {
            let zkb = ZkBlock::read(&mut r)?;
            slot = read_slot(&mut r, MAX_PASSKEYS)?;
            let pk = read_pubkey(&mut r)?;
            r.finish()?;
            zk_identity_of_wallet(&zkb, session_key, config, jwk, wallet_view, program_id)?;
            let d = wallet_view.try_borrow()?;
            let w = Wallet::from_bytes(&d)?;
            if !w.has_passkey() {
                // Pa passkey, `add_passkey` me zk është i menjëhershëm.
                return Err(AuthError::InvalidInstruction.into());
            }
            if w.passkey_slot(pk).is_some() {
                return Err(AuthError::InvalidInstruction.into());
            }
            payload[..33].copy_from_slice(pk);
        }
        RECOVERY_ADD_ZK => {
            let [sysvar, ..] = rest else {
                return Err(AuthError::InvalidAccount.into());
            };
            let client_data = passkey::read_block(&mut r)?;
            let signed = r.data;
            let zkb = ZkBlock::read(&mut r)?;
            slot = read_slot(&mut r, MAX_ZK)?;
            r.finish()?;
            Wallet::check(wallet_view, program_id)?;
            // Prova e identitetit të ri (çelësi i saj ephemeral nënshkruan).
            let v = verify_zk(&zkb, session_key, config, jwk, now()?, program_id)?;
            authorize_passkey(
                crate::OP_BEGIN_RECOVERY,
                &[kind],
                client_data,
                signed,
                sysvar,
                wallet_view,
                &accounts[..4],
                program_id,
            )?;
            let d = wallet_view.try_borrow()?;
            if Wallet::from_bytes(&d)?.has_identity(&v.identity) {
                return Err(AuthError::InvalidInstruction.into());
            }
            payload[..32].copy_from_slice(&v.identity);
        }
        _ => return Err(AuthError::InvalidInstruction.into()),
    }
    let now = now()?;
    let mut d = wallet_view.try_borrow_mut()?;
    let w = Wallet::from_bytes_mut(&mut d)?;
    if w.recovery.kind != RECOVERY_NONE {
        return Err(AuthError::RecoveryPending.into());
    }
    w.recovery.kind = kind;
    w.recovery.slot = slot as u8;
    w.recovery.eta.set(now.saturating_add(delay));
    w.recovery.data = payload;
    pinocchio_log("solanaauth: RecoveryStarted");
    Ok(())
}

/// 15. `cancel_recovery`.
pub fn cancel_recovery(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let mut r = Reader::new(data);
    let mode = r.u8()?;
    let wallet_view = match mode {
        0 => {
            let [session_key, config, jwk, wallet_view, ..] = accounts else {
                return Err(AuthError::InvalidAccount.into());
            };
            let zkb = ZkBlock::read(&mut r)?;
            r.finish()?;
            zk_identity_of_wallet(&zkb, session_key, config, jwk, wallet_view, program_id)?;
            wallet_view
        }
        1 => {
            let [sysvar, wallet_view, ..] = accounts else {
                return Err(AuthError::InvalidAccount.into());
            };
            let client_data = passkey::read_block(&mut r)?;
            r.finish()?;
            authorize_passkey(
                crate::OP_CANCEL_RECOVERY,
                &[mode],
                client_data,
                &[],
                sysvar,
                wallet_view,
                &accounts[1..2],
                program_id,
            )?;
            wallet_view
        }
        _ => return Err(AuthError::InvalidInstruction.into()),
    };
    let mut d = wallet_view.try_borrow_mut()?;
    let w = Wallet::from_bytes_mut(&mut d)?;
    if w.recovery.kind == RECOVERY_NONE {
        return Err(AuthError::NoRecovery.into());
    }
    clear_recovery(w);
    Ok(())
}

fn clear_recovery(w: &mut Wallet) {
    w.recovery = Recovery {
        kind: RECOVERY_NONE,
        slot: 0,
        _pad: [0; 6],
        eta: PodI64::default(),
        data: [0; 40],
    };
}

/// 16. `finish_recovery`.
pub fn finish_recovery(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [_config, wallet_view, ..] = accounts else {
        return Err(AuthError::InvalidAccount.into());
    };
    Reader::new(data).finish()?;
    Wallet::check(wallet_view, program_id)?;
    require_writable(wallet_view)?;
    let now = now()?;
    let mut d = wallet_view.try_borrow_mut()?;
    let w = Wallet::from_bytes_mut(&mut d)?;
    let slot = w.recovery.slot as usize;
    match w.recovery.kind {
        RECOVERY_NONE => return Err(AuthError::NoRecovery.into()),
        _ if now < w.recovery.eta.get() => return Err(AuthError::TimelockNotElapsed.into()),
        RECOVERY_ADD_PASSKEY => {
            w.passkeys[slot]
                .pubkey
                .copy_from_slice(&w.recovery.data[..33]);
            w.passkeys[slot].added_at.set(now);
        }
        RECOVERY_ADD_ZK => {
            w.zk[slot].identity.copy_from_slice(&w.recovery.data[..32]);
            w.zk[slot].added_at.set(now);
        }
        _ => return Err(AuthError::InvalidAccount.into()),
    }
    clear_recovery(w);
    Ok(())
}

#[inline(always)]
fn pinocchio_log(_msg: &str) {
    #[cfg(target_os = "solana")]
    unsafe {
        pinocchio::syscalls::sol_log_(_msg.as_ptr(), _msg.len() as u64)
    };
}
