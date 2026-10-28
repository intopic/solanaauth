//! 7. `execute`: sesioni ekzekuton instruksione me vault-in si nënshkrues, brenda politikës.
//!
//! Llogaritë: `[session_key (s), wallet, session (w), vault (w), ...të tjerat]`; me passkey,
//! llogaria e fundit është sysvar-i Instructions.
//! Data: `flags u8` (bit 0: passkey, pastaj `passkey_block`), `n_ix u8`, pastaj për çdo instruksion: `program_index u8, n_accounts u8,
//! (account_index u8, flags u8) * n, data_len u16, data`. `flags`: bit 0 writable, bit 1 signer.
//! Indekset i referohen listës së llogarive të instruksionit `execute`.
//!
//! Programi nuk interpreton instruksionet e brendshme: mat bilancet e vault-it dhe të token
//! account-eve të tij para dhe pas CPI-ve dhe kontrollon invariantet (DIZAJNI.md 5.2).

use pinocchio::{
    cpi::{invoke_signed_with_bounds, Seed, Signer},
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};

use crate::error::{AuthError, Result};
use crate::policy::{charge_execution, is_forbidden, record_execution};
use crate::processor::SYSTEM_PROGRAM;
use crate::state::{Session, Wallet, MAX_PROGRAMS, SEED_VAULT, THRESHOLD_WINDOW_SECS};
use crate::util::{derive_pda, find_pda, now, require_signer, require_writable, Account, Reader};

pub const TOKEN_PROGRAM: Address =
    Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN_2022_PROGRAM: Address =
    Address::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const ASSOCIATED_TOKEN_PROGRAM: Address =
    Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// Maksimumi i llogarive për një instruksion të brendshëm.
pub const MAX_INNER_ACCOUNTS: usize = 24;
/// Maksimumi i token account-eve të vault-it që maten në një `execute`.
pub const MAX_TRACKED: usize = 8;

const FIXED: usize = 4;
const WALLET_IDX: usize = 1;
const SESSION_IDX: usize = 2;

// Layout-i i SPL Token Account (i njëjtë në Token-2022 për 165 bytes e para).
const TA_LEN: usize = 165;
const TA_MINT: core::ops::Range<usize> = 0..32;
const TA_OWNER: core::ops::Range<usize> = 32..64;
const TA_AMOUNT: core::ops::Range<usize> = 64..72;
const TA_DELEGATE_TAG: core::ops::Range<usize> = 72..76;
const TA_CLOSE_AUTH_TAG: core::ops::Range<usize> = 129..133;

#[derive(Clone, Copy)]
struct Tracked {
    index: u8,
    mint: [u8; 32],
    amount: u64,
    lamports: u64,
}

fn is_token_program(a: &AccountView) -> bool {
    a.owned_by(&TOKEN_PROGRAM) || a.owned_by(&TOKEN_2022_PROGRAM)
}

/// Token account i vault-it? Kthen (mint, amount).
fn vault_token(a: &AccountView, vault: &Address) -> Result<Option<([u8; 32], u64)>> {
    if !a.is_writable() || !is_token_program(a) || a.data_len() < TA_LEN {
        return Ok(None);
    }
    let d = a.try_borrow()?;
    if &d[TA_OWNER] != vault.as_ref() {
        return Ok(None);
    }
    Ok(Some((
        d[TA_MINT].try_into().unwrap(),
        u64::from_le_bytes(d[TA_AMOUNT].try_into().unwrap()),
    )))
}

pub fn execute(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < FIXED {
        return Err(AuthError::InvalidAccount.into());
    }
    let session_key = &accounts[0];
    let wallet_view = &accounts[WALLET_IDX];
    let session_view = &accounts[SESSION_IDX];
    let vault = &accounts[3];
    require_signer(session_key)?;
    require_writable(session_view)?;
    require_writable(vault)?;
    let now = now()?;

    // Sesioni dhe portofoli.
    Wallet::check(wallet_view, program_id)?;
    Session::check(session_view, program_id)?;
    let vault_bump = Wallet::from_bytes(&wallet_view.try_borrow()?)?.vault_bump;
    let mut allowed = [[0u8; 32]; MAX_PROGRAMS];
    let n_allowed;
    let unrestricted_programs;
    {
        let d = session_view.try_borrow()?;
        let s = Session::from_bytes(&d)?;
        if &s.wallet != wallet_view.address().as_array()
            || &s.session_key != session_key.address().as_array()
        {
            return Err(AuthError::Unauthorized.into());
        }
        if s.revoked != 0 {
            return Err(AuthError::SessionRevoked.into());
        }
        if now >= s.expires_at.get() {
            return Err(AuthError::SessionExpired.into());
        }
        n_allowed = s.n_programs as usize;
        unrestricted_programs = s.unrestricted_programs();
        allowed[..n_allowed].copy_from_slice(s.programs());
    }
    let expected_vault = derive_pda(
        &[SEED_VAULT, wallet_view.address().as_ref()],
        vault_bump,
        program_id,
    );
    if vault.address() != &expected_vault {
        return Err(AuthError::InvalidAccount.into());
    }

    // Passkey (opsional): miraton daljet mbi pragun.
    let mut r = Reader::new(data);
    let flags = r.u8()?;
    if flags > 1 {
        return Err(AuthError::InvalidInstruction.into());
    }
    let passkey_ok = flags & 1 != 0;
    if passkey_ok {
        let client_data = crate::passkey::read_block(&mut r)?;
        let n = accounts.len();
        crate::authority::authorize_passkey(
            crate::OP_EXECUTE,
            &[flags],
            client_data,
            r.data,
            &accounts[n - 1],
            wallet_view,
            &accounts[..n - 1],
            program_id,
        )?;
    }

    // Matja para CPI-ve.
    let vault_before = vault.lamports();
    let mut tracked = [Tracked {
        index: 0,
        mint: [0; 32],
        amount: 0,
        lamports: 0,
    }; MAX_TRACKED];
    let mut n_tracked = 0usize;
    for (i, a) in accounts.iter().enumerate().skip(FIXED) {
        if let Some((mint, amount)) = vault_token(a, vault.address())? {
            // Llogaritë e dyfishuara maten një herë.
            if tracked[..n_tracked]
                .iter()
                .any(|t| accounts[t.index as usize].address() == a.address())
            {
                continue;
            }
            if n_tracked == MAX_TRACKED {
                return Err(AuthError::TooManyEntries.into());
            }
            tracked[n_tracked] = Tracked {
                index: i as u8,
                mint,
                amount,
                lamports: a.lamports(),
            };
            n_tracked += 1;
        }
    }

    // CPI-të.
    let bump_seed = [vault_bump];
    let seeds = [
        Seed::from(SEED_VAULT),
        Seed::from(wallet_view.address().as_ref()),
        Seed::from(&bump_seed),
    ];
    let signer = Signer::from(&seeds);
    let n_ix = r.u8()?;
    if n_ix == 0 {
        return Err(AuthError::InvalidInstruction.into());
    }
    for _ in 0..n_ix {
        let program = accounts
            .get(r.u8()? as usize)
            .ok_or(AuthError::InvalidAccount)?;
        if is_forbidden(program.address(), program_id) {
            return Err(AuthError::ForbiddenProgram.into());
        }
        if !unrestricted_programs && !allowed[..n_allowed].contains(program.address().as_array()) {
            return Err(AuthError::ProgramNotAllowed.into());
        }
        let n_acc = r.u8()? as usize;
        if n_acc > MAX_INNER_ACCOUNTS {
            return Err(AuthError::TooManyEntries.into());
        }
        let metas = r.take(2 * n_acc)?;
        let data_len = r.u16()? as usize;
        let ix_data = r.take(data_len)?;

        let mut ix_accounts: [core::mem::MaybeUninit<InstructionAccount>; MAX_INNER_ACCOUNTS] =
            [const { core::mem::MaybeUninit::uninit() }; MAX_INNER_ACCOUNTS];
        let mut views: [&AccountView; MAX_INNER_ACCOUNTS] = [session_key; MAX_INNER_ACCOUNTS];
        for (k, m) in metas.chunks_exact(2).enumerate() {
            let idx = m[0] as usize;
            let flags = m[1];
            if idx == WALLET_IDX || idx == SESSION_IDX || flags > 3 {
                return Err(AuthError::InvalidAccount.into());
            }
            let a = accounts.get(idx).ok_or(AuthError::InvalidAccount)?;
            let is_signer = flags & 2 != 0;
            // Vetëm vault-i nënshkruan në instruksionet e brendshme. Nënshkruesit e transaksionit
            // (fee payer-i, paymaster-i, çelësi i sesionit) nuk ia japin autoritetin e tyre
            // instruksioneve që zgjedh sesioni (D25).
            if is_signer && a.address() != vault.address() {
                return Err(AuthError::MissingSignature.into());
            }
            ix_accounts[k].write(InstructionAccount::new(
                a.address(),
                flags & 1 != 0,
                is_signer,
            ));
            views[k] = a;
        }
        // SAFETY: elementet [0, n_acc) u inicializuan më lart.
        let ix_accounts: &[InstructionAccount] = unsafe {
            core::slice::from_raw_parts(ix_accounts.as_ptr() as *const InstructionAccount, n_acc)
        };
        let ix = InstructionView {
            program_id: program.address(),
            data: ix_data,
            accounts: ix_accounts,
        };
        invoke_signed_with_bounds::<MAX_INNER_ACCOUNTS>(
            &ix,
            &views[..n_acc],
            core::slice::from_ref(&signer),
        )?;
    }
    r.finish()?;

    // Invariantet pas CPI-ve.
    if !vault.owned_by(&SYSTEM_PROGRAM) || vault.data_len() != 0 {
        return Err(AuthError::VaultInvariant.into());
    }
    // A CPI may create a vault token account that did not exist at snapshot time.
    // Validate the final authority of every vault token account, including new ATAs:
    // a delegate installed on an empty account could otherwise drain future deposits.
    for a in accounts.iter().skip(FIXED) {
        if !a.is_writable() || !is_token_program(a) || a.data_len() < TA_LEN {
            continue;
        }
        let d = a.try_borrow()?;
        if &d[TA_OWNER] == vault.address().as_ref() {
            if d[TA_DELEGATE_TAG] != [0; 4] || d[TA_CLOSE_AUTH_TAG] != [0; 4] {
                return Err(AuthError::TokenInvariant.into());
            }
        } else {
            // A newly created vault ATA must not change its token authority before the
            // final scan either: future deposits still target its deterministic address.
            let token_program = if a.owned_by(&TOKEN_PROGRAM) {
                &TOKEN_PROGRAM
            } else {
                &TOKEN_2022_PROGRAM
            };
            let (expected, _) = find_pda(
                &[
                    vault.address().as_ref(),
                    token_program.as_ref(),
                    &d[TA_MINT],
                ],
                &ASSOCIATED_TOKEN_PROGRAM,
            );
            if a.address() == &expected {
                return Err(AuthError::TokenInvariant.into());
            }
        }
    }
    // Rent-i i token account-eve të mbyllura llogaritet si SOL i vault-it.
    let mut sol_in = vault_before;
    let mut spent: [([u8; 32], u64); MAX_TRACKED] = [([0; 32], 0); MAX_TRACKED];
    let mut n_spent = 0usize;
    for t in &tracked[..n_tracked] {
        let a = &accounts[t.index as usize];
        if a.lamports() == 0 || a.data_len() == 0 {
            if t.amount != 0 {
                return Err(AuthError::TokenInvariant.into());
            }
            sol_in = sol_in.saturating_add(t.lamports);
            continue;
        }
        let d = a.try_borrow()?;
        if !is_token_program(a)
            || d.len() < TA_LEN
            || d[TA_OWNER] != *vault.address().as_ref()
            || d[TA_MINT] != t.mint
            || d[TA_DELEGATE_TAG] != [0; 4]
            || d[TA_CLOSE_AUTH_TAG] != [0; 4]
        {
            return Err(AuthError::TokenInvariant.into());
        }
        let after = u64::from_le_bytes(d[TA_AMOUNT].try_into().unwrap());
        let out = t.amount.saturating_sub(after);
        if out > 0 {
            match spent[..n_spent].iter_mut().find(|(m, _)| *m == t.mint) {
                Some((_, v)) => *v = v.saturating_add(out),
                None => {
                    spent[n_spent] = (t.mint, out);
                    n_spent += 1;
                }
            }
        }
    }
    let sol_out = sol_in.saturating_sub(vault.lamports());

    // Pragu ditor (D14): pa passkey, daljet e SOL brenda 24 orëve s'kalojnë `threshold_lamports`.
    if !passkey_ok && sol_out > 0 {
        let mut wd = wallet_view.try_borrow_mut()?;
        let w = Wallet::from_bytes_mut(&mut wd)?;
        let threshold = w.threshold_lamports.get();
        if threshold > 0 && w.has_passkey() {
            require_writable(wallet_view)?;
            if now
                >= w.threshold_window_start
                    .get()
                    .saturating_add(THRESHOLD_WINDOW_SECS)
            {
                w.threshold_window_start.set(now);
                w.threshold_spent.set(0);
            }
            let total = w.threshold_spent.get().saturating_add(sol_out);
            if total > threshold {
                return Err(AuthError::AboveThreshold.into());
            }
            w.threshold_spent.set(total);
        }
    }

    let mut d = session_view.try_borrow_mut()?;
    record_execution(&mut d, now)?;
    charge_execution(&mut d, &[0u8; 32], sol_out, now)?;
    for (mint, amount) in &spent[..n_spent] {
        charge_execution(&mut d, mint, *amount, now)?;
    }
    Ok(())
}
