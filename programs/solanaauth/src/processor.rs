//! Instruksionet e programit. Formati i secilit është i dokumentuar te `lib.rs`.

use pinocchio::{
    cpi::{Seed, Signer},
    AccountView, Address, ProgramResult,
};

use crate::error::{AuthError, Result};
use crate::policy::Policy;
use crate::state::*;
use crate::util::*;
use crate::zk::{self, ZkBlock};

pub const SYSTEM_PROGRAM: Address = Address::from_str_const("11111111111111111111111111111111");
pub const BPF_LOADER_UPGRADEABLE: Address =
    Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");

/// Krijon një PDA të programit (funksionon edhe kur adresa ka marrë lamports më parë).
fn create_pda(
    payer: &AccountView,
    account: &AccountView,
    space: usize,
    seeds: &[Seed],
    program_id: &Address,
) -> ProgramResult {
    if account.data_len() != 0 || !account.owned_by(&SYSTEM_PROGRAM) {
        return Err(AuthError::AlreadyInitialized.into());
    }
    pinocchio_system::create_account_with_minimum_balance_signed(
        account,
        space,
        program_id,
        payer,
        None,
        &[Signer::from(seeds)],
    )
}

pub(crate) fn load_config<'a>(
    view: &'a AccountView,
    program_id: &Address,
) -> Result<pinocchio::account::Ref<'a, [u8]>> {
    Config::check(view, program_id)?;
    let data = view.try_borrow()?;
    let cfg = Config::from_bytes(&data)?;
    if view.address() != &derive_pda(&[SEED_CONFIG], cfg.bump, program_id) {
        return Err(AuthError::InvalidAccount.into());
    }
    Ok(data)
}

struct ConfigArgs<'a> {
    admin: &'a [u8; 32],
    oracle: &'a [u8; 32],
    jwk_timelock: i64,
    max_session_secs: i64,
    recovery_delay: i64,
    allow_test_vk: u8,
}

impl<'a> ConfigArgs<'a> {
    fn read(r: &mut Reader<'a>) -> Result<Self> {
        let a = ConfigArgs {
            admin: r.array()?,
            oracle: r.array()?,
            jwk_timelock: r.i64()?,
            max_session_secs: r.i64()?,
            recovery_delay: r.i64()?,
            allow_test_vk: r.u8()?,
        };
        r.finish()?;
        if a.jwk_timelock < 0
            || a.max_session_secs <= 0
            || a.recovery_delay < 0
            || a.allow_test_vk > 1
            || (cfg!(feature = "mainnet") && a.allow_test_vk != 0)
            || *a.admin == [0u8; 32]
        {
            return Err(AuthError::InvalidInstruction.into());
        }
        Ok(a)
    }

    fn write(&self, cfg: &mut Config) {
        cfg.admin = *self.admin;
        cfg.oracle = *self.oracle;
        cfg.jwk_timelock.set(self.jwk_timelock);
        cfg.max_session_secs.set(self.max_session_secs);
        cfg.recovery_delay.set(self.recovery_delay);
        cfg.allow_test_vk = self.allow_test_vk;
    }
}

/// 0. `init_config`: `[authority (s, w), config (w), program_data, system_program]`.
/// Vetëm upgrade authority e programit mund ta thërrasë (një herë).
pub fn init_config(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [authority, config, program_data, _system, ..] = accounts else {
        return Err(AuthError::InvalidAccount.into());
    };
    require_signer(authority)?;
    let args = ConfigArgs::read(&mut Reader::new(data))?;

    let (expected_pd, _) = find_pda(&[program_id.as_ref()], &BPF_LOADER_UPGRADEABLE);
    require_address(program_data, &expected_pd)?;
    if !program_data.owned_by(&BPF_LOADER_UPGRADEABLE) {
        return Err(AuthError::InvalidAccount.into());
    }
    {
        // UpgradeableLoaderState::ProgramData { slot: u64, upgrade_authority: Option<Pubkey> }
        let pd = program_data.try_borrow()?;
        if pd.len() < 45
            || pd[0..4] != 3u32.to_le_bytes()
            || pd[12] != 1
            || &pd[13..45] != authority.address().as_ref()
        {
            return Err(AuthError::Unauthorized.into());
        }
    }

    let (expected, bump) = find_pda(&[SEED_CONFIG], program_id);
    require_address(config, &expected)?;
    let bump_seed = [bump];
    create_pda(
        authority,
        config,
        Config::LEN,
        &[Seed::from(SEED_CONFIG), Seed::from(&bump_seed)],
        program_id,
    )?;
    let mut d = config.try_borrow_mut()?;
    let cfg = Config::init_bytes(&mut d)?;
    cfg.version = VERSION;
    cfg.bump = bump;
    args.write(cfg);
    Ok(())
}

/// 1. `update_config`: `[admin (s), config (w)]`.
pub fn update_config(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [admin, config, ..] = accounts else {
        return Err(AuthError::InvalidAccount.into());
    };
    require_signer(admin)?;
    require_writable(config)?;
    let args = ConfigArgs::read(&mut Reader::new(data))?;
    drop(load_config(config, program_id)?);
    let mut d = config.try_borrow_mut()?;
    let cfg = Config::from_bytes_mut(&mut d)?;
    if &cfg.admin != admin.address().as_array() {
        return Err(AuthError::Unauthorized.into());
    }
    args.write(cfg);
    Ok(())
}

/// 2. `propose_jwk`: `[authority (s), payer (s, w), config, jwk (w), system_program]`.
/// Data: `iss_len u8, iss, kid_len u8, kid, modulus_len u16, modulus (BE), valid_from i64,
/// valid_until i64`. Hash-i i modulus-it llogaritet këtu, që propozimi të krahasohet lehtë
/// me JWKS publike gjatë timelock-ut.
pub fn propose_jwk(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    use zklogin_verifier::inputs::{hash_modulus, modulus_num_bits, Circuit};

    let [authority, payer, config, jwk_view, _system, ..] = accounts else {
        return Err(AuthError::InvalidAccount.into());
    };
    require_signer(authority)?;
    let mut r = Reader::new(data);
    let iss_len = r.u8()? as usize;
    let iss = r.take(iss_len)?;
    let kid_len = r.u8()? as usize;
    let kid = r.take(kid_len)?;
    let modulus_len = r.u16()? as usize;
    let modulus = r.take(modulus_len)?;
    let valid_from = r.i64()?;
    let valid_until = r.i64()?;
    r.finish()?;

    let timelock = {
        let d = load_config(config, program_id)?;
        let cfg = Config::from_bytes(&d)?;
        let who = authority.address().as_array();
        if who != &cfg.admin && who != &cfg.oracle {
            return Err(AuthError::Unauthorized.into());
        }
        cfg.jwk_timelock.get()
    };

    if iss.is_empty()
        || iss.len() > crate::iss::MAX_ISS_LEN
        || kid.is_empty()
        || modulus.is_empty()
        || modulus[0] == 0
        || valid_from >= valid_until
    {
        return Err(AuthError::InvalidJwkWindow.into());
    }
    let modulus_hash = hash_modulus(modulus, Circuit::V1.max_modulus_len())
        .map_err(|_| AuthError::InvalidJwkWindow)?;
    let modulus_bits = modulus_num_bits(modulus) as u16;

    let iss_hash = sha256(&[iss]);
    let kid_hash = sha256(&[kid]);
    let now = now()?;

    if jwk_view.data_len() == 0 {
        require_signer(payer)?;
        let (expected, bump) = find_pda(&[SEED_JWK, &iss_hash, &kid_hash], program_id);
        require_address(jwk_view, &expected)?;
        let bump_seed = [bump];
        create_pda(
            payer,
            jwk_view,
            Jwk::LEN,
            &[
                Seed::from(SEED_JWK),
                Seed::from(&iss_hash),
                Seed::from(&kid_hash),
                Seed::from(&bump_seed),
            ],
            program_id,
        )?;
        let mut d = jwk_view.try_borrow_mut()?;
        let jwk = Jwk::init_bytes(&mut d)?;
        jwk.version = VERSION;
        jwk.bump = bump;
        jwk.iss_hash = iss_hash;
        jwk.kid_hash = kid_hash;
    }

    Jwk::check(jwk_view, program_id)?;
    require_writable(jwk_view)?;
    let mut d = jwk_view.try_borrow_mut()?;
    let jwk = Jwk::from_bytes_mut(&mut d)?;
    if jwk.iss_hash != iss_hash || jwk.kid_hash != kid_hash {
        return Err(AuthError::InvalidAccount.into());
    }
    jwk.pending.modulus_hash = modulus_hash;
    jwk.pending.modulus_bits.set(modulus_bits);
    jwk.pending.valid_from.set(valid_from);
    jwk.pending.valid_until.set(valid_until);
    jwk.pending_eta.set(now.saturating_add(timelock));
    jwk.has_pending = 1;
    Ok(())
}

/// 3. `apply_jwk`: `[jwk (w)]`. Kushdo, pasi kalon timelock-u.
pub fn apply_jwk(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [jwk_view, ..] = accounts else {
        return Err(AuthError::InvalidAccount.into());
    };
    Reader::new(data).finish()?;
    Jwk::check(jwk_view, program_id)?;
    require_writable(jwk_view)?;
    let mut d = jwk_view.try_borrow_mut()?;
    let jwk = Jwk::from_bytes_mut(&mut d)?;
    if jwk.has_pending == 0 {
        return Err(AuthError::NothingPending.into());
    }
    if now()? < jwk.pending_eta.get() {
        return Err(AuthError::TimelockNotElapsed.into());
    }
    jwk.active.modulus_hash = jwk.pending.modulus_hash;
    jwk.active.modulus_bits = jwk.pending.modulus_bits;
    jwk.active.valid_from = jwk.pending.valid_from;
    jwk.active.valid_until = jwk.pending.valid_until;
    jwk.pending = JwkKey {
        modulus_hash: [0; 32],
        modulus_bits: PodU16::default(),
        _pad: [0; 6],
        valid_from: PodI64::default(),
        valid_until: PodI64::default(),
    };
    jwk.pending_eta.set(0);
    jwk.has_pending = 0;
    jwk.revoked = 0;
    Ok(())
}

/// 4. `revoke_jwk`: `[admin (s), config, jwk (w)]`. Menjëherë (emergjencë).
pub fn revoke_jwk(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [admin, config, jwk_view, ..] = accounts else {
        return Err(AuthError::InvalidAccount.into());
    };
    Reader::new(data).finish()?;
    require_signer(admin)?;
    {
        let d = load_config(config, program_id)?;
        if &Config::from_bytes(&d)?.admin != admin.address().as_array() {
            return Err(AuthError::Unauthorized.into());
        }
    }
    Jwk::check(jwk_view, program_id)?;
    require_writable(jwk_view)?;
    let mut d = jwk_view.try_borrow_mut()?;
    let jwk = Jwk::from_bytes_mut(&mut d)?;
    jwk.revoked = 1;
    jwk.has_pending = 0;
    jwk.pending_eta.set(0);
    Ok(())
}

/// Verifikon provën me config-un dhe JWK-në e dhënë.
pub(crate) fn verify_zk(
    zkb: &ZkBlock<'_>,
    session_key: &AccountView,
    config: &AccountView,
    jwk: &AccountView,
    now: i64,
    program_id: &Address,
) -> Result<zk::Verified> {
    let d = load_config(config, program_id)?;
    let cfg = Config::from_bytes(&d)?;
    zk::verify(zkb, session_key, cfg, jwk, now, program_id)
}

/// Krijon `Session` për `session_key` me politikën e dhënë.
#[allow(clippy::too_many_arguments)]
fn create_session(
    payer: &AccountView,
    session_key: &AccountView,
    wallet_view: &AccountView,
    session_view: &AccountView,
    policy: &Policy<'_>,
    proof_expires_at: i64,
    now: i64,
    program_id: &Address,
) -> ProgramResult {
    require_signer(payer)?;
    let (expected, bump) = find_pda(
        &[
            SEED_SESSION,
            wallet_view.address().as_ref(),
            session_key.address().as_ref(),
        ],
        program_id,
    );
    require_address(session_view, &expected)?;
    let bump_seed = [bump];
    create_pda(
        payer,
        session_view,
        Session::LEN,
        &[
            Seed::from(SEED_SESSION),
            Seed::from(wallet_view.address().as_ref()),
            Seed::from(session_key.address().as_ref()),
            Seed::from(&bump_seed),
        ],
        program_id,
    )?;
    let mut d = session_view.try_borrow_mut()?;
    let s = Session::init_bytes(&mut d)?;
    s.version = VERSION;
    s.bump = bump;
    s.wallet = *wallet_view.address().as_array();
    s.session_key = *session_key.address().as_array();
    s.created_at.set(now);
    s.expires_at
        .set(proof_expires_at.min(now.saturating_add(policy.expires_in as i64)));
    policy.apply(s, now, program_id)?;

    let mut wd = wallet_view.try_borrow_mut()?;
    let w = Wallet::from_bytes_mut(&mut wd)?;
    w.sessions_opened
        .set(w.sessions_opened.get().saturating_add(1));
    Ok(())
}

/// 5. `create_wallet`: `[payer (s, w), session_key (s), config, jwk, wallet (w), system_program,
/// session (w, vetëm me flag-un 1)]`. Data: `zk_block, flags u8 [, policy]`.
pub fn create_wallet(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [payer, session_key, config, jwk, wallet_view, _system, rest @ ..] = accounts else {
        return Err(AuthError::InvalidAccount.into());
    };
    require_signer(payer)?;
    let mut r = Reader::new(data);
    let zkb = ZkBlock::read(&mut r)?;
    let flags = r.u8()?;
    if flags > 1 {
        return Err(AuthError::InvalidInstruction.into());
    }
    let policy = if flags & 1 != 0 {
        Some(Policy::read(&mut r)?)
    } else {
        None
    };
    r.finish()?;

    let now = now()?;
    let v = verify_zk(&zkb, session_key, config, jwk, now, program_id)?;

    let wallet_id = sha256(&[DOMAIN_WALLET, &v.identity]);
    let (expected, bump) = find_pda(&[SEED_WALLET, &wallet_id], program_id);
    require_address(wallet_view, &expected)?;
    let (_, vault_bump) = find_pda(&[SEED_VAULT, expected.as_ref()], program_id);
    let bump_seed = [bump];
    create_pda(
        payer,
        wallet_view,
        Wallet::LEN,
        &[
            Seed::from(SEED_WALLET),
            Seed::from(&wallet_id),
            Seed::from(&bump_seed),
        ],
        program_id,
    )?;
    {
        let mut d = wallet_view.try_borrow_mut()?;
        let w = Wallet::init_bytes(&mut d)?;
        w.version = VERSION;
        w.bump = bump;
        w.vault_bump = vault_bump;
        w.wallet_id = wallet_id;
        w.created_at.set(now);
        w.zk[0].identity = v.identity;
        w.zk[0].added_at.set(now);
    }

    if let Some(policy) = policy {
        let [session_view, ..] = rest else {
            return Err(AuthError::InvalidAccount.into());
        };
        create_session(
            payer,
            session_key,
            wallet_view,
            session_view,
            &policy,
            v.expires_at,
            now,
            program_id,
        )?;
    }
    Ok(())
}

fn require_wallet_identity(
    wallet_view: &AccountView,
    identity: &[u8; 32],
    program_id: &Address,
) -> ProgramResult {
    Wallet::check(wallet_view, program_id)?;
    let d = wallet_view.try_borrow()?;
    if !Wallet::from_bytes(&d)?.has_identity(identity) {
        return Err(AuthError::UnknownIdentity.into());
    }
    Ok(())
}

/// 6. `open_session`: `[payer (s, w), session_key (s), config, jwk, wallet (w), session (w),
/// system_program]`. Data: `zk_block, policy`.
pub fn open_session(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [payer, session_key, config, jwk, wallet_view, session_view, _system, ..] = accounts else {
        return Err(AuthError::InvalidAccount.into());
    };
    let mut r = Reader::new(data);
    let zkb = ZkBlock::read(&mut r)?;
    let policy = Policy::read(&mut r)?;
    r.finish()?;
    require_writable(wallet_view)?;

    let now = now()?;
    let v = verify_zk(&zkb, session_key, config, jwk, now, program_id)?;
    require_wallet_identity(wallet_view, &v.identity, program_id)?;
    create_session(
        payer,
        session_key,
        wallet_view,
        session_view,
        &policy,
        v.expires_at,
        now,
        program_id,
    )
}

/// Kontrollon që `session_view` është sesion i `wallet_view`.
fn check_session_of(
    session_view: &AccountView,
    wallet_view: &AccountView,
    program_id: &Address,
) -> ProgramResult {
    Wallet::check(wallet_view, program_id)?;
    Wallet::from_bytes(&wallet_view.try_borrow()?)?;
    Session::check(session_view, program_id)?;
    let d = session_view.try_borrow()?;
    let s = Session::from_bytes(&d)?;
    if &s.wallet != wallet_view.address().as_array() {
        return Err(AuthError::InvalidAccount.into());
    }
    Ok(())
}

/// 8. `revoke_session`. Data: `mode u8, ...`.
/// - mode 0 (vetë sesioni): `[session_key (s), wallet, session (w)]`.
/// - mode 1 (provë zk e re): `[session_key_i_ri (s), wallet, session (w), config, jwk]`, data
///   `zk_block` pas mode-it.
/// - mode 2 (passkey): `[instructions_sysvar, wallet (w), session (w)]`, data `passkey_block`.
pub fn revoke_session(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let [signer, wallet_view, session_view, rest @ ..] = accounts else {
        return Err(AuthError::InvalidAccount.into());
    };
    require_writable(session_view)?;
    check_session_of(session_view, wallet_view, program_id)?;
    let mut r = Reader::new(data);
    match r.u8()? {
        0 => {
            r.finish()?;
            require_signer(signer)?;
            let d = session_view.try_borrow()?;
            if &Session::from_bytes(&d)?.session_key != signer.address().as_array() {
                return Err(AuthError::Unauthorized.into());
            }
        }
        1 => {
            let zkb = ZkBlock::read(&mut r)?;
            r.finish()?;
            let [config, jwk, ..] = rest else {
                return Err(AuthError::InvalidAccount.into());
            };
            let v = verify_zk(&zkb, signer, config, jwk, now()?, program_id)?;
            require_wallet_identity(wallet_view, &v.identity, program_id)?;
        }
        2 => {
            // Passkey: llogaria e parë është sysvar-i Instructions.
            let client_data = crate::passkey::read_block(&mut r)?;
            r.finish()?;
            crate::authority::authorize_passkey(
                crate::OP_REVOKE_SESSION,
                &[2],
                client_data,
                &[],
                signer,
                wallet_view,
                &accounts[1..3],
                program_id,
            )?;
        }
        _ => return Err(AuthError::InvalidInstruction.into()),
    }
    let mut d = session_view.try_borrow_mut()?;
    Session::from_bytes_mut(&mut d)?.revoked = 1;
    Ok(())
}

/// 10. `close_session`: `[wallet, session (w), vault (w)]`. Kushdo, pasi sesioni skadon ose
/// revokohet; rent-i shkon te vault-i.
pub fn close_session(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [wallet_view, session_view, vault, ..] = accounts else {
        return Err(AuthError::InvalidAccount.into());
    };
    Reader::new(data).finish()?;
    require_writable(session_view)?;
    require_writable(vault)?;
    check_session_of(session_view, wallet_view, program_id)?;
    {
        let wd = wallet_view.try_borrow()?;
        let w = Wallet::from_bytes(&wd)?;
        let expected = derive_pda(
            &[SEED_VAULT, wallet_view.address().as_ref()],
            w.vault_bump,
            program_id,
        );
        require_address(vault, &expected)?;
        let sd = session_view.try_borrow()?;
        if Session::from_bytes(&sd)?.is_usable(now()?) {
            return Err(AuthError::SessionStillActive.into());
        }
    }
    let lamports = session_view.lamports();
    vault.set_lamports(
        vault
            .lamports()
            .checked_add(lamports)
            .ok_or(AuthError::InvalidAccount)?,
    );
    session_view.set_lamports(0);
    session_view.close()
}
