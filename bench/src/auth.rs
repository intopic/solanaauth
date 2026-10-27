//! Klient testi për programin `solanaauth` në LiteSVM: ndërtimi i instruksioneve, llogaritë
//! dhe ora (Clock) e kontrolluar.

use std::path::{Path, PathBuf};

use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::svm::{Svm, MAX_TX_CU};
use crate::Case;

pub const SYSTEM: Address = Address::from_str_const("11111111111111111111111111111111");
pub const LOADER_UPGRADEABLE: Address =
    Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
pub const INSTRUCTIONS_SYSVAR: Address =
    Address::from_str_const("Sysvar1nstructions1111111111111111111111111");
pub const SECP256R1: Address =
    Address::from_str_const("Secp256r1SigVerify1111111111111111111111111");
pub const TOKEN: Address = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

pub fn default_so_path() -> PathBuf {
    if let Ok(p) = std::env::var("SOLANAAUTH_SO") {
        return PathBuf::from(p);
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../programs/solanaauth/target/deploy/solanaauth.so")
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Rezultati i një transaksioni.
pub struct Run {
    pub ok: bool,
    pub cu: u64,
    pub tx_bytes: usize,
    pub logs: Vec<String>,
    pub err: Option<String>,
}

impl Run {
    /// Kodi `Custom(n)` i gabimit, nëse ka.
    pub fn custom_code(&self) -> Option<u32> {
        let e = self.err.as_ref()?;
        let i = e.find("Custom(")? + 7;
        e[i..].split(')').next()?.parse().ok()
    }
}

pub struct Env {
    pub svm: LiteSVM,
    pub program_id: Address,
    pub payer: Keypair,
    pub admin: Keypair,
    pub oracle: Keypair,
}

pub struct ConfigParams {
    pub jwk_timelock: i64,
    pub max_session_secs: i64,
    pub recovery_delay: i64,
    pub allow_test_vk: bool,
}

impl Default for ConfigParams {
    fn default() -> Self {
        ConfigParams {
            jwk_timelock: 2,
            max_session_secs: 30 * 24 * 3600,
            recovery_delay: 48 * 3600,
            allow_test_vk: false,
        }
    }
}

/// Politika e një sesioni.
#[derive(Clone)]
pub struct Policy {
    pub expires_in: u32,
    pub label: [u8; 32],
    pub programs: Vec<Address>,
    /// (mint, amount, period_secs); mint `Address::default()` = SOL.
    pub limits: Vec<(Address, u64, u32)>,
}

impl Policy {
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&self.expires_in.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes());
        d.extend_from_slice(&self.label);
        d.push(self.programs.len() as u8);
        for p in &self.programs {
            d.extend_from_slice(p.as_ref());
        }
        d.push(self.limits.len() as u8);
        for (m, a, p) in &self.limits {
            d.extend_from_slice(m.as_ref());
            d.extend_from_slice(&a.to_le_bytes());
            d.extend_from_slice(&p.to_le_bytes());
        }
        d
    }
}

pub fn label(s: &str) -> [u8; 32] {
    let mut l = [0u8; 32];
    l[..s.len()].copy_from_slice(s.as_bytes());
    l
}

/// Çelësi ephemeral i fixture-it (pa vlerë reale).
pub fn eph_keypair(c: &Case) -> Keypair {
    let sk: [u8; 32] = c.fx.ephemeral_private_key();
    let kp = Keypair::new_from_array(sk);
    assert_eq!(kp.pubkey().to_bytes(), c.eph_pubkey, "çelësi ephemeral");
    kp
}

/// Blloku zk i instruksioneve (shih `programs/solanaauth/src/zk.rs`).
pub fn zk_block(c: &Case, proof: &[u8; 256]) -> Vec<u8> {
    let mut d = vec![match c.vk {
        zklogin_verifier::vk::VkId::Mainnet => 0,
        _ => 1,
    }];
    d.extend_from_slice(proof);
    d.extend_from_slice(&c.fx.max_epoch.to_le_bytes());
    d.extend_from_slice(&c.address_seed);
    d.push(c.index_mod_4);
    d.push(c.iss.len() as u8);
    d.extend_from_slice(&c.iss);
    d.extend_from_slice(&(c.header.len() as u16).to_le_bytes());
    d.extend_from_slice(&c.header);
    d
}

pub fn identity(iss: &str, address_seed: &[u8; 32]) -> [u8; 32] {
    sha256(&[b"solanaauth:zk:v1", iss.as_bytes(), address_seed])
}

impl Env {
    pub fn new(so: &Path) -> Self {
        let mut svm = LiteSVM::new();
        let program_id = Address::new_from_array([9u8; 32]);
        svm.add_program_from_file(program_id, so)
            .unwrap_or_else(|e| panic!("s'ngarkohet {}: {e:?}", so.display()));
        let payer = Keypair::new();
        let admin = Keypair::new();
        let oracle = Keypair::new();
        for k in [&payer, &admin, &oracle] {
            svm.airdrop(&k.pubkey(), 100_000_000_000).unwrap();
        }
        let mut env = Env {
            svm,
            program_id,
            payer,
            admin,
            oracle,
        };
        // Upgrade authority = admin (LiteSVM e krijon programin pa authority).
        let pd = env.program_data();
        let mut acc = env.svm.get_account(&pd).unwrap();
        acc.data[12] = 1;
        acc.data[13..45].copy_from_slice(env.admin.pubkey().as_ref());
        env.svm.set_account(pd, acc).unwrap();
        env.set_time(1);
        env
    }

    /// Pa program të ngarkuar dhe me çelësa fiks: për vektorët e testit të SDK-së.
    pub fn offline() -> Self {
        Env {
            svm: LiteSVM::new(),
            program_id: Address::new_from_array([9u8; 32]),
            payer: Keypair::new_from_array([1u8; 32]),
            admin: Keypair::new_from_array([2u8; 32]),
            oracle: Keypair::new_from_array([3u8; 32]),
        }
    }

    pub fn program_data(&self) -> Address {
        Address::find_program_address(&[self.program_id.as_ref()], &LOADER_UPGRADEABLE).0
    }

    pub fn set_time(&mut self, unix_timestamp: i64) {
        let mut c: Clock = self.svm.get_sysvar();
        c.unix_timestamp = unix_timestamp;
        self.svm.set_sysvar(&c);
    }

    pub fn pda(&self, seeds: &[&[u8]]) -> Address {
        Address::find_program_address(seeds, &self.program_id).0
    }

    pub fn config(&self) -> Address {
        self.pda(&[b"config"])
    }

    pub fn jwk(&self, iss: &str, kid: &str) -> Address {
        self.pda(&[
            b"jwk",
            &sha256(&[iss.as_bytes()]),
            &sha256(&[kid.as_bytes()]),
        ])
    }

    pub fn wallet_of(&self, identity: &[u8; 32]) -> Address {
        let id = sha256(&[b"solanaauth:wallet:v1", identity]);
        self.pda(&[b"wallet", &id])
    }

    pub fn vault(&self, wallet: &Address) -> Address {
        self.pda(&[b"vault", wallet.as_ref()])
    }

    pub fn session(&self, wallet: &Address, key: &Address) -> Address {
        self.pda(&[b"session", wallet.as_ref(), key.as_ref()])
    }

    pub fn account(&self, a: &Address) -> Option<Account> {
        self.svm.get_account(a)
    }

    pub fn lamports(&self, a: &Address) -> u64 {
        self.account(a).map(|a| a.lamports).unwrap_or(0)
    }

    pub fn ix(&self, data: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
        Instruction {
            program_id: self.program_id,
            accounts,
            data,
        }
    }

    /// Dërgon instruksionet me `payer` si fee payer dhe nënshkruesit shtesë.
    pub fn send(&mut self, ixs: &[Instruction], signers: &[&Keypair]) -> Run {
        self.send_with_payer(ixs, signers, None)
    }

    pub fn send_with_payer(
        &mut self,
        ixs: &[Instruction],
        signers: &[&Keypair],
        fee_payer: Option<&Keypair>,
    ) -> Run {
        self.svm.expire_blockhash();
        let mut all = vec![ComputeBudgetInstruction::set_compute_unit_limit(MAX_TX_CU)];
        all.extend_from_slice(ixs);
        let fee_payer = fee_payer.unwrap_or(&self.payer);
        let msg = Message::new(&all, Some(&fee_payer.pubkey()));
        let mut keys: Vec<&Keypair> = vec![fee_payer];
        for s in signers {
            if !keys.iter().any(|k| k.pubkey() == s.pubkey()) {
                keys.push(s);
            }
        }
        let tx = Transaction::new(&keys, msg, self.svm.latest_blockhash());
        let tx_bytes = Svm::tx_size(&tx);
        let (ok, meta, err) = match self.svm.send_transaction(tx) {
            Ok(meta) => (true, meta, None),
            Err(f) => (false, f.meta, Some(format!("{:?}", f.err))),
        };
        let prefix = format!("Program {} consumed ", self.program_id);
        let cu = meta
            .logs
            .iter()
            .filter_map(|l| {
                l.strip_prefix(&prefix)?
                    .split(' ')
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
            .last()
            .unwrap_or(meta.compute_units_consumed);
        Run {
            ok,
            cu,
            tx_bytes,
            logs: meta.logs,
            err,
        }
    }

    // ---- Instruksionet ----

    pub fn config_data(&self, op: u8, admin: &Address, p: &ConfigParams) -> Vec<u8> {
        let mut d = vec![op];
        d.extend_from_slice(admin.as_ref());
        d.extend_from_slice(self.oracle.pubkey().as_ref());
        d.extend_from_slice(&p.jwk_timelock.to_le_bytes());
        d.extend_from_slice(&p.max_session_secs.to_le_bytes());
        d.extend_from_slice(&p.recovery_delay.to_le_bytes());
        d.push(p.allow_test_vk as u8);
        d
    }

    pub fn ix_init_config(&self, authority: &Address, p: &ConfigParams) -> Instruction {
        self.ix(
            self.config_data(0, &self.admin.pubkey(), p),
            vec![
                AccountMeta::new(*authority, true),
                AccountMeta::new(self.config(), false),
                AccountMeta::new_readonly(self.program_data(), false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
        )
    }

    pub fn ix_update_config(&self, signer: &Address, p: &ConfigParams) -> Instruction {
        self.ix(
            self.config_data(1, &self.admin.pubkey(), p),
            vec![
                AccountMeta::new_readonly(*signer, true),
                AccountMeta::new(self.config(), false),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ix_propose_jwk(
        &self,
        authority: &Address,
        iss: &str,
        kid: &str,
        modulus: &[u8],
        valid_from: i64,
        valid_until: i64,
    ) -> Instruction {
        let mut d = vec![2, iss.len() as u8];
        d.extend_from_slice(iss.as_bytes());
        d.push(kid.len() as u8);
        d.extend_from_slice(kid.as_bytes());
        d.extend_from_slice(&(modulus.len() as u16).to_le_bytes());
        d.extend_from_slice(modulus);
        d.extend_from_slice(&valid_from.to_le_bytes());
        d.extend_from_slice(&valid_until.to_le_bytes());
        self.ix(
            d,
            vec![
                AccountMeta::new_readonly(*authority, true),
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.config(), false),
                AccountMeta::new(self.jwk(iss, kid), false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
        )
    }

    pub fn ix_apply_jwk(&self, jwk: &Address) -> Instruction {
        self.ix(vec![3], vec![AccountMeta::new(*jwk, false)])
    }

    pub fn ix_revoke_jwk(&self, signer: &Address, jwk: &Address) -> Instruction {
        self.ix(
            vec![4],
            vec![
                AccountMeta::new_readonly(*signer, true),
                AccountMeta::new_readonly(self.config(), false),
                AccountMeta::new(*jwk, false),
            ],
        )
    }

    pub fn ix_create_wallet(
        &self,
        zk: &[u8],
        session_key: &Address,
        jwk: &Address,
        wallet: &Address,
        policy: Option<&Policy>,
    ) -> Instruction {
        let mut d = vec![5];
        d.extend_from_slice(zk);
        let mut accounts = vec![
            AccountMeta::new(self.payer.pubkey(), true),
            AccountMeta::new_readonly(*session_key, true),
            AccountMeta::new_readonly(self.config(), false),
            AccountMeta::new_readonly(*jwk, false),
            AccountMeta::new(*wallet, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ];
        match policy {
            Some(p) => {
                d.push(1);
                d.extend_from_slice(&p.encode());
                accounts.push(AccountMeta::new(self.session(wallet, session_key), false));
            }
            None => d.push(0),
        }
        self.ix(d, accounts)
    }

    pub fn ix_open_session(
        &self,
        zk: &[u8],
        session_key: &Address,
        jwk: &Address,
        wallet: &Address,
        policy: &Policy,
    ) -> Instruction {
        let mut d = vec![6];
        d.extend_from_slice(zk);
        d.extend_from_slice(&policy.encode());
        self.ix(
            d,
            vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(*session_key, true),
                AccountMeta::new_readonly(self.config(), false),
                AccountMeta::new_readonly(*jwk, false),
                AccountMeta::new(*wallet, false),
                AccountMeta::new(self.session(wallet, session_key), false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
        )
    }

    /// Llogaritë dhe të dhënat e `execute` (pa op dhe flags): `inner` janë instruksione normale;
    /// llogaritë e tyre shtohen pas 4 të parave dhe kodohen me indekse.
    pub fn execute_parts(
        &self,
        session_key: &Address,
        wallet: &Address,
        inner: &[Instruction],
    ) -> (Vec<AccountMeta>, Vec<u8>) {
        let vault = self.vault(wallet);
        let mut metas = vec![
            AccountMeta::new_readonly(*session_key, true),
            AccountMeta::new(*wallet, false),
            AccountMeta::new(self.session(wallet, session_key), false),
            AccountMeta::new(vault, false),
        ];
        let index_of = |a: &Address, w: bool, metas: &mut Vec<AccountMeta>| -> u8 {
            if let Some(i) = metas.iter().position(|m| &m.pubkey == a) {
                if w {
                    metas[i].is_writable = true;
                }
                return i as u8;
            }
            metas.push(if w {
                AccountMeta::new(*a, false)
            } else {
                AccountMeta::new_readonly(*a, false)
            });
            (metas.len() - 1) as u8
        };
        let mut d = vec![inner.len() as u8];
        for ix in inner {
            let p = index_of(&ix.program_id, false, &mut metas);
            d.push(p);
            d.push(ix.accounts.len() as u8);
            for m in &ix.accounts {
                let i = index_of(&m.pubkey, m.is_writable, &mut metas);
                d.push(i);
                d.push(m.is_writable as u8 | ((m.is_signer as u8) << 1));
            }
            d.extend_from_slice(&(ix.data.len() as u16).to_le_bytes());
            d.extend_from_slice(&ix.data);
        }
        (metas, d)
    }

    pub fn ix_execute(
        &self,
        session_key: &Address,
        wallet: &Address,
        inner: &[Instruction],
    ) -> Instruction {
        let (metas, rest) = self.execute_parts(session_key, wallet, inner);
        let mut d = vec![7, 0];
        d.extend_from_slice(&rest);
        self.ix(d, metas)
    }

    /// `execute` i miratuar me passkey (llogaria e fundit = sysvar-i Instructions).
    pub fn ix_execute_passkey(
        &self,
        pk: &PasskeyKey,
        session_key: &Address,
        wallet: &Address,
        inner: &[Instruction],
    ) -> Vec<Instruction> {
        let (mut metas, rest) = self.execute_parts(session_key, wallet, inner);
        metas.push(AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR, false));
        self.passkey_ix(pk, wallet, 7, &[1], &rest, metas)
    }

    /// Ndërton `[precompile secp256r1, instruksioni]` me bllokun passkey midis `prefix` dhe
    /// `payload`. Sysvar-i Instructions duhet të jetë te `accounts`; nuk hyn në hash.
    pub fn passkey_ix(
        &self,
        pk: &PasskeyKey,
        wallet: &Address,
        op: u8,
        prefix: &[u8],
        payload: &[u8],
        accounts: Vec<AccountMeta>,
    ) -> Vec<Instruction> {
        let mut parts: Vec<&[u8]> = vec![std::slice::from_ref(&op), prefix, payload];
        for m in accounts.iter().filter(|m| m.pubkey != INSTRUCTIONS_SYSVAR) {
            parts.push(m.pubkey.as_ref());
        }
        let action = sha256(&parts);
        let nonce = self.wallet_nonce(wallet);
        let challenge = sha256(&[
            b"solanaauth:passkey:v1",
            wallet.as_ref(),
            &nonce.to_le_bytes(),
            &action,
        ]);
        let (pre, client_data) = pk.sign(&challenge);
        let mut d = vec![op];
        d.extend_from_slice(prefix);
        d.extend_from_slice(&(client_data.len() as u16).to_le_bytes());
        d.extend_from_slice(&client_data);
        d.extend_from_slice(payload);
        vec![pre, self.ix(d, accounts)]
    }

    pub fn wallet_nonce(&self, wallet: &Address) -> u64 {
        let d = self.account(wallet).unwrap().data;
        u64::from_le_bytes(d[48..56].try_into().unwrap())
    }

    pub fn ix_add_passkey_zk(
        &self,
        zk: &[u8],
        session_key: &Address,
        jwk: &Address,
        wallet: &Address,
        slot: u8,
        pubkey: &[u8; 33],
    ) -> Instruction {
        let mut d = vec![11, 0];
        d.extend_from_slice(zk);
        d.push(slot);
        d.extend_from_slice(pubkey);
        self.ix(
            d,
            vec![
                AccountMeta::new_readonly(*session_key, true),
                AccountMeta::new_readonly(self.config(), false),
                AccountMeta::new_readonly(*jwk, false),
                AccountMeta::new(*wallet, false),
            ],
        )
    }

    fn sysvar_wallet(wallet: &Address) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR, false),
            AccountMeta::new(*wallet, false),
        ]
    }

    pub fn ix_add_passkey_pk(
        &self,
        pk: &PasskeyKey,
        wallet: &Address,
        slot: u8,
        pubkey: &[u8; 33],
    ) -> Vec<Instruction> {
        let mut payload = vec![slot];
        payload.extend_from_slice(pubkey);
        self.passkey_ix(pk, wallet, 11, &[1], &payload, Self::sysvar_wallet(wallet))
    }

    pub fn ix_remove_passkey(
        &self,
        pk: &PasskeyKey,
        wallet: &Address,
        slot: u8,
    ) -> Vec<Instruction> {
        self.passkey_ix(pk, wallet, 12, &[], &[slot], Self::sysvar_wallet(wallet))
    }

    pub fn ix_set_threshold(
        &self,
        pk: &PasskeyKey,
        wallet: &Address,
        lamports: u64,
    ) -> Vec<Instruction> {
        self.passkey_ix(
            pk,
            wallet,
            13,
            &[],
            &lamports.to_le_bytes(),
            Self::sysvar_wallet(wallet),
        )
    }

    fn zk_metas(&self, session_key: &Address, jwk: &Address, wallet: &Address) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(*session_key, true),
            AccountMeta::new_readonly(self.config(), false),
            AccountMeta::new_readonly(*jwk, false),
            AccountMeta::new(*wallet, false),
        ]
    }

    pub fn ix_recovery_add_passkey(
        &self,
        zk: &[u8],
        session_key: &Address,
        jwk: &Address,
        wallet: &Address,
        slot: u8,
        pubkey: &[u8; 33],
    ) -> Instruction {
        let mut d = vec![14, 1];
        d.extend_from_slice(zk);
        d.push(slot);
        d.extend_from_slice(pubkey);
        self.ix(d, self.zk_metas(session_key, jwk, wallet))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ix_recovery_add_zk(
        &self,
        pk: &PasskeyKey,
        new_zk: &[u8],
        session_key: &Address,
        jwk: &Address,
        wallet: &Address,
        slot: u8,
    ) -> Vec<Instruction> {
        let mut payload = new_zk.to_vec();
        payload.push(slot);
        let mut metas = self.zk_metas(session_key, jwk, wallet);
        metas.push(AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR, false));
        self.passkey_ix(pk, wallet, 14, &[2], &payload, metas)
    }

    pub fn ix_cancel_recovery_zk(
        &self,
        zk: &[u8],
        session_key: &Address,
        jwk: &Address,
        wallet: &Address,
    ) -> Instruction {
        let mut d = vec![15, 0];
        d.extend_from_slice(zk);
        self.ix(d, self.zk_metas(session_key, jwk, wallet))
    }

    pub fn ix_cancel_recovery_pk(&self, pk: &PasskeyKey, wallet: &Address) -> Vec<Instruction> {
        self.passkey_ix(pk, wallet, 15, &[1], &[], Self::sysvar_wallet(wallet))
    }

    pub fn ix_finish_recovery(&self, wallet: &Address) -> Instruction {
        self.ix(
            vec![16],
            vec![
                AccountMeta::new_readonly(self.config(), false),
                AccountMeta::new(*wallet, false),
            ],
        )
    }

    pub fn ix_revoke_passkey(
        &self,
        pk: &PasskeyKey,
        wallet: &Address,
        session: &Address,
    ) -> Vec<Instruction> {
        self.passkey_ix(
            pk,
            wallet,
            8,
            &[2],
            &[],
            vec![
                AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR, false),
                AccountMeta::new(*wallet, false),
                AccountMeta::new(*session, false),
            ],
        )
    }

    pub fn ix_revoke_self(&self, session_key: &Address, wallet: &Address) -> Instruction {
        self.ix(
            vec![8, 0],
            vec![
                AccountMeta::new_readonly(*session_key, true),
                AccountMeta::new_readonly(*wallet, false),
                AccountMeta::new(self.session(wallet, session_key), false),
            ],
        )
    }

    pub fn ix_revoke_zk(
        &self,
        zk: &[u8],
        signer: &Address,
        wallet: &Address,
        session: &Address,
        jwk: &Address,
    ) -> Instruction {
        let mut d = vec![8, 1];
        d.extend_from_slice(zk);
        self.ix(
            d,
            vec![
                AccountMeta::new_readonly(*signer, true),
                AccountMeta::new_readonly(*wallet, false),
                AccountMeta::new(*session, false),
                AccountMeta::new_readonly(self.config(), false),
                AccountMeta::new_readonly(*jwk, false),
            ],
        )
    }

    pub fn ix_close_session(&self, wallet: &Address, session: &Address) -> Instruction {
        self.ix(
            vec![10],
            vec![
                AccountMeta::new_readonly(*wallet, false),
                AccountMeta::new(*session, false),
                AccountMeta::new(self.vault(wallet), false),
            ],
        )
    }

    // ---- SPL Token (llogaritë vendosen direkt) ----

    pub fn set_mint(&mut self, mint: &Address, authority: &Address) {
        let mut d = vec![0u8; 82];
        d[0..4].copy_from_slice(&1u32.to_le_bytes());
        d[4..36].copy_from_slice(authority.as_ref());
        d[44] = 6;
        d[45] = 1;
        self.set_token_owned(mint, d);
    }

    pub fn set_token_account(
        &mut self,
        account: &Address,
        mint: &Address,
        owner: &Address,
        amount: u64,
    ) {
        let mut d = vec![0u8; 165];
        d[0..32].copy_from_slice(mint.as_ref());
        d[32..64].copy_from_slice(owner.as_ref());
        d[64..72].copy_from_slice(&amount.to_le_bytes());
        d[108] = 1;
        self.set_token_owned(account, d);
    }

    fn set_token_owned(&mut self, a: &Address, data: Vec<u8>) {
        let lamports = self.svm.minimum_balance_for_rent_exemption(data.len());
        self.svm
            .set_account(
                *a,
                Account {
                    lamports,
                    data,
                    owner: TOKEN,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
    }

    pub fn token_amount(&self, a: &Address) -> u64 {
        let d = self.account(a).unwrap().data;
        u64::from_le_bytes(d[64..72].try_into().unwrap())
    }
}

pub fn system_transfer(from: &Address, to: &Address, lamports: u64) -> Instruction {
    let mut d = 2u32.to_le_bytes().to_vec();
    d.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: SYSTEM,
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
        data: d,
    }
}

pub fn system_assign(account: &Address, owner: &Address) -> Instruction {
    let mut d = 1u32.to_le_bytes().to_vec();
    d.extend_from_slice(owner.as_ref());
    Instruction {
        program_id: SYSTEM,
        accounts: vec![AccountMeta::new(*account, true)],
        data: d,
    }
}

pub fn token_transfer(src: &Address, dst: &Address, owner: &Address, amount: u64) -> Instruction {
    let mut d = vec![3];
    d.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: TOKEN,
        accounts: vec![
            AccountMeta::new(*src, false),
            AccountMeta::new(*dst, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data: d,
    }
}

pub fn token_approve(
    src: &Address,
    delegate: &Address,
    owner: &Address,
    amount: u64,
) -> Instruction {
    let mut d = vec![4];
    d.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: TOKEN,
        accounts: vec![
            AccountMeta::new(*src, false),
            AccountMeta::new_readonly(*delegate, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data: d,
    }
}

/// Një passkey testi (P-256) që nënshkruan si një shfletues WebAuthn.
pub struct PasskeyKey {
    sk: p256::ecdsa::SigningKey,
}

impl PasskeyKey {
    pub fn from_seed(seed: u8) -> Self {
        let mut b = [0u8; 32];
        b[31] = seed;
        b[0] = 1;
        PasskeyKey {
            sk: p256::ecdsa::SigningKey::from_bytes(&b.into()).unwrap(),
        }
    }

    pub fn pubkey(&self) -> [u8; 33] {
        self.sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    pub fn client_data(challenge: &[u8; 32]) -> Vec<u8> {
        use base64ct::Encoding;
        let ch = base64ct::Base64UrlUnpadded::encode_string(challenge);
        format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{ch}\",\"origin\":\"https://solanaauth.dev\",\"crossOrigin\":false}}"
        )
        .into_bytes()
    }

    /// Nënshkruan `authenticatorData || sha256(clientDataJSON)`; kthen instruksionin e
    /// precompile-it dhe `clientDataJSON`.
    pub fn sign(&self, challenge: &[u8; 32]) -> (Instruction, Vec<u8>) {
        let client_data = Self::client_data(challenge);
        self.sign_client_data(client_data)
    }

    pub fn sign_client_data(&self, client_data: Vec<u8>) -> (Instruction, Vec<u8>) {
        use p256::ecdsa::signature::Signer as _;
        let mut msg = sha256(&[b"solanaauth.dev"]).to_vec();
        msg.push(0x05); // UP | UV
        msg.extend_from_slice(&1u32.to_be_bytes());
        msg.extend_from_slice(&sha256(&[&client_data]));
        let sig: p256::ecdsa::Signature = self.sk.sign(&msg);
        let sig = sig.normalize_s().unwrap_or(sig);
        let (pk_off, sig_off, msg_off) = (16u16, 16u16 + 33, 16u16 + 33 + 64);
        let mut d = vec![1u8, 0];
        for v in [
            sig_off,
            u16::MAX,
            pk_off,
            u16::MAX,
            msg_off,
            msg.len() as u16,
            u16::MAX,
        ] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d.extend_from_slice(&self.pubkey());
        d.extend_from_slice(&sig.to_bytes());
        d.extend_from_slice(&msg);
        (
            Instruction {
                program_id: SECP256R1,
                accounts: vec![],
                data: d,
            },
            client_data,
        )
    }
}
