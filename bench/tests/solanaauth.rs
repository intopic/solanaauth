//! M2: programi `solanaauth` në LiteSVM. Skenari i plotë (config → JWK → portofol → sesion →
//! execute → revokim → mbyllje), testet negative me kodin e saktë të gabimit, dhe matjet e CU
//! që shkruhen te `results/solanaauth-cu.{md,json}`.
//!
//! Fixture-t kanë `max_epoch = 10`, prandaj ora (Clock::unix_timestamp) mbahet nën 10.

use std::fmt::Write as _;

use bench::auth::*;
use bench::Case;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;

const GOOGLE: &str = "https://accounts.google.com";
const SUI_TEST: &str = "https://oauth.sui.io";

struct Measure {
    name: String,
    cu: u64,
    tx_bytes: usize,
    note: String,
}

struct Negative {
    case: String,
    expected: u32,
    got: Option<u32>,
}

#[derive(Default)]
struct Out {
    rows: Vec<Measure>,
    negatives: Vec<Negative>,
}

impl Out {
    fn ok(&mut self, name: &str, note: &str, r: Run) -> Run {
        assert!(r.ok, "{name} dështoi: {:?}\n{}", r.err, r.logs.join("\n"));
        self.rows.push(Measure {
            name: name.into(),
            cu: r.cu,
            tx_bytes: r.tx_bytes,
            note: note.into(),
        });
        r
    }

    fn fail(&mut self, case: &str, expected: u32, r: Run) {
        let got = r.custom_code();
        assert!(!r.ok, "{case}: duhej të refuzohej\n{}", r.logs.join("\n"));
        assert_eq!(
            got,
            Some(expected),
            "{case}: kodi i gabimit {:?}\n{}",
            r.err,
            r.logs.join("\n")
        );
        self.negatives.push(Negative {
            case: case.into(),
            expected,
            got,
        });
    }
}

fn policy(programs: Vec<Address>, limits: Vec<(Address, u64, u32)>) -> Policy {
    Policy {
        expires_in: 3600,
        label: label("test"),
        programs,
        limits,
    }
}

#[test]
fn solanaauth_m2() {
    let so = default_so_path();
    let mut env = Env::new(&so);
    let mut out = Out::default();
    let admin = env.admin.pubkey();
    let oracle = env.oracle.pubkey();
    let admin_kp = env.admin.insecure_clone();
    let oracle_kp = env.oracle.insecure_clone();

    let google = Case::load("google-mainnet-v1");
    let dev = Case::load("dev-v1-pinned");
    let eph = eph_keypair(&google);
    let k = eph.pubkey();
    let gkid = google.fx.jwk.kid.clone();
    let dkid = dev.fx.jwk.kid.clone();
    let gjwk = env.jwk(GOOGLE, &gkid);
    let djwk = env.jwk(SUI_TEST, &dkid);
    let gzk = zk_block(&google, &google.proof);
    let dzk = zk_block(&dev, &dev.proof);
    let gwallet = env.wallet_of(&identity(GOOGLE, &google.address_seed));
    let dwallet = env.wallet_of(&identity(SUI_TEST, &dev.address_seed));
    let gvault = env.vault(&gwallet);
    let gsession = env.session(&gwallet, &k);

    // ---- Config ----
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();
    let ix = env.ix_init_config(&stranger.pubkey(), &ConfigParams::default());
    let r = env.send(&[ix], &[&stranger]);
    out.fail("init_config nga dikush që s'është upgrade authority", 4, r);

    let ix = env.ix_init_config(&admin, &ConfigParams::default());
    let r = env.send(&[ix], &[&admin_kp]);
    out.ok("init_config", "një herë, nga upgrade authority", r);

    // ---- JWK registry ----
    let ix = env.ix_propose_jwk(
        &stranger.pubkey(),
        GOOGLE,
        &gkid,
        &google.modulus,
        0,
        i64::MAX,
    );
    let r = env.send(&[ix], &[&stranger]);
    out.fail("propose_jwk nga dikush që s'është admin/oracle", 4, r);

    let ix = env.ix_propose_jwk(&oracle, GOOGLE, &gkid, &google.modulus, 0, i64::MAX);
    let r = env.send(&[ix], &[&oracle_kp]);
    out.ok(
        "propose_jwk",
        "oracle; Poseidon i modulus-it 2048-bit on-chain + krijimi i llogarisë",
        r,
    );

    // JWK në pritje: ende jo aktiv.
    let ix = env.ix_create_wallet(&gzk, &k, &gjwk, &gwallet, None);
    let r = env.send(&[ix], &[&eph]);
    out.fail("create_wallet me JWK ende në timelock", 11, r);

    let r = env.send(&[env.ix_apply_jwk(&gjwk)], &[]);
    out.fail("apply_jwk para timelock-ut", 20, r);

    env.set_time(3);
    let r = env.send(&[env.ix_apply_jwk(&gjwk)], &[]);
    out.ok("apply_jwk", "kushdo, pas timelock-ut", r);
    let r = env.send(&[env.ix_apply_jwk(&gjwk)], &[]);
    out.fail("apply_jwk pa ndryshim në pritje", 21, r);

    let ix = env.ix_propose_jwk(&admin, SUI_TEST, &dkid, &dev.modulus, 0, i64::MAX);
    let r = env.send(&[ix], &[&admin_kp]);
    assert!(r.ok, "{:?}", r.err);
    env.set_time(5);
    let r = env.send(&[env.ix_apply_jwk(&djwk)], &[]);
    assert!(r.ok, "{:?}", r.err);

    // ---- create_wallet: negative ----
    let mut bad = google.proof;
    bad[63] ^= 1;
    let ix = env.ix_create_wallet(&zk_block(&google, &bad), &k, &gjwk, &gwallet, None);
    let r = env.send(&[ix], &[&eph]);
    out.fail("create_wallet: 1 byte i ndryshuar në provë", 10, r);

    let other = Keypair::new();
    let ix = env.ix_create_wallet(&gzk, &other.pubkey(), &gjwk, &gwallet, None);
    let r = env.send(&[ix], &[&other]);
    out.fail(
        "create_wallet: session_key tjetër nga eph_pubkey i provës",
        10,
        r,
    );

    let mut ix = env.ix_create_wallet(&gzk, &k, &gjwk, &gwallet, None);
    ix.accounts[1].is_signer = false;
    let r = env.send(&[ix], &[]);
    out.fail("create_wallet: session_key nuk nënshkruan", 3, r);

    let ix = env.ix_create_wallet(&gzk, &k, &djwk, &gwallet, None);
    let r = env.send(&[ix], &[&eph]);
    out.fail(
        "create_wallet: JWK i lëshuesit tjetër (iss mismatch)",
        12,
        r,
    );

    let ix = env.ix_create_wallet(&dzk, &k, &djwk, &dwallet, None);
    let r = env.send(&[ix], &[&eph]);
    out.fail(
        "create_wallet: verifying key test kur allow_test_vk = 0",
        16,
        r,
    );

    let wrong_wallet = env.wallet_of(&[1u8; 32]);
    let ix = env.ix_create_wallet(&gzk, &k, &gjwk, &wrong_wallet, None);
    let r = env.send(&[ix], &[&eph]);
    out.fail(
        "create_wallet: adresë portofoli që s'del nga identiteti",
        2,
        r,
    );

    let short = ConfigParams {
        max_session_secs: 4,
        ..ConfigParams::default()
    };
    let r = env.send(&[env.ix_update_config(&admin, &short)], &[&admin_kp]);
    assert!(r.ok, "{:?}", r.err);
    let ix = env.ix_create_wallet(&gzk, &k, &gjwk, &gwallet, None);
    let r = env.send(&[ix], &[&eph]);
    out.fail("create_wallet: max_epoch > now + max_session_secs", 15, r);
    let r = env.send(
        &[env.ix_update_config(&oracle, &ConfigParams::default())],
        &[&oracle_kp],
    );
    out.fail("update_config nga oracle (jo admin)", 4, r);
    let r = env.send(
        &[env.ix_update_config(&admin, &ConfigParams::default())],
        &[&admin_kp],
    );
    out.ok("update_config", "admin", r);

    env.set_time(10);
    let ix = env.ix_create_wallet(&gzk, &k, &gjwk, &gwallet, None);
    let r = env.send(&[ix], &[&eph]);
    out.fail("create_wallet: prova ka skaduar (now >= max_epoch)", 14, r);
    env.set_time(5);

    // ---- create_wallet + open_session (Google, mainnet vk) ----
    let ix = env.ix_create_wallet(&gzk, &k, &gjwk, &gwallet, None);
    let r = env.send(&[ix], &[&eph]);
    out.ok(
        "create_wallet",
        "Google, vk mainnet: verify_full + PDA + krijimi i Wallet",
        r,
    );
    let ix = env.ix_create_wallet(&gzk, &k, &gjwk, &gwallet, None);
    let r = env.send(&[ix], &[&eph]);
    out.fail("create_wallet: portofoli ekziston", 5, r);

    let self_policy = policy(vec![env.program_id], vec![]);
    let ix = env.ix_open_session(&gzk, &k, &gjwk, &gwallet, &self_policy);
    let r = env.send(&[ix], &[&eph]);
    out.fail(
        "open_session: politika lejon vetë programin solanaauth",
        40,
        r,
    );

    let ix = env.ix_open_session(&dzk, &k, &djwk, &gwallet, &policy(vec![SYSTEM], vec![]));
    let r = env.send(&[ix], &[&eph]);
    out.fail(
        "open_session: verifying key test kur allow_test_vk = 0",
        16,
        r,
    );

    let mint = Address::new_unique();
    let other_mint = Address::new_unique();
    let pol = policy(
        vec![SYSTEM, TOKEN],
        vec![(Address::default(), 1_000_000_000, 3600), (mint, 500, 3600)],
    );
    let ix = env.ix_open_session(&gzk, &k, &gjwk, &gwallet, &pol);
    let r = env.send(&[ix], &[&eph]);
    out.ok(
        "open_session",
        "verify_full + identiteti + Session (2 programe, 2 limite)",
        r,
    );
    let ix = env.ix_open_session(&gzk, &k, &gjwk, &gwallet, &pol);
    let r = env.send(&[ix], &[&eph]);
    out.fail("open_session: sesioni ekziston", 5, r);

    // ---- execute ----
    env.svm.airdrop(&gvault, 5_000_000_000).unwrap();
    let dest = Address::new_unique();
    let ix = env.ix_execute(
        &k,
        &gwallet,
        &[system_transfer(&gvault, &dest, 400_000_000)],
    );
    let r = env.send(&[ix], &[&eph]);
    out.ok(
        "execute: transfer SOL",
        "1 CPI te System, brenda limitit",
        r,
    );
    assert_eq!(env.lamports(&dest), 400_000_000);

    let ix = env.ix_execute(
        &k,
        &gwallet,
        &[system_transfer(&gvault, &dest, 700_000_000)],
    );
    let r = env.send(&[ix], &[&eph]);
    out.fail("execute: SOL mbi limitin e dritares", 33, r);

    // Token-at.
    let mint_auth = Address::new_unique();
    env.set_mint(&mint, &mint_auth);
    env.set_mint(&other_mint, &mint_auth);
    let vta = Address::new_unique();
    let vta2 = Address::new_unique();
    let dta = Address::new_unique();
    let dta2 = Address::new_unique();
    env.set_token_account(&vta, &mint, &gvault, 1_000);
    env.set_token_account(&vta2, &other_mint, &gvault, 1_000);
    env.set_token_account(&dta, &mint, &dest, 0);
    env.set_token_account(&dta2, &other_mint, &dest, 0);

    let ix = env.ix_execute(&k, &gwallet, &[token_transfer(&vta, &dta, &gvault, 200)]);
    let r = env.send(&[ix], &[&eph]);
    out.ok(
        "execute: transfer token",
        "1 CPI te SPL Token, matja para/pas",
        r,
    );
    assert_eq!(env.token_amount(&dta), 200);

    let ix = env.ix_execute(
        &k,
        &gwallet,
        &[
            system_transfer(&gvault, &dest, 100_000_000),
            token_transfer(&vta, &dta, &gvault, 100),
        ],
    );
    let r = env.send(&[ix], &[&eph]);
    out.ok("execute: SOL + token", "2 CPI në një instruksion", r);

    let ix = env.ix_execute(&k, &gwallet, &[token_transfer(&vta, &dta, &gvault, 201)]);
    let r = env.send(&[ix], &[&eph]);
    out.fail("execute: token mbi limitin (300 + 201 > 500)", 33, r);

    let ix = env.ix_execute(&k, &gwallet, &[token_transfer(&vta2, &dta2, &gvault, 1)]);
    let r = env.send(&[ix], &[&eph]);
    out.fail("execute: token pa limit (deny by default)", 34, r);

    let ix = env.ix_execute(&k, &gwallet, &[token_approve(&vta, &dest, &gvault, 1)]);
    let r = env.send(&[ix], &[&eph]);
    out.fail(
        "execute: Approve (delegate) mbi token account të vault-it",
        36,
        r,
    );

    let ix = env.ix_execute(&k, &gwallet, &[system_assign(&gvault, &TOKEN)]);
    let r = env.send(&[ix], &[&eph]);
    out.fail("execute: Assign i vault-it te një program tjetër", 35, r);

    let memo = Address::from_str_const("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
    let memo_ix = Instruction {
        program_id: memo,
        accounts: vec![],
        data: b"x".to_vec(),
    };
    let ix = env.ix_execute(&k, &gwallet, &[memo_ix]);
    let r = env.send(&[ix], &[&eph]);
    out.fail("execute: program jashtë allowlist-it", 32, r);

    let self_ix = Instruction {
        program_id: env.program_id,
        accounts: vec![],
        data: vec![3],
    };
    let ix = env.ix_execute(&k, &gwallet, &[self_ix]);
    let r = env.send(&[ix], &[&eph]);
    out.fail("execute: CPI te vetë programi", 37, r);

    // Fee payer-i (p.sh. paymaster-i) nënshkruan tx-in; sesioni s'mund ta përdorë si nënshkrues.
    let fee_payer = env.payer.pubkey();
    let ix = env.ix_execute(&k, &gwallet, &[system_transfer(&fee_payer, &dest, 1)]);
    let r = env.send(&[ix], &[&eph]);
    out.fail(
        "execute: fee payer-i si nënshkrues i instruksionit të brendshëm",
        3,
        r,
    );

    let ix = env.ix_execute(
        &other.pubkey(),
        &gwallet,
        &[system_transfer(&gvault, &dest, 1)],
    );
    let r = env.send(&[ix], &[&other]);
    out.fail("execute: nënshkrues që s'është session_key", 2, r);

    let ix = env.ix_execute(&k, &gwallet, &[system_transfer(&gvault, &gwallet, 1)]);
    let r = env.send(&[ix], &[&eph]);
    out.fail(
        "execute: portofoli si llogari e instruksionit të brendshëm",
        2,
        r,
    );

    let r = env.send(&[env.ix_close_session(&gwallet, &gsession)], &[]);
    out.fail("close_session: sesioni ende aktiv", 39, r);

    // Dritarja e limitit rifillon pas `period_secs`... por prova skadon në 10, ndaj
    // kontrollohet me skadimin e sesionit.
    env.set_time(10);
    let ix = env.ix_execute(&k, &gwallet, &[system_transfer(&gvault, &dest, 1)]);
    let r = env.send(&[ix], &[&eph]);
    out.fail("execute: sesioni ka skaduar", 30, r);
    let vault_before = env.lamports(&gvault);
    let r = env.send(&[env.ix_close_session(&gwallet, &gsession)], &[]);
    out.ok(
        "close_session",
        "pas skadimit; rent-i kthehet te vault-i",
        r,
    );
    assert!(env.lamports(&gvault) > vault_before);
    assert!(env
        .account(&gsession)
        .map(|a| a.lamports == 0)
        .unwrap_or(true));
    env.set_time(6);

    // ---- Test vk (devnet) + create_wallet_with_session + revokimet ----
    let test_vk = ConfigParams {
        allow_test_vk: true,
        ..ConfigParams::default()
    };
    let r = env.send(&[env.ix_update_config(&admin, &test_vk)], &[&admin_kp]);
    assert!(r.ok, "{:?}", r.err);
    let dsession = env.session(&dwallet, &k);
    let pol = policy(vec![SYSTEM], vec![(Address::default(), 1_000_000, 60)]);
    let ix = env.ix_create_wallet(&dzk, &k, &djwk, &dwallet, Some(&pol));
    let r = env.send(&[ix], &[&eph]);
    out.ok(
        "create_wallet + open_session",
        "hyrja e parë në një instruksion (vk test, allow_test_vk = 1)",
        r,
    );

    let ix = env.ix_revoke_zk(&gzk, &k, &dwallet, &dsession, &gjwk);
    let r = env.send(&[ix], &[&eph]);
    out.fail(
        "revoke_session (zk): identitet që s'është i portofolit",
        18,
        r,
    );

    let ix = env.ix_revoke_zk(&dzk, &k, &dwallet, &dsession, &djwk);
    let r = env.send(&[ix], &[&eph]);
    out.ok("revoke_session (zk)", "me provë të re zkLogin", r);
    env.svm
        .airdrop(&env.vault(&dwallet), 1_000_000_000)
        .unwrap();
    let dvault = env.vault(&dwallet);
    let ix = env.ix_execute(&k, &dwallet, &[system_transfer(&dvault, &dest, 1)]);
    let r = env.send(&[ix], &[&eph]);
    out.fail("execute: sesioni i revokuar", 31, r);
    let r = env.send(&[env.ix_close_session(&dwallet, &dsession)], &[]);
    out.ok("close_session (pas revokimit)", "", r);

    // Sesion i ri, revokim nga vetë sesioni.
    let ix = env.ix_open_session(&dzk, &k, &djwk, &dwallet, &pol);
    let r = env.send(&[ix], &[&eph]);
    out.ok("open_session (vk test)", "", r);
    let r = env.send(&[env.ix_revoke_self(&other.pubkey(), &dwallet)], &[&other]);
    out.fail("revoke_session (self): nënshkrues tjetër", 2, r);
    let r = env.send(&[env.ix_revoke_self(&k, &dwallet)], &[&eph]);
    out.ok("revoke_session (self)", "nga çelësi i sesionit", r);

    // ---- revoke_jwk ----
    let r = env.send(&[env.ix_revoke_jwk(&oracle, &gjwk)], &[&oracle_kp]);
    out.fail("revoke_jwk nga oracle (jo admin)", 4, r);
    let r = env.send(&[env.ix_revoke_jwk(&admin, &gjwk)], &[&admin_kp]);
    out.ok("revoke_jwk", "admin, menjëherë", r);
    let ix = env.ix_open_session(&gzk, &k, &gjwk, &gwallet, &policy(vec![SYSTEM], vec![]));
    let r = env.send(&[ix], &[&eph]);
    out.fail("open_session me JWK të revokuar", 11, r);

    // Madhësitë dhe rent-i i llogarive, nga llogaritë e krijuara në këtë skenar.
    let accounts: Vec<(&str, Address, &str)> = vec![
        ("Config", env.config(), "një për program"),
        ("Jwk", gjwk, "një për (iss, kid); paguan oracle/admini"),
        ("Wallet", gwallet, "një për përdorues; rent-i paguhet një herë"),
        ("Vault", gvault, "pa të dhëna (D4); mban SOL-in e përdoruesit"),
        ("Session", dsession, "një për pajisje/agjent; rent-i kthehet me `close_session`"),
    ];
    let rows: Vec<(String, usize, u64, String)> = accounts
        .into_iter()
        .filter_map(|(name, a, note)| {
            let acc = env.svm.get_account(&a)?;
            let len = acc.data.len();
            Some((name.to_string(), len, env.svm.minimum_balance_for_rent_exemption(len), note.to_string()))
        })
        .collect();
    assert!(rows.iter().any(|r| r.0 == "Wallet") && rows.iter().any(|r| r.0 == "Session"));
    write_report(&out, &so);
    write_accounts(&rows);
}

fn write_accounts(rows: &[(String, usize, u64, String)]) {
    let mut md = String::from("## Llogaritë e `solanaauth`: madhësia dhe rent-i\n\n");
    md.push_str("Lexuar nga llogaritë që krijon skenari M2 në LiteSVM (CI), me rent-in e rrjetit (minimumi pa rent).\n\n");
    md.push_str("| Llogaria | Bytes | Rent (lamports) | Rent (SOL) | Shënim |\n|---|---:|---:|---:|---|\n");
    for (name, len, rent, note) in rows {
        let _ = writeln!(md, "| `{name}` | {len} | {} | {:.6} | {note} |", fmt_num(*rent), *rent as f64 / 1e9);
    }
    let json = serde_json::json!(rows.iter().map(|(n, l, r, _)| serde_json::json!({"account": n, "bytes": l, "rent_lamports": r})).collect::<Vec<_>>());
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../results");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("solanaauth-accounts.md"), &md).unwrap();
    std::fs::write(dir.join("solanaauth-accounts.json"), serde_json::to_string_pretty(&json).unwrap() + "\n").unwrap();
    println!("{md}");
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut o = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            o.push(',');
        }
        o.push(c);
    }
    o
}

fn write_report(out: &Out, so: &std::path::Path) {
    let so_size = std::fs::metadata(so).map(|m| m.len()).unwrap_or(0);
    let mut md = String::from("## Matjet e CU — programi `solanaauth` (M2)\n\n");
    md.push_str("Të gjitha numrat vijnë nga LiteSVM në CI, me programin e ndërtuar me `cargo build-sbf`.\n\n");
    md.push_str("| Instruksioni | CU | Tx (bytes) | Shënim |\n|---|---:|---:|---|\n");
    for r in &out.rows {
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} |",
            r.name,
            fmt_num(r.cu),
            r.tx_bytes,
            r.note
        );
    }
    let _ = writeln!(
        md,
        "\n### Testet negative: {}/{} të refuzuara me kodin e pritur\n",
        out.negatives
            .iter()
            .filter(|n| n.got == Some(n.expected))
            .count(),
        out.negatives.len()
    );
    md.push_str("| Rasti | Kodi |\n|---|---:|\n");
    for n in &out.negatives {
        let _ = writeln!(md, "| {} | `Custom({})` |", n.case, n.expected);
    }
    let _ = writeln!(md, "\n<sub>solanaauth.so: {} bytes</sub>", fmt_num(so_size));

    let json = serde_json::json!({
        "program_size_bytes": so_size,
        "instructions": out.rows.iter().map(|r| serde_json::json!({
            "name": r.name, "cu": r.cu, "tx_bytes": r.tx_bytes, "note": r.note,
        })).collect::<Vec<_>>(),
        "negatives": out.negatives.iter().map(|n| serde_json::json!({
            "case": n.case, "expected_code": n.expected, "rejected": n.got == Some(n.expected),
        })).collect::<Vec<_>>(),
    });
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../results");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("solanaauth-cu.md"), &md).unwrap();
    std::fs::write(
        dir.join("solanaauth-cu.json"),
        serde_json::to_string_pretty(&json).unwrap() + "\n",
    )
    .unwrap();
    println!("{md}");
}
