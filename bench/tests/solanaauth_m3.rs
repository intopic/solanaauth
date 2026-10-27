//! M3: passkey (secp256r1 + WebAuthn), pragu ditor, revokimi me passkey dhe rikuperimi me
//! timelock. Rezultatet: `results/solanaauth-m3-cu.{md,json}`.

use std::fmt::Write as _;

use bench::auth::*;
use bench::Case;
use solana_address::Address;
use solana_signer::Signer;

const GOOGLE: &str = "https://accounts.google.com";
const SUI_TEST: &str = "https://oauth.sui.io";

#[derive(Default)]
struct Out {
    rows: Vec<(String, u64, usize, String)>,
    negatives: Vec<(String, u32)>,
}

impl Out {
    fn ok(&mut self, name: &str, note: &str, r: Run) {
        assert!(r.ok, "{name} dështoi: {:?}\n{}", r.err, r.logs.join("\n"));
        self.rows.push((name.into(), r.cu, r.tx_bytes, note.into()));
    }

    /// I refuzuar nga precompile-i secp256r1 para programit (kodi 0 në raport).
    fn fail_precompile(&mut self, case: &str, r: Run) {
        assert!(!r.ok, "{case}: duhej të refuzohej");
        let e = r.err.clone().unwrap_or_default();
        assert!(e.contains("InstructionError(1,"), "{case}: {e}");
        self.negatives.push((case.into(), 0));
    }

    fn fail(&mut self, case: &str, expected: u32, r: Run) {
        assert!(!r.ok, "{case}: duhej të refuzohej\n{}", r.logs.join("\n"));
        assert_eq!(
            r.custom_code(),
            Some(expected),
            "{case}: {:?}\n{}",
            r.err,
            r.logs.join("\n")
        );
        self.negatives.push((case.into(), expected));
    }
}

fn wallet_bytes(env: &Env, w: &Address) -> Vec<u8> {
    env.account(w).unwrap().data
}

// Offset-et e `Wallet` (state.rs).
const ZK1: usize = 40 + 8 + 8 + 40; // zk[1].identity
const PASSKEYS: usize = 136;
const RECOVERY_KIND: usize = 336;

#[test]
fn solanaauth_m3() {
    let so = default_so_path();
    let mut env = Env::new(&so);
    let mut out = Out::default();
    let admin = env.admin.pubkey();
    let admin_kp = env.admin.insecure_clone();

    let google = Case::load("google-mainnet-v1");
    let dev = Case::load("dev-v1-pinned");
    let eph = eph_keypair(&google);
    let k = eph.pubkey();
    let gjwk = env.jwk(GOOGLE, &google.fx.jwk.kid);
    let djwk = env.jwk(SUI_TEST, &dev.fx.jwk.kid);
    let gzk = zk_block(&google, &google.proof);
    let dzk = zk_block(&dev, &dev.proof);
    let wallet = env.wallet_of(&identity(GOOGLE, &google.address_seed));
    let vault = env.vault(&wallet);
    let session = env.session(&wallet, &k);

    let params = ConfigParams {
        allow_test_vk: true,
        ..ConfigParams::default()
    };
    let delay = params.recovery_delay;
    let r = env.send(&[env.ix_init_config(&admin, &params)], &[&admin_kp]);
    assert!(r.ok, "{:?}", r.err);
    for (iss, c) in [(GOOGLE, &google), (SUI_TEST, &dev)] {
        let ix = env.ix_propose_jwk(&admin, iss, &c.fx.jwk.kid, &c.modulus, 0, i64::MAX);
        assert!(env.send(&[ix], &[&admin_kp]).ok);
    }
    env.set_time(3);
    for j in [gjwk, djwk] {
        assert!(env.send(&[env.ix_apply_jwk(&j)], &[]).ok);
    }

    let pol = Policy {
        expires_in: 3600,
        label: label("m3"),
        programs: vec![SYSTEM],
        limits: vec![(Address::default(), 10_000_000_000, 3600)],
    };
    let ix = env.ix_create_wallet(&gzk, &k, &gjwk, &wallet, Some(&pol));
    assert!(env.send(&[ix], &[&eph]).ok);
    env.svm.airdrop(&vault, 20_000_000_000).unwrap();

    let p1 = PasskeyKey::from_seed(1);
    let p2 = PasskeyKey::from_seed(2);
    let p3 = PasskeyKey::from_seed(3);

    // ---- add_passkey ----
    let ix = env.ix_add_passkey_zk(&gzk, &k, &gjwk, &wallet, 0, &p1.pubkey());
    let r = env.send(&[ix], &[&eph]);
    out.ok("add_passkey (zk)", "passkey-i i parë, me provë zkLogin", r);
    assert_eq!(
        &wallet_bytes(&env, &wallet)[PASSKEYS..PASSKEYS + 33],
        &p1.pubkey()
    );

    let ix = env.ix_add_passkey_zk(&gzk, &k, &gjwk, &wallet, 1, &p2.pubkey());
    let r = env.send(&[ix], &[&eph]);
    out.fail("add_passkey (zk) kur portofoli ka passkey", 41, r);

    let ixs = env.ix_add_passkey_pk(&p3, &wallet, 1, &p2.pubkey());
    let r = env.send(&ixs, &[]);
    out.fail("add_passkey: passkey që s'është i portofolit", 41, r);

    let ixs = env.ix_add_passkey_pk(&p1, &wallet, 0, &p2.pubkey());
    let r = env.send(&ixs, &[]);
    out.fail("add_passkey: slot i zënë", 46, r);

    let ixs = env.ix_add_passkey_pk(&p1, &wallet, 1, &p2.pubkey());
    let replay = ixs.clone();
    let r = env.send(&ixs, &[]);
    out.ok("add_passkey (passkey)", "secp256r1 + WebAuthn + nonce", r);
    let r = env.send(&replay, &[]);
    out.fail("passkey: replay i të njëjtit nënshkrim (nonce)", 42, r);

    let mut ixs = env.ix_set_threshold(&p1, &wallet, 1_000_000_000);
    ixs[0].data[16 + 33 + 10] ^= 1;
    let r = env.send(&ixs, &[]);
    out.fail_precompile("passkey: nënshkrim P-256 i pavlefshëm", r);

    // clientDataJSON i ndryshuar / pa precompile.
    let mut ixs = env.ix_set_threshold(&p1, &wallet, 1_000_000_000);
    let (pre, _) = p1.sign_client_data(PasskeyKey::client_data(&[7u8; 32]));
    ixs[0] = pre;
    let r = env.send(&ixs, &[]);
    out.fail("passkey: clientDataJSON me challenge tjetër", 42, r);
    let ixs = env.ix_set_threshold(&p1, &wallet, 1_000_000_000);
    let r = env.send(&ixs[1..], &[]);
    out.fail("passkey: pa instruksionin e precompile-it", 42, r);
    let mut ixs = env.ix_set_threshold(&p1, &wallet, 1_000_000_000);
    let n = ixs[1].data.len();
    ixs[1].data[n - 1] ^= 1; // pragu i ndryshuar pas nënshkrimit
    let r = env.send(&ixs, &[]);
    out.fail("passkey: të dhëna të ndryshuara pas nënshkrimit", 42, r);

    let ixs = env.ix_set_threshold(&p1, &wallet, 1_000_000_000);
    let r = env.send(&ixs, &[]);
    out.ok("set_threshold", "1 SOL në 24 orë pa passkey", r);

    // ---- pragu ----
    let dest = Address::new_unique();
    let ix = env.ix_execute(&k, &wallet, &[system_transfer(&vault, &dest, 600_000_000)]);
    let r = env.send(&[ix], &[&eph]);
    out.ok(
        "execute nën prag",
        "transfer SOL, pragu ditor përditësohet",
        r,
    );
    let ix = env.ix_execute(&k, &wallet, &[system_transfer(&vault, &dest, 600_000_000)]);
    let r = env.send(&[ix], &[&eph]);
    out.fail("execute: SOL mbi pragun ditor pa passkey", 45, r);
    let ixs = env.ix_execute_passkey(
        &p2,
        &k,
        &wallet,
        &[system_transfer(&vault, &dest, 600_000_000)],
    );
    let r = env.send(&ixs, &[&eph]);
    out.ok("execute me passkey (mbi prag)", "sesion + passkey", r);
    assert_eq!(env.lamports(&dest), 1_200_000_000);
    let ixs = env.ix_execute_passkey(&p3, &k, &wallet, &[system_transfer(&vault, &dest, 1)]);
    let r = env.send(&ixs, &[&eph]);
    out.fail("execute me passkey që s'është i portofolit", 41, r);

    // ---- remove_passkey ----
    let ixs = env.ix_remove_passkey(&p1, &wallet, 1);
    let r = env.send(&ixs, &[]);
    out.ok("remove_passkey", "", r);
    let ixs = env.ix_remove_passkey(&p2, &wallet, 0);
    let r = env.send(&ixs, &[]);
    out.fail("remove_passkey me passkey-n e hequr", 41, r);

    // ---- rikuperimi ----
    let r = env.send(&[env.ix_finish_recovery(&wallet)], &[]);
    out.fail("finish_recovery pa rikuperim", 44, r);
    let ix = env.ix_recovery_add_passkey(&gzk, &k, &gjwk, &wallet, 0, &p3.pubkey());
    let r = env.send(&[ix], &[&eph]);
    out.ok(
        "begin_recovery (zk → passkey)",
        "humbi passkey-n; timelock 48 orë",
        r,
    );
    assert_eq!(wallet_bytes(&env, &wallet)[RECOVERY_KIND], 1);
    let ix = env.ix_recovery_add_passkey(&gzk, &k, &gjwk, &wallet, 1, &p2.pubkey());
    let r = env.send(&[ix], &[&eph]);
    out.fail("begin_recovery kur ka një në pritje", 43, r);
    let r = env.send(&[env.ix_finish_recovery(&wallet)], &[]);
    out.fail("finish_recovery para timelock-ut", 20, r);
    let ixs = env.ix_cancel_recovery_pk(&p1, &wallet);
    let r = env.send(&ixs, &[]);
    out.ok(
        "cancel_recovery (passkey)",
        "pronari anulon rikuperimin e filluar me Google",
        r,
    );
    assert_eq!(wallet_bytes(&env, &wallet)[RECOVERY_KIND], 0);

    let ixs = env.ix_recovery_add_zk(&p1, &dzk, &k, &djwk, &wallet, 1);
    let r = env.send(&ixs, &[&eph]);
    out.ok(
        "begin_recovery (passkey → zk)",
        "humbi Google/salt: provë e identitetit të ri + passkey",
        r,
    );
    let r = env.send(
        &[env.ix_cancel_recovery_zk(&dzk, &k, &djwk, &wallet)],
        &[&eph],
    );
    out.fail(
        "cancel_recovery me identitet që s'është ende i portofolit",
        18,
        r,
    );
    let r = env.send(
        &[env.ix_cancel_recovery_zk(&gzk, &k, &gjwk, &wallet)],
        &[&eph],
    );
    out.ok("cancel_recovery (zk)", "identiteti ekzistues anulon", r);
    let ixs = env.ix_recovery_add_zk(&p1, &dzk, &k, &djwk, &wallet, 1);
    let r = env.send(&ixs, &[&eph]);
    assert!(r.ok, "{:?}", r.err);

    // ---- revoke_session me passkey ----
    let ixs = env.ix_revoke_passkey(&p1, &wallet, &session);
    let r = env.send(&ixs, &[]);
    out.ok("revoke_session (passkey)", "", r);
    let ix = env.ix_execute(&k, &wallet, &[system_transfer(&vault, &dest, 1)]);
    let r = env.send(&[ix], &[&eph]);
    out.fail("execute pas revokimit me passkey", 31, r);

    // ---- finish_recovery pas 48 orëve ----
    env.set_time(2 + delay);
    let r = env.send(&[env.ix_finish_recovery(&wallet)], &[]);
    out.fail("finish_recovery 1 sekondë para eta", 20, r);
    env.set_time(3 + delay);
    let r = env.send(&[env.ix_finish_recovery(&wallet)], &[]);
    out.ok("finish_recovery", "kushdo, pas timelock-ut", r);
    let w = wallet_bytes(&env, &wallet);
    assert_eq!(&w[ZK1..ZK1 + 32], &identity(SUI_TEST, &dev.address_seed));
    assert_eq!(w[RECOVERY_KIND], 0);

    write_report(&out, &so);
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut o = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            o.push(',');
        }
        o.push(c);
    }
    o
}

fn write_report(out: &Out, so: &std::path::Path) {
    let so_size = std::fs::metadata(so).map(|m| m.len()).unwrap_or(0);
    let mut md = String::from("## Matjet e CU — `solanaauth` M3 (passkey, pragu, rikuperimi)\n\n");
    md.push_str("Nga LiteSVM në CI. CU e instruksionit `solanaauth` (pa precompile-in secp256r1, që nuk konsumon CU të programit).\n\n");
    md.push_str("| Instruksioni | CU | Tx (bytes) | Shënim |\n|---|---:|---:|---|\n");
    for (n, cu, tx, note) in &out.rows {
        let _ = writeln!(md, "| {n} | {} | {tx} | {note} |", fmt_num(*cu));
    }
    let _ = writeln!(
        md,
        "\n### Testet negative: {}/{} të refuzuara me kodin e pritur\n",
        out.negatives.len(),
        out.negatives.len()
    );
    md.push_str("| Rasti | Kodi |\n|---|---:|\n");
    for (c, code) in &out.negatives {
        if *code == 0 {
            let _ = writeln!(md, "| {c} | precompile secp256r1 |");
        } else {
            let _ = writeln!(md, "| {c} | `Custom({code})` |");
        }
    }
    let _ = writeln!(md, "\n<sub>solanaauth.so: {} bytes</sub>", fmt_num(so_size));
    let json = serde_json::json!({
        "program_size_bytes": so_size,
        "instructions": out.rows.iter().map(|(n, cu, tx, note)| serde_json::json!({
            "name": n, "cu": cu, "tx_bytes": tx, "note": note,
        })).collect::<Vec<_>>(),
        "negatives": out.negatives.iter().map(|(c, code)| serde_json::json!({
            "case": c, "expected_code": if *code == 0 { serde_json::Value::from("precompile") } else { serde_json::Value::from(*code) }, "rejected": true,
        })).collect::<Vec<_>>(),
    });
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../results");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("solanaauth-m3-cu.md"), &md).unwrap();
    std::fs::write(
        dir.join("solanaauth-m3-cu.json"),
        serde_json::to_string_pretty(&json).unwrap() + "\n",
    )
    .unwrap();
    println!("{md}");
}
