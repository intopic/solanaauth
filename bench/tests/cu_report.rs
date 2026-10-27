//! Ekzekutohet nga CI: `cargo test -p bench --test cu_report -- --nocapture`.
//!
//! Ngarkon `zklogin_verifier.so` (nga `cargo build-sbf`) në LiteSVM, mat CU për çdo
//! instruksion me provat referencë, teston rastet negative dhe shkruan
//! `results/cu-report.json` + `results/cu-report.md`.
//!
//! Pa `.so`: në CI testi dështon; lokalisht anashkalohet (dhe `results/` nuk preket).

use base64ct::Encoding;
use bench::svm::{default_program_path, Outcome, Svm, MAX_TX_BYTES};
use bench::{be32_to_dec, Case, ModulusMode, NegativeCase, Report, Row, Section};
use reference::FIXTURE_NAMES;
use sha2::Digest;
use zklogin_verifier::inputs::Circuit;

/// Kostoja e vetë thirrjes `sol_log_compute_units` (syscall_base_cost), e zbritur
/// nga diferencat mes dy shenjave.
const LOG_CU_COST: u64 = 100;

fn steps(o: &Outcome) -> Vec<u64> {
    o.remaining_marks()
        .windows(2)
        .map(|w| w[0] - w[1] - LOG_CU_COST)
        .collect()
}

fn row(name: &str, o: &Outcome, note: &str) -> Row {
    assert!(o.ok, "{name} dështoi: {:?}\n{}", o.err, o.logs.join("\n"));
    Row {
        name: name.into(),
        cu: Some(o.cu),
        tx_bytes: Some(o.tx_bytes),
        note: note.into(),
    }
}

fn step_row(name: &str, cu: u64, note: &str) -> Row {
    Row {
        name: name.into(),
        cu: Some(cu),
        tx_bytes: None,
        note: note.into(),
    }
}

#[test]
fn write_cu_report() {
    let so = default_program_path();
    if !so.exists() {
        if std::env::var_os("CI").is_some() {
            panic!(
                "{} mungon: ekzekuto `cargo build-sbf` para bench-it",
                so.display()
            );
        }
        eprintln!(
            "KUJDES: {} mungon, matjet anashkalohen (results/ nuk preket).",
            so.display()
        );
        return;
    }
    let so_bytes = std::fs::read(&so).unwrap();
    let mut svm = Svm::new(&so);
    let mut report = Report::default();

    for name in FIXTURE_NAMES {
        let case = Case::load(name);
        let hash = case.all_inputs_hash();
        let mut rows = Vec::new();

        // 1. verify_proof: vetëm Groth16.
        let o = svm.run(case.ix_verify_proof(&case.proof, &hash, false));
        rows.push(row(
            "`verify_proof`",
            &o,
            "Groth16 me groth16-solana (input-i publik jepet gati)",
        ));
        let o = svm.run(case.ix_verify_proof(&case.proof, &hash, true));
        assert!(o.ok);
        rows.push(step_row(
            "↳ Groth16 (pa parsimin)",
            steps(&o)[0],
            "neg(A) + MSM me 1 input + pairing me 4 çifte",
        ));

        // 2. compute_inputs_hash: hash-i rillogaritet në SVM dhe krahasohet bit për bit.
        let full_supported = case.vk.circuit() == Circuit::V1;
        let mode = if full_supported {
            ModulusMode::Full
        } else {
            ModulusMode::Precomputed
        };
        let o = svm.run(case.ix_compute_inputs_hash(&case.public_inputs(mode)));
        assert!(o.ok, "{name}: compute_inputs_hash dështoi: {:?}", o.err);
        let logged = base64ct::Base64::decode_vec(&o.data_logs()[0]).unwrap();
        assert_eq!(
            logged, hash,
            "{name}: hash-i on-chain ndryshon nga ai off-chain"
        );
        if let Some(expected) = &case.fx.expected_all_inputs_hash {
            assert_eq!(&be32_to_dec(&hash), expected);
        }

        // 3. verify_full.
        if full_supported {
            let p = case.public_inputs(ModulusMode::Full);
            let o = svm.run(case.ix_verify_full(&p, &case.proof, false));
            rows.push(row(
                "**`verify_full`**",
                &o,
                "**Poseidon (me modulus-in e plotë) + Groth16, kriteri GO/NO-GO**",
            ));
            let o = svm.run(case.ix_verify_full(&p, &case.proof, true));
            assert!(o.ok);
            let s = steps(&o);
            assert_eq!(s.len(), 5, "{name}: {:?}", o.remaining_marks());
            rows.push(step_row(
                "↳ Poseidon: header (8 input-e)",
                s[0],
                "248 bytes → 8 copa × 31",
            ));
            rows.push(step_row(
                "↳ Poseidon: iss (8 input-e)",
                s[1],
                "224 bytes → 8 copa",
            ));
            rows.push(step_row(
                "↳ Poseidon: modulus RSA (9 input-e)",
                s[2],
                "2048 bit → 9 copa; kandidat për JWK registry",
            ));
            rows.push(step_row(
                "↳ Poseidon: all_inputs_hash (8 input-e)",
                s[3],
                "input-i i vetëm publik i qarkut",
            ));
            rows.push(step_row("↳ Groth16", s[4], ""));
            rows.push(step_row(
                "↳ Poseidon gjithsej (4 thirrje)",
                s[0] + s[1] + s[2] + s[3],
                "",
            ));
        } else {
            let p = case.public_inputs(ModulusMode::Full);
            let o = svm.run(case.ix_verify_full(&p, &case.proof, false));
            assert!(!o.ok, "{name}: v2 me modulus 8192-bit nuk duhet të kalojë");
            rows.push(Row {
                name: "`verify_full` (modulus i plotë)".into(),
                cu: None,
                tx_bytes: Some(o.tx_bytes),
                note: format!(
                    "s'mbështetet: 8192 bit → 34 copa, Sui përdor Poseidon me 16 input-e, `sol_poseidon` pranon ≤ 12; tx {} > {MAX_TX_BYTES} bytes",
                    o.tx_bytes
                ),
            });
        }

        let p = case.public_inputs(ModulusMode::Precomputed);
        let o = svm.run(case.ix_verify_full(&p, &case.proof, false));
        rows.push(row(
            "`verify_full` (modulus i para-llogaritur)",
            &o,
            "hash-i i modulus-it si nga një llogari JWK registry",
        ));
        let o = svm.run(case.ix_verify_full(&p, &case.proof, true));
        assert!(o.ok);
        let s = steps(&o);
        rows.push(step_row(
            "↳ Poseidon gjithsej (3 thirrje)",
            s[0] + s[1] + s[3],
            "header + iss + all_inputs_hash",
        ));

        if name == "google-mainnet-v1" {
            report.decisive_cu = rows
                .iter()
                .find(|r| r.name == "**`verify_full`**")
                .and_then(|r| r.cu);
            report.decisive_label = "JWT e vërtetë Google, key mainnet, qarku v1".into();
        }
        for r in &rows {
            if let Some(b) = r.tx_bytes {
                if r.cu.is_some() {
                    assert!(
                        b <= MAX_TX_BYTES,
                        "{name}/{}: tx {b} bytes > {MAX_TX_BYTES}",
                        r.name
                    );
                }
            }
        }
        report.sections.push(Section {
            fixture: name.into(),
            description: case.fx.description.clone(),
            rows,
        });
    }

    // Detyra 7: rastet negative duhet të refuzohen nga programi në SVM.
    for (fixture, c) in bench::negative::cases() {
        let o = svm.run(c.data);
        let detail = o.err.clone().unwrap_or_else(|| "OK".into());
        let detail = match detail.strip_prefix("InstructionError(1, ") {
            Some(rest) => rest.strip_suffix(')').unwrap_or(rest).to_string(),
            None => detail,
        };
        report.negatives.push(NegativeCase {
            fixture,
            case: c.label,
            rejected: !o.ok,
            detail,
        });
    }
    let accepted: Vec<_> = report
        .negatives
        .iter()
        .filter(|n| !n.rejected)
        .map(|n| n.case.clone())
        .collect();

    report.notes = vec![
        format!("CU = njësitë e konsumuara nga instruksioni i programit në LiteSVM (\"Program … consumed N\"); limiti i kërkuar me `SetComputeUnitLimit({})`.", bench::svm::MAX_TX_CU),
        format!("Hapat (↳) maten me `sol_log_compute_units` në një ekzekutim të veçantë me flamurin TRACE; nga çdo diferencë zbritet kostoja e thirrjes së log-ut ({LOG_CU_COST} CU)."),
        "Tx (bytes) = transaksioni i plotë i serializuar: 1 nënshkrim + `SetComputeUnitLimit` + instruksioni; limiti 1232 bytes.".into(),
        "Hash-i `all_inputs_hash` i rillogaritur në SVM (`compute_inputs_hash`, `sol_log_data`) përputhet bit për bit me sui-crypto/fastcrypto për të tri provat.".into(),
        "Kodet e gabimeve: Custom(3) = prova u refuzua nga Groth16, Custom(4) = input publik jashtë fushës.".into(),
    ];
    report.meta = vec![
        (
            "program.so sha256".into(),
            format!("{:x}", sha2::Sha256::digest(&so_bytes)),
        ),
        (
            "svm".into(),
            "litesvm 0.17.0 (Agave 4.x feature set)".into(),
        ),
        (
            "commit".into(),
            std::env::var("GITHUB_SHA").unwrap_or_else(|_| "lokal".into()),
        ),
        (
            "solana".into(),
            std::env::var("SOLANA_VERSION").unwrap_or_else(|_| "?".into()),
        ),
    ];

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../results");
    std::fs::create_dir_all(&dir).unwrap();
    let md = report.render_markdown();
    std::fs::write(dir.join("cu-report.md"), &md).unwrap();
    std::fs::write(dir.join("cu-report.json"), report.render_json()).unwrap();
    println!("{md}");

    assert!(
        accepted.is_empty(),
        "raste negative u pranuan: {accepted:?}"
    );
}
