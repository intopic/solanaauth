//! Ekzekutohet nga CI: `cargo test -p bench -- --nocapture`.
//! Shkruan results/cu-report.json dhe results/cu-report.md.
//!
//! TODO(Detyra 6): zëvendëso `None` me matje reale duke ngarkuar
//! `target/deploy/zklogin_verifier.so` në Mollusk/LiteSVM me provën nga `fixtures/`,
//! dhe shto testet negative (1 byte i ndryshuar në provë / input → refuzim).

use bench::{render_json, render_markdown, Measurement};

#[test]
fn write_cu_report() {
    let ms = [
        Measurement { name: "verify_proof", cu: None, note: "Groth16 me groth16-solana" },
        Measurement { name: "poseidon (secili hap)", cu: None, note: "sol_poseidon" },
        Measurement { name: "modulus RSA hash", cu: None, note: "kandidat për JWK registry" },
        Measurement { name: "verify_full", cu: None, note: "Poseidon + Groth16, kriteri GO/NO-GO" },
    ];
    let total = ms.iter().find(|m| m.name == "verify_full").and_then(|m| m.cu);

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../results");
    std::fs::create_dir_all(&dir).unwrap();
    let md = render_markdown(&ms, total);
    std::fs::write(dir.join("cu-report.md"), &md).unwrap();
    std::fs::write(dir.join("cu-report.json"), render_json(&ms, total)).unwrap();
    println!("{md}");
}
