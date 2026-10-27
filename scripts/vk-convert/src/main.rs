//! Detyra 3: konverton verifying key-t zkLogin nga formati snarkjs
//! (`fixtures/vk/*.vkey.json`) në konstante `Groth16Verifyingkey` për programin.
//!
//! Përdor gjeneratorin zyrtar të groth16-solana (`vk::circom`), i cili:
//! - shkruan koordinatat në big endian (siç kërkojnë syscall-et alt_bn128),
//! - i rendit koordinatat G2 si (c1, c0), d.m.th. pjesa imagjinare e para (EIP-197),
//!   ndërsa snarkjs/arkworks i ruajnë si (c0, c1).
//!
//! Ekzekutim: `cargo run -p vk-convert` (CI kontrollon që skedarët janë të përditësuar
//! me `cargo run -p vk-convert -- --check`).

use std::path::Path;

/// (vkey json, skedari Rust në programs/zklogin-verifier/src/vk/)
const KEYS: [(&str, &str); 3] = [
    ("zkLogin-main.vkey.json", "mainnet.rs"),
    ("zkLogin-test.vkey.json", "dev_v1.rs"),
    ("zkLogin-dev-v2.vkey.json", "dev_v2.rs"),
];

fn main() {
    let check = std::env::args().any(|a| a == "--check");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out_dir = root.join("programs/zklogin-verifier/src/vk");
    std::fs::create_dir_all(&out_dir).unwrap();

    let mut stale = Vec::new();
    for (json, rs) in KEYS {
        let json_path = root.join("fixtures/vk").join(json);
        let content = std::fs::read_to_string(&json_path)
            .unwrap_or_else(|e| panic!("s'lexohet {}: {e}", json_path.display()));
        let code = groth16_solana::vk::circom::parse_vk_json_to_rust_string(&content)
            .unwrap_or_else(|e| panic!("{json}: {e}"));
        let code = format!(
            "// Burimi: fixtures/vk/{json} (gjeneruar nga `cargo run -p vk-convert`).\n{code}"
        );
        let out = out_dir.join(rs);
        if check {
            if std::fs::read_to_string(&out).ok().as_deref() != Some(code.as_str()) {
                stale.push(rs);
            }
        } else {
            std::fs::write(&out, code).unwrap();
            println!("{json} -> programs/zklogin-verifier/src/vk/{rs}");
        }
    }
    if !stale.is_empty() {
        eprintln!("Verifying key-t e konvertuara s'janë të përditësuara: {stale:?}. Ekzekuto `cargo run -p vk-convert`.");
        std::process::exit(1);
    }
}
