//! Eksporton instruksionet e provave referencë (base64) për skriptin e devnet-it:
//! `cargo run -p bench --bin export_ix -- target/devnet-ix.json`.

use base64ct::Encoding;
use bench::{Case, ModulusMode};
use zklogin_verifier::inputs::Circuit;

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "target/devnet-ix.json".into());
    let mut items = Vec::new();
    for name in reference::FIXTURE_NAMES {
        let case = Case::load(name);
        let hash = case.all_inputs_hash();
        let mut push = |label: String, data: Vec<u8>| {
            items.push(serde_json::json!({ "label": label, "data": base64ct::Base64::encode_string(&data) }));
        };
        push(
            format!("{name} / verify_proof"),
            case.ix_verify_proof(&case.proof, &hash, false),
        );
        if case.vk.circuit() == Circuit::V1 {
            push(
                format!("{name} / verify_full"),
                case.ix_verify_full(&case.public_inputs(ModulusMode::Full), &case.proof, false),
            );
        }
        push(
            format!("{name} / verify_full (modulus i para-llogaritur)"),
            case.ix_verify_full(
                &case.public_inputs(ModulusMode::Precomputed),
                &case.proof,
                false,
            ),
        );
    }
    std::fs::write(&out, serde_json::to_string_pretty(&items).unwrap()).unwrap();
    println!("{} instruksione -> {out}", items.len());
}
