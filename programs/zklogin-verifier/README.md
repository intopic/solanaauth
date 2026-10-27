# zklogin-verifier (programi Solana)

Bosh me qëllim. Detyra 4 te [`docs/HAPI-1-BRIEF.md`](../../docs/HAPI-1-BRIEF.md):

- `verify_proof(proof, public_input)` — vetëm Groth16 me `groth16-solana`.
- `verify_full(proof, inputs...)` — rillogarit `all_inputs_hash` me `sol_poseidon`, pastaj verifikon.

Sapo të shtohet `Cargo.toml` këtu, CI fillon automatikisht ta ndërtojë me `cargo build-sbf`.
Emri i crate-it duhet të jetë `zklogin-verifier` (prodhon `target/deploy/zklogin_verifier.so`).
