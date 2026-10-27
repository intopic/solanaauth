# zklogin-verifier (programi Solana)

Program native (pinocchio, pa Anchor) pa llogari dhe pa gjendje, vetëm për matje.

| op | Instruksioni | Çfarë bën |
|---|---|---|
| 0 | `verify_proof(vk, proof, public_input)` | vetëm Groth16 me `groth16-solana` |
| 1 | `verify_full(vk, proof, inputs…)` | rillogarit `all_inputs_hash` me `sol_poseidon`, pastaj Groth16 |
| 2 | `compute_inputs_hash(vk, proof, inputs…)` | vetëm Poseidon; e shkruan hash-in me `sol_log_data` (për krahasim bit për bit) |

Flamuri `0x80` në byte-in e parë shton `sol_log_compute_units` pas çdo hapi. Formati i plotë i
bytes është te koka e [`src/lib.rs`](src/lib.rs); logjika e hash-it te [`src/inputs.rs`](src/inputs.rs).

```bash
cargo build-sbf --manifest-path programs/zklogin-verifier/Cargo.toml
# -> programs/zklogin-verifier/target/deploy/zklogin_verifier.so
```

Programi nuk është pjesë e workspace-it kryesor (ka `Cargo.lock` të vetin për toolchain-in SBF),
por `bench/` e përdor si librari (`features = ["no-entrypoint"]`) për testet në host.
