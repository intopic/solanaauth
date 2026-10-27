# fixtures

Test vectors për Detyrën 1 (asgjë sekrete këtu):

- `proof.json` — prova Groth16 (a, b, c) nga sui-crypto `tests.rs` ose nga `prover-dev`.
- `inputs.json` — JWT-ja e testit, ephemeral public key, `max_epoch`, `address_seed`, `iss`, header, modulus.
- `zklogin.vkey.json` — verifying key që i përket provës (test vs main, v1 vs v2 — shih Kurthet).
- `verifying_key.rs` — key-i i konvertuar për `groth16-solana` (Detyra 3).

Shëno te çdo skedar burimin dhe versionin e qarkut.
