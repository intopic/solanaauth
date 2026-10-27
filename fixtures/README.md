# fixtures

Test vectors për Hapin 1. Asgjë sekrete këtu: çelësi ephemeral është ai i test vectors
të sui-crypto (nga seed `[0; 32]`), pa asnjë vlerë.

## Provat (`proofs/`)

| Skedari | Qarku | Verifying key | JWT | Burimi |
|---|---|---|---|---|
| `google-mainnet-v1.json` | v1 | `zkLogin-main` (ceremonia, MAIN) | **JWT e vërtetë nga Google** (`accounts.google.com`) | sui-crypto `verify.rs::test_verify_zklogin_google` |
| `dev-v1-pinned.json` | v1 | `zkLogin-test` (ceremonia, TEST) | JWT testi (`oauth.sui.io`), provë nga prover-dev | sui-crypto `tests.rs::pinned_circuit_proof_material` |
| `dev-v2-pinned.json` | v2 | dev v2 (`zklogin-circuits` v2-main) | JWT nga `jwt-tester.mystenlabs.com`, RSA 8192-bit, provë nga prover-dev-v2 | sui-crypto `tests.rs::pinned_circuit_proof_material` |

Çdo skedar ka: `inputs` (formati `ZkLoginInputs` i Sui-t: `proof_points`, `iss_base64_details`,
`header_base64`, `address_seed`), `jwk` (iss, kid, modulus `n`), `max_epoch`, çelësin ephemeral
dhe, kur dihet, `expected_all_inputs_hash` nga fastcrypto. Për Google-in, `address_seed`
rillogaritet nga `address_seed_inputs` (salt, `sub`, `aud`) në `reference/`.

## Verifying keys (`vk/`)

| Skedari | Burimi |
|---|---|
| `zkLogin-main.vkey.json` | [sui-foundation/zklogin-ceremony-contributions](https://github.com/sui-foundation/zklogin-ceremony-contributions) `zkLogin-main.vkey` (commit `252cec4`), identik me `mainnet_verifying_key()` në sui-crypto |
| `zkLogin-test.vkey.json` | i njëjti repo, `zkLogin-test.vkey`, identik me `dev_verifying_key()` në sui-crypto |
| `zkLogin-dev-v2.vkey.json` | ndërtuar nga konstantet e `dev_verifying_key_v2()` në sui-crypto 0.4.0 (format snarkjs) |

`cargo run -p vk-convert` i konverton në `programs/zklogin-verifier/src/vk/*.rs` (Detyra 3).
