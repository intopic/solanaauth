## Matjet e CU — zklogin-verifier

**Vendimi:** GO — `verify_full` (JWT e vërtetë Google, key mainnet, qarku v1) = **110,428 CU** nga limiti 1,400,000 CU i transaksionit.

### `google-mainnet-v1`

JWT e vërtetë nga Google (accounts.google.com), provë e verifikuar me verifying key-n MAINNET të ceremonisë (qarku v1). Burimi: sui-crypto verify.rs::test_verify_zklogin_google.

| Matja | CU | Tx (bytes) | Shënim |
|---|---:|---:|---|
| `verify_proof` | 78,368 | 500 | Groth16 me groth16-solana (input-i publik jepet gati) |
| ↳ Groth16 (pa parsimin) | 78,321 |  | neg(A) + MSM me 1 input + pairing me 4 çifte |
| **`verify_full`** | 110,428 | 954 | **Poseidon (me modulus-in e plotë) + Groth16, kriteri GO/NO-GO** |
| ↳ Poseidon: header (8 input-e) | 8,328 |  | 248 bytes → 8 copa × 31 |
| ↳ Poseidon: iss (8 input-e) | 7,844 |  | 224 bytes → 8 copa |
| ↳ Poseidon: modulus RSA (9 input-e) | 11,083 |  | 2048 bit → 9 copa; kandidat për JWK registry |
| ↳ Poseidon: all_inputs_hash (8 input-e) | 4,706 |  | input-i i vetëm publik i qarkut |
| ↳ Groth16 | 78,360 |  |  |
| ↳ Poseidon gjithsej (4 thirrje) | 31,961 |  |  |
| `verify_full` (modulus i para-llogaritur) | 99,356 | 730 | hash-i i modulus-it si nga një llogari JWK registry |
| ↳ Poseidon gjithsej (3 thirrje) | 20,878 |  | header + iss + all_inputs_hash |

### `dev-v1-pinned`

Provë nga prover-dev (qarku v1) mbi një JWT testi (oauth.sui.io), verifying key TEST i ceremonisë. Burimi: sui-crypto tests.rs::pinned_circuit_proof_material.

| Matja | CU | Tx (bytes) | Shënim |
|---|---:|---:|---|
| `verify_proof` | 78,367 | 500 | Groth16 me groth16-solana (input-i publik jepet gati) |
| ↳ Groth16 (pa parsimin) | 78,320 |  | neg(A) + MSM me 1 input + pairing me 4 çifte |
| **`verify_full`** | 110,280 | 905 | **Poseidon (me modulus-in e plotë) + Groth16, kriteri GO/NO-GO** |
| ↳ Poseidon: header (8 input-e) | 8,208 |  | 248 bytes → 8 copa × 31 |
| ↳ Poseidon: iss (8 input-e) | 7,817 |  | 224 bytes → 8 copa |
| ↳ Poseidon: modulus RSA (9 input-e) | 11,083 |  | 2048 bit → 9 copa; kandidat për JWK registry |
| ↳ Poseidon: all_inputs_hash (8 input-e) | 4,706 |  | input-i i vetëm publik i qarkut |
| ↳ Groth16 | 78,359 |  |  |
| ↳ Poseidon gjithsej (4 thirrje) | 31,814 |  |  |
| `verify_full` (modulus i para-llogaritur) | 99,208 | 681 | hash-i i modulus-it si nga një llogari JWK registry |
| ↳ Poseidon gjithsej (3 thirrje) | 20,731 |  | header + iss + all_inputs_hash |

### `dev-v2-pinned`

Provë nga prover-dev-v2 (qarku v2) mbi një JWT nga jwt-tester.mystenlabs.com me çelës RSA 8192-bit; verifying key dev v2 (zklogin-circuits v2-main). Burimi: sui-crypto tests.rs::pinned_circuit_proof_material.

| Matja | CU | Tx (bytes) | Shënim |
|---|---:|---:|---|
| `verify_proof` | 78,370 | 500 | Groth16 me groth16-solana (input-i publik jepet gati) |
| ↳ Groth16 (pa parsimin) | 78,323 |  | neg(A) + MSM me 1 input + pairing me 4 çifte |
| `verify_full` (modulus i plotë) | — | 1681 | s'mbështetet: 8192 bit → 34 copa, Sui përdor Poseidon me 16 input-e, `sol_poseidon` pranon ≤ 12; tx 1681 > 1232 bytes |
| `verify_full` (modulus i para-llogaritur) | 98,427 | 689 | hash-i i modulus-it si nga një llogari JWK registry |
| ↳ Poseidon gjithsej (3 thirrje) | 19,948 |  | header + iss + all_inputs_hash |

### Testet negative: 28/28 të refuzuara

| Fixture | Ndryshimi | Rezultati |
|---|---|---|
| `google-mainnet-v1` | verify_proof: 1 byte në A | refuzohet ✅ (Custom(3)) |
| `google-mainnet-v1` | verify_proof: 1 byte në B | refuzohet ✅ (Custom(3)) |
| `google-mainnet-v1` | verify_proof: 1 byte në C | refuzohet ✅ (Custom(3)) |
| `google-mainnet-v1` | verify_proof: 1 byte në input-in publik | refuzohet ✅ (Custom(3)) |
| `google-mainnet-v1` | verify_proof: verifying key tjetër (main ↔ test) | refuzohet ✅ (Custom(3)) |
| `google-mainnet-v1` | verify_full: 1 byte në provë (A) | refuzohet ✅ (Custom(3)) |
| `google-mainnet-v1` | verify_full: 1 byte në provë (C) | refuzohet ✅ (Custom(3)) |
| `google-mainnet-v1` | verify_full: 1 byte në çelësin ephemeral | refuzohet ✅ (Custom(3)) |
| `google-mainnet-v1` | verify_full: max_epoch + 1 | refuzohet ✅ (Custom(3)) |
| `google-mainnet-v1` | verify_full: 1 byte në address_seed | refuzohet ✅ (Custom(3)) |
| `google-mainnet-v1` | verify_full: 1 byte në iss | refuzohet ✅ (Custom(3)) |
| `google-mainnet-v1` | verify_full: index_mod_4 tjetër | refuzohet ✅ (Custom(3)) |
| `google-mainnet-v1` | verify_full: 1 byte në header | refuzohet ✅ (Custom(3)) |
| `google-mainnet-v1` | verify_full: 1 byte në modulus-in RSA | refuzohet ✅ (Custom(3)) |
| `dev-v1-pinned` | verify_proof: 1 byte në A | refuzohet ✅ (Custom(3)) |
| `dev-v1-pinned` | verify_proof: 1 byte në B | refuzohet ✅ (Custom(3)) |
| `dev-v1-pinned` | verify_proof: 1 byte në C | refuzohet ✅ (Custom(3)) |
| `dev-v1-pinned` | verify_proof: 1 byte në input-in publik | refuzohet ✅ (Custom(3)) |
| `dev-v1-pinned` | verify_proof: verifying key tjetër (main ↔ test) | refuzohet ✅ (Custom(3)) |
| `dev-v1-pinned` | verify_full: 1 byte në provë (A) | refuzohet ✅ (Custom(3)) |
| `dev-v1-pinned` | verify_full: 1 byte në provë (C) | refuzohet ✅ (Custom(3)) |
| `dev-v1-pinned` | verify_full: 1 byte në çelësin ephemeral | refuzohet ✅ (Custom(3)) |
| `dev-v1-pinned` | verify_full: max_epoch + 1 | refuzohet ✅ (Custom(3)) |
| `dev-v1-pinned` | verify_full: 1 byte në address_seed | refuzohet ✅ (Custom(3)) |
| `dev-v1-pinned` | verify_full: 1 byte në iss | refuzohet ✅ (Custom(3)) |
| `dev-v1-pinned` | verify_full: index_mod_4 tjetër | refuzohet ✅ (Custom(3)) |
| `dev-v1-pinned` | verify_full: 1 byte në header | refuzohet ✅ (Custom(3)) |
| `dev-v1-pinned` | verify_full: 1 byte në modulus-in RSA | refuzohet ✅ (Custom(3)) |

### Shënime

- CU = njësitë e konsumuara nga instruksioni i programit në LiteSVM ("Program … consumed N"); limiti i kërkuar me `SetComputeUnitLimit(1400000)`.
- Hapat (↳) maten me `sol_log_compute_units` në një ekzekutim të veçantë me flamurin TRACE; nga çdo diferencë zbritet kostoja e thirrjes së log-ut (100 CU).
- Tx (bytes) = transaksioni i plotë i serializuar: 1 nënshkrim + `SetComputeUnitLimit` + instruksioni; limiti 1232 bytes.
- Hash-i `all_inputs_hash` i rillogaritur në SVM (`compute_inputs_hash`, `sol_log_data`) përputhet bit për bit me sui-crypto/fastcrypto për të tri provat.
- Kodet e gabimeve: Custom(3) = prova u refuzua nga Groth16, Custom(4) = input publik jashtë fushës.

<sub>program.so sha256: `65cbb7790d1860a24ec905c329feea7825287e6371fb49a6370b2e18dda3add2` · svm: `litesvm 0.17.0 (Agave 4.x feature set)` · commit: `d13615e7a7ce2f3ca01800d1f8bd3ecb366913d8` · solana: `solana-cli 4.3.2 (src:92555e42; feat:c9ad34d2, client:Agave)`</sub>
