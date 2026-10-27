//! Testet në host (pa SVM): i njëjti kod i programit, i kompiluar për x86, kundër
//! së vërtetës referencë. Këtu kapen gabimet e formatit (endianness, G2, key)
//! para se të shkojmë te `.so`.

use bench::{be32_to_dec, offchain_modulus_hash, Case, ModulusMode};
use reference::FIXTURE_NAMES;
use zklogin_verifier::inputs::{self, Circuit, InputError};
use zklogin_verifier::{process, verify_groth16, VerifierError};

#[test]
fn all_inputs_hash_matches_fastcrypto_bit_for_bit() {
    for name in FIXTURE_NAMES {
        let case = Case::load(name);
        let hash = case.all_inputs_hash();
        println!("{name}: all_inputs_hash = {}", be32_to_dec(&hash));
        if let Some(expected) = &case.fx.expected_all_inputs_hash {
            assert_eq!(
                &be32_to_dec(&hash),
                expected,
                "{name}: hash ndryshon nga fastcrypto"
            );
        }
        if case.vk.circuit() == Circuit::V1 {
            // Rruga on-chain (modulus i plotë) jep të njëjtin rezultat.
            let full =
                inputs::all_inputs_hash(&case.public_inputs(ModulusMode::Full), |_| {}).unwrap();
            assert_eq!(full, hash, "{name}");
        }
    }
}

#[test]
fn modulus_hash_two_implementations_agree() {
    for name in ["google-mainnet-v1", "dev-v1-pinned"] {
        let case = Case::load(name);
        let onchain = inputs::hash_modulus(&case.modulus, 256).unwrap();
        assert_eq!(onchain, offchain_modulus_hash(&case.modulus, 256), "{name}");
    }
}

#[test]
fn v2_full_modulus_needs_more_than_12_poseidon_inputs() {
    let case = Case::load("dev-v2-pinned");
    assert_eq!(case.modulus.len(), 1024);
    let err = inputs::all_inputs_hash(&case.public_inputs(ModulusMode::Full), |_| {}).unwrap_err();
    assert_eq!(err, InputError::TooManyPoseidonInputs);
}

#[test]
fn groth16_solana_accepts_converted_proofs() {
    for name in FIXTURE_NAMES {
        let case = Case::load(name);
        let proof = zklogin_verifier::Proof {
            a: case.proof[0..64].try_into().unwrap(),
            b: case.proof[64..192].try_into().unwrap(),
            c: case.proof[192..256].try_into().unwrap(),
        };
        verify_groth16(&proof, &case.all_inputs_hash(), case.vk)
            .unwrap_or_else(|e| panic!("{name}: groth16-solana e refuzoi provën: {e:?}"));
    }
}

#[test]
fn process_accepts_valid_instructions() {
    for name in FIXTURE_NAMES {
        let case = Case::load(name);
        let hash = case.all_inputs_hash();
        process(&case.ix_verify_proof(&case.proof, &hash, false)).unwrap();
        process(&case.ix_verify_full(
            &case.public_inputs(ModulusMode::Precomputed),
            &case.proof,
            false,
        ))
        .unwrap();
        if case.vk.circuit() == Circuit::V1 {
            process(&case.ix_verify_full(
                &case.public_inputs(ModulusMode::Full),
                &case.proof,
                true,
            ))
            .unwrap();
        } else {
            assert_eq!(
                process(&case.ix_verify_full(
                    &case.public_inputs(ModulusMode::Full),
                    &case.proof,
                    false
                )),
                Err(VerifierError::TooManyPoseidonInputs)
            );
        }
    }
}

#[test]
fn process_rejects_tampered_instructions() {
    for (name, c) in bench::negative::cases() {
        let res = process(&c.data);
        assert!(res.is_err(), "{name}: '{}' u pranua", c.label);
    }
}
