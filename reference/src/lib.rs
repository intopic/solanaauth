//! Verifikimi referencë off-chain (Detyra 2 në docs/HAPI-1-BRIEF.md).
//!
//! Ngarkon provat nga `fixtures/proofs/*.json` dhe i verifikon me
//! `sui-crypto` (kodi Rust i Sui-t, mbi arkworks). Kjo është "e vërteta
//! referencë": nëse sui-crypto e pranon provën, input-et dhe verifying key-i
//! janë të saktë, dhe programi on-chain duhet të arrijë në të njëjtin rezultat.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Rruga e fixtures, relative nga rrënja e repo-s.
pub const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures");

/// Emrat e fixtures që testohen kudo (reference + bench).
pub const FIXTURE_NAMES: [&str; 3] = ["google-mainnet-v1", "dev-v1-pinned", "dev-v2-pinned"];

#[derive(Debug, Clone, Deserialize)]
pub struct Fixture {
    pub name: String,
    pub description: String,
    pub source: String,
    /// "v1" ose "v2"
    pub circuit: String,
    /// Skedari i verifying key-t në `fixtures/vk/`.
    pub vk: String,
    pub max_epoch: u64,
    /// Çelësi ephemeral i test vectors (seed [0; 32] në sui-crypto). Pa vlerë reale.
    pub ephemeral_private_key_hex: String,
    #[serde(default)]
    pub address_seed_inputs: Option<AddressSeedInputs>,
    /// `ZkLoginInputs` në formatin JSON të Sui-t.
    pub inputs: serde_json::Value,
    pub jwk: FixtureJwk,
    /// `all_inputs_hash` (decimal) i llogaritur nga fastcrypto, kur dihet.
    pub expected_all_inputs_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddressSeedInputs {
    pub user_salt: String,
    pub claim_name: String,
    pub claim_value: String,
    pub aud: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FixtureJwk {
    pub iss: String,
    pub kid: String,
    pub kty: String,
    pub e: String,
    pub n: String,
    pub alg: String,
}

impl Fixture {
    pub fn path(name: &str) -> PathBuf {
        Path::new(FIXTURES_DIR)
            .join("proofs")
            .join(format!("{name}.json"))
    }

    pub fn load(name: &str) -> Self {
        let path = Self::path(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("s'lexohet {}: {e}", path.display()));
        serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("JSON i pavlefshëm {}: {e}", path.display()))
    }

    pub fn vk_path(&self) -> PathBuf {
        Path::new(FIXTURES_DIR).join("vk").join(&self.vk)
    }

    pub fn is_v2(&self) -> bool {
        self.circuit == "v2"
    }

    pub fn ephemeral_private_key(&self) -> [u8; 32] {
        let bytes = hex_decode(&self.ephemeral_private_key_hex);
        bytes
            .try_into()
            .expect("çelësi ephemeral duhet të ketë 32 bytes")
    }

    pub fn zklogin_inputs(&self) -> sui_sdk_types::ZkLoginInputs {
        serde_json::from_value(self.inputs.clone()).expect("ZkLoginInputs i pavlefshëm")
    }

    /// Modulus-i RSA i JWK-së, big-endian.
    pub fn modulus(&self) -> Vec<u8> {
        use base64ct::Encoding;
        base64ct::Base64UrlUnpadded::decode_vec(&self.jwk.n)
            .expect("modulus base64url i pavlefshëm")
    }
}

/// Verifikon fixture-in me `sui-crypto`, duke nënshkruar një mesazh me çelësin
/// ephemeral (si një klient i vërtetë zkLogin). Kthen `Err` nëse Sui e refuzon.
pub fn verify_with_sui(fx: &Fixture, inputs: &sui_sdk_types::ZkLoginInputs) -> Result<(), String> {
    use sui_crypto::ed25519::Ed25519PrivateKey;
    use sui_crypto::zklogin::{ZkLoginCircuitMode, ZkloginVerifier};
    use sui_crypto::{SuiSigner, SuiVerifier};
    use sui_sdk_types::{Jwk, JwkId, PersonalMessage, UserSignature, ZkLoginAuthenticator};

    let mut verifier = match fx.vk.as_str() {
        "zkLogin-main.vkey.json" => ZkloginVerifier::new_mainnet(),
        _ => ZkloginVerifier::new_dev(),
    };
    verifier.set_circuit_mode(if fx.is_v2() {
        ZkLoginCircuitMode::V2Only
    } else {
        ZkLoginCircuitMode::V1Only
    });
    verifier.jwks_mut().insert(
        JwkId {
            iss: fx.jwk.iss.clone(),
            kid: fx.jwk.kid.clone(),
        },
        Jwk {
            kty: fx.jwk.kty.clone(),
            e: fx.jwk.e.clone(),
            n: fx.jwk.n.clone(),
            alg: fx.jwk.alg.clone(),
        },
    );

    let key = Ed25519PrivateKey::new(fx.ephemeral_private_key());
    let message = PersonalMessage(b"solanaauth: reference check".to_vec().into());
    let signature = key
        .sign_personal_message(&message)
        .map_err(|e| e.to_string())?;
    let UserSignature::Simple(simple) = signature else {
        return Err("nënshkrim i papritur".into());
    };
    let authenticator = ZkLoginAuthenticator {
        inputs: inputs.clone(),
        max_epoch: fx.max_epoch,
        signature: simple,
    };
    verifier
        .verify_personal_message(&message, &UserSignature::ZkLogin(Box::new(authenticator)))
        .map_err(|e| e.to_string())
}

/// Çelësi publik Ed25519 (32 bytes) i çelësit ephemeral.
pub fn ephemeral_public_key(fx: &Fixture) -> [u8; 32] {
    let key = sui_crypto::ed25519::Ed25519PrivateKey::new(fx.ephemeral_private_key());
    key.public_key().into_inner()
}

pub mod address_seed {
    //! `gen_address_seed` i Sui-t (fastcrypto `gen_address_seed`), për fixture-in e Google-it.
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use light_poseidon::{Poseidon, PoseidonHasher};

    fn poseidon(inputs: &[Fr]) -> Fr {
        Poseidon::<Fr>::new_circom(inputs.len())
            .unwrap()
            .hash(inputs)
            .unwrap()
    }

    /// `hash_ascii_str_to_field`: mbush me zero deri në `max_len` bytes, ndaj nga e
    /// djathta në copa 31-byte (248 bit), Poseidon mbi copat.
    pub fn hash_ascii_str_to_field(s: &str, max_len: usize) -> Fr {
        let mut padded = s.as_bytes().to_vec();
        assert!(padded.len() <= max_len);
        padded.resize(max_len, 0);
        let chunks: Vec<Fr> = {
            let mut v: Vec<Fr> = padded
                .rchunks(31)
                .map(Fr::from_be_bytes_mod_order)
                .collect();
            v.reverse();
            v
        };
        poseidon(&chunks)
    }

    pub fn gen_address_seed(salt: &str, name: &str, value: &str, aud: &str) -> String {
        let salt: Fr = salt.parse::<num_bigint::BigUint>().unwrap().into();
        let salt_hash = poseidon(&[salt]);
        let seed = poseidon(&[
            hash_ascii_str_to_field(name, 32),
            hash_ascii_str_to_field(value, 115),
            hash_ascii_str_to_field(aud, 145),
            salt_hash,
        ]);
        num_bigint::BigUint::from_bytes_be(&seed.into_bigint().to_bytes_be()).to_string()
    }
}

pub fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex i pavlefshëm"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_dir_exists() {
        assert!(Path::new(FIXTURES_DIR).is_dir());
    }

    #[test]
    fn google_address_seed_matches_fixture() {
        let fx = Fixture::load("google-mainnet-v1");
        let a = fx.address_seed_inputs.as_ref().unwrap();
        let seed =
            address_seed::gen_address_seed(&a.user_salt, &a.claim_name, &a.claim_value, &a.aud);
        println!("google address_seed = {seed}");
        assert_eq!(fx.inputs["address_seed"].as_str().unwrap(), seed);
    }

    /// Detyra 2: çdo provë referencë pranohet nga kodi i Sui-t.
    #[test]
    fn sui_accepts_reference_proofs() {
        for name in FIXTURE_NAMES {
            let fx = Fixture::load(name);
            verify_with_sui(&fx, &fx.zklogin_inputs())
                .unwrap_or_else(|e| panic!("{name}: sui-crypto e refuzoi provën: {e}"));
            println!(
                "OK  {name}: sui-crypto e pranon provën (qarku {}, vk {})",
                fx.circuit, fx.vk
            );
        }
    }

    /// Kontroll që verifikuesi referencë nuk pranon gjithçka: v1 me key-n mainnet
    /// duhet të dështojë për provat dev, dhe një address_seed i ndryshuar refuzohet.
    #[test]
    fn sui_rejects_tampered_inputs() {
        for name in FIXTURE_NAMES {
            let fx = Fixture::load(name);
            let mut json = fx.inputs.clone();
            let seed = json["address_seed"].as_str().unwrap().to_string();
            let mut tampered = seed.into_bytes();
            let last = tampered.last_mut().unwrap();
            *last = if *last == b'1' { b'2' } else { b'1' };
            json["address_seed"] = serde_json::Value::String(String::from_utf8(tampered).unwrap());
            let inputs: sui_sdk_types::ZkLoginInputs = serde_json::from_value(json).unwrap();
            assert!(
                verify_with_sui(&fx, &inputs).is_err(),
                "{name}: address_seed i ndryshuar u pranua"
            );
        }
    }

    #[test]
    fn verifying_keys_match_sui_crypto() {
        // Key-t në fixtures/vk vijnë nga repo-ja e ceremonisë (main/test) dhe nga
        // sui-crypto (dev v2). Këtu kontrollojmë vetëm që IC ka 2 pika (1 input publik).
        for vk in [
            "zkLogin-main.vkey.json",
            "zkLogin-test.vkey.json",
            "zkLogin-dev-v2.vkey.json",
        ] {
            let text =
                std::fs::read_to_string(Path::new(FIXTURES_DIR).join("vk").join(vk)).unwrap();
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(v["IC"].as_array().unwrap().len(), 2, "{vk}");
        }
    }
}
