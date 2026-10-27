//! Blloku i provës zkLogin në instruksione dhe verifikimi i tij kundër JWK registry.
//!
//! Formati (little endian):
//! `vk u8 (0 = main, 1 = test), proof [256], max_epoch u64, address_seed [32], index_mod_4 u8,
//! iss_len u8, iss_base64, header_len u16, header_base64`.
//!
//! `eph_pubkey` nuk dërgohet: është adresa e llogarisë `session_key`, e cila duhet të nënshkruajë.
//! Hash-i i modulus-it merret vetëm nga llogaria JWK.

use pinocchio::{AccountView, Address};
use zklogin_verifier::inputs::{all_inputs_hash, Circuit, Modulus, Step, ZkLoginPublicInputs};
use zklogin_verifier::vk::VkId;
use zklogin_verifier::{verify_groth16, Proof, PROOF_LEN};

use crate::error::{AuthError, Result};
use crate::iss::{decode_claim, iss_value, MAX_ISS_B64};
use crate::state::{Config, Jwk, DOMAIN_ZK, SEED_JWK};
use crate::util::{derive_pda, require_signer, sha256, Account, Reader};

pub struct ZkBlock<'a> {
    pub vk_test: bool,
    pub proof: &'a [u8; PROOF_LEN],
    pub max_epoch: u64,
    pub address_seed: &'a [u8; 32],
    pub index_mod_4: u8,
    pub iss_b64: &'a [u8],
    pub header: &'a [u8],
}

impl<'a> ZkBlock<'a> {
    pub fn read(r: &mut Reader<'a>) -> Result<Self> {
        let vk_test = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(AuthError::InvalidInstruction.into()),
        };
        let proof = r.array()?;
        let max_epoch = r.u64()?;
        let address_seed = r.array()?;
        let index_mod_4 = r.u8()?;
        let iss_len = r.u8()? as usize;
        let iss_b64 = r.take(iss_len)?;
        let header_len = r.u16()? as usize;
        let header = r.take(header_len)?;
        Ok(ZkBlock {
            vk_test,
            proof,
            max_epoch,
            address_seed,
            index_mod_4,
            iss_b64,
            header,
        })
    }
}

/// Rezultati i një prove të vlefshme.
pub struct Verified {
    pub identity: [u8; 32],
    /// `max_epoch` si timestamp Unix (D2).
    pub expires_at: i64,
}

/// Verifikon provën: JWK aktiv dhe i lëshuesit të saktë, skadimi, Groth16. `session_key` është
/// çelësi ephemeral i lidhur në provë dhe duhet të jetë nënshkrues.
pub fn verify(
    zk: &ZkBlock<'_>,
    session_key: &AccountView,
    config: &Config,
    jwk_view: &AccountView,
    now: i64,
    program_id: &Address,
) -> Result<Verified> {
    require_signer(session_key)?;

    let vk = if zk.vk_test {
        if cfg!(feature = "mainnet") || config.allow_test_vk == 0 {
            return Err(AuthError::TestVkNotAllowed.into());
        }
        VkId::DevV1
    } else {
        VkId::Mainnet
    };

    // iss: copa base64 → `"iss":"<vlera>",` → vlera.
    let mut claim = [0u8; MAX_ISS_B64];
    let n =
        decode_claim(zk.iss_b64, zk.index_mod_4, &mut claim).map_err(|_| AuthError::InvalidIss)?;
    let iss = iss_value(&claim[..n]).map_err(|_| AuthError::InvalidIss)?;

    // JWK: PDA e saktë, e programit, e lëshuesit të njëjtë, aktive tani.
    Jwk::check(jwk_view, program_id)?;
    let data = jwk_view.try_borrow()?;
    let jwk = Jwk::from_bytes(&data)?;
    let expected = derive_pda(
        &[SEED_JWK, &jwk.iss_hash, &jwk.kid_hash],
        jwk.bump,
        program_id,
    );
    if jwk_view.address() != &expected {
        return Err(AuthError::InvalidAccount.into());
    }
    if jwk.iss_hash != sha256(&[iss]) {
        return Err(AuthError::IssMismatch.into());
    }
    if !jwk.is_active(now) {
        return Err(AuthError::JwkNotActive.into());
    }

    // Skadimi (D2): now < max_epoch <= now + max_session_secs.
    let max_epoch = i64::try_from(zk.max_epoch).map_err(|_| AuthError::ProofTooLong)?;
    if max_epoch <= now {
        return Err(AuthError::ProofExpired.into());
    }
    if max_epoch > now.saturating_add(config.max_session_secs.get()) {
        return Err(AuthError::ProofTooLong.into());
    }

    let eph_pubkey: &[u8; 32] = session_key.address().as_array();
    let inputs = ZkLoginPublicInputs {
        circuit: Circuit::V1,
        eph_pubkey,
        max_epoch: zk.max_epoch,
        address_seed: zk.address_seed,
        iss: zk.iss_b64,
        index_mod_4: zk.index_mod_4,
        header_base64: zk.header,
        modulus: Modulus::Precomputed {
            hash: &jwk.active.modulus_hash,
            num_bits: jwk.active.modulus_bits.get(),
        },
    };
    let hash = all_inputs_hash(&inputs, |_: Step| {}).map_err(AuthError::from)?;
    let proof = Proof {
        a: zk.proof[0..64].try_into().unwrap(),
        b: zk.proof[64..192].try_into().unwrap(),
        c: zk.proof[192..256].try_into().unwrap(),
    };
    verify_groth16(&proof, &hash, vk).map_err(|_| AuthError::ProofRejected)?;

    Ok(Verified {
        identity: identity(iss, zk.address_seed),
        expires_at: max_epoch,
    })
}

pub fn identity(iss: &[u8], address_seed: &[u8; 32]) -> [u8; 32] {
    sha256(&[DOMAIN_ZK, iss, address_seed])
}
