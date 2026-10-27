//! zklogin-verifier: programi minimal i Hapit 1.
//!
//! Verifikon në Solana një provë zkLogin (Groth16 mbi BN254, nga qarku i Sui-t) me
//! `groth16-solana` (syscall-et alt_bn128) dhe rillogarit input-in publik me
//! `sol_poseidon`. Nuk ka llogari dhe nuk ruan gjendje: qëllimi është vetëm matja e CU.
//!
//! # Formati i instruksionit
//!
//! Byte-i i parë: `op | TRACE` ku `TRACE = 0x80` shton `sol_log_compute_units` pas çdo hapi.
//!
//! | op | instruksioni          | payload |
//! |----|-----------------------|---------|
//! | 0  | `verify_proof`        | `vk_id u8, proof [256], public_input [32]` |
//! | 1  | `verify_full`         | `vk_id u8, proof [256], zklogin_inputs` |
//! | 2  | `compute_inputs_hash` | `vk_id u8, proof [256], zklogin_inputs` (pa Groth16; log-on hash-in) |
//!
//! `proof` = `A (64) || B (128) || C (64)`, big endian, B me koordinatat G2 në renditjen
//! `x.c1, x.c0, y.c1, y.c0` (EIP-197). A dërgohet ashtu siç e jep prover-i; programi e
//! neg-on vetë.
//!
//! `zklogin_inputs` = `eph_pubkey [32], max_epoch u64 LE, address_seed [32], index_mod_4 u8,
//! iss_len u8, iss, header_len u16 LE, header_base64, modulus_kind u8` dhe pastaj
//! `modulus_len u16 LE, modulus` (kind 0) ose `modulus_hash [32], modulus_bits u16 LE` (kind 1,
//! modulus i para-llogaritur si nga një JWK registry).

pub mod inputs;
pub mod vk;

use groth16_solana::groth16::{negate_g1_be, Groth16Verifier};
use inputs::{Fe, InputError, Modulus, Step, ZkLoginPublicInputs};
use pinocchio::error::ProgramError;
use vk::VkId;

pub const OP_VERIFY_PROOF: u8 = 0;
pub const OP_VERIFY_FULL: u8 = 1;
pub const OP_COMPUTE_INPUTS_HASH: u8 = 2;
pub const TRACE: u8 = 0x80;

pub const PROOF_LEN: usize = 256;

/// Kodet e gabimeve (`ProgramError::Custom`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum VerifierError {
    InvalidInstruction = 1,
    UnknownVk = 2,
    /// Prova u refuzua nga verifikuesi Groth16.
    ProofRejected = 3,
    PublicInputNotCanonical = 4,
    HeaderTooLong = 10,
    IssTooLong = 11,
    ModulusTooLong = 12,
    AddressSeedNotCanonical = 13,
    TooManyPoseidonInputs = 14,
    Poseidon = 15,
}

impl From<VerifierError> for ProgramError {
    fn from(e: VerifierError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

impl From<InputError> for VerifierError {
    fn from(e: InputError) -> Self {
        match e {
            InputError::HeaderTooLong => VerifierError::HeaderTooLong,
            InputError::IssTooLong => VerifierError::IssTooLong,
            InputError::ModulusTooLong => VerifierError::ModulusTooLong,
            InputError::NonCanonicalAddressSeed => VerifierError::AddressSeedNotCanonical,
            InputError::TooManyPoseidonInputs => VerifierError::TooManyPoseidonInputs,
            InputError::Poseidon => VerifierError::Poseidon,
        }
    }
}

/// Lexues i thjeshtë i payload-it.
struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], VerifierError> {
        if self.data.len() < n {
            return Err(VerifierError::InvalidInstruction);
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], VerifierError> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    fn u8(&mut self) -> Result<u8, VerifierError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, VerifierError> {
        Ok(u16::from_le_bytes(*self.array::<2>()?))
    }

    fn u64(&mut self) -> Result<u64, VerifierError> {
        Ok(u64::from_le_bytes(*self.array::<8>()?))
    }

    fn finish(&self) -> Result<(), VerifierError> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(VerifierError::InvalidInstruction)
        }
    }
}

pub struct Proof<'a> {
    pub a: &'a [u8; 64],
    pub b: &'a [u8; 128],
    pub c: &'a [u8; 64],
}

fn read_proof<'a>(r: &mut Reader<'a>) -> Result<Proof<'a>, VerifierError> {
    Ok(Proof {
        a: r.array()?,
        b: r.array()?,
        c: r.array()?,
    })
}

fn read_zklogin_inputs<'a>(
    r: &mut Reader<'a>,
    vk: VkId,
) -> Result<ZkLoginPublicInputs<'a>, VerifierError> {
    let eph_pubkey = r.array()?;
    let max_epoch = r.u64()?;
    let address_seed = r.array()?;
    let index_mod_4 = r.u8()?;
    let iss_len = r.u8()? as usize;
    let iss = r.take(iss_len)?;
    let header_len = r.u16()? as usize;
    let header_base64 = r.take(header_len)?;
    let modulus = match r.u8()? {
        0 => {
            let len = r.u16()? as usize;
            Modulus::Full(r.take(len)?)
        }
        1 => Modulus::Precomputed {
            hash: r.array()?,
            num_bits: r.u16()?,
        },
        _ => return Err(VerifierError::InvalidInstruction),
    };
    Ok(ZkLoginPublicInputs {
        circuit: vk.circuit(),
        eph_pubkey,
        max_epoch,
        address_seed,
        iss,
        index_mod_4,
        header_base64,
        modulus,
    })
}

/// Verifikimi Groth16 me 1 input publik. A neg-ohet këtu (shih Kurthet në brief).
pub fn verify_groth16(proof: &Proof<'_>, public_input: &Fe, vk: VkId) -> Result<(), VerifierError> {
    if !inputs::is_canonical(public_input) {
        return Err(VerifierError::PublicInputNotCanonical);
    }
    let neg_a = negate_g1_be(proof.a);
    let public_inputs = [*public_input];
    let mut verifier =
        Groth16Verifier::<1>::new(&neg_a, proof.b, proof.c, &public_inputs, vk.key())
            .map_err(|_| VerifierError::ProofRejected)?;
    verifier.verify().map_err(|_| VerifierError::ProofRejected)
}

/// Logjika e programit, e pavarur nga entrypoint-i (ekzekutohet edhe në host për teste).
pub fn process(data: &[u8]) -> Result<(), VerifierError> {
    let (&tag, payload) = data
        .split_first()
        .ok_or(VerifierError::InvalidInstruction)?;
    let trace = tag & TRACE != 0;
    let op = tag & !TRACE;
    let mut r = Reader { data: payload };
    let vk = VkId::from_u8(r.u8()?).ok_or(VerifierError::UnknownVk)?;
    let proof = read_proof(&mut r)?;

    match op {
        OP_VERIFY_PROOF => {
            let public_input = r.array::<32>()?;
            r.finish()?;
            if trace {
                log::compute_units();
            }
            verify_groth16(&proof, public_input, vk)?;
            if trace {
                log::compute_units();
            }
            Ok(())
        }
        OP_VERIFY_FULL | OP_COMPUTE_INPUTS_HASH => {
            let zk = read_zklogin_inputs(&mut r, vk)?;
            r.finish()?;
            if trace {
                log::compute_units();
            }
            let hash = inputs::all_inputs_hash(&zk, |_step: Step| {
                if trace {
                    log::compute_units();
                }
            })
            .map_err(VerifierError::from)?;
            if op == OP_COMPUTE_INPUTS_HASH {
                log::data(&[&hash]);
                return Ok(());
            }
            verify_groth16(&proof, &hash, vk)?;
            if trace {
                log::compute_units();
            }
            Ok(())
        }
        _ => Err(VerifierError::InvalidInstruction),
    }
}

/// Log-et on-chain; jashtë Solana-s nuk bëjnë asgjë.
pub mod log {
    #[inline(always)]
    pub fn compute_units() {
        #[cfg(target_os = "solana")]
        unsafe {
            pinocchio::syscalls::sol_log_compute_units_()
        };
    }

    #[inline(always)]
    pub fn data(_fields: &[&[u8]]) {
        #[cfg(target_os = "solana")]
        unsafe {
            pinocchio::syscalls::sol_log_data(_fields.as_ptr() as *const u8, _fields.len() as u64)
        };
    }
}

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    use pinocchio::{entrypoint, AccountView, Address, ProgramResult};

    entrypoint!(process_instruction);

    fn process_instruction(
        _program_id: &Address,
        _accounts: &[AccountView],
        instruction_data: &[u8],
    ) -> ProgramResult {
        crate::process(instruction_data).map_err(Into::into)
    }
}
