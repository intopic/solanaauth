//! Rillogaritja e input-it publik të qarkut zkLogin (`all_inputs_hash`).
//!
//! E njëjta logjikë si `calculate_all_inputs_hash` në fastcrypto-zkp / sui-crypto,
//! por pa heap dhe me `sol_poseidon` (përmes `solana-poseidon`; jashtë Solana-s
//! i njëjti kod përdor `light-poseidon`). Të gjitha elementet e fushës janë
//! 32 bytes big endian.
//!
//! Qarku v1 (Sui mainnet):
//! ```text
//! all_inputs_hash = Poseidon(eph_pk_0, eph_pk_1, address_seed, max_epoch,
//!                            H(iss_base64, 224), index_mod_4, H(header, 248), H(modulus, 2048 bit))
//! ```
//! Qarku v2:
//! ```text
//! all_inputs_hash = Poseidon(eph_pk_0, eph_pk_1, address_seed, max_epoch,
//!                            H(ext_iss, 186), H(header, 279), H(modulus, 8192 bit), rsa_num_bits)
//! ```
//! ku `H(x, n)` mbush `x` deri në `n` bytes, e ndan nga e djathta në copa 31-byte
//! (248 bit) dhe bën Poseidon mbi copat.

// solana-poseidon 3.x e shënon API-n si "unstable" (deprecated); syscall-i vetë është i qëndrueshëm.
#[allow(deprecated)]
use solana_poseidon::{hashv, Endianness, Parameters};

/// Element i fushës BN254 Fr, 32 bytes big endian.
pub type Fe = [u8; 32];

/// Numri maksimal i input-eve që pranon syscall-i `sol_poseidon`.
pub const MAX_POSEIDON_INPUTS: usize = 12;

/// Gjerësia e paketimit të qarkut: 248 bit = 31 bytes për element.
const PACK_BYTES: usize = 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Circuit {
    V1,
    V2,
}

impl Circuit {
    pub const fn max_header_len(self) -> usize {
        match self {
            Circuit::V1 => 248,
            Circuit::V2 => 279,
        }
    }

    /// V1: gjatësia base64 e iss (4 * (1 + 165 / 3)); V2: gjatësia e claim-it të dekoduar.
    pub const fn max_iss_len(self) -> usize {
        match self {
            Circuit::V1 => 224,
            Circuit::V2 => 186,
        }
    }

    pub const fn max_modulus_len(self) -> usize {
        match self {
            Circuit::V1 => 2048 / 8,
            Circuit::V2 => 8192 / 8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputError {
    HeaderTooLong,
    IssTooLong,
    ModulusTooLong,
    /// address_seed >= modulus-i i fushës.
    NonCanonicalAddressSeed,
    /// Hash-i kërkon më shumë se 12 input-e (p.sh. modulus 8192-bit i v2: 34 copa).
    /// `sol_poseidon` nuk e mbështet; duhet modulus i para-llogaritur (JWK registry).
    TooManyPoseidonInputs,
    Poseidon,
}

/// Modulus-i RSA i JWK-së: i plotë (hash-i llogaritet on-chain) ose i para-llogaritur
/// (si do të vinte nga një llogari "JWK registry").
#[derive(Clone, Copy, Debug)]
pub enum Modulus<'a> {
    /// Big endian, pa zero në fillim.
    Full(&'a [u8]),
    Precomputed {
        hash: &'a Fe,
        num_bits: u16,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct ZkLoginPublicInputs<'a> {
    pub circuit: Circuit,
    /// Çelësi publik Ed25519 i çelësit ephemeral.
    pub eph_pubkey: &'a [u8; 32],
    pub max_epoch: u64,
    pub address_seed: &'a Fe,
    /// V1: `iss_base64_details.value`; V2: claim-i i dekoduar (`"iss":"...",`).
    pub iss: &'a [u8],
    /// Vetëm V1.
    pub index_mod_4: u8,
    pub header_base64: &'a [u8],
    pub modulus: Modulus<'a>,
}

/// Hapat e llogaritjes, për matjen e CU (`trace` thirret pas secilit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Header,
    Iss,
    Modulus,
    Final,
}

/// Poseidon (circom, BN254, x^5) mbi 1..=12 elemente big endian.
#[allow(deprecated)]
pub fn poseidon(inputs: &[Fe]) -> Result<Fe, InputError> {
    if inputs.is_empty() || inputs.len() > MAX_POSEIDON_INPUTS {
        return Err(InputError::TooManyPoseidonInputs);
    }
    let mut refs: [&[u8]; MAX_POSEIDON_INPUTS] = [&[]; MAX_POSEIDON_INPUTS];
    for (r, fe) in refs.iter_mut().zip(inputs) {
        *r = fe;
    }
    hashv(
        Parameters::Bn254X5,
        Endianness::BigEndian,
        &refs[..inputs.len()],
    )
    .map(|h| h.to_bytes())
    .map_err(|_| InputError::Poseidon)
}

/// Paketon një buffer konceptual me gjatësi `len` (byte-i `j` jepet nga `byte_at`)
/// në copa 31-byte nga e djathta, dhe bën Poseidon mbi to.
fn hash_packed(len: usize, byte_at: impl Fn(usize) -> u8) -> Result<Fe, InputError> {
    let n = len.div_ceil(PACK_BYTES);
    if n == 0 || n > MAX_POSEIDON_INPUTS {
        return Err(InputError::TooManyPoseidonInputs);
    }
    let mut chunks = [[0u8; 32]; MAX_POSEIDON_INPUTS];
    for (k, chunk) in chunks[..n].iter_mut().enumerate() {
        let end = len - (n - 1 - k) * PACK_BYTES;
        let start = end.saturating_sub(PACK_BYTES);
        let width = end - start;
        for i in 0..width {
            chunk[32 - width + i] = byte_at(start + i);
        }
    }
    poseidon(&chunks[..n])
}

/// `hash_ascii_str_to_field`: vargu mbushet me zero në të djathtë deri në `max_len`.
pub fn hash_str_to_field(s: &[u8], max_len: usize) -> Result<Fe, InputError> {
    debug_assert!(s.len() <= max_len);
    hash_packed(max_len, |j| if j < s.len() { s[j] } else { 0 })
}

/// Hash-i i modulus-it: numri mbushet me zero në të majtë deri në `max_len` bytes.
pub fn hash_modulus(modulus: &[u8], max_len: usize) -> Result<Fe, InputError> {
    if modulus.len() > max_len {
        return Err(InputError::ModulusTooLong);
    }
    let pad = max_len - modulus.len();
    hash_packed(max_len, |j| if j < pad { 0 } else { modulus[j - pad] })
}

/// Numri i bit-eve domethënëse të modulus-it (big endian).
pub fn modulus_num_bits(modulus: &[u8]) -> u64 {
    let mut iter = modulus.iter().skip_while(|b| **b == 0);
    match iter.next() {
        Some(first) => (8 - first.leading_zeros()) as u64 + iter.count() as u64 * 8,
        None => 0,
    }
}

fn fe_from_u64(v: u64) -> Fe {
    let mut fe = [0u8; 32];
    fe[24..].copy_from_slice(&v.to_be_bytes());
    fe
}

/// Ndan `flag || pk` (33 bytes, flag 0x00 = Ed25519) në dy elemente: 17 bytes të parët
/// dhe 16 të fundit, si `public_key_to_frs` në Sui.
pub fn eph_pubkey_to_fes(pk: &[u8; 32]) -> (Fe, Fe) {
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    // first[15] = 0x00 (flag Ed25519), first[16..] = pk[..16]
    first[16..].copy_from_slice(&pk[..16]);
    second[16..].copy_from_slice(&pk[16..]);
    (first, second)
}

pub fn is_canonical(fe: &Fe) -> bool {
    groth16_solana::groth16::is_less_than_bn254_field_size_be(fe)
}

/// Rillogarit `all_inputs_hash`. `trace` thirret pas çdo hapi Poseidon.
pub fn all_inputs_hash(
    p: &ZkLoginPublicInputs<'_>,
    mut trace: impl FnMut(Step),
) -> Result<Fe, InputError> {
    let c = p.circuit;
    if p.header_base64.len() > c.max_header_len() {
        return Err(InputError::HeaderTooLong);
    }
    if p.iss.len() > c.max_iss_len() {
        return Err(InputError::IssTooLong);
    }
    if !is_canonical(p.address_seed) {
        return Err(InputError::NonCanonicalAddressSeed);
    }

    let header_f = hash_str_to_field(p.header_base64, c.max_header_len())?;
    trace(Step::Header);
    let iss_f = hash_str_to_field(p.iss, c.max_iss_len())?;
    trace(Step::Iss);
    let (modulus_f, num_bits) = match p.modulus {
        Modulus::Full(m) => (hash_modulus(m, c.max_modulus_len())?, modulus_num_bits(m)),
        Modulus::Precomputed { hash, num_bits } => (*hash, num_bits as u64),
    };
    trace(Step::Modulus);

    let (pk0, pk1) = eph_pubkey_to_fes(p.eph_pubkey);
    let max_epoch_f = fe_from_u64(p.max_epoch);
    let out = match c {
        Circuit::V1 => poseidon(&[
            pk0,
            pk1,
            *p.address_seed,
            max_epoch_f,
            iss_f,
            fe_from_u64(p.index_mod_4 as u64),
            header_f,
            modulus_f,
        ])?,
        Circuit::V2 => poseidon(&[
            pk0,
            pk1,
            *p.address_seed,
            max_epoch_f,
            iss_f,
            header_f,
            modulus_f,
            fe_from_u64(num_bits),
        ])?,
    };
    trace(Step::Final);
    Ok(out)
}
