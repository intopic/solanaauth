//! Verifying key-t zkLogin, të konvertuara nga `fixtures/vk/*.vkey.json` me
//! `cargo run -p vk-convert` (Detyra 3). Mos i ndrysho skedarët e gjeneruar me dorë.

use groth16_solana::groth16::Groth16Verifyingkey;

use crate::inputs::Circuit;

pub mod dev_v1;
pub mod dev_v2;
pub mod mainnet;

/// Identifikuesi i verifying key-t në instruksion (byte-i i parë i payload-it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VkId {
    /// Ceremonia zkLogin, key MAIN (qarku v1). Ky është key-i që përdor Sui mainnet.
    Mainnet = 0,
    /// Ceremonia zkLogin, key TEST (qarku v1), për provat nga prover-dev.
    DevV1 = 1,
    /// Key dev i qarkut v2 (zklogin-circuits v2-main), vetëm për teste.
    DevV2 = 2,
}

impl VkId {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Mainnet),
            1 => Some(Self::DevV1),
            2 => Some(Self::DevV2),
            _ => None,
        }
    }

    pub fn key(self) -> &'static Groth16Verifyingkey<'static> {
        match self {
            Self::Mainnet => &mainnet::VERIFYINGKEY,
            Self::DevV1 => &dev_v1::VERIFYINGKEY,
            Self::DevV2 => &dev_v2::VERIFYINGKEY,
        }
    }

    pub fn circuit(self) -> Circuit {
        match self {
            Self::Mainnet | Self::DevV1 => Circuit::V1,
            Self::DevV2 => Circuit::V2,
        }
    }
}
