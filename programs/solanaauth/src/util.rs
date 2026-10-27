//! Ndihmës: leximi i instruksionit, numrat little endian me alignment 1, PDA-t dhe sha256.

use pinocchio::{error::ProgramError, AccountView, Address};

use crate::error::{AuthError, Result};

/// Lexues i thjeshtë mbi bytes e instruksionit (little endian).
pub struct Reader<'a> {
    pub data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.data.len() < n {
            return Err(AuthError::InvalidInstruction.into());
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    pub fn array<const N: usize>(&mut self) -> Result<&'a [u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(*self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(*self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(*self.array()?))
    }

    pub fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(*self.array()?))
    }

    pub fn finish(&self) -> Result<()> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(AuthError::InvalidInstruction.into())
        }
    }
}

macro_rules! pod_int {
    ($name:ident, $t:ty, $n:expr) => {
        /// Numër little endian me alignment 1 (llogaritë lexohen pa kërkesa alignment-i).
        #[repr(transparent)]
        #[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
        pub struct $name(pub [u8; $n]);

        impl $name {
            #[inline(always)]
            pub fn get(&self) -> $t {
                <$t>::from_le_bytes(self.0)
            }
            #[inline(always)]
            pub fn set(&mut self, v: $t) {
                self.0 = v.to_le_bytes();
            }
        }
    };
}

pod_int!(PodU16, u16, 2);
pod_int!(PodU32, u32, 4);
pod_int!(PodU64, u64, 8);
pod_int!(PodI64, i64, 8);

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    solana_sha256_hasher::hashv(parts).to_bytes()
}

/// Llogaria duhet të nënshkruajë transaksionin.
pub fn require_signer(a: &AccountView) -> Result<()> {
    if a.is_signer() {
        Ok(())
    } else {
        Err(AuthError::MissingSignature.into())
    }
}

pub fn require_writable(a: &AccountView) -> Result<()> {
    if a.is_writable() {
        Ok(())
    } else {
        Err(AuthError::InvalidAccount.into())
    }
}

pub fn require_address(a: &AccountView, expected: &Address) -> Result<()> {
    if a.address() == expected {
        Ok(())
    } else {
        Err(AuthError::InvalidAccount.into())
    }
}

/// PDA me bump kanonik (me syscall-in `sol_try_find_program_address`). Përdoret vetëm kur
/// krijohet llogaria; më pas bump-i ruhet dhe verifikohet me `derive_address`.
pub fn find_pda<const N: usize>(seeds: &[&[u8]; N], program_id: &Address) -> (Address, u8) {
    Address::find_program_address(seeds, program_id)
}

pub fn derive_pda<const N: usize>(seeds: &[&[u8]; N], bump: u8, program_id: &Address) -> Address {
    Address::derive_address(seeds, Some(bump), program_id)
}

/// Kthen një pamje të llogarisë si struct-i `T` (alignment 1), pasi kontrollon pronarin,
/// gjatësinë dhe diskriminuesin.
///
/// # Safety (e brendshme)
/// `T` ka vetëm fusha bytes/`Pod*` me alignment 1 dhe madhësi `T::LEN`.
pub trait Account: Sized {
    const LEN: usize;
    const DISC: u8;

    fn check(view: &AccountView, program_id: &Address) -> Result<()> {
        if !view.owned_by(program_id) {
            return Err(AuthError::InvalidAccount.into());
        }
        if view.data_len() != Self::LEN {
            return Err(AuthError::InvalidAccount.into());
        }
        Ok(())
    }

    fn from_bytes(data: &[u8]) -> Result<&Self> {
        if data.len() != Self::LEN || data[0] != Self::DISC {
            return Err(AuthError::InvalidAccount.into());
        }
        // SAFETY: gjatësia = `LEN` = size_of::<Self>() dhe alignment 1 (assert-et në state.rs);
        // çdo varg bytes është vlerë e vlefshme e `Self` (vetëm fusha bytes/`Pod*`).
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self> {
        if data.len() != Self::LEN || data[0] != Self::DISC {
            return Err(AuthError::InvalidAccount.into());
        }
        // SAFETY: gjatësia = `LEN` = size_of::<Self>() dhe alignment 1 (assert-et në state.rs);
        // çdo varg bytes është vlerë e vlefshme e `Self` (vetëm fusha bytes/`Pod*`).
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    /// Për llogari të sapokrijuar (të dhëna zero).
    fn init_bytes(data: &mut [u8]) -> Result<&mut Self> {
        if data.len() != Self::LEN || data[0] != 0 {
            return Err(AuthError::AlreadyInitialized.into());
        }
        data[0] = Self::DISC;
        // SAFETY: gjatësia = `LEN` = size_of::<Self>() dhe alignment 1 (assert-et në state.rs);
        // çdo varg bytes është vlerë e vlefshme e `Self` (vetëm fusha bytes/`Pod*`).
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }
}

pub fn now() -> Result<i64> {
    use pinocchio::sysvars::{clock::Clock, Sysvar};
    Ok(Clock::get()?.unix_timestamp)
}

pub fn map_err<E>(e: AuthError) -> impl FnOnce(E) -> ProgramError {
    move |_| e.into()
}
