//! Verifikimi i passkey (WebAuthn, P-256) me precompile-in secp256r1 (SIMD-0075).
//!
//! Transaksioni ka instruksionin e precompile-it menjëherë para instruksionit tonë, me një
//! nënshkrim dhe me të gjitha të dhënat brenda vetes. Mesazhi i nënshkruar është
//! `authenticatorData || sha256(clientDataJSON)`. Programi kontrollon:
//! - çelësi publik është në `wallet.passkeys`;
//! - `sha256(clientDataJSON)` = 32 bytes e fundit të mesazhit; flag-u UP në `authenticatorData`;
//! - `clientDataJSON` ka `"type":"webauthn.get"` dhe `"challenge":"<base64url(c)>"` ku
//!   `c = sha256(DOMAIN_PASSKEY || wallet || nonce || action_hash)`.
//!
//! Blloku në instruksion: `client_data_len u16, client_data_json`.
//! `action_hash = sha256(op || bytes para bllokut || bytes pas bllokut || adresat e llogarive
//! pa sysvar-in)`.

use pinocchio::{sysvars::instructions::Instructions, AccountView, Address};

use crate::error::{AuthError, Result};
use crate::state::{Wallet, DOMAIN_PASSKEY};
use crate::util::{sha256, Reader};

pub const SECP256R1_PROGRAM: Address =
    Address::from_str_const("Secp256r1SigVerify1111111111111111111111111");
pub use pinocchio::sysvars::instructions::INSTRUCTIONS_ID;

/// Maksimumi i llogarive që hyjnë në `action_hash`.
pub const MAX_HASHED_ACCOUNTS: usize = 40;
const MAX_CLIENT_DATA: usize = 1024;

pub fn read_block<'a>(r: &mut Reader<'a>) -> Result<&'a [u8]> {
    let n = r.u16()? as usize;
    if n > MAX_CLIENT_DATA {
        return Err(AuthError::InvalidPasskeySignature.into());
    }
    r.take(n)
}

/// `sha256(op || prefix || payload || adresat)`. `prefix` janë bytes para bllokut passkey
/// (p.sh. mode-i), `payload` ato pas tij.
pub fn action_hash(
    op: u8,
    prefix: &[u8],
    payload: &[u8],
    accounts: &[AccountView],
) -> Result<[u8; 32]> {
    if accounts.len() > MAX_HASHED_ACCOUNTS {
        return Err(AuthError::TooManyEntries.into());
    }
    let opb = [op];
    let mut parts: [&[u8]; MAX_HASHED_ACCOUNTS + 3] = [&[]; MAX_HASHED_ACCOUNTS + 3];
    parts[0] = &opb;
    parts[1] = prefix;
    parts[2] = payload;
    for (i, a) in accounts.iter().enumerate() {
        parts[3 + i] = a.address().as_ref();
    }
    Ok(sha256(&parts[..3 + accounts.len()]))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url pa padding i 32 bytes (43 karaktere).
pub fn b64url32(input: &[u8; 32]) -> [u8; 43] {
    let mut out = [0u8; 43];
    let mut o = 0;
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        let chars = chunk.len() + 1;
        for k in 0..chars {
            out[o] = B64[((n >> (18 - 6 * k)) & 63) as usize];
            o += 1;
        }
    }
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Kontrollon `clientDataJSON` kundër challenge-it të pritur.
pub fn check_client_data(client_data: &[u8], challenge: &[u8; 32]) -> Result<()> {
    const TYPE: &[u8] = b"\"type\":\"webauthn.get\"";
    const CHALLENGE: &[u8] = b"\"challenge\":\"";
    let bad = || AuthError::InvalidPasskeySignature;
    find(client_data, TYPE).ok_or_else(bad)?;
    let start = find(client_data, CHALLENGE).ok_or_else(bad)? + CHALLENGE.len();
    // Vetëm një fushë "challenge".
    if find(&client_data[start..], CHALLENGE).is_some() {
        return Err(bad().into());
    }
    let expected = b64url32(challenge);
    let end = start + expected.len();
    if client_data.len() <= end || client_data[start..end] != expected || client_data[end] != b'"' {
        return Err(bad().into());
    }
    Ok(())
}

/// Verifikon passkey-n për `action_hash` dhe kthen slot-in e tij. Nuk rrit nonce-in.
pub fn verify(
    sysvar: &AccountView,
    wallet: &Wallet,
    wallet_address: &Address,
    client_data: &[u8],
    action_hash: &[u8; 32],
) -> Result<usize> {
    let bad = || AuthError::InvalidPasskeySignature;
    let ixs = Instructions::try_from(sysvar).map_err(|_| AuthError::InvalidAccount)?;
    let ix = ixs.get_instruction_relative(-1).map_err(|_| bad())?;
    if ix.get_program_id() != &SECP256R1_PROGRAM {
        return Err(bad().into());
    }
    let d = ix.get_instruction_data();
    // num_signatures u8, padding u8, offsets (7 * u16)
    if d.len() < 16 || d[0] != 1 {
        return Err(bad().into());
    }
    let u16_at = |i: usize| u16::from_le_bytes([d[2 + 2 * i], d[3 + 2 * i]]);
    let (sig_ix, pk_off, pk_ix, msg_off, msg_len, msg_ix) = (
        u16_at(1),
        u16_at(2) as usize,
        u16_at(3),
        u16_at(4) as usize,
        u16_at(5) as usize,
        u16_at(6),
    );
    if sig_ix != u16::MAX || pk_ix != u16::MAX || msg_ix != u16::MAX {
        return Err(bad().into());
    }
    let pubkey: &[u8; 33] = d
        .get(pk_off..pk_off + 33)
        .ok_or_else(bad)?
        .try_into()
        .unwrap();
    let msg = d.get(msg_off..msg_off + msg_len).ok_or_else(bad)?;
    let slot = wallet
        .passkey_slot(pubkey)
        .ok_or(AuthError::PasskeyRequired)?;

    // authenticatorData (≥ 37 bytes, flag-u UP) || sha256(clientDataJSON)
    if msg.len() < 37 + 32 || msg[32] & 0x01 == 0 {
        return Err(bad().into());
    }
    if msg[msg.len() - 32..] != sha256(&[client_data]) {
        return Err(bad().into());
    }
    let challenge = sha256(&[
        DOMAIN_PASSKEY,
        wallet_address.as_ref(),
        &wallet.nonce.0,
        action_hash,
    ]);
    check_client_data(client_data, &challenge)?;
    Ok(slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url() {
        let mut x = [0u8; 32];
        for (i, b) in x.iter_mut().enumerate() {
            *b = i as u8 * 7;
        }
        // base64url i njohur i 0x00, 0x07, ..., 0xd9
        assert_eq!(
            &b64url32(&x),
            b"AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK-2vcTL0tk"
        );
        assert_eq!(
            &b64url32(&[0xff; 32]),
            b"__________________________________________8"
        );
    }

    #[test]
    fn client_data() {
        let c = [3u8; 32];
        let ch = core::str::from_utf8(&b64url32(&c)).unwrap().to_string();
        let ok = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{ch}\",\"origin\":\"https://x\"}}"
        );
        assert!(check_client_data(ok.as_bytes(), &c).is_ok());
        let create = ok.replace("webauthn.get", "webauthn.create");
        assert!(check_client_data(create.as_bytes(), &c).is_err());
        let other = ok.replace(&ch, &core::str::from_utf8(&b64url32(&[4u8; 32])).unwrap());
        assert!(check_client_data(other.as_bytes(), &c).is_err());
        let twice =
            format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{ch}\",\"challenge\":\"x\"}}");
        assert!(check_client_data(twice.as_bytes(), &c).is_err());
    }
}
