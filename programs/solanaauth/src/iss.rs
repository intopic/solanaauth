//! Dekodimi i `iss` nga copa base64url e JWT-së (`iss_base64_details`), si
//! `decode_base64_url` + `verify_extended_claim` në sui-sdk-types.

/// Gjatësia maksimale e copës base64 për qarkun v1 (4 * (1 + 165 / 3)).
pub const MAX_ISS_B64: usize = 224;
/// Gjatësia maksimale e vlerës së `iss` që pranojmë.
pub const MAX_ISS_LEN: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub enum IssError {
    Invalid,
}

fn b64_index(c: u8) -> Result<u8, IssError> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(IssError::Invalid),
    }
}

/// Dekodon `s` (base64url pa padding) duke hequr bit-et e para sipas `index_mod_4` dhe
/// bit-et e fundit sipas pozicionit të karakterit të fundit. Kthen numrin e bytes në `out`.
pub fn decode_claim(
    s: &[u8],
    index_mod_4: u8,
    out: &mut [u8; MAX_ISS_B64],
) -> Result<usize, IssError> {
    if s.len() < 2 || s.len() > MAX_ISS_B64 || index_mod_4 > 2 {
        return Err(IssError::Invalid);
    }
    let skip_front = 2 * index_mod_4 as usize;
    let skip_back = match (index_mod_4 as usize + s.len() - 1) % 4 {
        3 => 0,
        2 => 2,
        1 => 4,
        _ => return Err(IssError::Invalid),
    };
    let total_bits = s.len() * 6;
    let used = total_bits - skip_front - skip_back;
    if used % 8 != 0 {
        return Err(IssError::Invalid);
    }
    let n = used / 8;
    let mut acc: u32 = 0;
    let mut acc_bits = 0usize;
    let mut bit_pos = 0usize; // pozicioni i bit-it në rrjedhën e plotë
    let mut written = 0usize;
    for &c in s {
        let v = b64_index(c)? as u32;
        for i in (0..6).rev() {
            let bit = (v >> i) & 1;
            if bit_pos >= skip_front && bit_pos < total_bits - skip_back {
                acc = (acc << 1) | bit;
                acc_bits += 1;
                if acc_bits == 8 {
                    out[written] = acc as u8;
                    written += 1;
                    acc = 0;
                    acc_bits = 0;
                }
            }
            bit_pos += 1;
        }
    }
    debug_assert_eq!(written, n);
    Ok(n)
}

/// Nga claim-i i dekoduar `"iss":"<vlera>",` (ose me `}` në fund) nxjerr `<vlera>`.
pub fn iss_value(claim: &[u8]) -> Result<&[u8], IssError> {
    const PREFIX: &[u8] = b"\"iss\":\"";
    let last = *claim.last().ok_or(IssError::Invalid)?;
    if last != b',' && last != b'}' {
        return Err(IssError::Invalid);
    }
    let body = &claim[..claim.len() - 1];
    // Lejojmë hapësira rreth ':' si në JSON, por jo escape: iss-at e Google/Apple s'kanë.
    let rest = body.strip_prefix(PREFIX).ok_or(IssError::Invalid)?;
    let value = rest.strip_suffix(b"\"").ok_or(IssError::Invalid)?;
    if value.is_empty()
        || value.len() > MAX_ISS_LEN
        || value.iter().any(|&b| b == b'"' || b == b'\\')
    {
        return Err(IssError::Invalid);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(s: &str, i: u8) -> Vec<u8> {
        let mut out = [0u8; MAX_ISS_B64];
        let n = decode_claim(s.as_bytes(), i, &mut out).unwrap();
        out[..n].to_vec()
    }

    #[test]
    fn google() {
        let claim = decode("yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC", 1);
        assert_eq!(claim, b"\"iss\":\"https://accounts.google.com\",");
        assert_eq!(iss_value(&claim).unwrap(), b"https://accounts.google.com");
    }

    #[test]
    fn sui_test_issuers() {
        let claim = decode("wiaXNzIjoiaHR0cHM6Ly9vYXV0aC5zdWkuaW8iLC", 2);
        assert_eq!(iss_value(&claim).unwrap(), b"https://oauth.sui.io");
        let claim = decode("wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw", 2);
        assert_eq!(iss_value(&claim).unwrap(), b"https://id.twitch.tv/oauth2");
    }

    #[test]
    fn rejects_bad_input() {
        let mut out = [0u8; MAX_ISS_B64];
        assert!(decode_claim(b"yJpc3M*", 1, &mut out).is_err());
        assert!(decode_claim(b"yJ", 3, &mut out).is_err());
        assert!(iss_value(b"\"aud\":\"x\",").is_err());
        assert!(iss_value(b"\"iss\":\"a\\\"b\",").is_err());
        assert!(iss_value(b"\"iss\":\"x\"").is_err());
    }
}
