//! Verifikimi referencë off-chain (Detyra 2 në docs/HAPI-1-BRIEF.md).
//!
//! TODO(Detyra 2): ngarko provën dhe input-et nga `fixtures/`, verifikoji me
//! `sui-crypto` / `fastcrypto-zkp` dhe eksporto `all_inputs_hash` që programi
//! on-chain duhet ta riprodhojë bit për bit.

/// Rruga e fixtures, relative nga rrënja e repo-s.
pub const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_dir_exists() {
        assert!(std::path::Path::new(FIXTURES_DIR).is_dir());
    }

    #[test]
    #[ignore = "Detyra 2: verifikimi i provës referencë ende s'është implementuar"]
    fn verifies_reference_proof() {
        unimplemented!()
    }
}
