//! solanaauth: portofol Solana me hyrje zkLogin, sesione me politika on-chain dhe (M3) passkey.
//!
//! Dizajni: `docs/DIZAJNI.md`. Byte-i i parë i instruksionit është op-i:
//!
//! | op | instruksioni      | llogaritë |
//! |----|-------------------|-----------|
//! | 0  | `init_config`     | authority (s, w), config (w), program_data, system |
//! | 1  | `update_config`   | admin (s), config (w) |
//! | 2  | `propose_jwk`     | authority (s), payer (s, w), config, jwk (w), system |
//! | 3  | `apply_jwk`       | jwk (w) |
//! | 4  | `revoke_jwk`      | admin (s), config, jwk (w) |
//! | 5  | `create_wallet`   | payer (s, w), session_key (s), config, jwk, wallet (w), system [, session (w)] |
//! | 6  | `open_session`    | payer (s, w), session_key (s), config, jwk, wallet (w), session (w), system |
//! | 7  | `execute`         | session_key (s), wallet, session (w), vault (w), ... |
//! | 8  | `revoke_session`  | signer (s), wallet, session (w) [, config, jwk] |
//! | 10 | `close_session`   | wallet, session (w), vault (w) |
//!
//! Formati i të dhënave të secilit është te funksioni përkatës (`processor`, `execute`).

pub mod error;
pub mod execute;
pub mod iss;
pub mod policy;
pub mod processor;
pub mod state;
pub mod util;
pub mod zk;

use pinocchio::{AccountView, Address, ProgramResult};

use error::AuthError;

pub const OP_INIT_CONFIG: u8 = 0;
pub const OP_UPDATE_CONFIG: u8 = 1;
pub const OP_PROPOSE_JWK: u8 = 2;
pub const OP_APPLY_JWK: u8 = 3;
pub const OP_REVOKE_JWK: u8 = 4;
pub const OP_CREATE_WALLET: u8 = 5;
pub const OP_OPEN_SESSION: u8 = 6;
pub const OP_EXECUTE: u8 = 7;
pub const OP_REVOKE_SESSION: u8 = 8;
pub const OP_CLOSE_SESSION: u8 = 10;

pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let (&op, rest) = data.split_first().ok_or(AuthError::InvalidInstruction)?;
    match op {
        OP_INIT_CONFIG => processor::init_config(program_id, accounts, rest),
        OP_UPDATE_CONFIG => processor::update_config(program_id, accounts, rest),
        OP_PROPOSE_JWK => processor::propose_jwk(program_id, accounts, rest),
        OP_APPLY_JWK => processor::apply_jwk(program_id, accounts, rest),
        OP_REVOKE_JWK => processor::revoke_jwk(program_id, accounts, rest),
        OP_CREATE_WALLET => processor::create_wallet(program_id, accounts, rest),
        OP_OPEN_SESSION => processor::open_session(program_id, accounts, rest),
        OP_EXECUTE => execute::execute(program_id, accounts, rest),
        OP_REVOKE_SESSION => processor::revoke_session(program_id, accounts, rest),
        OP_CLOSE_SESSION => processor::close_session(program_id, accounts, rest),
        _ => Err(AuthError::InvalidInstruction.into()),
    }
}

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}
