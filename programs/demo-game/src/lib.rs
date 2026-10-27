//! Lojë demo: `join` krijon PDA-në `["player", player]` (16 bytes: pikët u64, lëvizja e fundit i64),
//! `play` rrit pikët. Lojtari është vault-i i një portofoli solanaauth, që nënshkruan nga programi
//! `solanaauth` brenda `execute`; sesioni lejon vetëm këtë program (dhe System për `join`).
//!
//! | op | instruksioni | llogaritë |
//! |----|--------------|-----------|
//! | 0  | `join`       | player (s, w), state (w), system |
//! | 1  | `play`       | player (s), state (w) |

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};

const SEED: &[u8] = b"player";
const LEN: usize = 16;

pub fn process_instruction(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [player, state, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !player.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (expected, bump) = Address::find_program_address(&[SEED, player.address().as_ref()], program_id);
    if state.address() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    match data.first() {
        Some(0) => {
            if state.data_len() != 0 {
                return Err(ProgramError::AccountAlreadyInitialized);
            }
            let bump = [bump];
            let seeds = [Seed::from(SEED), Seed::from(player.address().as_ref()), Seed::from(&bump)];
            pinocchio_system::create_account_with_minimum_balance_signed(state, LEN, program_id, player, None, &[Signer::from(&seeds)])
        }
        Some(1) => {
            if !state.owned_by(program_id) || state.data_len() != LEN {
                return Err(ProgramError::UninitializedAccount);
            }
            let now = Clock::get()?.unix_timestamp;
            let mut d = state.try_borrow_mut()?;
            let score = u64::from_le_bytes(d[0..8].try_into().unwrap()) + 1;
            d[0..8].copy_from_slice(&score.to_le_bytes());
            d[8..16].copy_from_slice(&now.to_le_bytes());
            Ok(())
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}
