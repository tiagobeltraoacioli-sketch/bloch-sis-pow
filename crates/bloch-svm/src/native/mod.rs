// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native programs — the ONLY programs that execute in v0 (spec §0: no SBF
//! bytecode runs; spec §11: programs are genesis-registered and immutable,
//! there is no deploy path).
//!
//! [`NativeExecutor`] is the v0 [`crate::runtime::ProgramExecutor`]: it
//! dispatches on program id and knows exactly one program, the System
//! subset. When the sbpf front lands, its executor either wraps this one or
//! both sit behind a dispatching executor — that seam is the
//! `ProgramExecutor` trait itself, whose rustdoc (runtime.rs) carries the
//! written inter-front contract.

use crate::account::Account;
use crate::errors::ProgramError;
use crate::meter::ComputeMeter;
use crate::params::SYSTEM_PROGRAM_ID;
use crate::runtime::{AccountHandle, ExecEnv, ProgramExecutor};

pub mod system;

#[cfg(test)]
pub(crate) mod adversarial;

/// The v0 executor: System program only. Any other id is
/// [`ProgramError::UnknownProgram`] — reachable only if a manifest registers
/// an executable account this executor has no implementation for, and a
/// typed abort (not a panic) even then (§2).
pub struct NativeExecutor;

impl ProgramExecutor for NativeExecutor {
    fn execute(
        &self,
        program_id: &[u8; 32],
        instruction_data: &[u8],
        accounts: &mut [AccountHandle<'_>],
        meter: &mut ComputeMeter,
        env: &ExecEnv,
    ) -> Result<(), ProgramError> {
        if *program_id == SYSTEM_PROGRAM_ID {
            system::execute(instruction_data, accounts, meter, env)
        } else {
            Err(ProgramError::UnknownProgram { program_id: *program_id })
        }
    }
}

/// The genesis manifest entry for the System program itself: executable,
/// self-owned, zero balance, no data. Programs are never merged as writable
/// (§6.2: executable accounts are fully immutable, and the commit-time bond
/// check applies to writable survivors only), so the zero balance does not
/// meet the §4.2 bond machinery.
pub fn system_program_account() -> Account {
    Account {
        balance_sat: 0,
        owner: SYSTEM_PROGRAM_ID,
        nonce: 0,
        executable: true,
        data: Vec::new(),
    }
}
