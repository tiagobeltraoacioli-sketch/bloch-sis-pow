// SPDX-License-Identifier: AGPL-3.0-or-later

//! The System-program subset (spec §12): CreateAccount, Transfer, Assign,
//! Allocate, Delete-with-refund.
//!
//! Everything here goes through the [`crate::runtime::AccountMut`] mutators,
//! so the §6.2 owner rules are enforced by the handles, not re-implemented —
//! a wallet debit inside Transfer fails with `HolderSignatureMissing` because
//! the HANDLE says so. The one rule this module adds on top is
//! CreateAccount's new-account signature (below).
//!
//! Instruction encoding: `tag u8` then fixed LE fields, trailing bytes
//! rejected — the same canonicity discipline as every codec in the crate.
//!
//! v0-absent, deliberately (spec §11 + nao-feito ledger): CreateAccount for
//! PDAs (would need CPI so a program can authorize creation at its derived
//! address — v0 has no CPI, so only signer-addressed accounts can be
//! created); `create_with_seed`; any deploy/upgrade instruction.

use crate::account::{Account, Reader};
use crate::errors::ProgramError;
use crate::meter::ComputeMeter;
use crate::params::{COST_NATIVE_OP, COST_PER_DATA_BYTE_WRITE, MAX_ACCOUNT_DATA};
use crate::runtime::{AccountHandle, ExecEnv};

/// Instruction tags. u8, append-only for the same reason state_root.rs tags
/// are (state_root.rs:126): reusing one silently re-keys meaning.
pub const TAG_CREATE_ACCOUNT: u8 = 0;
/// See [`TAG_CREATE_ACCOUNT`].
pub const TAG_TRANSFER: u8 = 1;
/// See [`TAG_CREATE_ACCOUNT`].
pub const TAG_ASSIGN: u8 = 2;
/// See [`TAG_CREATE_ACCOUNT`].
pub const TAG_ALLOCATE: u8 = 3;
/// See [`TAG_CREATE_ACCOUNT`].
pub const TAG_DELETE: u8 = 4;

/// Program-defined error: Allocate on an account whose data is nonempty.
pub const ERR_ALREADY_ALLOCATED: u32 = 1;

/// Split the first two handles out of the slice, typed-erroring when the
/// instruction declared fewer. `split_at_mut` because both must be `&mut`
/// simultaneously (they are distinct entries — §5.2 banned duplicate indices
/// within an instruction, which is exactly what makes this sound).
fn two<'h, 'a>(
    accounts: &'h mut [AccountHandle<'a>],
) -> Result<(&'h mut AccountHandle<'a>, &'h mut AccountHandle<'a>), ProgramError> {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccounts { got: accounts.len(), need: 2 });
    }
    let (a, b) = accounts.split_at_mut(1);
    Ok((&mut a[0], &mut b[0]))
}

fn one<'h, 'a>(
    accounts: &'h mut [AccountHandle<'a>],
) -> Result<&'h mut AccountHandle<'a>, ProgramError> {
    accounts
        .first_mut()
        .ok_or(ProgramError::NotEnoughAccounts { got: 0, need: 1 })
}

/// Execute one System instruction. Charge-then-do throughout (§6.3): the
/// flat op cost lands before decoding, byte costs before the byte work.
pub fn execute(
    data: &[u8],
    accounts: &mut [AccountHandle<'_>],
    meter: &mut ComputeMeter,
    _env: &ExecEnv,
) -> Result<(), ProgramError> {
    meter.charge(COST_NATIVE_OP)?;
    let mut r = Reader::new(data);
    let tag = r.u8().map_err(|_| ProgramError::InvalidInstructionData)?;
    match tag {
        TAG_CREATE_ACCOUNT => {
            // [funder ws] [new ws] — lamports u64, space u32, owner [32].
            let lamports = r.u64().map_err(|_| ProgramError::InvalidInstructionData)?;
            let space = r.u32().map_err(|_| ProgramError::InvalidInstructionData)? as usize;
            let owner = r.array32().map_err(|_| ProgramError::InvalidInstructionData)?;
            r.finish().map_err(|_| ProgramError::InvalidInstructionData)?;
            if space > MAX_ACCOUNT_DATA {
                // Refused before charging for the bytes: a hostile `space`
                // must not be able to exhaust the meter as a side channel.
                return Err(ProgramError::AccessViolation(
                    crate::errors::AccessError::DataCapExceeded {
                        address: accounts.get(1).map(|h| h.address()).unwrap_or_default(),
                        len: space,
                    },
                ));
            }
            meter.charge_bytes(0, COST_PER_DATA_BYTE_WRITE, space)?;
            let (funder, new) = two(accounts)?;
            // The kept-on-purpose Solana rule: the NEW account must sign.
            // Without it, anyone could squat a future wallet address with a
            // hostile owner program and inherit every satoshi later sent
            // there. (PDA creation is the CPI-shaped exception v0 does not
            // have — module docs.)
            if !new.is_signer() {
                return Err(ProgramError::MissingRequiredSignature { address: new.address() });
            }
            funder.try_mut()?.debit(lamports)?;
            new.try_mut()?.create(Account {
                balance_sat: lamports,
                owner,
                nonce: 0,
                executable: false,
                data: vec![0u8; space],
            })?;
            // The §4.2 bond (lamports ≥ bond_for(space)) is layer-2's commit
            // check — enforced where the FINAL balance is known, so a later
            // instruction topping the account up can rescue a lowball here.
            Ok(())
        }
        TAG_TRANSFER => {
            // [from ws] [to w] — amount u64.
            let amount = r.u64().map_err(|_| ProgramError::InvalidInstructionData)?;
            r.finish().map_err(|_| ProgramError::InvalidInstructionData)?;
            let (from, to) = two(accounts)?;
            // Handle mutators carry the whole §6.2 story: owner check,
            // holder-signature check, checked arithmetic.
            from.try_mut()?.debit(amount)?;
            to.try_mut()?.credit(amount)?;
            Ok(())
        }
        TAG_ASSIGN => {
            // [account ws] — new_owner [32]. Data-zeroed rule enforced by
            // the mutator (§6.2).
            let new_owner = r.array32().map_err(|_| ProgramError::InvalidInstructionData)?;
            r.finish().map_err(|_| ProgramError::InvalidInstructionData)?;
            one(accounts)?.try_mut()?.set_owner(new_owner)?;
            Ok(())
        }
        TAG_ALLOCATE => {
            // [account ws] — space u32. Only from empty data: allocate is
            // "give me my zeroed bytes", not "resize whatever is there" —
            // resizing live program data is an owner-program decision made
            // through set_data.
            let space = r.u32().map_err(|_| ProgramError::InvalidInstructionData)? as usize;
            r.finish().map_err(|_| ProgramError::InvalidInstructionData)?;
            if space > MAX_ACCOUNT_DATA {
                return Err(ProgramError::AccessViolation(
                    crate::errors::AccessError::DataCapExceeded {
                        address: accounts.first().map(|h| h.address()).unwrap_or_default(),
                        len: space,
                    },
                ));
            }
            meter.charge_bytes(0, COST_PER_DATA_BYTE_WRITE, space)?;
            let h = one(accounts)?;
            if h.account().is_some_and(|a| !a.data.is_empty()) {
                return Err(ProgramError::Custom(ERR_ALREADY_ALLOCATED));
            }
            h.try_mut()?.set_data(vec![0u8; space])?;
            Ok(())
        }
        TAG_DELETE => {
            // [victim ws] [refund_to w] — no args. The §4.2 refund is the
            // explicit move of the ENTIRE balance (bond included) before the
            // delete; the mutator's zero-balance rule then makes the delete
            // itself burn-free by construction.
            r.finish().map_err(|_| ProgramError::InvalidInstructionData)?;
            let (victim, refund_to) = two(accounts)?;
            let balance = victim.account().map(|a| a.balance_sat).unwrap_or(0);
            victim.try_mut()?.debit(balance)?;
            refund_to.try_mut()?.credit(balance)?;
            victim.try_mut()?.delete()?;
            Ok(())
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
