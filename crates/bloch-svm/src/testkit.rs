// SPDX-License-Identifier: AGPL-3.0-or-later

//! Test-only shared fixtures: verifiers, the dispatching executor, manifest
//! and transaction builders, and a deterministic byte generator.
//!
//! `#[cfg(test)]` at the module declaration (lib.rs) — none of this exists
//! in a production build. The builders construct transactions the §5.2
//! validator accepts, with placeholder witnesses meant for [`AcceptAll`];
//! signature-path tests use [`RejectAll`] to prove the callback is actually
//! consulted.

use crate::account::Account;
use crate::errors::ProgramError;
use crate::meter::ComputeMeter;
use crate::native::adversarial;
use crate::native::{system, system_program_account};
use crate::params::SYSTEM_PROGRAM_ID;
use crate::runtime::{AccountHandle, ExecEnv, ProgramExecutor, SignatureVerifier};
use crate::tree::SvmState;
use crate::tx::{AccountMeta, Instruction, SvmTransaction, Witness};
use sha3::{Digest, Sha3_256};

/// A fixed environment: values arbitrary, and PART OF THE POINT is that
/// nothing in these tests may depend on them changing (no clock — §2).
pub(crate) const ENV: ExecEnv = ExecEnv { slot: 77, epoch: 2 };

/// Accepts every signature. The §5.2 pubkey↔address binding still runs — an
/// accept-all verifier does not bypass structure.
pub(crate) struct AcceptAll;
impl SignatureVerifier for AcceptAll {
    fn verify(&self, _pk: &[u8], _root: &[u8; 32], _sig: &[u8]) -> bool {
        true
    }
}

/// Rejects every signature — the control proving the callback is consulted.
pub(crate) struct RejectAll;
impl SignatureVerifier for RejectAll {
    fn verify(&self, _pk: &[u8], _root: &[u8; 32], _sig: &[u8]) -> bool {
        false
    }
}

/// System program + the adversarial test programs.
pub(crate) struct TestExecutor;
impl ProgramExecutor for TestExecutor {
    fn execute(
        &self,
        program_id: &[u8; 32],
        data: &[u8],
        accounts: &mut [AccountHandle<'_>],
        meter: &mut ComputeMeter,
        env: &ExecEnv,
    ) -> Result<(), ProgramError> {
        if let Some(r) = adversarial::try_execute(program_id, data, accounts, meter, env) {
            return r;
        }
        if *program_id == SYSTEM_PROGRAM_ID {
            return system::execute(data, accounts, meter, env);
        }
        Err(ProgramError::UnknownProgram { program_id: *program_id })
    }
}

/// An executable, self-owned program account for the manifest.
pub(crate) fn program_account(program_id: [u8; 32]) -> Account {
    Account { balance_sat: 0, owner: program_id, nonce: 0, executable: true, data: Vec::new() }
}

/// A state holding the programs (System + adversarial) and the given wallets
/// (`(hybrid_pubkey, balance)`). Spec §9.2: tests fund from a genesis-style
/// manifest only — there is no value bridge yet.
pub(crate) fn manifest(wallets: &[(&[u8], u64)]) -> SvmState {
    let mut entries: Vec<([u8; 32], Account)> = vec![
        (SYSTEM_PROGRAM_ID, system_program_account()),
        (adversarial::ATTACK_READONLY_ID, program_account(adversarial::ATTACK_READONLY_ID)),
        (adversarial::LAYER1_BYPASS_ID, program_account(adversarial::LAYER1_BYPASS_ID)),
        (adversarial::MINTER_ID, program_account(adversarial::MINTER_ID)),
        (adversarial::METER_HOG_ID, program_account(adversarial::METER_HOG_ID)),
        (adversarial::BALANCE_GATE_ID, program_account(adversarial::BALANCE_GATE_ID)),
    ];
    for (pk, bal) in wallets {
        entries.push((crate::address::wallet_address(pk), Account::wallet(*bal)));
    }
    SvmState::from_manifest(entries)
}

/// Standard compute budget for the small fixtures: dispatch (1,000) + one
/// native op (150) + slack. Fee = 5,000 + 5 = 5,005 sat under the
/// provisional formula — several tests pin that number on purpose, so a
/// params.rs economics change is a visible diff here.
pub(crate) const BUDGET: u32 = 5_000;
/// `fee_for(BUDGET)` — see [`BUDGET`].
pub(crate) const FEE: u64 = 5_005;

fn witness_for(pk: &[u8]) -> Witness {
    Witness { pubkey: pk.to_vec(), sig: vec![0xEE] }
}

/// `payer` transfers `amount` to `to` via the System program.
/// Layout: `[payer ws | to w | System ro]`, instruction over `[0, 1]`.
pub(crate) fn transfer_tx(payer_pk: &[u8], to: [u8; 32], amount: u64, nonce: u64) -> SvmTransaction {
    let mut data = vec![system::TAG_TRANSFER];
    data.extend_from_slice(&amount.to_le_bytes());
    SvmTransaction {
        version: 0,
        compute_budget: BUDGET,
        nonce,
        accounts: vec![
            AccountMeta { address: crate::address::wallet_address(payer_pk) },
            AccountMeta { address: to },
            AccountMeta { address: SYSTEM_PROGRAM_ID },
        ],
        header: (1, 0, 1),
        instructions: vec![Instruction { program_index: 2, account_indices: vec![0, 1], data }],
        witnesses: vec![witness_for(payer_pk)],
    }
}

/// `payer` runs the BalanceGate over readonly `target` with `threshold`.
/// Layout: `[payer ws | target ro | Gate ro]`, instruction over `[1]`.
/// This is the workload ingredient that makes read-write conflicts
/// OBSERVABLE in result codes even when write sets are disjoint — the §7.1
/// W∩R arm has to matter for the equivalence test to bite on it.
pub(crate) fn gate_tx(payer_pk: &[u8], target: [u8; 32], threshold: u64, nonce: u64) -> SvmTransaction {
    SvmTransaction {
        version: 0,
        compute_budget: BUDGET,
        nonce,
        accounts: vec![
            AccountMeta { address: crate::address::wallet_address(payer_pk) },
            AccountMeta { address: target },
            AccountMeta { address: adversarial::BALANCE_GATE_ID },
        ],
        header: (1, 0, 0),
        instructions: vec![Instruction {
            program_index: 2,
            account_indices: vec![1],
            data: threshold.to_le_bytes().to_vec(),
        }],
        witnesses: vec![witness_for(payer_pk)],
    }
}

/// `funder` creates the wallet of `new_pk` with `lamports` and `space`
/// zeroed data bytes, owned by `owner`.
/// Layout: `[funder ws | new ws | System ro]`, instruction over `[0, 1]`.
pub(crate) fn create_tx(
    funder_pk: &[u8],
    new_pk: &[u8],
    lamports: u64,
    space: u32,
    owner: [u8; 32],
    nonce: u64,
) -> SvmTransaction {
    let mut data = vec![system::TAG_CREATE_ACCOUNT];
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(&owner);
    SvmTransaction {
        version: 0,
        compute_budget: 50_000, // space bytes cost 10 CU each — headroom
        nonce,
        accounts: vec![
            AccountMeta { address: crate::address::wallet_address(funder_pk) },
            AccountMeta { address: crate::address::wallet_address(new_pk) },
            AccountMeta { address: SYSTEM_PROGRAM_ID },
        ],
        header: (2, 0, 0),
        instructions: vec![Instruction { program_index: 2, account_indices: vec![0, 1], data }],
        witnesses: vec![witness_for(funder_pk), witness_for(new_pk)],
    }
}

/// `payer` pays the fee; `victim` (signing) is deleted with its whole
/// balance refunded to `refund_to`.
/// Layout: `[payer ws | victim ws | refund_to w | System ro]`.
pub(crate) fn delete_tx(
    payer_pk: &[u8],
    victim_pk: &[u8],
    refund_to: [u8; 32],
    nonce: u64,
) -> SvmTransaction {
    SvmTransaction {
        version: 0,
        compute_budget: BUDGET,
        nonce,
        accounts: vec![
            AccountMeta { address: crate::address::wallet_address(payer_pk) },
            AccountMeta { address: crate::address::wallet_address(victim_pk) },
            AccountMeta { address: refund_to },
            AccountMeta { address: SYSTEM_PROGRAM_ID },
        ],
        header: (2, 0, 1),
        instructions: vec![Instruction {
            program_index: 3,
            account_indices: vec![1, 2],
            data: vec![system::TAG_DELETE],
        }],
        witnesses: vec![witness_for(payer_pk), witness_for(victim_pk)],
    }
}

/// `payer` runs the MeterHog: `count` charges of `chunk` CU under `budget`.
/// Layout: `[payer ws | Hog ro]`.
pub(crate) fn hog_tx(payer_pk: &[u8], count: u32, chunk: u32, budget: u32, nonce: u64) -> SvmTransaction {
    let mut data = count.to_le_bytes().to_vec();
    data.extend_from_slice(&chunk.to_le_bytes());
    SvmTransaction {
        version: 0,
        compute_budget: budget,
        nonce,
        accounts: vec![
            AccountMeta { address: crate::address::wallet_address(payer_pk) },
            AccountMeta { address: adversarial::METER_HOG_ID },
        ],
        header: (1, 0, 0),
        instructions: vec![Instruction { program_index: 1, account_indices: vec![], data }],
        witnesses: vec![witness_for(payer_pk)],
    }
}

/// `payer` runs the readonly-mutation attack program over `target`,
/// declared writable or readonly per `declare_writable` — the §8-2 pair.
/// Layout: `[payer ws | target (w|ro) | Attack ro]`, instruction over `[1]`.
pub(crate) fn attack_tx(
    payer_pk: &[u8],
    target: [u8; 32],
    declare_writable: bool,
    nonce: u64,
) -> SvmTransaction {
    SvmTransaction {
        version: 0,
        compute_budget: BUDGET,
        nonce,
        accounts: vec![
            AccountMeta { address: crate::address::wallet_address(payer_pk) },
            AccountMeta { address: target },
            AccountMeta { address: adversarial::ATTACK_READONLY_ID },
        ],
        header: (1, 0, u8::from(declare_writable)),
        instructions: vec![Instruction { program_index: 2, account_indices: vec![1], data: vec![] }],
        witnesses: vec![witness_for(payer_pk)],
    }
}

/// Like [`attack_tx`] but for the layer-1 BYPASS program (target always
/// readonly — the point is to scribble on it through the test backdoor).
pub(crate) fn bypass_tx(payer_pk: &[u8], target: [u8; 32], nonce: u64) -> SvmTransaction {
    SvmTransaction {
        version: 0,
        compute_budget: BUDGET,
        nonce,
        accounts: vec![
            AccountMeta { address: crate::address::wallet_address(payer_pk) },
            AccountMeta { address: target },
            AccountMeta { address: adversarial::LAYER1_BYPASS_ID },
        ],
        header: (1, 0, 0),
        instructions: vec![Instruction { program_index: 2, account_indices: vec![1], data: vec![] }],
        witnesses: vec![witness_for(payer_pk)],
    }
}

/// `payer` runs the Minter over writable `target`, crediting `amount` from
/// thin air — the §8-6 conservation attack.
/// Layout: `[payer ws | target w | Minter ro]`.
pub(crate) fn minter_tx(payer_pk: &[u8], target: [u8; 32], amount: u64, nonce: u64) -> SvmTransaction {
    SvmTransaction {
        version: 0,
        compute_budget: BUDGET,
        nonce,
        accounts: vec![
            AccountMeta { address: crate::address::wallet_address(payer_pk) },
            AccountMeta { address: target },
            AccountMeta { address: adversarial::MINTER_ID },
        ],
        header: (1, 0, 1),
        instructions: vec![Instruction {
            program_index: 2,
            account_indices: vec![1],
            data: amount.to_le_bytes().to_vec(),
        }],
        witnesses: vec![witness_for(payer_pk)],
    }
}

/// Deterministic u64 stream: SHA3-256 in counter mode. Deliberately NOT a
/// library RNG — the workload sweep in scheduler.rs is a *pin* (same seeds,
/// same vectors, every run, every machine), which is the property the front
/// plan found missing in default proptest entropy.
pub(crate) struct DetRng {
    seed: u64,
    ctr: u64,
}

impl DetRng {
    pub(crate) fn new(seed: u64) -> Self {
        DetRng { seed, ctr: 0 }
    }
    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut h = Sha3_256::new();
        h.update(b"bloch-svm-detrng");
        h.update(self.seed.to_le_bytes());
        h.update(self.ctr.to_le_bytes());
        self.ctr += 1;
        let out: [u8; 32] = h.finalize().into();
        u64::from_le_bytes([out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]])
    }
    /// Uniform-ish draw in `0..n` (modulo bias irrelevant at test scale).
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0);
        self.next_u64() % n
    }
}
