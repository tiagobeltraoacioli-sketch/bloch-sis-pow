// SPDX-License-Identifier: AGPL-3.0-or-later

//! ADVERSARIAL TEST PROGRAMS — `#[cfg(test)]` only, never in a production
//! build (spec §12: "in-tree, clearly marked, because the negative tests are
//! spec obligations, not afterthoughts").
//!
//! Each program here exists to attack one boundary of §6, and the flow tests
//! at the bottom are the §8 obligations that use them. Every negative test
//! carries its control half in the same test function (repo discipline #2).

use crate::errors::ProgramError;
use crate::meter::ComputeMeter;
use crate::params::COST_NATIVE_OP;
use crate::runtime::{AccountHandle, ExecEnv};

/// Attacks layer 1: attempts mutation of `accounts[0]` through the ONLY
/// reachable surface, `try_mut` (the compile-fail doctests in runtime.rs pin
/// that no other surface exists on a `View`). Conservation-neutral on the
/// success path (`set_data`, no balance change) so the §8-2 CONTROL commits
/// cleanly.
pub(crate) const ATTACK_READONLY_ID: [u8; 32] = [0xA1; 32];
/// Bypasses layer 1 through the crate-internal test backdoor and scribbles
/// on a readonly-declared working copy — proving layer 2 catches what layer
/// 1 misses (§6.4 "belt and suspenders"; mutation roster item c).
pub(crate) const LAYER1_BYPASS_ID: [u8; 32] = [0xA2; 32];
/// Credits its writable account from thin air. Layer-1 LEGAL (anyone may
/// credit a writable account, §6.2) — exactly the §8-6 shape: only the
/// layer-2 conservation check stands between this and inflation.
pub(crate) const MINTER_ID: [u8; 32] = [0xA3; 32];
/// Charges the meter in fixed chunks — the §8-5 exhaustion-determinism
/// vehicle. Data: `count u32le ‖ chunk u32le`.
pub(crate) const METER_HOG_ID: [u8; 32] = [0xA4; 32];
/// Reads `accounts[0]` (readonly) and fails with `Custom(GATE_ERR)` when its
/// balance is below the u64le threshold in data. Makes W∩R conflicts
/// observable in RESULT CODES even when write sets are disjoint — the
/// ingredient that lets the §8-1 equivalence test bite on the read arms of
/// §7.1 (mutation roster items a and g).
pub(crate) const BALANCE_GATE_ID: [u8; 32] = [0xA5; 32];

/// The gate's failure code.
pub(crate) const GATE_ERR: u32 = 7;

/// Dispatch an adversarial program, or `None` if `program_id` is not one.
pub(crate) fn try_execute(
    program_id: &[u8; 32],
    data: &[u8],
    accounts: &mut [AccountHandle<'_>],
    meter: &mut ComputeMeter,
    _env: &ExecEnv,
) -> Option<Result<(), ProgramError>> {
    match *program_id {
        ATTACK_READONLY_ID => Some(attack_readonly(accounts, meter)),
        LAYER1_BYPASS_ID => Some(layer1_bypass(accounts, meter)),
        MINTER_ID => Some(minter(data, accounts, meter)),
        METER_HOG_ID => Some(meter_hog(data, meter)),
        BALANCE_GATE_ID => Some(balance_gate(data, accounts, meter)),
        _ => None,
    }
}

fn attack_readonly(
    accounts: &mut [AccountHandle<'_>],
    meter: &mut ComputeMeter,
) -> Result<(), ProgramError> {
    meter.charge(COST_NATIVE_OP)?;
    let h = accounts
        .first_mut()
        .ok_or(ProgramError::NotEnoughAccounts { got: 0, need: 1 })?;
    // The attack: ask for mutation. On a readonly declaration this is the
    // typed layer-1 refusal (§6.1); on a writable declaration it succeeds
    // and the owner rules apply (the manifest makes the target owned by this
    // program, so set_data passes the §6.2 gate).
    h.try_mut()?.set_data(vec![0xAA])?;
    Ok(())
}

fn layer1_bypass(
    accounts: &mut [AccountHandle<'_>],
    meter: &mut ComputeMeter,
) -> Result<(), ProgramError> {
    meter.charge(COST_NATIVE_OP)?;
    if let Some(AccountHandle::View(v)) = accounts.first_mut() {
        // TEST BACKDOOR (crate-private, cfg(test)): mutate the readonly
        // working copy without layer 1 noticing, then return Ok. If layer 2
        // does not abort this transaction, readonly drift became silent
        // corruption — which is precisely what §8-2's second half proves
        // cannot happen.
        if let Some(a) = v.bypass_layer1_for_tests().as_mut() {
            a.data = vec![0xEE];
        }
    }
    Ok(())
}

fn minter(
    data: &[u8],
    accounts: &mut [AccountHandle<'_>],
    meter: &mut ComputeMeter,
) -> Result<(), ProgramError> {
    meter.charge(COST_NATIVE_OP)?;
    let amount = u64::from_le_bytes(data.try_into().map_err(|_| ProgramError::InvalidInstructionData)?);
    let h = accounts
        .first_mut()
        .ok_or(ProgramError::NotEnoughAccounts { got: 0, need: 1 })?;
    // Layer-1 legal: crediting a writable account needs no authority (§6.2).
    // No debit anywhere — the satoshis come from nowhere.
    h.try_mut()?.credit(amount)?;
    Ok(())
}

fn meter_hog(data: &[u8], meter: &mut ComputeMeter) -> Result<(), ProgramError> {
    if data.len() != 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let chunk = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    for _ in 0..count {
        // Charge-then-do: the refusal reading is exact (§6.3).
        meter.charge(chunk)?;
    }
    Ok(())
}

fn balance_gate(
    data: &[u8],
    accounts: &mut [AccountHandle<'_>],
    meter: &mut ComputeMeter,
) -> Result<(), ProgramError> {
    meter.charge(COST_NATIVE_OP)?;
    let threshold = u64::from_le_bytes(data.try_into().map_err(|_| ProgramError::InvalidInstructionData)?);
    let balance = accounts
        .first()
        .and_then(|h| h.account())
        .map_or(0, |a| a.balance_sat);
    if balance < threshold {
        return Err(ProgramError::Custom(GATE_ERR));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The §8 flow obligations that ride on these programs.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod flow_tests {
    use super::*;
    use crate::account::Account;
    use crate::address::wallet_address;
    use crate::errors::{AbortCause, AccessError, MeterError, RejectCause};
    use crate::params::{bond_for, fee_for, COST_INSTRUCTION_DISPATCH, SYSTEM_PROGRAM_ID};
    use crate::runtime::{TxOutcome, TxResult};
    use crate::scheduler::execute_block_serial;
    use crate::testkit::{
        attack_tx, bypass_tx, create_tx, delete_tx, gate_tx, hog_tx, manifest, minter_tx,
        transfer_tx, AcceptAll, DetRng, RejectAll, TestExecutor, ENV, FEE,
    };
    use crate::tree::SvmState;

    const PAYER: &[u8] = b"payer-key";
    /// Enough for bond floor + many fees, far from overflow.
    const RICH: u64 = 100_000_000;

    /// Serial one-block run — the reference semantics every flow test pins.
    fn run(state: &mut SvmState, txs: Vec<crate::tx::SvmTransaction>) -> Vec<TxOutcome> {
        execute_block_serial(state, &txs, &TestExecutor, &AcceptAll, &ENV)
            .expect("structurally valid fixtures")
            .outcomes
    }

    /// The expected post-state when a tx ABORTS: initial state, payer
    /// debited exactly the fee and nonce bumped, nothing else. Comparing
    /// FULL ROOTS against this is what kills the "abort-path merges every
    /// writable post" mutation (roster item d) — an abort that leaks any
    /// other write moves the root.
    fn fee_only_root(initial: &SvmState, payer_pk: &[u8], fee: u64, bumps: u64) -> [u8; 32] {
        let mut s = initial.clone();
        let addr = wallet_address(payer_pk);
        let mut p = s.get(&addr).expect("payer in manifest").clone();
        p.balance_sat -= fee;
        p.nonce += bumps;
        s.set_account(addr, Some(p));
        s.svm_root()
    }

    /// §8-2 — undeclared write attack + control. The attack program reaches
    /// for mutation of a readonly-declared account through every surface it
    /// has (try_mut — the compile-fail doctests pin that a View offers
    /// nothing else) ⇒ typed abort naming layer 1. Control: identical
    /// program, identical target, declared writable ⇒ succeeds and the state
    /// change is verified.
    #[test]
    fn undeclared_write_is_a_typed_layer1_abort() {
        let target = [0x77; 32];
        let mut state = manifest(&[(PAYER, RICH)]);
        // Target owned by the attack program, funded to its post-write bond.
        state.set_account(
            target,
            Some(Account { balance_sat: bond_for(1), owner: ATTACK_READONLY_ID, nonce: 0, executable: false, data: vec![] }),
        );
        let initial = state.clone();

        // Attack: target declared READONLY.
        let out = run(&mut state, vec![attack_tx(PAYER, target, false, 0)]);
        assert_eq!(
            out[0].result,
            TxResult::Aborted(AbortCause::Program {
                instruction: 0,
                error: ProgramError::AccessViolation(AccessError::MutOnReadonlyDeclared { address: target }),
            }),
            "layer 1 must refuse, typed, naming the layer"
        );
        assert_eq!(out[0].fee_paid, FEE, "abort still pays (§6.4)");
        // Nothing but fee+nonce reached state — kills the abort-merge-all
        // mutation (d).
        assert_eq!(state.svm_root(), fee_only_root(&initial, PAYER, FEE, 1));
        assert_eq!(state.get(&target).unwrap().data, Vec::<u8>::new());

        // CONTROL: same program, target declared WRITABLE ⇒ mutation lands.
        let mut state2 = initial.clone();
        let out2 = run(&mut state2, vec![attack_tx(PAYER, target, true, 0)]);
        assert_eq!(out2[0].result, TxResult::Executed);
        assert_eq!(state2.get(&target).unwrap().data, vec![0xAA]);
    }

    /// §8-2 second half / §6.4 defense-in-depth: a runtime bug (simulated by
    /// the cfg(test) backdoor) that mutates a readonly copy WITHOUT tripping
    /// layer 1 is caught by layer 2's byte verification. This is the test
    /// that goes red if the ReadonlyDrift check is disabled (mutation c) —
    /// proving the two layers are independent, not one layer tested twice.
    #[test]
    fn layer2_catches_a_layer1_bypass() {
        let target = [0x78; 32];
        let mut state = manifest(&[(PAYER, RICH)]);
        state.set_account(target, Some(Account::wallet(bond_for(0))));
        let initial = state.clone();

        let out = run(&mut state, vec![bypass_tx(PAYER, target, 0)]);
        assert_eq!(
            out[0].result,
            TxResult::Aborted(AbortCause::ReadonlyDrift { address: target }),
            "layer 2 must detect the drifted bytes"
        );
        assert_eq!(state.svm_root(), fee_only_root(&initial, PAYER, FEE, 1));
        // Control: the bypass program pointed at a WRITABLE-declared account
        // does nothing (it only scribbles through View) — commits cleanly.
        let mut state2 = initial.clone();
        let mut tx = bypass_tx(PAYER, target, 0);
        tx.header = (1, 0, 1); // reclassify target as writable
        let out2 = run(&mut state2, vec![tx]);
        assert_eq!(out2[0].result, TxResult::Executed);
        assert_eq!(state2.get(&target).unwrap(), initial.get(&target).unwrap());
    }

    /// §8-6 — conservation attack + control. The minter's credit is layer-1
    /// LEGAL; the commit-time u128 conservation check is what refuses the
    /// minted satoshi. Control: a balanced transfer commits.
    #[test]
    fn minting_is_a_commit_time_abort() {
        let target = [0x79; 32];
        let mut state = manifest(&[(PAYER, RICH)]);
        state.set_account(target, Some(Account::wallet(bond_for(0))));
        let initial = state.clone();

        let out = run(&mut state, vec![minter_tx(PAYER, target, 1_000, 0)]);
        match &out[0].result {
            TxResult::Aborted(AbortCause::ConservationViolated { pre_sum, post_sum, fee }) => {
                // payer(RICH) + target(bond) pre; post has the minted 1,000
                // on top of the fee-debited payer.
                assert_eq!(*fee, FEE);
                assert_eq!(post_sum + u128::from(*fee), pre_sum + 1_000);
            }
            other => panic!("expected ConservationViolated, got {other:?}"),
        }
        // Full-root check: the minted satoshis never reached state (kills
        // mutation d on this path too).
        assert_eq!(state.svm_root(), fee_only_root(&initial, PAYER, FEE, 1));

        // CONTROL: balanced transfer of the same magnitude commits.
        let mut state2 = initial.clone();
        let out2 = run(&mut state2, vec![transfer_tx(PAYER, target, 1_000, 0)]);
        assert_eq!(out2[0].result, TxResult::Executed);
        assert_eq!(state2.get(&target).unwrap().balance_sat, bond_for(0) + 1_000);
        assert_eq!(
            state2.get(&wallet_address(PAYER)).unwrap().balance_sat,
            RICH - 1_000 - FEE
        );
    }

    /// §8-5 — meter determinism. Exhaustion aborts at an exactly pinned
    /// reading, identical across repeated runs; control: budget covering
    /// exactly the next step completes. (The cross-thread half of §8-5 rides
    /// in scheduler.rs's equivalence sweep, which includes hog
    /// transactions.)
    #[test]
    fn exhaustion_reading_is_exact_and_reproducible() {
        let mut state = manifest(&[(PAYER, RICH)]);
        let initial = state.clone();
        // Budget: dispatch (1,000) + 2 chunks of 400, then the 3rd refused.
        let budget = COST_INSTRUCTION_DISPATCH + 2 * 400 + 100;
        let expected_reading = COST_INSTRUCTION_DISPATCH + 2 * 400;

        let out = run(&mut state, vec![hog_tx(PAYER, 3, 400, budget, 0)]);
        assert_eq!(
            out[0].result,
            TxResult::Aborted(AbortCause::Program {
                instruction: 0,
                error: ProgramError::Meter(MeterError::Exhausted {
                    requested: 400,
                    consumed: expected_reading,
                    budget,
                }),
            })
        );
        assert_eq!(out[0].units_consumed, expected_reading, "the reading is the refusal point");
        assert_eq!(out[0].fee_paid, fee_for(budget));

        // Reproducibility: identical run, identical bytes.
        let mut state_b = initial.clone();
        let out_b = run(&mut state_b, vec![hog_tx(PAYER, 3, 400, budget, 0)]);
        assert_eq!(out, out_b);
        assert_eq!(state.svm_root(), state_b.svm_root());

        // CONTROL: budget of exactly dispatch + 3 chunks completes.
        let exact = COST_INSTRUCTION_DISPATCH + 3 * 400;
        let mut state_c = initial.clone();
        let out_c = run(&mut state_c, vec![hog_tx(PAYER, 3, 400, exact, 0)]);
        assert_eq!(out_c[0].result, TxResult::Executed);
        assert_eq!(out_c[0].units_consumed, exact);
    }

    /// §5.3 — replay protection. The same transaction twice in one block:
    /// first commits and bumps the nonce, the replay is rejected with NO
    /// second fee. Control: the properly incremented successor commits.
    /// This is the test that goes red if the nonce bump is removed
    /// (mutation b).
    #[test]
    fn replay_is_rejected_fee_free() {
        let target = [0x7A; 32];
        let mut state = manifest(&[(PAYER, RICH)]);
        state.set_account(target, Some(Account::wallet(bond_for(0))));

        let txs = vec![
            transfer_tx(PAYER, target, 100, 0),
            transfer_tx(PAYER, target, 100, 0), // exact replay
            transfer_tx(PAYER, target, 100, 1), // control: correct successor
        ];
        let out = run(&mut state, txs);
        assert_eq!(out[0].result, TxResult::Executed);
        assert_eq!(
            out[1].result,
            TxResult::Rejected(RejectCause::NonceMismatch { expected: 1, got: 0 })
        );
        assert_eq!(out[1].fee_paid, 0, "a replay must not drain fees");
        assert_eq!(out[2].result, TxResult::Executed);
        // Exactly two fees and two transfers left the payer.
        assert_eq!(
            state.get(&wallet_address(PAYER)).unwrap().balance_sat,
            RICH - 2 * (100 + FEE)
        );
        assert_eq!(state.get(&wallet_address(PAYER)).unwrap().nonce, 2);
    }

    /// Signature verification is consulted: the same block under RejectAll
    /// rejects every tx fee-free; under AcceptAll it executes. (The
    /// stateless pubkey↔address binding test lives in tx.rs.)
    #[test]
    fn signature_callback_gates_execution() {
        let target = [0x7B; 32];
        let mk_state = || {
            let mut s = manifest(&[(PAYER, RICH)]);
            s.set_account(target, Some(Account::wallet(bond_for(0))));
            s
        };
        let txs = vec![transfer_tx(PAYER, target, 100, 0)];

        let mut s1 = mk_state();
        let initial_root = s1.svm_root();
        let out = execute_block_serial(&mut s1, &txs, &TestExecutor, &RejectAll, &ENV)
            .unwrap()
            .outcomes;
        assert_eq!(out[0].result, TxResult::Rejected(RejectCause::BadSignature { witness: 0 }));
        assert_eq!(s1.svm_root(), initial_root, "rejected ⇒ zero state effect");

        let mut s2 = mk_state();
        let out2 = execute_block_serial(&mut s2, &txs, &TestExecutor, &AcceptAll, &ENV)
            .unwrap()
            .outcomes;
        assert_eq!(out2[0].result, TxResult::Executed, "control");
    }

    /// §4.2 — the bond floor gates creation. Creating an account funded
    /// below `bond_for(space)` is a commit-time abort; control: funding at
    /// exactly the bond commits, and delete refunds the whole balance.
    #[test]
    fn bond_floor_and_delete_refund() {
        const NEW: &[u8] = b"new-wallet-key";
        // Distinct refund destination: refunding to the fee payer would put
        // the same address in two sections — the §5.2 dedup would (rightly)
        // reject the transaction.
        const HEIR: &[u8] = b"heir-wallet-key";
        let mut state = manifest(&[(PAYER, RICH), (HEIR, RICH)]);
        let initial = state.clone();
        let space = 100u32;
        let bond = bond_for(space as usize);
        let create_fee = fee_for(50_000);

        // Below the floor by one satoshi ⇒ BondFloorViolated.
        let out = run(&mut state, vec![create_tx(PAYER, NEW, bond - 1, space, SYSTEM_PROGRAM_ID, 0)]);
        assert_eq!(
            out[0].result,
            TxResult::Aborted(AbortCause::BondFloorViolated {
                address: wallet_address(NEW),
                balance: bond - 1,
                bond,
            })
        );
        assert_eq!(state.svm_root(), fee_only_root(&initial, PAYER, create_fee, 1));

        // CONTROL: exactly the bond ⇒ created, zeroed data of `space` bytes.
        let mut s2 = initial.clone();
        let out2 = run(&mut s2, vec![create_tx(PAYER, NEW, bond, space, SYSTEM_PROGRAM_ID, 0)]);
        assert_eq!(out2[0].result, TxResult::Executed);
        let created = s2.get(&wallet_address(NEW)).unwrap();
        assert_eq!(created.balance_sat, bond);
        assert_eq!(created.data, vec![0u8; space as usize]);
        assert_eq!(created.owner, SYSTEM_PROGRAM_ID);

        // Delete refunds the WHOLE balance (bond included) and removes the
        // entry — entry-count cost stops when the entry goes (§4.2-2).
        let refund_to = wallet_address(HEIR);
        let out3 = run(&mut s2, vec![delete_tx(PAYER, NEW, refund_to, 1)]);
        assert_eq!(out3[0].result, TxResult::Executed);
        assert!(s2.get(&wallet_address(NEW)).is_none());
        assert_eq!(s2.get(&refund_to).unwrap().balance_sat, RICH + bond);
        assert_eq!(
            s2.get(&wallet_address(PAYER)).unwrap().balance_sat,
            RICH - bond - create_fee - FEE,
        );
    }

    /// The gate program makes read-dependencies observable: outcome depends
    /// on a balance another tx writes. Serial semantics: the gate AFTER the
    /// credit passes, the gate BEFORE it fails — the scheduler equivalence
    /// sweep leans on exactly this observability.
    #[test]
    fn gate_outcomes_track_serial_order() {
        const OTHER: &[u8] = b"other-payer";
        let target = [0x7C; 32];
        let mut state = manifest(&[(PAYER, RICH), (OTHER, RICH)]);
        state.set_account(target, Some(Account::wallet(bond_for(0))));
        let threshold = bond_for(0) + 500;

        let txs = vec![
            gate_tx(OTHER, target, threshold, 0),         // before credit ⇒ fails
            transfer_tx(PAYER, target, 500, 0),           // credit to threshold
            gate_tx(OTHER, target, threshold, 1),         // after credit ⇒ passes
        ];
        let out = run(&mut state, txs);
        assert_eq!(
            out[0].result,
            TxResult::Aborted(AbortCause::Program { instruction: 0, error: ProgramError::Custom(GATE_ERR) })
        );
        assert_eq!(out[1].result, TxResult::Executed);
        assert_eq!(out[2].result, TxResult::Executed, "control: same gate, post-credit");
    }

    /// Rejected pre-checks leave literally nothing behind (the third effect
    /// family): missing payer, non-wallet payer, unpayable fee.
    #[test]
    fn rejections_have_zero_state_effect() {
        let target = [0x7D; 32];
        let mut state = manifest(&[(PAYER, RICH)]);
        state.set_account(target, Some(Account::wallet(bond_for(0))));
        // A payer whose wallet was never funded:
        let ghost: &[u8] = b"ghost-payer";
        // A payer that cannot cover fee + own bond floor:
        let poor: &[u8] = b"poor-payer";
        state.set_account(wallet_address(poor), Some(Account::wallet(bond_for(0) + 100)));
        let initial_root = state.svm_root();

        let out = run(
            &mut state,
            vec![transfer_tx(ghost, target, 1, 0), transfer_tx(poor, target, 1, 0)],
        );
        assert_eq!(out[0].result, TxResult::Rejected(RejectCause::FeePayerMissing));
        assert_eq!(
            out[1].result,
            TxResult::Rejected(RejectCause::FeeUnpayable {
                required: FEE + bond_for(0),
                available: bond_for(0) + 100,
            })
        );
        assert_eq!(state.svm_root(), initial_root);

        // Control: a funded payer in the same shape executes.
        let out2 = run(&mut state, vec![transfer_tx(PAYER, target, 1, 0)]);
        assert_eq!(out2[0].result, TxResult::Executed);
    }

    /// Determinism smoke over a mixed workload: the same block replayed from
    /// the same state twice produces byte-identical outcomes and roots.
    /// (The serial/parallel matrix is scheduler.rs's §8-1; this pins plain
    /// run-to-run stability including abort readings.)
    #[test]
    fn identical_replays_are_byte_identical() {
        let target = [0x7E; 32];
        let mk = || {
            let mut s = manifest(&[(PAYER, RICH)]);
            s.set_account(target, Some(Account::wallet(bond_for(0))));
            s
        };
        let mut rng = DetRng::new(99);
        let mut txs = Vec::new();
        for n in 0..10u64 {
            let amt = rng.below(1_000) + 1;
            txs.push(transfer_tx(PAYER, target, amt, n));
        }
        txs.push(hog_tx(PAYER, 5, 300, 2_000, 10)); // exhausts mid-stream

        let (mut a, mut b) = (mk(), mk());
        let oa = run(&mut a, txs.clone());
        let ob = run(&mut b, txs);
        assert_eq!(oa, ob);
        assert_eq!(a.svm_root(), b.svm_root());
    }
}
