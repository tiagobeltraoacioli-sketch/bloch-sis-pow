// SPDX-License-Identifier: AGPL-3.0-or-later
//! GIP-0002 at the mempool door and in proposer selection: network-bound
//! transfer signing (WT-03) and the delegation commission cap (WT-04), each
//! behind a dual-acceptance window. The schedules are passed in, so both
//! boundaries are exercised without arming anything in this build.
use super::*;
use bloch_pos_committee::params::DualAcceptanceGate;
use bloch_pos_committee::transition::{
    FundedDelegate, FundedDelegateV2, FundingInput, TransferInput, TransferInputV2, TransferOutput, WitnessKey,
};
use std::cell::Cell;

const NET: [u8; 32] = [0xA1; 32];
const OTHER_NET: [u8; 32] = [0xB2; 32];
const ACCEPT: u64 = 9_000;
const ENFORCE: u64 = 9_630;

fn schedule(sighash: DualAcceptanceGate, commission_cap: DualAcceptanceGate) -> WalletConsensusSchedule {
    WalletConsensusSchedule { sighash, commission_cap }
}

fn window() -> WalletConsensusSchedule {
    let gate = DualAcceptanceGate { accept_epoch: ACCEPT, enforce_epoch: ENFORCE };
    schedule(gate, gate)
}

fn unset() -> WalletConsensusSchedule {
    schedule(DualAcceptanceGate::INERT, DualAcceptanceGate::INERT)
}

/// Which root the witnesses of a fixture transfer are signed over.
#[derive(Clone, Copy)]
enum Signed {
    Legacy,
    Bound([u8; 32]),
    /// First input over the bound root, second over the legacy root.
    Mixed,
}

/// A two-input V1 transfer with real hybrid witnesses.
fn transfer(signed: Signed) -> PosTransaction {
    let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[9u8; 32]).expect("hybrid keypair");
    let input = |vout| TransferInput { txid: [0x11; 32], vout, pubkey: pk.clone(), signature: Vec::new() };
    let mut tx = PosTransaction::Transfer {
        inputs: vec![input(0), input(1)],
        outputs: vec![TransferOutput { value: 1_000, script_hash: [0x22; 32] }],
        tx_bytes: 0,
        tip_millisat_per_gas: 0,
    };
    let legacy = tx.spend_signing_root();
    let roots = match signed {
        Signed::Legacy => [legacy, legacy],
        Signed::Bound(domain) => [tx.network_bound_signing_root(&domain); 2],
        Signed::Mixed => [tx.network_bound_signing_root(&NET), legacy],
    };
    if let PosTransaction::Transfer { inputs, .. } = &mut tx {
        for (i, root) in inputs.iter_mut().zip(roots) {
            i.signature = bloch_crypto::crypto::sign(&sk, &root).expect("sign");
        }
    }
    tx
}

/// The same logical transfer in the deduplicated-witness format.
fn transfer_v2(domain: Option<[u8; 32]>) -> PosTransaction {
    let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[9u8; 32]).expect("hybrid keypair");
    let mut tx = PosTransaction::TransferV2 {
        keys: vec![WitnessKey { pubkey: pk, signature: Vec::new() }],
        inputs: (0..2).map(|vout| TransferInputV2 { txid: [0x11; 32], vout, key_index: 0 }).collect(),
        outputs: vec![TransferOutput { value: 1_000, script_hash: [0x22; 32] }],
        tx_bytes: 0,
        tip_millisat_per_gas: 0,
    };
    let root = match domain {
        Some(domain) => tx.network_bound_signing_root(&domain),
        None => tx.spend_signing_root(),
    };
    if let PosTransaction::TransferV2 { keys, .. } = &mut tx {
        keys[0].signature = bloch_crypto::crypto::sign(&sk, &root).expect("sign");
    }
    tx
}

/// The real verifier, counting its calls.
struct Counting<'a>(&'a Cell<usize>);
impl SignatureVerifier for Counting<'_> {
    fn verify_with_key(&self, pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
        self.0.set(self.0.get() + 1);
        HybridVerifier::new().verify_with_key(pk, root, sig)
    }
}

/// Admission verdict, with how many verifications the charged verifier and
/// the trial verifier ran.
fn admit(
    tx: &PosTransaction,
    epoch: u64,
    domain: Option<&[u8; 32]>,
    schedule: &WalletConsensusSchedule,
) -> (Result<Option<SpendRootKind>, &'static str>, usize, usize) {
    let (charged, trial) = (Cell::new(0), Cell::new(0));
    let verdict = admissible_under(tx, epoch, domain, &Counting(&charged), &Counting(&trial), schedule);
    (verdict, charged.get(), trial.get())
}

/// **Unset means unchanged at the mempool door.** With both windows unset a
/// legacy-signed transfer is admitted with one verification per input and no
/// trial, at any epoch, with or without a network domain; a transfer signed
/// over a bound root is refused. This is what the compiled schedule is.
#[test]
fn with_the_window_unset_admission_is_the_historical_rule() {
    assert_eq!(WalletConsensusSchedule::compiled(), unset(), "this build arms neither window");
    let legacy = transfer(Signed::Legacy);
    let bound = transfer(Signed::Bound(NET));
    // Epochs below HF3 (7360): one `verify_with_key` per witness.
    for epoch in [0, 4_669, 7_000] {
        for domain in [None, Some(&NET)] {
            assert_eq!(admit(&legacy, epoch, domain, &unset()), (Ok(Some(SpendRootKind::Legacy)), 2, 0));
            let (verdict, charged, trial) = admit(&bound, epoch, domain, &unset());
            assert_eq!(verdict, Err("transfer carries a signature that does not verify"));
            assert_eq!((charged, trial), (1, 0), "refused at the first witness, no trial");
        }
    }
    // The wrapper every other caller uses reads the compiled (unset) schedule.
    assert!(admissible_with_network_verifier(&legacy, 0, Some(&NET), &HybridVerifier::new()).is_ok());
    assert!(admissible_with_network_verifier(&bound, 0, Some(&NET), &HybridVerifier::new()).is_err());
}

/// The window at the mempool door, at each boundary epoch, for both
/// transfer formats.
#[test]
fn each_root_is_admitted_exactly_inside_its_side_of_the_window() {
    let s = window();
    let (legacy, bound) = (transfer(Signed::Legacy), transfer(Signed::Bound(NET)));
    let (legacy_v2, bound_v2) = (transfer_v2(None), transfer_v2(Some(NET)));
    let refused = Err("transfer carries a signature that does not verify");
    for (epoch, legacy_ok, bound_ok) in [
        (ACCEPT - 1, true, false),
        (ACCEPT, true, true),
        (ENFORCE - 1, true, true),
        (ENFORCE, false, true),
        (ENFORCE + 1, false, true),
    ] {
        let verdict = |ok: bool, kind| if ok { Ok(Some(kind)) } else { refused };
        assert_eq!(admit(&legacy, epoch, Some(&NET), &s).0, verdict(legacy_ok, SpendRootKind::Legacy), "epoch {epoch}");
        assert_eq!(admit(&bound, epoch, Some(&NET), &s).0, verdict(bound_ok, SpendRootKind::NetworkBound), "epoch {epoch}");
        assert_eq!(admit(&legacy_v2, epoch, Some(&NET), &s).0, verdict(legacy_ok, SpendRootKind::Legacy), "V2, epoch {epoch}");
        assert_eq!(admit(&bound_v2, epoch, Some(&NET), &s).0, verdict(bound_ok, SpendRootKind::NetworkBound), "V2, epoch {epoch}");
    }
}

/// Inside the window the only extra work is one TRIAL of the first witness
/// (uncharged at the real door); a bound transfer needs no second root, and
/// a transfer signed half and half is refused.
#[test]
fn inside_the_window_the_first_witness_is_tried_once() {
    let s = window();
    // Bound: the trial answers yes, the second witness is an ordinary check.
    assert_eq!(
        admit(&transfer(Signed::Bound(NET)), ACCEPT, Some(&NET), &s),
        (Ok(Some(SpendRootKind::NetworkBound)), 1, 1)
    );
    // Legacy: the trial answers no, then both witnesses under the legacy root.
    assert_eq!(admit(&transfer(Signed::Legacy), ACCEPT, Some(&NET), &s), (Ok(Some(SpendRootKind::Legacy)), 2, 1));
    // Mixed: refused, whichever witness comes first.
    assert!(admit(&transfer(Signed::Mixed), ACCEPT, Some(&NET), &s).0.is_err());
    // Bound to another network: refused in the window and after it.
    for epoch in [ACCEPT, ENFORCE] {
        assert!(admit(&transfer(Signed::Bound(OTHER_NET)), epoch, Some(&NET), &s).0.is_err());
    }
    // From enforcement there is one root again: no trial.
    assert_eq!(
        admit(&transfer(Signed::Bound(NET)), ENFORCE, Some(&NET), &s),
        (Ok(Some(SpendRootKind::NetworkBound)), 2, 0)
    );
    // A node whose state has no network domain: legacy through the window,
    // nothing from enforcement.
    assert_eq!(admit(&transfer(Signed::Legacy), ACCEPT, None, &s), (Ok(Some(SpendRootKind::Legacy)), 2, 0));
    assert_eq!(
        admit(&transfer(Signed::Legacy), ENFORCE, None, &s).0,
        Err("network-bound spend gate requires a committed genesis domain")
    );
}

/// A failed trial is not charged to the sender; the verification after it
/// is. So a legacy-signed transfer relayed inside the window does not spend
/// its relayer's failure allowance, and garbage still does.
#[test]
fn a_failed_trial_is_not_charged_but_a_failed_verification_is() {
    let gossip = verification::GossipVerifier::new(HybridVerifier::new());
    let source = Some([0x5C; 32]);
    let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[9u8; 32]).unwrap();
    let sig = bloch_crypto::crypto::sign(&sk, &[1; 32]).unwrap();
    let verifier = |charge: bool| {
        let v = gossip.budgeted_for_source(7, 64, source, 64).with_failure_allowance(1);
        if charge { v } else { v.without_failure_charge() }
    };
    // Three failed trials (three different wrong roots): still admitted.
    for wrong in [[2u8; 32], [3; 32], [4; 32]] {
        let trial = verifier(false);
        assert!(!trial.verify_with_key(&pk, &wrong, &sig));
        assert!(!trial.limited());
    }
    assert!(verifier(true).verify_with_key(&pk, &[1; 32], &sig), "the source is not cut off");
    // One charged failure spends the allowance of 1: both kinds are refused
    // without verification from here on.
    let charged = verifier(true);
    assert!(!charged.verify_with_key(&pk, &[5; 32], &sig));
    for charge in [true, false] {
        let next = verifier(charge);
        assert!(!next.verify_with_key(&pk, &[1; 32], &sig));
        assert!(next.limited() && next.failure_limited());
    }
}

fn delegate() -> FundedDelegate {
    let (pk, _) = bloch_crypto::crypto::generate_keypair_from_seed(&[9u8; 32]).unwrap();
    let mut tx = FundedDelegate {
        network_domain: NET,
        valid_until_epoch: ENFORCE + 100,
        funding_pubkey: pk,
        inputs: vec![FundingInput { txid: [0x31; 32], vout: 0 }],
        validator_pubkey_hash: [0x44; 32],
        amount_sat: bloch_pos_committee::delegation::MIN_DELEGATION_SAT,
        change: TransferOutput { value: 50_000, script_hash: [0x82; 32] },
        max_base_fee_millisat_per_gas: 100,
        tip_millisat_per_gas: 0,
        tx_bytes: 0,
        funding_signature: Vec::new(),
    };
    tx.tx_bytes = tx.reserved_tx_bytes();
    tx
}

fn capped(max_commission_bps: u128) -> FundedDelegateV2 {
    let mut tx = FundedDelegateV2 { request: delegate(), max_commission_bps };
    tx.request.tx_bytes = tx.reserved_tx_bytes();
    tx
}

/// The delegation forms at the mempool door (shape and gate; the stateful
/// lifecycle door then runs the consensus rule itself, including the cap).
#[test]
fn each_delegation_form_is_admitted_exactly_inside_its_side_of_the_window() {
    let v1 = PosTransaction::FundedDelegate(delegate());
    let v2 = PosTransaction::FundedDelegateV2(capped(500));
    let ok = |tx: &PosTransaction, epoch, s: &WalletConsensusSchedule| admit(tx, epoch, Some(&NET), s).0.is_ok();
    // Unset: the capless form as always, the capped tag never.
    for epoch in [4_669, ACCEPT, ENFORCE + 1] {
        assert!(ok(&v1, epoch, &unset()));
        assert!(!ok(&v2, epoch, &unset()));
    }
    let s = window();
    for (epoch, v1_ok, v2_ok) in [
        (ACCEPT - 1, true, false),
        (ACCEPT, true, true),
        (ENFORCE - 1, true, true),
        (ENFORCE, false, true),
        (ENFORCE + 1, false, true),
    ] {
        assert_eq!(ok(&v1, epoch, &s), v1_ok, "capless at epoch {epoch}");
        assert_eq!(ok(&v2, epoch, &s), v2_ok, "capped at epoch {epoch}");
    }
    // A cap above 100% and an expired capped request are refused.
    assert!(!ok(&PosTransaction::FundedDelegateV2(capped(10_001)), ACCEPT, &s));
    assert!(!ok(&v2, ENFORCE + 101, &s));
    // The capped form is a funded delegation: nothing before that feature.
    let early = DualAcceptanceGate { accept_epoch: 100, enforce_epoch: 200 };
    assert!(!ok(&v2, 150, &schedule(DualAcceptanceGate::INERT, early)));
}

/// What the proposer leaves out across each boundary: entries that were
/// valid when admitted and are not valid in the block being built.
#[test]
fn selection_drops_entries_that_a_boundary_made_invalid() {
    let s = window();
    let transfer = transfer_v2(None);
    let v1 = PosTransaction::FundedDelegate(delegate());
    let v2 = PosTransaction::FundedDelegateV2(capped(500));
    for (epoch, legacy_transfer, capless, capped_form) in [
        (ACCEPT - 1, false, false, true),
        (ACCEPT, false, false, false),
        (ENFORCE - 1, false, false, false),
        (ENFORCE, true, true, false),
    ] {
        assert_eq!(wallet_rules_refuse_selection(&transfer, true, epoch, &s), legacy_transfer, "epoch {epoch}");
        // A transfer admission saw signed over the bound root is never dropped.
        assert!(!wallet_rules_refuse_selection(&transfer, false, epoch, &s));
        assert_eq!(wallet_rules_refuse_selection(&v1, false, epoch, &s), capless, "epoch {epoch}");
        assert_eq!(wallet_rules_refuse_selection(&v2, false, epoch, &s), capped_form, "epoch {epoch}");
    }
    // Unset: nothing is dropped except the capped tag, which was never valid.
    for epoch in [0, ENFORCE, u64::MAX] {
        assert!(!wallet_rules_refuse_selection(&transfer, true, epoch, &unset()));
        assert!(!wallet_rules_refuse_selection(&v1, false, epoch, &unset()));
        assert!(wallet_rules_refuse_selection(&v2, false, epoch, &unset()));
    }
}

/// The mempool remembers which transfers were signed over the legacy root,
/// and forgets with the entry.
#[test]
fn the_mempool_tracks_legacy_signed_transfers_with_their_entries() {
    let mut pool = admission::Mempool::default();
    let tx = transfer_v2(None);
    let key = tx.canonical_bytes();
    pool.mark_legacy_spend_root(&key);
    assert!(!pool.signed_over_legacy_root(&key), "no entry, no mark");
    let txid = tx.txid();
    pool.insert_with_txid(key.clone(), tx, txid);
    assert!(!pool.signed_over_legacy_root(&key));
    pool.mark_legacy_spend_root(&key);
    assert!(pool.signed_over_legacy_root(&key));
    pool.remove(&key);
    assert!(!pool.signed_over_legacy_root(&key));
}

/// The capped request maps to the same mempool source and reserved inputs
/// as the capless one, so the per-source and input-conflict limits hold.
#[test]
fn a_capped_delegation_has_the_capless_ones_source_and_inputs() {
    let v1 = PosTransaction::FundedDelegate(delegate());
    let v2 = PosTransaction::FundedDelegateV2(capped(500));
    assert!(tx_source_hash(&v1).is_some());
    assert_eq!(tx_source_hash(&v1), tx_source_hash(&v2));
    assert_eq!(Engine::spent_outpoints(&v1), Engine::spent_outpoints(&v2));
    assert_eq!(Engine::spent_outpoints(&v2), Some(vec![([0x31; 32], 0)]));
}
