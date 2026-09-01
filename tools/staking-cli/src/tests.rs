// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for `bloch-stake` — round-trips through the REAL consensus decoder
//! with REAL hybrid keys, and the adversarial refusals: every rail the tool
//! promises is pinned here.
//!
//! The activation-epoch trick: the four staking flag days ship INERT
//! (`u64::MAX`), and this crate must not (and cannot) reach into the
//! consensus crate's test-only rehearsal hooks. `u64::MAX` is the one epoch
//! value that satisfies an unarmed gate (`epoch >= u64::MAX`), so positive
//! paths plan at `EPOCH_PAST_GATE` and the gate refusals plan at a live
//! epoch. If a flag day is ever armed to a real epoch, both sides keep
//! working — the gate check reads the constant, never a copy.

use super::*;
use std::sync::OnceLock;

const EPOCH_PAST_GATE: u64 = u64::MAX;
const LIVE_EPOCH: u64 = 1_400;

/// One real hybrid keypair (ML-DSA-65 ‖ Falcon-1024), generated once —
/// keygen is expensive and every test that signs shares it.
fn funding_key() -> &'static (Vec<u8>, Vec<u8>) {
    static K: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    K.get_or_init(bloch_crypto::crypto::generate_keypair)
}

fn validator_key() -> &'static (Vec<u8>, Vec<u8>) {
    static K: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    K.get_or_init(bloch_crypto::crypto::generate_keypair)
}

fn stranger_key() -> &'static (Vec<u8>, Vec<u8>) {
    static K: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    K.get_or_init(bloch_crypto::crypto::generate_keypair)
}

fn funding_addr() -> Address {
    Address::from_pubkey(&funding_key().0, Network::Mainnet)
}

fn withdrawal_addr() -> Address {
    // A cold address unrelated to both keys.
    Address::from_pubkey(&stranger_key().0, Network::Mainnet)
}

/// Coins that comfortably cover the minimum bond plus fees.
fn rich_coins() -> Vec<Coin> {
    vec![
        Coin { txid: [0x11; 32], vout: 0, value_sat: 3_000_000_000_000 }, // 30,000 BLCH
        Coin { txid: [0x22; 32], vout: 1, value_sat: 1_000_000_000_000 }, // 10,000 BLCH
    ]
}

const ACTIVE_STAKE: u128 = 3_200_000 * SAT_PER_BLCH as u128; // 64 × 50k BLCH
const BASE_FEE: u128 = 10; // the floor
const MIN_BOND: u128 = MIN_DEPOSIT_SAT; // 25,000 BLCH

fn plan_min_deposit(epoch: u64, rehearsal: bool) -> Result<DepositPlan, DepositBuildError> {
    build_deposit_plan(
        &funding_addr(),
        &withdrawal_addr(),
        &validator_key().0,
        [0x5A; 32],
        250,
        MIN_BOND,
        &rich_coins(),
        epoch,
        ACTIVE_STAKE,
        BASE_FEE,
        DEFAULT_TIP_MILLISAT_PER_GAS,
        &[],
        rehearsal,
    )
}

// ═══════════════════════════════════════════ deposit: the positive path ═════

/// The full deposit lifecycle with real keys: plan → both signatures →
/// broadcast checks → canonical bytes → THE REAL DECODER → byte-identical
/// transaction. This is the test that proves a third party can build the
/// bytes the chain will accept.
#[test]
fn deposit_round_trips_through_the_real_decoder_with_real_keys() {
    let plan = plan_min_deposit(EPOCH_PAST_GATE, false).expect("a funded, active plan builds");
    check_deposit_plan(&plan).expect("a fresh plan passes its own integrity check");

    // Exact conservation is in the plan by construction.
    let spent: u128 = plan.inputs.iter().map(|i| i.value_sat as u128).sum();
    assert_eq!(
        spent,
        plan.amount_sat + plan.change_sat as u128 + plan.base_fee_sat + plan.tip_fee_sat,
        "sum(inputs) == amount + change + fee, exactly"
    );

    let mut sd = SignedDeposit {
        plan: plan.clone(),
        funding_pubkey: None,
        funding_signature: None,
        proof_of_possession: None,
    };
    let (fpk, fsk) = funding_key();
    let (vpk, vsk) = validator_key();
    sign_deposit_funding(&mut sd, fpk, fsk).expect("the owning key signs the funding role");
    sign_deposit_pop(&mut sd, vpk, vsk).expect("the validator key signs its own PoP");

    let raw = check_signed_deposit(&sd).expect("a fully signed deposit passes broadcast checks");
    assert!((raw.len() as u64) <= plan.tx_bytes, "the declared tx_bytes bounds the encoding");

    // Through the REAL decoder, and byte-identical on re-encode.
    let decoded = PosTransaction::from_canonical_bytes(&raw).expect("canonical bytes decode");
    assert_eq!(decoded.canonical_bytes(), raw, "decode ∘ encode is the identity");
    assert_eq!(hex::encode(decoded.txid()), plan.txid, "the txid survives the round trip");
    match &decoded {
        PosTransaction::DepositV2 { amount_sat, inputs, change, .. } => {
            assert_eq!(*amount_sat, MIN_BOND);
            assert_eq!(inputs.len(), plan.inputs.len());
            assert_eq!(change.len(), usize::from(plan.change_sat > 0));
        }
        other => panic!("decoded to the wrong variant: {other:?}"),
    }

    // The roots the plan advertised are the consensus crate's, not copies.
    let tx = deposit_tx_from_plan(&plan, &[], &[], &[]).unwrap();
    assert_eq!(hex::encode(tx.spend_signing_root()), plan.spend_signing_root);
    assert_eq!(
        hex::encode(tx.deposit_pop_signing_root().expect("framed key parses")),
        plan.pop_signing_root
    );
}

/// The two roles can be filled on different machines, in either order, and
/// broadcast refuses until both are present.
#[test]
fn deposit_split_custody_requires_both_roles() {
    let plan = plan_min_deposit(EPOCH_PAST_GATE, false).unwrap();
    let mut sd = SignedDeposit {
        plan,
        funding_pubkey: None,
        funding_signature: None,
        proof_of_possession: None,
    };
    let err = check_signed_deposit(&sd).unwrap_err();
    assert!(err.contains("funding witness is missing"), "{err}");

    let (vpk, vsk) = validator_key();
    sign_deposit_pop(&mut sd, vpk, vsk).unwrap();
    let err = check_signed_deposit(&sd).unwrap_err();
    assert!(err.contains("funding witness is missing"), "{err}");

    let (fpk, fsk) = funding_key();
    sign_deposit_funding(&mut sd, fpk, fsk).unwrap();
    check_signed_deposit(&sd).expect("both roles present — broadcastable");
}

// ═══════════════════════════════════════════════ deposit: the refusals ═════

#[test]
fn deposit_refuses_below_minimum() {
    let too_small = MIN_BOND - 1;
    let err = build_deposit_plan(
        &funding_addr(),
        &withdrawal_addr(),
        &validator_key().0,
        [0x5A; 32],
        0,
        too_small,
        &rich_coins(),
        EPOCH_PAST_GATE,
        ACTIVE_STAKE,
        BASE_FEE,
        DEFAULT_TIP_MILLISAT_PER_GAS,
        &[],
        false,
    )
    .unwrap_err();
    assert_eq!(
        err,
        DepositBuildError::BelowMinimum { amount_sat: too_small, min_sat: MIN_DEPOSIT_SAT }
    );
    assert!(err.to_string().contains("MIN_DEPOSIT_SAT"), "{err}");
}

#[test]
fn deposit_refuses_above_the_chain_derived_cap() {
    // 1% of this active stake is 32,000 BLCH; a 40,000 BLCH bond exceeds it.
    let big = 40_000 * SAT_PER_BLCH as u128;
    let cap = deposit_cap_sat(ACTIVE_STAKE);
    assert!(big > cap, "test setup: the bond must exceed the cap");
    let coins = vec![Coin { txid: [0x11; 32], vout: 0, value_sat: 5_000_000_000_000 }];
    let err = build_deposit_plan(
        &funding_addr(),
        &withdrawal_addr(),
        &validator_key().0,
        [0x5A; 32],
        0,
        big,
        &coins,
        EPOCH_PAST_GATE,
        ACTIVE_STAKE,
        BASE_FEE,
        DEFAULT_TIP_MILLISAT_PER_GAS,
        &[],
        false,
    )
    .unwrap_err();
    assert_eq!(err, DepositBuildError::AboveCap { amount_sat: big, cap_sat: cap });
    assert!(err.to_string().contains("per-validator cap"), "{err}");
}

#[test]
fn deposit_refuses_when_the_format_is_not_active_naming_the_epoch() {
    let err = plan_min_deposit(LIVE_EPOCH, false).unwrap_err();
    let DepositBuildError::NotActive(msg) = &err else {
        panic!("expected NotActive, got {err:?}");
    };
    // The gate names FUNDED_STAKING_ACTIVATION_EPOCH, not a second
    // deposit-only constant: consensus unified the two ("ONE constant for the
    // whole feature", `transition::deposit_funding_active`), and an earlier
    // draft of this tool named the retired `DEPOSIT_FUNDING_ACTIVATION_EPOCH`.
    // A refusal that names a constant the codebase does not have sends the
    // operator hunting for a flag day nobody can arm, so the name is pinned
    // here against the crate that owns it.
    assert_eq!(
        StakingFormat::DepositV2.constant_name(),
        "FUNDED_STAKING_ACTIVATION_EPOCH"
    );
    assert_eq!(
        StakingFormat::DepositV2.activation_epoch(),
        bloch_pos_committee::params::FUNDED_STAKING_ACTIVATION_EPOCH
    );
    assert!(msg.contains("FUNDED_STAKING_ACTIVATION_EPOCH"), "{msg}");
    assert!(msg.contains("INERT"), "names the unarmed state: {msg}");
    assert!(msg.contains(&LIVE_EPOCH.to_string()), "names the chain's epoch: {msg}");
}

#[test]
fn deposit_rehearsal_plans_but_can_never_broadcast() {
    let plan = plan_min_deposit(LIVE_EPOCH, true).expect("--rehearsal lifts only the gate");
    assert!(plan.rehearsal);
    let mut sd = SignedDeposit {
        plan,
        funding_pubkey: None,
        funding_signature: None,
        proof_of_possession: None,
    };
    let (fpk, fsk) = funding_key();
    let (vpk, vsk) = validator_key();
    sign_deposit_funding(&mut sd, fpk, fsk).expect("rehearsal artifacts may be signed");
    sign_deposit_pop(&mut sd, vpk, vsk).unwrap();
    let err = check_signed_deposit(&sd).unwrap_err();
    assert!(err.contains("REHEARSAL"), "{err}");
}

#[test]
fn deposit_refuses_sub_dust_change_with_exact_alternatives() {
    // One coin, sized so that change lands at 100 sat (< 546).
    let (_, _, base_fee_sat, tip_fee_sat) = {
        // Derive the fee the builder will compute for 1 input + 1 change.
        let tx_bytes = {
            // Probe through the public path: build a plan with generous
            // funds and read its fee terms — the builder's own arithmetic.
            let p = plan_min_deposit(EPOCH_PAST_GATE, false).unwrap();
            assert_eq!(p.inputs.len(), 1, "largest-first selects the 30k coin alone");
            p.tx_bytes
        };
        let c = bloch_pos_committee::fee_market::charge(
            bloch_pos_committee::fee_market::TxClass::Eutxo { inputs: 2 },
            tx_bytes,
            BASE_FEE,
            DEFAULT_TIP_MILLISAT_PER_GAS,
        );
        (tx_bytes, c.gas, c.base_fee_sat, c.priority_fee_sat)
    };
    let fee = base_fee_sat + tip_fee_sat;
    let trapped_change: u64 = 100;
    let coin_value = MIN_BOND + fee + trapped_change as u128;
    let coins = vec![Coin { txid: [0x33; 32], vout: 0, value_sat: coin_value as u64 }];
    let err = build_deposit_plan(
        &funding_addr(),
        &withdrawal_addr(),
        &validator_key().0,
        [0x5A; 32],
        0,
        MIN_BOND,
        &coins,
        EPOCH_PAST_GATE,
        ACTIVE_STAKE,
        BASE_FEE,
        DEFAULT_TIP_MILLISAT_PER_GAS,
        &[],
        false,
    )
    .unwrap_err();
    let DepositBuildError::DustChange { change_sat, bond_less_sat, bond_more_sat } = err else {
        panic!("expected DustChange, got {err:?}");
    };
    assert_eq!(change_sat, trapped_change);
    // The alternatives are exact: bonding more consumes the coin exactly;
    // bonding less parks the change on the dust floor.
    assert_eq!(bond_more_sat, MIN_BOND + trapped_change as u128);
    assert_eq!(bond_less_sat, MIN_BOND - (DUST_THRESHOLD_SAT - trapped_change) as u128);
}

#[test]
fn deposit_refuses_a_registered_key() {
    let pubkey_hash: [u8; 32] =
        sha3::Sha3_256::digest(&validator_key().0).into();
    let err = build_deposit_plan(
        &funding_addr(),
        &withdrawal_addr(),
        &validator_key().0,
        [0x5A; 32],
        0,
        MIN_BOND,
        &rich_coins(),
        EPOCH_PAST_GATE,
        ACTIVE_STAKE,
        BASE_FEE,
        DEFAULT_TIP_MILLISAT_PER_GAS,
        &[(7, pubkey_hash)],
        false,
    )
    .unwrap_err();
    assert_eq!(err, DepositBuildError::AlreadyRegistered { index: 7 });
}

#[test]
fn deposit_refuses_a_malformed_validator_key() {
    // Right length, wrong magic.
    let mut bad = validator_key().0.clone();
    bad[0] ^= 0xFF;
    let err = build_deposit_plan(
        &funding_addr(),
        &withdrawal_addr(),
        &bad,
        [0x5A; 32],
        0,
        MIN_BOND,
        &rich_coins(),
        EPOCH_PAST_GATE,
        ACTIVE_STAKE,
        BASE_FEE,
        DEFAULT_TIP_MILLISAT_PER_GAS,
        &[],
        false,
    )
    .unwrap_err();
    assert!(matches!(err, DepositBuildError::BadValidatorKey(_)), "{err:?}");
}

#[test]
fn deposit_plan_tamper_is_caught() {
    let plan = plan_min_deposit(EPOCH_PAST_GATE, false).unwrap();

    // A one-satoshi lie about change breaks exact conservation.
    let mut worse = plan.clone();
    worse.change_sat += 1;
    let err = check_deposit_plan(&worse).unwrap_err();
    assert!(err.contains("does not conserve value"), "{err}");

    // A redirected withdrawal address changes the PoP root and the txid.
    let mut redirected = plan.clone();
    redirected.withdrawal_address =
        Address::from_pubkey(&stranger_key().0, Network::Mainnet).to_string();
    // (stranger IS the withdrawal address in the fixture — redirect to the
    // funding address instead so the address actually changes)
    redirected.withdrawal_address = funding_addr().to_string();
    let err = check_deposit_plan(&redirected).unwrap_err();
    assert!(
        err.contains("signing root") || err.contains("PoP"),
        "a moved credential must break a committed root: {err}"
    );

    // A fee term that is not the consensus fee market's is refused.
    let mut misfeed = plan.clone();
    misfeed.tip_fee_sat += 1;
    let err = check_deposit_plan(&misfeed).unwrap_err();
    assert!(err.contains("conserve") || err.contains("fee market"), "{err}");
}

#[test]
fn deposit_wrong_keys_are_refused_at_signing() {
    let plan = plan_min_deposit(EPOCH_PAST_GATE, false).unwrap();
    let mut sd = SignedDeposit {
        plan,
        funding_pubkey: None,
        funding_signature: None,
        proof_of_possession: None,
    };
    // A stranger cannot fill the funding role: the key must derive the
    // funding address.
    let (spk, ssk) = stranger_key();
    let err = sign_deposit_funding(&mut sd, spk, ssk).unwrap_err();
    assert!(err.contains("does not own the funding address"), "{err}");
    // A stranger cannot fill the PoP role: the key must BE the registered
    // validator key.
    let err = sign_deposit_pop(&mut sd, spk, ssk).unwrap_err();
    assert!(err.contains("not the plan's validator key"), "{err}");
}

#[test]
fn deposit_forged_pop_is_refused_at_broadcast() {
    let plan = plan_min_deposit(EPOCH_PAST_GATE, false).unwrap();
    let mut sd = SignedDeposit {
        plan,
        funding_pubkey: None,
        funding_signature: None,
        proof_of_possession: None,
    };
    let (fpk, fsk) = funding_key();
    sign_deposit_funding(&mut sd, fpk, fsk).unwrap();
    // A "PoP" produced by the wrong key, pasted into the artifact by hand.
    let root_v = hex::decode(&sd.plan.pop_signing_root).unwrap();
    let root: [u8; 32] = root_v.try_into().unwrap();
    let forged = bloch_crypto::crypto::sign(&stranger_key().1, &root).unwrap();
    sd.proof_of_possession = Some(hex::encode(forged));
    let err = check_signed_deposit(&sd).unwrap_err();
    assert!(err.contains("proof of possession does not verify"), "{err}");
}

// ═════════════════════════════════════════════════════════════════ exit ═════

fn active_validator(pubkey: &[u8]) -> rpc::ValidatorInfo {
    rpc::ValidatorInfo {
        index: 3,
        pubkey_hash: sha3::Sha3_256::digest(pubkey).into(),
        state: "active".into(),
        own_stake_sat: MIN_BOND,
        slashed: false,
        activation_epoch: Some(100),
        exit_epoch: None,
        withdrawable_epoch: None,
    }
}

#[test]
fn exit_signs_and_verifies_with_the_controlling_key() {
    let (vpk, vsk) = validator_key();
    let v = active_validator(vpk);
    let plan = build_exit_plan(&v, EPOCH_PAST_GATE, false).expect("an active record can exit");
    // The signing root is the consensus crate's, not a copy.
    let exit = check_exit_plan(&plan).unwrap();
    assert_eq!(hex::encode(exit.signing_root()), plan.signing_root);

    let signed = sign_exit(&plan, vpk, vsk).expect("the controlling key signs");
    check_signed_exit(&signed, vpk).expect("the artifact verifies end to end");

    // Tampering with the epoch after signing breaks the root.
    let mut moved = signed.clone();
    moved.plan.epoch = moved.plan.epoch.wrapping_sub(1);
    assert!(check_signed_exit(&moved, vpk).is_err(), "a moved epoch must break the root");
}

#[test]
fn exit_refuses_a_key_that_does_not_control_the_validator() {
    let (vpk, _) = validator_key();
    let v = active_validator(vpk);
    let plan = build_exit_plan(&v, EPOCH_PAST_GATE, false).unwrap();
    let (spk, ssk) = stranger_key();
    let err = sign_exit(&plan, spk, ssk).unwrap_err();
    assert!(err.contains("does not control validator 3"), "{err}");
    assert!(err.contains(&plan.pubkey_hash), "names the committed hash: {err}");
}

#[test]
fn exit_refuses_an_already_exited_or_slashed_record() {
    let (vpk, _) = validator_key();
    let mut v = active_validator(vpk);
    v.exit_epoch = Some(500);
    let err = build_exit_plan(&v, EPOCH_PAST_GATE, false).unwrap_err();
    assert!(err.contains("already exited"), "{err}");

    let mut v = active_validator(vpk);
    v.slashed = true;
    let err = build_exit_plan(&v, EPOCH_PAST_GATE, false).unwrap_err();
    assert!(err.contains("slashed"), "{err}");
}

#[test]
fn exit_gate_names_its_epoch_and_broadcast_refusal_names_the_gap() {
    let (vpk, _) = validator_key();
    let v = active_validator(vpk);
    let err = build_exit_plan(&v, LIVE_EPOCH, false).unwrap_err();
    assert!(err.contains("SIGNED_EXIT_ACTIVATION_EPOCH"), "{err}");

    let refusal = exit_broadcast_refusal();
    assert!(refusal.contains("NO wire carrier"), "{refusal}");
    assert!(refusal.contains("SIGNED_EXIT_ACTIVATION_EPOCH"), "{refusal}");
}

// ═════════════════════════════════════════════════════════════ delegate ═════

#[test]
fn delegate_refusal_names_the_gate_and_the_missing_format() {
    let msg = delegate_refusal();
    assert!(msg.contains("FUNDED_STAKING_ACTIVATION_EPOCH"), "{msg}");
    assert!(msg.contains("wire format"), "{msg}");
    assert!(msg.contains("does not invent"), "{msg}");
}

// ═════════════════════════════════════════════════════════════ withdraw ═════

fn withdrawable_validator() -> rpc::ValidatorInfo {
    rpc::ValidatorInfo {
        index: 9,
        pubkey_hash: [0x77; 32],
        state: "exited".into(),
        own_stake_sat: MIN_BOND,
        slashed: false,
        activation_epoch: Some(100),
        exit_epoch: Some(1_000),
        withdrawable_epoch: Some(3_048),
    }
}

#[test]
fn withdraw_round_trips_through_the_real_decoder() {
    let v = withdrawable_validator();
    let plan = build_withdraw_plan(&v, EPOCH_PAST_GATE, false)
        .expect("an exited, matured record withdraws");
    let raw = check_withdraw_plan(&plan).expect("a fresh plan re-derives");
    let decoded = PosTransaction::from_canonical_bytes(&raw).expect("canonical bytes decode");
    assert_eq!(decoded, PosTransaction::Withdraw { validator: 9 });
    assert_eq!(decoded.canonical_bytes(), raw, "decode ∘ encode is the identity");
    assert_eq!(hex::encode(decoded.txid()), plan.txid);
}

#[test]
fn withdraw_refuses_before_withdrawable_epoch_naming_both_epochs() {
    let v = withdrawable_validator();
    // The gate itself is inert, so pass it via rehearsal and pin the
    // DELAY refusal specifically — it must fire even in a rehearsal.
    let err = build_withdraw_plan(&v, 2_000, true).unwrap_err();
    assert!(err.contains("not withdrawable until epoch 3048"), "{err}");
    assert!(err.contains("epoch 2000"), "names the chain's epoch: {err}");
    assert!(err.contains("DelayNotElapsed"), "{err}");
}

#[test]
fn withdraw_refuses_a_bonded_or_spent_record() {
    let mut v = withdrawable_validator();
    v.exit_epoch = None;
    v.withdrawable_epoch = None;
    let err = build_withdraw_plan(&v, EPOCH_PAST_GATE, false).unwrap_err();
    assert!(err.contains("no exit on record"), "{err}");
    assert!(err.contains("NotExited"), "{err}");

    let mut v = withdrawable_validator();
    v.own_stake_sat = 0;
    let err = build_withdraw_plan(&v, EPOCH_PAST_GATE, false).unwrap_err();
    assert!(err.contains("already withdrawn"), "{err}");
}

#[test]
fn withdraw_gate_names_its_epoch_and_rehearsal_never_broadcasts() {
    let v = withdrawable_validator();
    let err = build_withdraw_plan(&v, LIVE_EPOCH * 3, false).unwrap_err();
    assert!(err.contains("WITHDRAWAL_ACTIVATION_EPOCH"), "{err}");

    let plan = build_withdraw_plan(&v, LIVE_EPOCH * 3, true).expect("rehearsal lifts the gate");
    let err = check_withdraw_plan(&plan).unwrap_err();
    assert!(err.contains("REHEARSAL"), "{err}");
}

#[test]
fn withdraw_plan_tamper_is_caught() {
    let v = withdrawable_validator();
    let plan = build_withdraw_plan(&v, EPOCH_PAST_GATE, false).unwrap();
    let mut other_index = plan.clone();
    other_index.validator_index = 10;
    let err = check_withdraw_plan(&other_index).unwrap_err();
    assert!(err.contains("does not match"), "{err}");
}

// ══════════════════════════════════════════════════════ shared plumbing ═════

#[test]
fn blch_amounts_round_trip() {
    for (s, sat) in [
        ("25000", 2_500_000_000_000_u64),
        ("0.5", 50_000_000),
        ("1.00000001", 100_000_001),
    ] {
        assert_eq!(parse_blch(s).unwrap(), sat);
        assert_eq!(format_blch(sat as u128), s);
    }
    assert!(parse_blch("").is_err());
    assert!(parse_blch("1e8").is_err());
    assert!(parse_blch("0").is_err());
    assert!(parse_blch("1.000000001").is_err(), "9 fractional digits");
}

#[test]
fn keystore_round_trips() {
    // Assemble a keystore exactly as `keys::Keystore::save` lays it out.
    let (pk, sk) = (vec![0xAB; 40], vec![0xCD; 64]);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"BPOSKEY1");
    bytes.extend_from_slice(&7u32.to_le_bytes());
    bytes.extend_from_slice(&(pk.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&pk);
    bytes.extend_from_slice(&(sk.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&sk);
    bytes.extend_from_slice(&[0x11; 32]);
    let (index, rpk, rsk, seed) = parse_node_keystore(&bytes).unwrap();
    assert_eq!((index, rpk, rsk, seed), (7, pk, sk, [0x11; 32]));
    assert!(parse_node_keystore(&bytes[..bytes.len() - 1]).is_err(), "truncated");
    assert!(parse_node_keystore(b"NOTAKEY1........").is_err(), "wrong magic");
}

/// The witness byte budgets must fit real hybrid material — pinned against
/// real keygen the same way partner-send pins its budgets.
#[test]
fn byte_budgets_fit_real_hybrid_material() {
    let (vpk, vsk) = validator_key();
    assert!(vpk.len() <= 3_800, "framed pubkey {} bytes exceeds the budget", vpk.len());
    let sig = bloch_crypto::crypto::sign(vsk, &[0x42; 32]).unwrap();
    assert!(sig.len() <= 4_700, "hybrid signature {} bytes exceeds the budget", sig.len());
}

// ── Wire-tag freeze and the inertness tripwire ──────────────────────────────
//
// Added 2026-08-31 with the staking-client consolidation. Both tests close
// gaps the PMO wire registry believed were already closed:
//
// `docs/WIRE-NAMESPACE-REGISTRY.md` §1 records tag `0x08` (`Withdraw`) as
// "Frozen by `crates/bloch-withdraw/tests/race.rs`". That is not true and
// never was: `bloch-withdraw` is the exchange **payout** client and encodes
// only `Transfer`/`TransferV2` — it contains no `PosTransaction::Withdraw`,
// no `withdrawable_epoch` and no validator index anywhere. Tags `0x07` and
// `0x08` were, until this test, frozen by NOTHING in the tree, which is the
// one class of tag collision the registry says the compiler *can* catch —
// but only after a merge that keeps both arms.

/// The two funded staking tags are pinned to the bytes the registry
/// allocated, measured at the front of the CONSENSUS encoder's output.
///
/// If a merge renumbers either tag, this fails here — in the client that
/// emits the bytes — instead of at a flag day, when the renumber stops being
/// free. `0x07 = DepositV2`, `0x08 = Withdraw` is the C-4 resolution.
#[test]
fn wire_tags_are_frozen_0x07_deposit_v2_and_0x08_withdraw() {
    let plan = plan_min_deposit(EPOCH_PAST_GATE, false).expect("plan past the gate");
    let mut sd = SignedDeposit {
        plan,
        funding_pubkey: None,
        funding_signature: None,
        proof_of_possession: None,
    };
    let (fpk, fsk) = funding_key();
    let (vpk, vsk) = validator_key();
    sign_deposit_funding(&mut sd, fpk, fsk).unwrap();
    sign_deposit_pop(&mut sd, vpk, vsk).unwrap();
    let deposit_raw = check_signed_deposit(&sd).unwrap();
    assert_eq!(deposit_raw[0], 0x07, "the DepositV2 wire tag is frozen at 0x07");

    let withdraw_raw = PosTransaction::Withdraw { validator: 9 }.canonical_bytes();
    assert_eq!(withdraw_raw[0], 0x08, "the Withdraw wire tag is frozen at 0x08");

    // The two tags are distinct — the whole point of C-4. A merge that let
    // them collide would decode a withdrawal as a deposit.
    assert_ne!(deposit_raw[0], withdraw_raw[0]);

    // And both survive the real decoder as themselves.
    assert!(matches!(
        PosTransaction::from_canonical_bytes(&withdraw_raw).unwrap(),
        PosTransaction::Withdraw { validator: 9 }
    ));
}

/// Every staking format this tool can build reads its flag day from the
/// consensus crate, and every one of them is still INERT.
///
/// Two assertions with two different jobs:
///
/// 1. **No drift.** `StakingFormat::activation_epoch` must return the
///    consensus constant itself. A client that gates on its own copy of a
///    flag day is a client that will happily build a format the chain still
///    refuses (or refuse one the chain has opened).
///
/// 2. **Tripwire.** All four are `u64::MAX` today and this tool ships inert.
///    When a flag day IS armed, this test fails — deliberately. Arming a
///    staking format is a founder decision with a fleet rebuild behind it,
///    not something that should slip in under a green suite. Whoever arms it
///    updates this test in the same commit, which is the record that the
///    arming was intended.
#[test]
fn every_staking_format_gate_matches_consensus_and_ships_inert() {
    use bloch_pos_committee::params as p;
    let cases = [
        (StakingFormat::DepositV2, p::FUNDED_STAKING_ACTIVATION_EPOCH),
        (StakingFormat::SignedExit, p::SIGNED_EXIT_ACTIVATION_EPOCH),
        (StakingFormat::FundedDelegate, p::FUNDED_STAKING_ACTIVATION_EPOCH),
        (StakingFormat::Withdraw, p::WITHDRAWAL_ACTIVATION_EPOCH),
    ];
    for (format, consensus_epoch) in cases {
        assert_eq!(
            format.activation_epoch(),
            consensus_epoch,
            "{:?} must gate on the consensus constant, not a copy",
            format
        );
        assert_eq!(
            format.activation_epoch(),
            u64::MAX,
            "{:?} ({}) is armed. This tool ships INERT: if the arming is \
             intended, update this test in the arming commit.",
            format,
            format.constant_name(),
        );
        // And the refusal actually fires at a live epoch, naming the constant.
        let err = check_format_active(format, LIVE_EPOCH, false)
            .expect_err("an inert format must refuse at a live epoch");
        assert!(err.contains(format.constant_name()), "{err}");
        assert!(err.contains("INERT"), "{err}");
    }
}
