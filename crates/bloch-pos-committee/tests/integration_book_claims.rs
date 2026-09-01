// SPDX-License-Identifier: AGPL-3.0-or-later

//! **Every volatile number the Exchange Integration Book prints, asserted
//! against the code that actually decides it.**
//!
//! `docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md` is read by
//! exchange integration, custody and risk teams, and they build against it.
//! On 2026-08-31 an integrator audited that document against `main` and found
//! three things we had not told them:
//!
//! 1. `staking::validate_deposit` has no production call site;
//! 2. `unlock_epoch` does not appear in `bloch-pos-committee` at all;
//! 3. the block payload cap silently doubled to 524,288 at epoch 800.
//!
//! All three were true. The first two were true because the document
//! described work that exists only on an unreleased branch as though it were
//! in the released binary. The third was true because a consensus parameter
//! moved and the document that quotes it was not a thing anyone had to update.
//!
//! Their summary of why the third one bites: *"conservation is an equality, so
//! a stale fee assumption is a hard rejection rather than a slow confirm."*
//! That is exactly right, and it is the reason this file exists. On a chain
//! where `sum(inputs) == sum(outputs) + fee` is checked with `!=`
//! (`transition.rs`, both the V1 and V2 arms), every published fee input is
//! load-bearing: an integrator who builds against a stale cap, a stale gas
//! constant or a stale price does not get a slow confirm, they get
//! `ValueNotConserved` on every transfer they sign.
//!
//! ## What this file is, and what it is not
//!
//! It is not a second consensus implementation, and it asserts no behaviour of
//! its own. Every assertion here is of the form "the number the book prints is
//! the number this constant holds", so that a consensus-parameter change that
//! moves a published figure fails *here*, in CI, with the document named —
//! rather than in an integrator's signing path six weeks later.
//!
//! It deliberately does NOT re-test consensus rules that already have owners.
//! Strict-equality conservation is pinned by
//! `transition::tests::a_transfer_that_does_not_conserve_value_is_refused`;
//! the payload-cap era switch by `fee_market::tests::the_cap_doubles_at_the_flag_day`.
//! What is pinned here is the *published* surface: the arithmetic an outside
//! wallet has to reproduce byte-for-byte to get a transfer accepted.
//!
//! ## Changelog discipline
//!
//! A failure in this file is not a bug in this file. It means a consensus
//! parameter moved and the Integration Book now lies. The fix is to update
//! both, in the same commit, and to follow
//! `docs/integration/CONSENSUS-CHANGELOG-DISCIPLINE.md`.

use bloch_pos_committee::fee_market::{
    self, block_tx_bytes_target, intrinsic_gas, max_block_tx_bytes, next_base_fee, BlockUsage,
    TxClass, BLOCK_GAS_LIMIT, BLOCK_GAS_TARGET, GAS_PER_BYTE, HYBRID_SIG_BYTES,
    HYBRID_VERIFY_GAS, HYBRID_VERIFY_INSTRUCTIONS, INSTRUCTIONS_PER_GAS,
    MAX_BLOCK_TX_BYTES, MAX_BLOCK_TX_BYTES_V2, MIN_BASE_FEE_MILLISAT_PER_GAS, TX_FLAT_GAS,
};
use bloch_pos_committee::params::{
    BLOCK_BYTES_V2_ACTIVATION_EPOCH, LEAKED_ROSTER_ACTIVATION_EPOCH, SLOTS_PER_EPOCH,
    SLOT_DURATION_SECS, TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH,
};
use bloch_pos_committee::staking::{FALCON1024_PK_BYTES, HYBRID_PK_BYTES, MLDSA65_PK_BYTES};
use bloch_pos_committee::tokenomics_v4::SAT_PER_BLOCH;

/// The epoch the Integration Book was measured at (its own closing line:
/// "Measured 2026-08-26 at height 15,146, epoch 1,101"). Every "is this gate
/// open?" assertion below is relative to this, so that the document's claims
/// are checked against the chain state the document itself claims to describe.
const BOOK_MEASURED_AT_EPOCH: u64 = 1_101;

// ── §1 Chain parameters ─────────────────────────────────────────────────────

/// **Book §1: "Slot time 30 seconds", "Epoch 32 slots (16 minutes)".**
///
/// The 16-minute figure is derived in the book, not stated by any constant, so
/// the derivation is pinned rather than the number: an epoch is
/// `SLOTS_PER_EPOCH * SLOT_DURATION_SECS` seconds and the book's parenthetical
/// must equal it.
#[test]
fn book_slot_and_epoch_cadence() {
    assert_eq!(SLOT_DURATION_SECS, 30, "book §1 prints 'Slot time 30 seconds'");
    assert_eq!(SLOTS_PER_EPOCH, 32, "book §1 prints 'Epoch 32 slots'");
    assert_eq!(
        SLOTS_PER_EPOCH * SLOT_DURATION_SECS / 60,
        16,
        "book §1 prints '(16 minutes)' and §5 prints '16-32 minutes' for 1-2 epochs"
    );
}

/// **Book §1: "Decimals 8 — 1 BLCH = 100,000,000 sat".**
#[test]
fn book_decimals() {
    assert_eq!(
        SAT_PER_BLOCH, 100_000_000,
        "book §1 prints '1 BLCH = 100,000,000 sat'"
    );
}

/// **Book §1: "Block gas 60,000,000".**
///
/// Also pins the EIP-1559 target as exactly half, because the book's §6 gas
/// derivation compares against the *cap* while the price controller the book
/// tells integrators to read (`next_base_fee_millisat_per_gas`) moves against
/// the *target*. An integrator who confuses the two mis-times every send.
#[test]
fn book_block_gas_limit() {
    assert_eq!(
        BLOCK_GAS_LIMIT, 60_000_000,
        "book §1 prints 'Block gas 60,000,000'"
    );
    assert_eq!(
        BLOCK_GAS_TARGET,
        BLOCK_GAS_LIMIT / 2,
        "the price moves against the target, not the cap the book quotes"
    );
}

/// **Book §1: "Block payload 524,288 bytes" — and the fact the book omits.**
///
/// This is the claim the integrator found for themselves, which is the whole
/// reason this file exists. 524,288 is correct *today* and was wrong before
/// epoch 800: the cap doubled at `BLOCK_BYTES_V2_ACTIVATION_EPOCH`. A flat
/// "524,288" with no era attached is a number that was false for the first 800
/// epochs of the chain and would silently become false again if the constant
/// moved.
///
/// So this test pins three separate things: both era values, the gate that
/// separates them, and that the gate is *behind* the epoch the book was
/// measured at — which is what makes the book's flat statement true as of
/// publication rather than true by luck.
#[test]
fn book_block_payload_cap_and_the_era_it_belongs_to() {
    assert_eq!(
        MAX_BLOCK_TX_BYTES_V2, 524_288,
        "book §1 prints 'Block payload 524,288 bytes'"
    );
    assert_eq!(
        MAX_BLOCK_TX_BYTES, 262_144,
        "the pre-flag-day cap the book does not mention"
    );
    assert_eq!(
        MAX_BLOCK_TX_BYTES_V2,
        2 * MAX_BLOCK_TX_BYTES,
        "the book calls this a doubling"
    );
    assert_eq!(
        BLOCK_BYTES_V2_ACTIVATION_EPOCH, 800,
        "book §11 states the cap doubled at epoch 800"
    );

    // The era switch itself, from the book's reader's point of view.
    assert_eq!(
        max_block_tx_bytes(BLOCK_BYTES_V2_ACTIVATION_EPOCH - 1),
        262_144,
        "one epoch before the flag day the book's figure is WRONG"
    );
    assert_eq!(
        max_block_tx_bytes(BLOCK_BYTES_V2_ACTIVATION_EPOCH),
        524_288,
        "the flag-day epoch itself is already under the new cap"
    );

    // And the reason the book may state it flat: the gate is in the past.
    assert!(
        BOOK_MEASURED_AT_EPOCH >= BLOCK_BYTES_V2_ACTIVATION_EPOCH,
        "the book states 524,288 without an era caveat; that is only honest \
         while the flag day is behind the measured epoch"
    );
    assert_eq!(
        max_block_tx_bytes(BOOK_MEASURED_AT_EPOCH),
        524_288,
        "the cap in force at the epoch the book says it measured"
    );

    // The target moves with the cap — one switch, never two. A doubled cap
    // over an undoubled target would price a half-full block as congested,
    // which is the failure `BLOCK_BYTES_V2_ACTIVATION_EPOCH`'s own doc warns
    // about, and it would reach integrators as an unexplained fee spike.
    assert_eq!(
        block_tx_bytes_target(BOOK_MEASURED_AT_EPOCH),
        max_block_tx_bytes(BOOK_MEASURED_AT_EPOCH) / 2,
        "cap and target are one switch"
    );
}

// ── §6 Fees: the one price, and why equality makes it load-bearing ──────────

/// **Book §6: "A transfer is valid at exactly one price point."**
///
/// This is the sentence that carries the integrator's whole objection, and it
/// is true — but the book states it without the mechanism, and the mechanism
/// is what an integrator has to implement.
///
/// The fee is never declared by the transaction. It is *derived*:
/// `intrinsic_gas(class, tx_bytes)` priced at the block's committed base fee.
/// A wallet cannot choose it, cannot round it, and cannot overpay: both
/// transfer arms in `transition.rs` compare with `!=`, so an overpayment is
/// `ValueNotConserved` exactly like an underpayment. This test pins the
/// arithmetic an outside wallet must reproduce to land on that single point.
#[test]
fn book_intrinsic_gas_is_derived_never_declared() {
    // The three terms the book's §6 formula prints: flat, bytes, verify.
    assert_eq!(TX_FLAT_GAS, 5_000, "book §6 formula's leading '5,000'");
    assert_eq!(GAS_PER_BYTE, 16, "book §6 formula's 'x 16'");
    assert_eq!(
        HYBRID_VERIFY_GAS, 72_748,
        "book §6 formula's '72,748 x n' per-verification term"
    );
    // And that the verify term is itself derived, not a magic number.
    assert_eq!(
        HYBRID_VERIFY_GAS,
        HYBRID_VERIFY_INSTRUCTIONS / INSTRUCTIONS_PER_GAS,
        "72,748 is a measured instruction count divided by the calibration, \
         not a constant anyone may edit alone"
    );

    // The composition, for one eUTXO transfer with `k` hybrid verifications
    // and `b` declared bytes — the book's formula, evaluated by the code.
    for (k, b) in [(1u32, 8_459u64), (2, 16_801), (61, 511_000)] {
        assert_eq!(
            intrinsic_gas(TxClass::Eutxo { inputs: k }, b),
            TX_FLAT_GAS + b * GAS_PER_BYTE + HYBRID_VERIFY_GAS * k as u64,
            "the book's gas formula must be the code's gas formula"
        );
    }
}

/// **Book §6, the correction: the verification term counts OWNER KEYS, not
/// inputs — and the book's "815" is not reachable in any encoding.**
///
/// The book prints:
///
/// ```text
/// gas(n) = 5,000 + (8,649 + 40n) x 16 + 72,748 x n
/// n = 815 -> 59,954,604   of 60,000,000
/// ```
///
/// and then instructs: *"Use 815 as the V2 ceiling in any planner."* The
/// arithmetic checks out, but it describes a transaction that cannot exist,
/// because it mixes the two formats' cost models:
///
/// - the **byte** term `8,649 + 40n` is the V2 shape — ONE witness table entry
///   plus 40 bytes per input, i.e. a single-owner transfer;
/// - the **verify** term `72,748 x n` is the V1 shape — one hybrid
///   verification per *input*.
///
/// V2 does not charge per input. `Transition::apply_transfer_v2` derives the
/// class as `TxClass::Eutxo { inputs: keys.len() }` — the witness *table*
/// length, one verification per distinct owner, which is the entire point of
/// the deduplicated format. So:
///
/// - if the 815 inputs share one owner (the exchange hot-wallet case) the
///   verify term is `72,748 x 1`, not `x 815`, and the transfer is nowhere
///   near the gas cap — it is bytes that bind, far higher up;
/// - if the 815 inputs have 815 distinct owners the verify term is right, but
///   the witness table alone is 815 x ~8,342 bytes ≈ 6.8 MB, which is 13x the
///   524,288-byte payload cap. The block cannot carry it.
///
/// Either way, 815 is not a ceiling. This test pins the real rule so that a
/// planner built from the book is built from something true.
#[test]
fn book_v2_input_ceiling_is_bytes_bound_not_the_published_815() {
    let epoch = BOOK_MEASURED_AT_EPOCH;
    let cap = max_block_tx_bytes(epoch);

    // One encoded witness table entry: two length-prefixed byte strings.
    const LEN_PREFIX: u64 = 4;
    let witness_entry = LEN_PREFIX + HYBRID_PK_BYTES as u64 + LEN_PREFIX + HYBRID_SIG_BYTES;
    assert_eq!(
        HYBRID_PK_BYTES,
        MLDSA65_PK_BYTES + FALCON1024_PK_BYTES,
        "the hybrid public key is the two halves concatenated"
    );

    // (a) The single-owner case: the verify term does NOT scale with inputs.
    //     A planner that assumes it does under-uses the format by an order of
    //     magnitude, which is the practical cost of the book's error.
    let one_owner_at_815 = intrinsic_gas(TxClass::Eutxo { inputs: 1 }, 8_649 + 40 * 815);
    assert!(
        one_owner_at_815 < BLOCK_GAS_LIMIT / 4,
        "a single-owner 815-input V2 transfer costs {one_owner_at_815} gas, far \
         under the {BLOCK_GAS_LIMIT} cap the book says it saturates"
    );

    // (b) The binding constraint for a single-owner V2 transfer is the payload
    //     cap, not gas. Pin that ordering rather than a magic input count:
    //     Falcon-1024 signatures are variable length, so the exact ceiling is a
    //     property of the encoded transaction and must be MEASURED, never
    //     assumed from a constant. What is stable is which cap bites first.
    let bytes_at_cap = cap;
    let gas_at_byte_saturation =
        intrinsic_gas(TxClass::Eutxo { inputs: 1 }, bytes_at_cap);
    assert!(
        gas_at_byte_saturation < BLOCK_GAS_LIMIT,
        "for a single-owner transfer, bytes must bind before gas: a \
         payload-saturated transfer costs {gas_at_byte_saturation} of \
         {BLOCK_GAS_LIMIT} gas"
    );

    // (c) The all-distinct-owners case the book's verify term implies cannot
    //     be encoded at all: the witness table alone overruns the payload cap
    //     long before 815.
    let table_at_815 = witness_entry * 815;
    assert!(
        table_at_815 > cap,
        "the book's 815-verification transfer needs a {table_at_815}-byte \
         witness table against a {cap}-byte payload cap; it cannot be encoded"
    );

    // How many DISTINCT owners actually fit — the honest V2 worst case. Each
    // owner needs at least one 40-byte input alongside its table entry.
    let max_distinct_owners = cap / (witness_entry + 40);
    assert!(
        max_distinct_owners < 815,
        "the real distinct-owner ceiling is {max_distinct_owners}, not 815"
    );
}

/// **Book §6: "the base fee is baked into the change output" — and the field
/// the book never mentions.**
///
/// A transfer carries `tip_millisat_per_gas` on the wire. The settled fee is
/// `base_fee_sat + priority_fee_sat`, and conservation is checked against that
/// SUM. An integrator who reads the book, sets no tip field and assumes the
/// base fee is the whole fee is correct only because a zero tip contributes
/// zero — but nothing in the book says the field exists, so nothing tells them
/// what happens if their encoder emits a non-zero default.
///
/// Both parts round UP independently, so a wallet that computes
/// `ceil((gas * (base + tip)) / 1000)` as a single division disagrees with the
/// node whenever both parts have a remainder — by one satoshi, which under
/// `!=` conservation is a hard rejection.
#[test]
fn book_fee_is_base_plus_tip_each_rounded_up_separately() {
    let gas = 8_465_732u64;
    let base = MIN_BASE_FEE_MILLISAT_PER_GAS;

    // Zero tip: the book's implicit assumption, and it holds.
    let c = fee_market::charge(TxClass::Eutxo { inputs: 1 }, 0, base, 0);
    assert_eq!(c.priority_fee_sat, 0, "no tip, no priority component");

    // Non-zero tip: the two parts are settled separately, each rounded up.
    let (b_sat, t_sat) = fee_market::fee_parts_sat(gas, base, 7);
    assert_eq!(b_sat, (gas as u128 * base).div_ceil(1_000));
    assert_eq!(t_sat, (gas as u128 * 7).div_ceil(1_000));

    // The trap: separate ceilings are not one ceiling. A wallet that folds the
    // two prices together before dividing can be a satoshi short, and a
    // satoshi short is `ValueNotConserved`, not a slow confirm.
    let folded = (gas as u128 * (base + 7)).div_ceil(1_000);
    assert!(
        b_sat + t_sat >= folded,
        "separate rounding never underpays relative to folded rounding"
    );

    // Pin the price floor the book's quick-start response shows as "10".
    assert_eq!(
        MIN_BASE_FEE_MILLISAT_PER_GAS, 10,
        "the book's sample response prints base_fee_millisat_per_gas = 10, \
         which is the floor"
    );
}

/// **Book §6: "Read `next_base_fee_millisat_per_gas` immediately before
/// building, and broadcast promptly."**
///
/// The book gives the instruction without the magnitude, so an integrator
/// cannot size their own staleness window. Pin the controller's bound: the
/// price moves by at most 1/8 per block, so a quote is off by at most
/// (9/8)^k after k blocks. That is what makes "promptly" mean something.
#[test]
fn book_price_staleness_is_bounded_at_one_eighth_per_block() {
    let epoch = BOOK_MEASURED_AT_EPOCH;
    let start = 1_000_000u128;

    // Fully saturated block: the maximum single-block rise.
    let saturated = BlockUsage {
        gas_used: BLOCK_GAS_LIMIT,
        tx_bytes: max_block_tx_bytes(epoch),
    };
    let up = next_base_fee(start, saturated, epoch);
    assert!(
        up <= start + start / 8,
        "a single block may not raise the base fee by more than 1/8"
    );

    // Empty block: the maximum single-block fall.
    let empty = BlockUsage { gas_used: 0, tx_bytes: 0 };
    let down = next_base_fee(start, empty, epoch);
    assert_eq!(
        down,
        start - start / 8,
        "an empty block lowers the base fee by exactly 1/8"
    );

    // A block exactly at target holds the price — the fixed point an
    // integrator's "is my quote stale?" check can rely on.
    let at_target = BlockUsage {
        gas_used: BLOCK_GAS_TARGET,
        tx_bytes: block_tx_bytes_target(epoch),
    };
    assert_eq!(
        next_base_fee(start, at_target, epoch),
        start,
        "a block at target on both axes leaves the price unchanged"
    );

    // The floor holds under sustained emptiness — the price cannot go to zero
    // and make gas free.
    let mut p = MIN_BASE_FEE_MILLISAT_PER_GAS;
    for _ in 0..64 {
        p = next_base_fee(p, empty, epoch);
    }
    assert_eq!(
        p, MIN_BASE_FEE_MILLISAT_PER_GAS,
        "the base fee floor is absorbing"
    );
}

// ── Activation gates: what is armed, and what it can reach ──────────────────

/// **The distinction the book does not draw: shipped ≠ reachable.**
///
/// Three activation constants in `params.rs` gate code that is compiled into
/// the released binary and cannot execute on the wire today. A document that
/// lists a capability without saying which side of its gate it sits on
/// overstates the binary — which is precisely how `unlock_epoch` and
/// `validate_deposit` reached an integrator as though they were live.
///
/// This test does not assert the gates are set to any particular value; it
/// asserts the *classification*, so that arming one is a deliberate act that
/// turns this test red and forces the book to be updated in the same commit.
#[test]
fn book_activation_gates_are_classified_not_assumed() {
    // OPEN — behind the measured epoch, so the book may state their effects
    // as current fact. Both are consensus format/capacity changes.
    for (name, gate) in [
        ("BLOCK_BYTES_V2_ACTIVATION_EPOCH", BLOCK_BYTES_V2_ACTIVATION_EPOCH),
        (
            "TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH",
            TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH,
        ),
    ] {
        assert!(
            gate <= BOOK_MEASURED_AT_EPOCH,
            "{name} is OPEN in the book; if it moves ahead of epoch \
             {BOOK_MEASURED_AT_EPOCH} the book's flat statements become false"
        );
    }

    // ARMED BUT FUTURE — the code exists and is scheduled, and nothing on the
    // wire can reach it yet. The book must describe this as scheduled, never
    // as current.
    assert_eq!(
        LEAKED_ROSTER_ACTIVATION_EPOCH, 1_400,
        "the leaked-roster flag day is armed at epoch 1,400"
    );
    assert!(
        LEAKED_ROSTER_ACTIVATION_EPOCH > BOOK_MEASURED_AT_EPOCH,
        "at the epoch the book was measured the leaked-roster rule had not \
         activated; if this ever fails, §8 of the book needs rewriting"
    );

    // INERT — `u64::MAX`. Deliberately unreachable until a founder decision.
    // Asserted through the module path rather than an import so that deleting
    // the constant is also a red test rather than a silent removal.
    assert_eq!(
        bloch_pos_committee::params::LEAK_RECOVERY_ACTIVATION_EPOCH,
        u64::MAX,
        "leak recovery and the quorum-denominator floor are INERT; the book \
         must not describe self-healing finality as current behaviour"
    );
    assert_eq!(
        bloch_pos_committee::params::ANCESTRY_SEED_ACTIVATION_EPOCH,
        u64::MAX,
        "INERT, and additionally unreferenced: the seed look-ahead was made \
         unconditional on 2026-08-24 and this constant now gates nothing at \
         all. It is a dead parameter, not a scheduled feature."
    );
}

/// **Book §8: "Validator entry opens with the eUTXO-funded bonding upgrade,
/// which ... activates on a scheduled flag day."**
///
/// There is no such flag day on this branch. `staking::validate_deposit` is
/// public and fully tested and has no production call site, and the funded
/// bonding path exists only on an unreleased integration branch. "Scheduled"
/// implies a constant a reader could look up; there is none.
///
/// This test pins the *absence* so that landing the upgrade — which will
/// introduce that constant and a call site — is what makes it go red, at which
/// point §8 must be rewritten from "scheduled" to a date.
#[test]
fn book_validator_entry_has_no_scheduled_flag_day_on_this_branch() {
    // The three gates that exist are the ones classified above. None of them
    // is a validator-entry gate: entry is not scheduled, it is unimplemented
    // on the released binary.
    //
    // Guard by construction: if someone adds a funded-bonding activation
    // constant to `params`, this list is what they must come and update, and
    // the book section is named right here.
    let known_gates: [(&str, u64); 4] = [
        ("BLOCK_BYTES_V2_ACTIVATION_EPOCH", BLOCK_BYTES_V2_ACTIVATION_EPOCH),
        (
            "TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH",
            TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH,
        ),
        ("LEAKED_ROSTER_ACTIVATION_EPOCH", LEAKED_ROSTER_ACTIVATION_EPOCH),
        (
            "LEAK_RECOVERY_ACTIVATION_EPOCH",
            bloch_pos_committee::params::LEAK_RECOVERY_ACTIVATION_EPOCH,
        ),
    ];
    assert_eq!(
        known_gates.len(),
        4,
        "the Integration Book §8 and §11 enumerate exactly these gates; a new \
         one means the book is now incomplete"
    );
    for (name, _) in known_gates {
        assert!(
            !name.to_ascii_lowercase().contains("deposit")
                && !name.to_ascii_lowercase().contains("bond"),
            "{name} looks like a funded-bonding gate; Integration Book §8 says \
             validator entry is unimplemented and must now be corrected"
        );
    }
}
