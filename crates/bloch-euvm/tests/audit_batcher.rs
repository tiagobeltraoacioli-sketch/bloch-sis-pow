//! Adversarial audit repros — lens: Batcher / AMM economic safety.
//!
//! These are integration tests (separate from the module's own `#[cfg(test)]`),
//! so they do NOT edit src/. Each test PINS an observed behavior that a batch-AMM
//! economic-safety auditor flagged. Run:
//!   cargo test --test audit_batcher

use bloch_euvm::batcher::{amm_out, settle, SwapOrder};
use bloch_euvm::{AssetId, ExtOutput, Val, Value};

const A: AssetId = [1u8; 32];
const B: AssetId = [2u8; 32];

fn pool(a: u64, b: u64) -> ExtOutput {
    let mut value = Value::new();
    value.insert(A, a);
    value.insert(B, b);
    ExtOutput {
        value,
        validator_hash: [0u8; 32],
        datum: Val::Int(0),
    }
}

fn order(own: u8, give: AssetId, amt: u64, want: AssetId, min_out: u64) -> SwapOrder {
    SwapOrder {
        owner_validator: [own; 32],
        give_asset: give,
        give_amount: amt,
        want_asset: want,
        min_out,
    }
}

/// FINDING 1 (economic fairness / grindable MEV priority).
///
/// `settle` folds orders against the *running* reserves in `canonical_key()` order,
/// and `canonical_key()` is `owner_validator || give_asset || give_amount || ...` —
/// i.e. it is sorted FIRST by the trader-chosen `owner_validator` address. So among
/// otherwise-identical orders, the one whose owner address sorts lower is executed
/// FIRST, against the freshest (best) reserves, and receives strictly MORE output for
/// the identical input. Later orders eat the accumulated slippage.
///
/// A trader can grind `owner_validator` to guarantee best-in-batch execution — an
/// intra-batch ordering advantage a batch auction is supposed to eliminate. The four
/// documented guarantees (determinism, k-preserved, never-drain, conservation) all
/// still hold; what is violated is "no order can extract value": a low-address order
/// extracts price improvement from its batch-mates deterministically.
#[test]
fn owner_address_grinds_execution_priority_and_extracts_price() {
    let p = pool(1_000_000, 1_000_000);
    // Two traders, IDENTICAL swap (give 200_000 A, want B), differ only in address.
    let lo = order(1, A, 200_000, B, 0); // low address -> sorts first
    let hi = order(255, A, 200_000, B, 0); // high address -> sorts last

    let s = settle(&p, &[lo.clone(), hi.clone()], 30, 1_000_000).unwrap();
    // fills are in canonical order: the [1;32] owner first, [255;32] owner second.
    assert!(s.fills[0].filled && s.fills[1].filled);
    let got_lo = s.fills[0].out_amount; // owner [1;32]
    let got_hi = s.fills[1].out_amount; // owner [255;32]

    // Identical input, strictly different output — purely because of the address.
    assert!(
        got_lo > got_hi,
        "low-address order must get MORE B than the identical high-address order: \
         got_lo={got_lo} got_hi={got_hi}"
    );

    // And it is grindable: if the SAME trader (same swap) instead picks a lower
    // address, it flips from the worse fill to the better fill. Give the would-be
    // loser the winning slot by lowering only its address.
    let hi_regrinded = order(0, A, 200_000, B, 0); // now the lowest address
    let s2 = settle(&p, &[lo, hi_regrinded], 30, 1_000_000).unwrap();
    // fills[0] is now the re-grinded [0;32] order — it seized the best fill.
    assert_eq!(s2.fills[0].out_amount, got_lo, "grinding a lower address bought the best slot");
    // submission order is irrelevant (determinism holds) — the advantage is the ADDRESS.
    let s2_rev = settle(&pool(1_000_000, 1_000_000), &[order(0, A, 200_000, B, 0), order(1, A, 200_000, B, 0)], 30, 1_000_000).unwrap();
    assert_eq!(s2, s2_rev, "advantage is address-determined, not submission-order");
}

/// FINDING 2 (pub-API panic on adversarial reserves — DoS / determinism hazard).
///
/// `Settlement::old_k()` / `new_k()` compute `old0 as i128 * old1 as i128` with the
/// NATIVE `*` operator (unchecked), unlike every other arithmetic site in the crate
/// (which is checked i128 / `checked_*`). For reserves near `u64::MAX`, the product
/// exceeds `i128::MAX` (~1.7e38 < (2^64)^2 = ~3.4e38): the multiply OVERFLOWS,
/// PANICKING in debug builds (incl. `cargo test`) and silently WRAPPING to a negative
/// `i128` in release. These are `pub` methods on a `pub` struct that any consensus
/// caller comparing `new_k() >= old_k()` would use — a panic path (node crash) and a
/// release-mode wrap that makes the invariant check nonsense, both reachable from a
/// pool whose reserves are a high-supply token.
#[test]
#[should_panic(expected = "overflow")]
fn settlement_old_k_panics_on_large_reserves_debug() {
    // Empty batch just carries the pool reserves through into old0/old1.
    let p = pool(u64::MAX, u64::MAX);
    let s = settle(&p, &[], 30, 1_000).unwrap();
    // old0 * old1 = (2^64-1)^2 overflows i128 -> panic in debug.
    let _ = s.old_k();
}

/// FINDING 3 (documented-but-live defect: `saturating_add` reserve update).
///
/// `settle`'s accept arm updates a reserve with `saturating_add`, not `checked_add`.
/// Near `u64::MAX` an accepted fill silently CLAMPS the reserve, so the returned
/// `Settlement.new0` is NOT `old0 + give_amount` — the module's own guarantee (d)
/// "every asset balances exactly" is violated INSIDE the struct `settle` hands back,
/// before any validator sees it. A caller reading `Settlement` fields directly (a
/// natural use — e.g. to display/settle without a full `build_settlement_tx` +
/// `validate_tx` round trip) observes a lying, non-conserving reserve number.
///
/// This confirms the in-module pin: today the corruption is only caught by the
/// *independent* conservation check in `validate_tx` (the funding input keeps the
/// true, un-clamped amount), not by `settle`/`amm_out` failing closed the way they
/// correctly do on i128 overflow. Fix: `checked_add` + drop/refund on overflow.
#[test]
fn settle_reserve_update_saturates_instead_of_failing_closed() {
    let mut value = Value::new();
    value.insert(A, u64::MAX - 10);
    value.insert(B, 1_000_000);
    let p = ExtOutput { value, validator_hash: [0u8; 32], datum: Val::Int(0) };

    // Large give so dy>0 (accept path) AND old0 + give overflows u64.
    let o = order(1, A, u64::MAX / 2, B, 0);
    let s = settle(&p, &[o], 0, 1_000_000).unwrap();

    assert!(s.fills[0].filled, "accept path taken");
    // True conserved reserve would be (u64::MAX-10) + u64::MAX/2 > u64::MAX.
    let true_sum = (u64::MAX - 10) as u128 + (u64::MAX / 2) as u128;
    assert!(true_sum > u64::MAX as u128, "precondition: real sum overflows u64");
    // settle returns the CLAMPED value, silently dropping the excess — not conserved.
    assert_eq!(s.new0, u64::MAX, "settle saturates instead of refusing the order");
    assert_ne!(s.new0 as u128, true_sum, "Settlement.new0 is NOT the conserved sum");
}

/// CONTROL: the pool itself is genuinely safe against a single order through the AMM
/// formula — `amm_out` never returns >= reserve_out (can't drain) and k grows. This
/// documents what the audit COULD NOT break: the pool-drain / value-mint paths are
/// closed for the honestly-built settlement tx. (Included so the findings above are
/// read as "fairness + hygiene", not "pool can be emptied".)
#[test]
fn control_amm_out_never_drains_pool() {
    for &fee in &[0u16, 30, 300, 10_000] {
        for &dx in &[1u64, 1_000, u64::MAX / 2, u64::MAX] {
            let dy = amm_out(1_000_000, 1_000_000, dx, fee).unwrap();
            assert!(dy < 1_000_000, "drain: fee={fee} dx={dx} dy={dy}");
        }
    }
}
