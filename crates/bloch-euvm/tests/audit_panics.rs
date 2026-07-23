//! Adversarial repro tests for the panics/overflow/memory-safety audit lens.
//! Integration tests only — no src/ files are edited.

use bloch_euvm::batcher::{settle, Settlement};
use bloch_euvm::{
    validate_tx, validator_hash, AssetId, Ctx, EuTx, EuTxInput, ExtOutput, Op, SigVerifier, TxError,
    Val, Value, VmError,
};

fn blch(n: u64) -> Value {
    let mut v = Value::new();
    if n > 0 {
        v.insert([0u8; 32], n);
    }
    v
}

struct Noop;
impl SigVerifier for Noop {
    fn verify(&self, _m: &[u8], _p: &[u8], _s: &[u8]) -> bool {
        false
    }
}

const A: AssetId = [1u8; 32];
const B: AssetId = [2u8; 32];

fn two_asset_pool(a: u64, b: u64) -> ExtOutput {
    let mut value = Value::new();
    value.insert(A, a);
    value.insert(B, b);
    ExtOutput {
        value,
        validator_hash: [0u8; 32],
        datum: Val::Int(0),
    }
}

/// FINDING FIXED (regression): `Settlement::old_k()` / `new_k()` used to multiply two
/// `u64` reserves as `i128` with an UNCHECKED `*`. `u64::MAX * u64::MAX ≈ 2^128` overflows
/// `i128` (max ≈ 2^127), which PANICKED under overflow-checks (plain `cargo test` and the
/// consensus profile) and wrapped negative in release — reachable from a well-formed
/// two-asset pool whose reserves are near `u64::MAX`.
///
/// Fixed: both helpers now use `checked_mul` and return `Option<i128>`, matching the VM's
/// own `Op::Mul` (-> `VmError::Overflow`). They return `None` (fail-closed) instead of
/// panicking. No `catch_unwind` needed — a direct call must not panic.
#[test]
fn settlement_k_overflows_i128_and_panics_on_large_reserves() {
    // A structurally valid two-asset pool with maxed reserves; empty batch is a no-op
    // so new0/new1 == old0/old1 == u64::MAX.
    let pool = two_asset_pool(u64::MAX, u64::MAX);
    let s: Settlement = settle(&pool, &[], 30, 1_000_000).expect("settle must set up a 2-asset pool");
    assert_eq!(s.old0, u64::MAX);
    assert_eq!(s.old1, u64::MAX);

    // (u64::MAX as i128)^2 ≈ 2^128 > i128::MAX -> fail-closed None, never a panic/wrap.
    assert_eq!(s.old_k(), None, "old_k must return None on i128 overflow, not panic");
    assert_eq!(s.new_k(), None, "new_k must return None on i128 overflow, not panic");
}

/// Same fix, at a reserve pair well inside the valid u64 x u64 domain: 14e18 is ~76% of
/// u64::MAX — a plausible high-supply pool — and (14e18)^2 ≈ 1.96e38 > i128::MAX ≈ 1.70e38.
/// The checked helpers fail closed to `None` rather than panicking here too.
#[test]
fn settlement_k_overflow_below_u64_max_reserves() {
    let r: u64 = 14_000_000_000_000_000_000; // ~0.76 * u64::MAX
    let pool = two_asset_pool(r, r);
    let s = settle(&pool, &[], 30, 1_000_000).unwrap();

    assert_eq!(s.old_k(), None, "old_k must fail closed to None at ~0.76*u64::MAX reserves");
    assert_eq!(s.new_k(), None, "new_k must fail closed to None at ~0.76*u64::MAX reserves");
}

/// FIXED (F2): `Op::Sha256d`/`Op::Shake256` now charge a base cost PLUS a term
/// proportional to the operand's byte length. Hashing a 1-byte blob and an 8 MB blob no
/// longer cost the same — the 8 MB hash costs far more gas, so a gas budget bounds CPU
/// work per op. Regression guard for the flat-schedule CPU-DoS on the
/// `accept_block` -> `validate_block` -> `run` path.
#[test]
fn flat_gas_makes_hashing_cost_independent_of_operand_length() {
    let ctx = Ctx::default();
    let prog = vec![Op::Sha256d];

    // Ample budget so both complete and the gas *difference* is what we measure.
    let budget = 100_000_000u64;

    let mut g_small = budget;
    let _ = bloch_euvm::run(&prog, vec![Val::Bytes(vec![0u8; 1])], &ctx, &Noop, &mut g_small);
    let used_small = budget - g_small;

    let mut g_big = budget;
    let _ = bloch_euvm::run(
        &prog,
        vec![Val::Bytes(vec![0u8; 8_000_000])], // 8 MB — 8 million times more work
        &ctx,
        &Noop,
        &mut g_big,
    );
    let used_big = budget - g_big;

    // The fix: gas now scales with operand length.
    assert!(
        used_big > used_small,
        "sha256d gas must grow with operand length (small={used_small}, big={used_big})"
    );
    // And it scales substantially — 8 MB is hundreds of thousands of 32-byte words.
    assert!(
        used_big > used_small * 1000,
        "8 MB hash must cost far more gas than a 1-byte hash: small={used_small}, big={used_big}"
    );
}

/// FIXED (F2): a validator that amplifies a single attacker-sized blob into ~`MAX_STACK`
/// resident copies via `Op::Dup` is now rejected fail-closed. `Dup` costs gas
/// proportional to the blob length AND the VM enforces a hard total-live-bytes ceiling
/// (`MAX_TOTAL_BYTES`). Driving the amplification through the *real* consensus entry
/// point (`validate_tx`, the layer `accept_block_model` calls via `validate_block`), a
/// 64 KB blob `Dup`'d 1000 times (~64 MB) trips the memory ceiling and the tx is
/// rejected — the >1000x memory amplification for ~1000 gas is closed.
#[test]
fn dup_amplifies_memory_to_a_multiple_of_gas_via_validate_tx() {
    const N: usize = 64 * 1024; // 64 KB operand
    const DUPS: usize = 1000; // ~1000 resident copies -> ~64 MB, over the 32 MiB ceiling

    let mut prog = Vec::with_capacity(DUPS + 2);
    prog.push(Op::PushBytes(vec![0xABu8; N]));
    for _ in 0..DUPS {
        prog.push(Op::Dup);
    }
    prog.push(Op::PushInt(1)); // would-be truthy tail (never reached — memory trips first)
    let vh = validator_hash(&prog);

    // Well-formed, value-conserving tx (100 BLCH in, 100 BLCH out) whose only input is
    // guarded by the amplifying validator.
    let tx = EuTx {
        inputs: vec![EuTxInput {
            prev_output: ExtOutput { value: blch(100), validator_hash: vh, datum: Val::Int(0) },
            validator: prog,
            redeemer: vec![],
        }],
        outputs: vec![ExtOutput { value: blch(100), validator_hash: vh, datum: Val::Int(0) }],
        fee: 0,
        sighash: vec![],
    };

    // Even under a generous 10M per-tx budget, the amplification is stopped by the hard
    // memory ceiling — the tx is rejected fail-closed, not silently accepted.
    let got = validate_tx(&tx, &Noop, 10_000_000);
    assert!(
        matches!(
            got,
            Err(TxError::Vm(0, VmError::MemoryLimitExceeded))
                | Err(TxError::Vm(0, VmError::OutOfGas))
                | Err(TxError::ResourceLimit { .. })
        ),
        "the Dup-amplifying tx must be rejected (memory/gas/resource ceiling), got {got:?}"
    );
}

/// FIXED (F3/F5): `minting::fixed_supply_cap_policy` used to compute `cap + 1` in
/// native Rust i128 to build a `PushInt(cap + 1)` operand. With `cap == i128::MAX` —
/// an in-range argument a caller may legitimately pass to mean "no effective cap" —
/// that addition overflowed i128 and PANICKED in any overflow-checked (debug /
/// consensus) build (and wrapped to a dead policy in release). The constructor now
/// emits `new_supply <= cap` as `!(cap < new_supply)` with `cap` pushed unmodified.
/// This regression test asserts it does NOT panic on the boundary argument and yields
/// a well-formed policy program. It FAILS if the `cap + 1` overflow is reintroduced.
#[test]
fn fixed_supply_cap_policy_panics_on_max_cap() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let built = std::panic::catch_unwind(|| {
        bloch_euvm::minting::fixed_supply_cap_policy(i128::MAX)
    });
    std::panic::set_hook(prev);
    let policy = built.expect(
        "fixed_supply_cap_policy(i128::MAX) must not panic after the F3/F5 checked-cap fix",
    );
    // A well-formed, non-empty policy program (fail-closed, no wrap, no panic).
    assert!(
        !policy.is_empty(),
        "the cap policy must be a well-formed non-empty program"
    );
}
