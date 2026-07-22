//! Adversarial repro tests for the panics/overflow/memory-safety audit lens.
//! Integration tests only — no src/ files are edited.

use bloch_euvm::batcher::{settle, Settlement};
use bloch_euvm::{
    validate_tx, validator_hash, AssetId, Ctx, EuTx, EuTxInput, ExtOutput, Op, SigVerifier, Val,
    Value,
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

/// FINDING: `Settlement::old_k()` / `new_k()` multiply two `u64` reserves as `i128`
/// with an UNCHECKED `*`. `u64::MAX * u64::MAX ≈ 2^128`, which overflows `i128`
/// (max ≈ 2^127). In a debug build (plain `cargo test`, and the consensus build's
/// checked-overflow profile) this PANICS with "attempt to multiply with overflow".
///
/// Reachability: `settle()` happily produces such a `Settlement` from a perfectly
/// well-formed two-asset pool whose reserves are near `u64::MAX` (both are valid
/// `u64` map values). Any consumer following the module's own documented pattern
/// `assert!(s.new_k() >= s.old_k())` to check the constant-product invariant then
/// panics. This is the exact site the VM's own `Op::Mul` guards with `checked_mul`
/// (-> VmError::Overflow); the helper methods do not.
#[test]
fn settlement_k_overflows_i128_and_panics_on_large_reserves() {
    // A structurally valid two-asset pool with maxed reserves; empty batch is a no-op
    // so new0/new1 == old0/old1 == u64::MAX.
    let pool = two_asset_pool(u64::MAX, u64::MAX);
    let s: Settlement = settle(&pool, &[], 30, 1_000_000).expect("settle must set up a 2-asset pool");
    assert_eq!(s.old0, u64::MAX);
    assert_eq!(s.old1, u64::MAX);

    // old_k() = (u64::MAX as i128) * (u64::MAX as i128) ≈ 2^128 > i128::MAX -> overflow.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let old_k = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.old_k()));
    let new_k = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.new_k()));
    std::panic::set_hook(prev);

    // In the debug/consensus (overflow-checks=on) profile this is a hard panic.
    assert!(
        old_k.is_err(),
        "expected old_k() to panic on i128 multiply overflow (u64::MAX^2), got {old_k:?}"
    );
    assert!(
        new_k.is_err(),
        "expected new_k() to panic on i128 multiply overflow (u64::MAX^2), got {new_k:?}"
    );
}

/// Demonstrates the panic is not an artifact of the extreme u64::MAX value: any
/// reserve pair whose product crosses 2^127 (well inside the valid u64 x u64 domain)
/// overflows i128. 14e18 is ~76% of u64::MAX — an entirely plausible reserve for a
/// high-supply token pool — and (14e18)^2 ≈ 1.96e38 > i128::MAX ≈ 1.70e38.
#[test]
fn settlement_k_overflow_below_u64_max_reserves() {
    let r: u64 = 14_000_000_000_000_000_000; // ~0.76 * u64::MAX
    let pool = two_asset_pool(r, r);
    let s = settle(&pool, &[], 30, 1_000_000).unwrap();

    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let old_k = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.old_k()));
    std::panic::set_hook(prev);

    assert!(
        old_k.is_err(),
        "expected old_k() to panic on i128 overflow at ~0.76*u64::MAX reserves, got {old_k:?}"
    );
}

/// FINDING (CPU-DoS): `gas_cost` charges a FLAT 60 for `Op::Sha256d`/`Op::Shake256`
/// and a FLAT 1 for `Op::Size`, independent of the operand's byte length. Hashing a
/// 1-byte blob and hashing an 8 MB blob cost the *same* 60 gas, while the second does
/// millions of times more work. A gas budget therefore does NOT bound CPU work per op.
///
/// This directly proves the gas schedule is length-independent — the root of the
/// unmetered-work DoS on the `accept_block` -> `validate_block` -> `run` path.
#[test]
fn flat_gas_makes_hashing_cost_independent_of_operand_length() {
    let ctx = Ctx::default();
    let prog = vec![Op::Sha256d];

    let mut g_small = 1_000u64;
    let _ = bloch_euvm::run(&prog, vec![Val::Bytes(vec![0u8; 1])], &ctx, &Noop, &mut g_small);
    let used_small = 1_000 - g_small;

    let mut g_big = 1_000u64;
    let _ = bloch_euvm::run(
        &prog,
        vec![Val::Bytes(vec![0u8; 8_000_000])], // 8 MB — 8 million times more work
        &ctx,
        &Noop,
        &mut g_big,
    );
    let used_big = 1_000 - g_big;

    assert_eq!(used_small, 60, "sha256d is flat-priced");
    assert_eq!(
        used_small, used_big,
        "identical gas for 1 byte vs 8 MB — work is unmetered per operand length"
    );
}

/// FINDING (memory-DoS, reachable through the consensus surface): a compiled validator
/// program can amplify a single attacker-sized blob into ~`MAX_STACK` resident copies
/// for ~1 gas each via `Op::Dup` (flat cost 1). Because there is no program-size or
/// operand-length ceiling, a small transaction (a ~N-byte `PushBytes` literal plus a
/// row of cheap `Dup`s) forces the node to allocate ~1000·N bytes while consuming only
/// ~1000 gas — a >1000x memory amplification that a `per_tx` gas ceiling does not bound.
///
/// This test drives the amplification through the *real* consensus entry point
/// (`validate_tx`, the layer `accept_block_model` calls via `validate_block`) inside the
/// DEFAULT-scale per-tx budget, using a CI-safe 64 KB blob (~64 MB resident). The same
/// program with a 16 MB `PushBytes` literal (a ~16 MB tx, still well-formed and still
/// ~1002 gas) makes the node allocate ~16 GB and OOM-crash — a whole-network DoS.
#[test]
fn dup_amplifies_memory_to_a_multiple_of_gas_via_validate_tx() {
    const N: usize = 64 * 1024; // 64 KB operand (CI-safe; scale it up for the real DoS)
    const DUPS: usize = 1000; // ~1000 resident copies -> ~64 MB for ~1002 gas

    let mut prog = Vec::with_capacity(DUPS + 2);
    prog.push(Op::PushBytes(vec![0xABu8; N]));
    for _ in 0..DUPS {
        prog.push(Op::Dup);
    }
    prog.push(Op::PushInt(1)); // finish truthy so the validator authorizes the spend
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

    // A generous, realistic per-tx budget (10M, the harness DEFAULT_GAS_CEILINGS.per_tx).
    let used = validate_tx(&tx, &Noop, 10_000_000).expect("amplifying tx is accepted");

    // Gas paid is trivial (1 PushBytes + DUPS Dups + 1 PushInt), yet the peak resident
    // memory is DUPS * N bytes. Gas does not bound memory.
    assert_eq!(used, (DUPS as u64) + 2, "only ~1002 gas charged for ~64 MB of allocation");
    assert!(
        (DUPS * N) as u64 > used * 60_000,
        "bytes-resident dwarfs gas: {} bytes for {} gas",
        DUPS * N,
        used
    );
}

/// FINDING (public-API panic on in-range input): `minting::fixed_supply_cap_policy`
/// computes `cap + 1` in native Rust i128 (not through the VM's checked ops) to build a
/// `PushInt(cap + 1)` operand. With `cap == i128::MAX` — an in-range argument a caller
/// may legitimately pass to mean "no effective cap" — this addition overflows i128 and
/// PANICS in any overflow-checked (debug / consensus) build. A reference constructor
/// crashing on a valid argument is a DoS surface for any tooling that builds policies.
#[test]
fn fixed_supply_cap_policy_panics_on_max_cap() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let built = std::panic::catch_unwind(|| {
        bloch_euvm::minting::fixed_supply_cap_policy(i128::MAX)
    });
    std::panic::set_hook(prev);
    assert!(
        built.is_err(),
        "expected fixed_supply_cap_policy(i128::MAX) to panic on the unchecked `cap + 1`"
    );
}
