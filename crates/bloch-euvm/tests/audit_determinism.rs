//! Audit lens: DETERMINISM / consensus-split hunt (integration test — src/ untouched).
//!
//! The bit-level determinism surface of bloch-euvm is clean: no f32/f64, no HashMap
//! iteration, no clock/IO, BTreeMap-canonical Value/state, checked i128 in the VM.
//! These repros instead pin the two places where an *adversary-controlled input* makes
//! the accept/reject outcome (or a public API) depend on the executing machine rather
//! than on the block bytes — which is a consensus-divergence risk, not a style nit.

use bloch_euvm::batcher::Settlement;
use bloch_euvm::{gas_cost, run, Ctx, Op, SigVerifier, VmError};

struct Noop;
impl SigVerifier for Noop {
    fn verify(&self, _m: &[u8], _p: &[u8], _s: &[u8]) -> bool {
        false
    }
}

/// FINDING 1 (FIXED — regression): `gas_cost` used to be a flat constant per op,
/// independent of the byte-length of the operand it processes — hashing a 1-byte blob
/// and a 1-MiB blob both cost 60, so gas did NOT bound CPU/memory work and a program
/// could buy O(n) work for O(1) gas (machine-dependent OOM = consensus split). Fixed by
/// the F2 length-proportional meter (`op_gas`): base cost PLUS one gas per 32-byte word
/// of the operand. `gas_cost` remains the length-INDEPENDENT base (60 for Sha256d); the
/// effective in-`run` charge now scales with operand length. This test fails closed if
/// gas ever stops tracking length again.
#[test]
fn gas_scales_with_operand_length_metered_work() {
    let ctx = Ctx::default();

    // Same opcode, wildly different input sizes -> gas must now differ proportionally.
    let small = vec![Op::PushBytes(vec![0u8; 1]), Op::Sha256d, Op::Drop, Op::PushInt(1)];
    let large = vec![
        Op::PushBytes(vec![0u8; 1_000_000]),
        Op::Sha256d,
        Op::Drop,
        Op::PushInt(1),
    ];

    let mut g_small = 1_000_000u64;
    let mut g_large = 1_000_000u64;
    assert_eq!(run(&small, vec![], &ctx, &Noop, &mut g_small), Ok(true));
    assert_eq!(run(&large, vec![], &ctx, &Noop, &mut g_large), Ok(true));

    let used_small = 1_000_000 - g_small;
    let used_large = 1_000_000 - g_large;

    // The 1M-byte hash now costs vastly more than the 1-byte hash: gas tracks work.
    assert!(
        used_large > used_small,
        "gas must grow with operand length (F2 fixed): small={used_small} large={used_large}"
    );
    // ~10^6 bytes ≈ 31_250 words, charged on BOTH the PushBytes and the Sha256d, so the
    // extra is ~2 words-terms — pin it well above any flat-cost regression.
    assert!(
        used_large - used_small >= 60_000,
        "length term must dominate: delta={}",
        used_large - used_small
    );
    // The op's BASE cost is still the length-independent flat constant.
    assert_eq!(gas_cost(&Op::Sha256d), 60);
}

/// FINDING 1 (amplification, FIXED — regression): `Dup` used to cost 1 gas while cloning
/// the whole top blob; stack DEPTH was capped at MAX_STACK but TOTAL BYTES (blob_len *
/// depth) had no ceiling, so ~1000 dups of a 50 KiB blob materialized ~50 MiB of live
/// memory for ~1001 gas — an unbounded memory/gas ratio. Fixed by F2: `Dup` now pays a
/// length-proportional charge AND `run` enforces the MAX_TOTAL_BYTES live-stack ceiling,
/// so the same program fails closed with `MemoryLimitExceeded` (deterministic across
/// nodes) instead of ballooning memory for near-zero gas.
#[test]
fn dup_amplification_bounded_by_memory_ceiling() {
    let ctx = Ctx::default();
    let blob_len = 50_000usize;
    let dups = 1_000u64; // 50_000 * 1001 ≈ 50 MiB > MAX_TOTAL_BYTES (32 MiB)

    let mut prog = vec![Op::PushBytes(vec![0xABu8; blob_len])];
    for _ in 0..dups {
        prog.push(Op::Dup);
    }
    prog.push(Op::Drop);
    prog.push(Op::PushInt(1));

    let mut gas = 10_000_000u64;
    let res = run(&prog, vec![], &ctx, &Noop, &mut gas);
    // Fail-closed and deterministic: the live-stack memory ceiling trips before the
    // amplification can materialize, the same on every node regardless of host RAM.
    assert_eq!(
        res,
        Err(VmError::MemoryLimitExceeded),
        "Dup memory amplification must be bounded by MAX_TOTAL_BYTES (F2 fixed)"
    );
}

/// FINDING 2 FIXED (regression): `Settlement::old_k`/`new_k` now use `checked_mul`
/// returning `Option<i128>`. Because u64::MAX^2 (~3.4e38) exceeds i128::MAX (~1.7e38),
/// two reserves near u64::MAX overflow i128. Pre-fix this PANICKED under debug/overflow-checks
/// and silently WRAPPED to a negative product in an unchecked release — a public reference API
/// that crashed / lied on in-range u64 reserves. Post-fix the helpers fail closed to `None`
/// identically across every build profile (matching the VM's own `Op::Mul` -> `VmError::Overflow`),
/// so the result is deterministic regardless of `overflow-checks`.
#[test]
fn settlement_k_helpers_overflow_i128_on_large_reserves() {
    let s = Settlement {
        asset0: [1u8; 32],
        asset1: [2u8; 32],
        old0: u64::MAX,
        old1: u64::MAX,
        new0: u64::MAX,
        new1: u64::MAX,
        fills: vec![],
        gas_used: 0,
    };

    // Must never panic and never wrap: fail closed to None, the same on debug/test/release.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.old_k()));
    std::panic::set_hook(prev);

    match r {
        Err(_) => panic!("old_k must fail closed to None on i128 overflow, not panic"),
        Ok(k) => assert_eq!(
            k, None,
            "expected None on i128 overflow (fail-closed), got {k:?}"
        ),
    }
    assert_eq!(s.new_k(), None, "new_k must also fail closed to None");
}
