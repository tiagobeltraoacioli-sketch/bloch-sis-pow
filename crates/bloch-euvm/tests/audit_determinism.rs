//! Audit lens: DETERMINISM / consensus-split hunt (integration test — src/ untouched).
//!
//! The bit-level determinism surface of bloch-euvm is clean: no f32/f64, no HashMap
//! iteration, no clock/IO, BTreeMap-canonical Value/state, checked i128 in the VM.
//! These repros instead pin the two places where an *adversary-controlled input* makes
//! the accept/reject outcome (or a public API) depend on the executing machine rather
//! than on the block bytes — which is a consensus-divergence risk, not a style nit.

use bloch_euvm::batcher::Settlement;
use bloch_euvm::{gas_cost, run, Ctx, Op, SigVerifier, Val};

struct Noop;
impl SigVerifier for Noop {
    fn verify(&self, _m: &[u8], _p: &[u8], _s: &[u8]) -> bool {
        false
    }
}

/// FINDING 1 (consensus-DoS): `gas_cost` is a flat constant per op, independent of the
/// byte-length of the operand it processes. Hashing a 1-byte blob and hashing a 1-MiB
/// blob both cost exactly `gas_cost(Op::Sha256d)` == 60. So gas does NOT bound CPU/
/// memory work; a program can buy O(n) work for O(1) gas. Under a real per-node memory
/// limit this makes block acceptance machine-dependent (some nodes OOM, others accept)
/// — a liveness/consensus split, not just a slowdown.
#[test]
fn gas_is_independent_of_operand_length_unmetered_work() {
    let ctx = Ctx::default();

    // Same opcode, wildly different input sizes -> identical gas.
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

    // The 1M-byte hash costs the SAME gas as the 1-byte hash: gas ignores work.
    assert_eq!(used_small, used_large, "gas must be equal despite 10^6x the input");
    // And the hashing op itself is charged the flat constant.
    assert_eq!(gas_cost(&Op::Sha256d), 60);
}

/// FINDING 1 (amplification): `Dup` costs 1 gas and clones the whole top blob. Stack
/// depth is capped at MAX_STACK=1024, but the TOTAL BYTES held is (blob_len * depth)
/// with no ceiling, since operand length is never metered. Here ~1000 dups of a 50 KiB
/// blob materialize ~50 MiB of live memory for ~1001 gas — an unbounded memory/gas
/// ratio the attacker scales by enlarging the blob (from the program, datum, or ctx).
#[test]
fn dup_amplifies_memory_for_near_constant_gas() {
    let ctx = Ctx::default();
    let blob_len = 50_000usize;
    let dups = 1_000u64;

    let mut prog = vec![Op::PushBytes(vec![0xABu8; blob_len])];
    for _ in 0..dups {
        prog.push(Op::Dup);
    }
    // finish truthy so run() returns Ok, not a type error, without affecting the point
    prog.push(Op::Drop);
    prog.push(Op::PushInt(1));

    let mut gas = 10_000_000u64;
    let res = run(&prog, vec![], &ctx, &Noop, &mut gas);
    assert_eq!(res, Ok(true));
    let used = 10_000_000 - gas;

    let bytes_materialized = blob_len as u64 * (dups + 1);
    // ~50 MiB of live copies bought for ~1001 gas: >48000 bytes per gas unit, unbounded.
    assert!(used < 2_000, "gas used was {used}, expected ~{}", dups + 2);
    assert!(
        bytes_materialized / used > 40_000,
        "amplification ratio {} bytes/gas is the DoS surface",
        bytes_materialized / used
    );
}

/// FINDING 2 (unchecked i128 mul → panic): `Settlement::old_k`/`new_k` compute
/// `old0 as i128 * old1 as i128` with NO checked_mul. Because u64::MAX^2 (~3.4e38)
/// exceeds i128::MAX (~1.7e38), two reserves near u64::MAX overflow i128: this PANICS
/// in a debug build (incl. `cargo test`) and silently wraps to a negative product in
/// release — a public reference API that crashes / lies on in-range u64 reserves,
/// unlike the VM's own `Op::Mul` which is checked_mul -> VmError::Overflow.
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

    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.old_k()));
    std::panic::set_hook(prev);

    match r {
        Err(_) => { /* debug build: confirmed panic on in-range u64 reserves */ }
        Ok(k) => {
            // release build: silently wrapped — a negative "constant product".
            assert!(
                k < 0,
                "expected wrap to a negative product on i128 overflow, got {k}"
            );
        }
    }
}
