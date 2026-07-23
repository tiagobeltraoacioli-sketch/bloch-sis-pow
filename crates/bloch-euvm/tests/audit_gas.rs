//! AUDIT (lens: gas metering & DoS bounds) — F2 REGRESSION tests.
//!
//! These were the adversarial repros that pinned the *flat* gas schedule and the
//! *unmetered* pre-VM work. They now assert the FIXED behavior (F2): gas scales with
//! operand byte length, hard memory/size ceilings fail closed, and the transaction-
//! level structural resource ceilings reject oversized txs before the unmetered scan /
//! per-input `ctx.clone`. Each test FAILS if the vulnerability returns.

use bloch_euvm::{
    blch, check_tx_resource_limits, run, validate_tx, validator_hash, Ctx, EuTx, EuTxInput,
    ExtOutput, Op, SigVerifier, TxError, Val, Value, VmError, BLCH,
};

struct Noop;
impl SigVerifier for Noop {
    fn verify(&self, _m: &[u8], _p: &[u8], _s: &[u8]) -> bool {
        false
    }
}

/// A validator that, for each iteration, clones (`Dup`) and hashes (`Sha256d`) the
/// blob sitting on the stack, then drops the digest — leaving the blob in place.
/// Net stack effect per iteration: zero. After F2, gas per iteration is NOT constant:
/// `Dup` and `Sha256d` each charge a term proportional to the blob's byte length.
fn hash_work_program(iters: usize) -> Vec<Op> {
    let mut p = Vec::with_capacity(iters * 3 + 2);
    for _ in 0..iters {
        p.push(Op::Dup);
        p.push(Op::Sha256d);
        p.push(Op::Drop);
    }
    p.push(Op::Drop); // drop the blob
    p.push(Op::PushInt(1)); // truthy result
    p
}

/// FIXED (F2) — gas is now a function of OPERAND BYTE LENGTH. The SAME op sequence run
/// over a 32-byte blob vs a 256-KiB blob no longer costs the same: the larger operand
/// costs proportionally more gas, so a fixed gas budget bounds CPU work. This is the
/// regression guard for the flat-schedule CPU-DoS.
#[test]
fn gas_is_decoupled_from_hashed_bytes_cpu_dos() {
    let iters = 256usize;
    let program = hash_work_program(iters);
    let ctx = Ctx::default();
    let noop = Noop;

    let small_len = 32usize; // 32 bytes
    let large_len = 256 * 1024usize; // 256 KiB — attacker picks this freely

    // Ample budget so BOTH complete; the point is the gas *difference*, not exhaustion.
    let budget = 50_000_000u64;

    let mut g_small = budget;
    let r_small = run(
        &program,
        vec![Val::Bytes(vec![0xAB; small_len])],
        &ctx,
        &noop,
        &mut g_small,
    );
    let gas_small = budget - g_small;

    let mut g_large = budget;
    let r_large = run(
        &program,
        vec![Val::Bytes(vec![0xAB; large_len])],
        &ctx,
        &noop,
        &mut g_large,
    );
    let gas_large = budget - g_large;

    assert_eq!(r_small, Ok(true));
    assert_eq!(r_large, Ok(true));

    // The fix: identical op sequence, wildly different operand length → wildly different
    // gas. Gas now tracks work.
    assert!(
        gas_large > gas_small,
        "gas MUST grow with operand length (small={gas_small}, large={gas_large})"
    );
    // It scales roughly with the byte ratio (8192x more bytes → ~hundreds x more gas),
    // certainly far more than a flat schedule (which was 1x).
    assert!(
        gas_large > gas_small * 50,
        "gas must scale with operand length: small={gas_small}, large={gas_large}"
    );
}

/// FIXED (F2) — memory amplification is now fail-closed. `Op::Dup` still copies the
/// top-of-stack blob, but (a) it now costs gas proportional to the blob length, and
/// (b) the VM enforces a hard total-live-bytes ceiling (`MAX_TOTAL_BYTES`). Cloning a
/// 256-KiB blob ~200 times (~50 MiB) trips the ceiling and aborts with
/// `MemoryLimitExceeded` — memory is no longer unbounded per gas unit.
#[test]
fn dup_amplifies_memory_independent_of_gas() {
    let blob_len = 256 * 1024usize;
    let copies = 200usize; // ~50 MiB requested — over the 32 MiB memory ceiling
    let mut program = Vec::with_capacity(copies);
    for _ in 0..copies {
        program.push(Op::Dup);
    }
    let ctx = Ctx::default();
    let noop = Noop;
    // Ample gas so the *memory* ceiling — not gas — is what stops the amplification.
    let budget = 50_000_000u64;
    let mut g = budget;
    let res = run(&program, vec![Val::Bytes(vec![7u8; blob_len])], &ctx, &noop, &mut g);

    // The fix: the VM refuses to allocate past MAX_TOTAL_BYTES, fail-closed.
    assert_eq!(
        res,
        Err(VmError::MemoryLimitExceeded),
        "Dup-amplification past the memory ceiling must fail closed"
    );
}

/// FIXED (F2) — a SMALL, well-formed transaction is still correctly evaluated: n=1 is
/// not a DoS, so it passes the structural resource ceilings and the (bounded)
/// conservation scan runs and reports the imbalance. This pins that the F2 ceilings do
/// NOT reject legitimate small transactions — they only bound adversarial-scale ones.
#[test]
fn conservation_scan_is_unmetered_runs_with_zero_gas() {
    let anyone = vec![Op::PushInt(1)];
    let vh = validator_hash(&anyone);
    let tx = EuTx {
        inputs: vec![EuTxInput {
            prev_output: ExtOutput { value: blch(100), validator_hash: vh, datum: Val::Int(0) },
            validator: anyone.clone(),
            redeemer: vec![],
        }],
        // 50 != 100 → conservation fails.
        outputs: vec![ExtOutput { value: blch(50), validator_hash: vh, datum: Val::Int(0) }],
        fee: 0,
        sighash: vec![],
    };
    // A one-input tx is within every ceiling; the conservation check correctly reports
    // the imbalance (this is legitimate behavior, not the DoS the audit flagged).
    let got = validate_tx(&tx, &Noop, 0);
    assert_eq!(
        got,
        Err(TxError::ValueNotConserved { asset: BLCH, in_sum: 100, out_plus_fee: 50 }),
        "a small tx must still be correctly validated within the resource ceilings"
    );
}

/// FIXED (F2) — an output carrying tens of thousands of distinct assets is now rejected
/// by the structural resource ceiling BEFORE the O(#assets · (#in+#out)) conservation
/// scan runs. The unmetered pre-VM scan can no longer be scaled at will.
#[test]
fn large_asset_map_forces_unmetered_work_regardless_of_gas_limit() {
    let anyone = vec![Op::PushInt(1)];
    let vh = validator_hash(&anyone);

    const N_ASSETS: u64 = 20_000; // over MAX_TX_DISTINCT_ASSETS
    let mut in_val: Value = Value::new();
    let mut out_val: Value = Value::new();
    for i in 0..N_ASSETS {
        let mut a = [0u8; 32];
        a[..8].copy_from_slice(&i.to_le_bytes());
        a[8] = 1; // keep off BLCH (all-zero)
        in_val.insert(a, 1);
        out_val.insert(a, 1);
    }

    let tx = EuTx {
        inputs: vec![EuTxInput {
            prev_output: ExtOutput { value: in_val, validator_hash: vh, datum: Val::Int(0) },
            validator: anyone.clone(),
            redeemer: vec![],
        }],
        outputs: vec![ExtOutput { value: out_val, validator_hash: vh, datum: Val::Int(0) }],
        fee: 0,
        sighash: vec![],
    };

    // The oversized asset map is rejected fail-closed by the structural ceiling.
    let got = validate_tx(&tx, &Noop, 1);
    assert!(
        matches!(got, Err(TxError::ResourceLimit { .. })),
        "the {N_ASSETS}-asset map must hit the resource ceiling, got {got:?}"
    );
    // And the shared checker agrees (the same bound the mint path reuses).
    assert!(matches!(check_tx_resource_limits(&tx), Err(TxError::ResourceLimit { .. })));
}

/// FIXED (F2) — the per-input `ctx.clone` (which deep-clones every output once per
/// input, O(#in · #out · output_size)) is now bounded: a tx whose total operand bytes
/// exceed `MAX_TX_BYTES` is rejected by the structural resource ceiling before any
/// cloning happens. The quadratic off-meter work is closed.
#[test]
fn per_input_ctx_clone_is_quadratic_and_unmetered() {
    let trivial = vec![Op::PushInt(1)];
    let vh = validator_hash(&trivial);

    const N_INPUTS: usize = 60;
    const N_OUTPUTS: usize = 60;
    const DATUM: usize = 100_000; // 100 KB datum per output → 6 MB total, over 1 MiB ceiling

    let inputs: Vec<EuTxInput> = (0..N_INPUTS)
        .map(|_| EuTxInput {
            prev_output: ExtOutput { value: Value::new(), validator_hash: vh, datum: Val::Int(0) },
            validator: trivial.clone(),
            redeemer: vec![],
        })
        .collect();

    let outputs: Vec<ExtOutput> = (0..N_OUTPUTS)
        .map(|_| ExtOutput {
            value: Value::new(),
            validator_hash: vh,
            datum: Val::Bytes(vec![0u8; DATUM]),
        })
        .collect();

    let tx = EuTx { inputs, outputs, fee: 0, sighash: vec![] };

    let got = validate_tx(&tx, &Noop, 10_000_000);
    assert!(
        matches!(got, Err(TxError::ResourceLimit { .. })),
        "the oversized tx must hit the resource ceiling before the quadratic ctx.clone, got {got:?}"
    );
}
