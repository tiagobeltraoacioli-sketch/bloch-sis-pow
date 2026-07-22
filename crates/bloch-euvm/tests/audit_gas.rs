//! AUDIT (lens: gas metering & DoS bounds) — adversarial repros.
//!
//! These integration tests demonstrate concrete ways the "every op is metered,
//! gas actually bounds work" invariant is violated. They are AUDIT ARTIFACTS:
//! each documents a real defect and pins today's (unsafe) behavior so it is
//! visible in the suite. They touch no `src/` file and no other test file.

use bloch_euvm::{
    blch, run, validate_tx, validator_hash, Ctx, EuTx, EuTxInput, ExtOutput, Op, SigVerifier,
    TxError, Val, Value, VmError, BLCH,
};

struct Noop;
impl SigVerifier for Noop {
    fn verify(&self, _m: &[u8], _p: &[u8], _s: &[u8]) -> bool {
        false
    }
}

/// A validator that, for each iteration, clones (`Dup`) and hashes (`Sha256d`) the
/// blob sitting on the stack, then drops the digest — leaving the blob in place.
/// Net stack effect per iteration: zero. Gas per iteration: 62 (Dup 1 + Sha256d 60
/// + Drop 1), INDEPENDENT of the blob's byte length. Terminates with a truthy Int.
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

/// FINDING 1 (CRITICAL) — gas cost is decoupled from operand byte-length, so a fixed
/// gas budget bounds an UNBOUNDED amount of CPU work. `gas_cost(Sha256d)` is a flat
/// 60 no matter whether it hashes 32 bytes or 256 KiB. Two programs with the SAME op
/// sequence (hence the SAME gas) hash amounts of data differing by 8192x. Gas does
/// not bound work; a single tx can pin every validating node's CPU for minutes.
#[test]
fn gas_is_decoupled_from_hashed_bytes_cpu_dos() {
    let iters = 256usize;
    let program = hash_work_program(iters);
    let ctx = Ctx::default();
    let noop = Noop;

    let small_len = 32usize; // 32 bytes
    let large_len = 256 * 1024usize; // 256 KiB — attacker picks this freely

    // Same program → same gas budget suffices for both.
    let budget = (62 * iters as u64) + 2;

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

    // The core violation: identical gas, wildly different work.
    assert_eq!(
        gas_small, gas_large,
        "gas MUST be identical — the schedule ignores operand length"
    );

    let bytes_small = iters * small_len; // total bytes fed to Sha256d
    let bytes_large = iters * large_len;
    assert!(
        bytes_large >= 8000 * bytes_small,
        "same gas ({gas_large}) hashed {bytes_large} bytes vs {bytes_small} bytes \
         — work is unbounded per gas unit"
    );

    // Extrapolation to the shipped ceiling (harness DEFAULT_GAS_CEILINGS.per_tx =
    // 10_000_000): at 62 gas/iter that is ~161k iterations. With a 1 MiB blob (which
    // an attacker embeds once via PushBytes) that is ~161 GiB hashed for ONE tx —
    // minutes of CPU per node, within budget. Nothing caps operand length.
    let iters_at_ceiling = 10_000_000u64 / 62;
    let gib_hashed = iters_at_ceiling * (1024 * 1024) / (1024 * 1024 * 1024);
    assert!(
        gib_hashed >= 100,
        "one in-budget tx forces >= {gib_hashed} GiB of hashing on every node"
    );
}

/// FINDING 1b (HIGH) — memory amplification. `Op::Dup` costs a flat 1 gas but clones
/// the entire top-of-stack blob. MAX_STACK (1024) lets the stack hold ~1023 copies of
/// an attacker-sized blob. Here 200 copies of a 256 KiB blob (~50 MiB resident) cost
/// ~200 gas; scaled to a 1 MiB blob and full stack that is ~1 GiB for ~1000 gas.
/// Memory allocation is not a function of gas.
#[test]
fn dup_amplifies_memory_independent_of_gas() {
    let blob_len = 256 * 1024usize;
    let copies = 200usize; // stays under MAX_STACK = 1024
    let mut program = Vec::with_capacity(copies + 2);
    for _ in 0..copies {
        program.push(Op::Dup); // 1 gas each, clones blob_len bytes each
    }
    // finish truthy: replace the byte stack top with an Int is not trivial; instead
    // just prove the Dups all executed by charging their gas, then error on truthy.
    let ctx = Ctx::default();
    let noop = Noop;
    let budget = copies as u64 + 8;
    let mut g = budget;
    let res = run(&program, vec![Val::Bytes(vec![7u8; blob_len])], &ctx, &noop, &mut g);
    let gas_used = budget - g;

    // All `copies` Dups were charged (1 gas each) — trivial gas for ~50 MiB resident.
    assert_eq!(gas_used, copies as u64, "each Dup is a flat 1 gas regardless of size");
    // The program ends with a Bytes on top → truthiness type error, AFTER the memory
    // was already allocated. The point is the allocation, not the terminal error.
    assert_eq!(res, Err(VmError::TypeError("expected Int for truthiness")));
}

/// FINDING 2 (HIGH) — the per-tx value-conservation scan in `validate_tx` runs
/// ENTIRELY OUTSIDE the gas meter. Proof: with `gas_limit == 0`, a non-conserving tx
/// still returns `ValueNotConserved` (the full asset scan executed) instead of
/// `OutOfGas`. The scan is O(#assets * (#inputs + #outputs)); neither the asset count
/// nor the output count is bounded anywhere, so an attacker can force large unmetered
/// work before a single gas unit is charged.
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
    // gas_limit = 0. If conservation were metered, we'd expect OutOfGas. Instead the
    // scan runs fully and reports the imbalance — it is outside the meter.
    let got = validate_tx(&tx, &Noop, 0);
    assert_eq!(
        got,
        Err(TxError::ValueNotConserved { asset: BLCH, in_sum: 100, out_plus_fee: 50 }),
        "conservation scan ran to completion under a ZERO gas budget — it is unmetered"
    );
}

/// FINDING 2b (HIGH) — scale the unmetered scan. A single output carrying a `Value`
/// with many thousands of distinct assets forces `validate_tx` to build an asset set
/// and sum every asset across every input/output BEFORE any validator runs and
/// regardless of `gas_limit`. This completes here with `gas_limit = 1`, proving the
/// work is not accounted against the DoS budget. An attacker scales the map at will.
#[test]
fn large_asset_map_forces_unmetered_work_regardless_of_gas_limit() {
    let anyone = vec![Op::PushInt(1)];
    let vh = validator_hash(&anyone);

    const N_ASSETS: u64 = 20_000;
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

    // gas_limit = 1: the ~20k-asset conservation scan runs fully (unmetered); only the
    // single PushInt(1) op afterward touches the meter (and 1 gas covers it). The tx
    // validates — the heavy scan never cost a thing against the budget.
    let got = validate_tx(&tx, &Noop, 1);
    assert!(
        got.is_ok(),
        "the {N_ASSETS}-asset scan ran under gas_limit=1 — unmetered pre-VM work: {got:?}"
    );
}

/// FINDING 3 (HIGH) — `spend()` performs `let mut ctx = ctx.clone();` for EVERY input,
/// and `ctx.tx_outputs` holds ALL of the transaction's outputs. So `validate_tx` deep-
/// clones the entire output set once per input: O(#inputs * #outputs * output_size)
/// work — quadratic in the tx's own size — performed ENTIRELY OUTSIDE the gas meter
/// (gas is only charged per-op inside `run`, and each input here runs a single 1-gas
/// op). The reported gas grossly under-counts the real work. Neither the input count
/// nor the output size is bounded anywhere in the crate, and the harness's per-tx /
/// block gas ceilings therefore do NOT bound this work.
///
/// The tx is value-conserving (all-zero `Value`, so BLCH balances 0 == 0) with many
/// trivial 1-op inputs and many large-datum outputs. It validates successfully while
/// having deep-cloned hundreds of MB that never touched the meter.
#[test]
fn per_input_ctx_clone_is_quadratic_and_unmetered() {
    let trivial = vec![Op::PushInt(1)];
    let vh = validator_hash(&trivial);

    const N_INPUTS: usize = 60;
    const N_OUTPUTS: usize = 60;
    const DATUM: usize = 100_000; // 100 KB datum per output, cloned once per input

    let inputs: Vec<EuTxInput> = (0..N_INPUTS)
        .map(|_| EuTxInput {
            // empty (zero) Value → conserves trivially; trivial 1-op validator.
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

    let used = validate_tx(&tx, &Noop, 10_000_000).expect("value-conserving tx validates");

    // Each input runs the 1-op PushInt(1) validator → ~1 gas apiece.
    assert!(
        used <= (N_INPUTS as u64) * 2,
        "gas charged is ~1 per trivial input, got {used} — the ctx.clone work is off the meter"
    );

    // Real work the node performed off-meter: clone every output once per input.
    let cloned_bytes: u64 = (N_INPUTS as u64) * (N_OUTPUTS as u64) * (DATUM as u64);
    let bytes_per_gas = cloned_bytes / used.max(1);
    assert!(
        bytes_per_gas > 1_000_000,
        "unmetered ctx-clone work per gas unit is enormous: {bytes_per_gas} bytes/gas \
         ({cloned_bytes} bytes cloned for {used} gas)"
    );
}
