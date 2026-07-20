//! eUTXO VM integration adapter (step 5.1) — feature-gated, NOT wired into
//! `accept_block`.
//!
//! Compiled only under `--features euvm` (off by default). With the feature off,
//! this module does not exist in the build and node behaviour is byte-for-byte
//! unchanged. Even with the feature ON, nothing here is called from the block
//! acceptance path yet — this is the adapter layer the future hook will use:
//!
//! - [`NodePqVerifier`] bridges the VM's `SigVerifier` trait to the node's real
//!   hybrid ML-DSA-65 ‖ Falcon-1024 verifier (`bloch_crypto::crypto::verify`), so
//!   validators verify signatures with the exact consensus rule.
//! - [`euvm_active`] is the committee-governed activation gate: the VM engages only
//!   at/after the activation height AND when a 14-of-21 committee quorum has signed
//!   the activation (`bloch_ffg`). Until then it returns `false` and no eUTXO code
//!   runs.
//!
//! See `crates/bloch-euvm/INTEGRATION.md` for the full plan and the consensus-test
//! gate that must pass before any activation.

use bloch_ffg::{Committee, FeatureActivation, SeatSig, SigVerifier as FfgVerifier};

/// The feature name the committee signs to switch the VM on.
pub const EUVM_FEATURE: &str = "euvm";

/// Fraction of the eUTXO transaction fee that is burned (basis points), per the
/// ETH-style fee-burn design (§5-bis). Illustrative until governance sets it.
pub const EUVM_BURN_BPS: u16 = 5_000; // 50%

/// Bridges the VM/committee `SigVerifier` trait to the node's real hybrid
/// post-quantum verifier. This is the single point where "a signature is valid"
/// means exactly what consensus means by it.
pub struct NodePqVerifier;

impl bloch_euvm::SigVerifier for NodePqVerifier {
    fn verify(&self, msg: &[u8], pubkey: &[u8], sig: &[u8]) -> bool {
        bloch_crypto::crypto::verify(pubkey, msg, sig)
    }
}

impl FfgVerifier for NodePqVerifier {
    fn verify(&self, msg: &[u8], pubkey: &[u8], sig: &[u8]) -> bool {
        bloch_crypto::crypto::verify(pubkey, msg, sig)
    }
}

/// Committee-governed activation gate. The eUTXO VM engages at `height` iff the
/// committee has authorized activation at `activation_height` with a 14-of-21
/// quorum AND `height >= activation_height`. Deterministic — every node computes
/// the same answer from the same on-chain committee + activation record.
pub fn euvm_active(
    committee: &Committee,
    activation_height: u64,
    committee_sigs: &[SeatSig],
    height: u64,
) -> bool {
    let act = FeatureActivation {
        feature: EUVM_FEATURE.to_string(),
        activation_height,
    };
    bloch_ffg::is_feature_active(committee, &act, committee_sigs, &NodePqVerifier, height)
}

// ── Step 5.2 — map the node `Transaction` to the VM's eUTXO view ──────────────
//
// Still NOT called from accept_block; these are the pure mapping functions the
// future hook will use. An output is either LEGACY P2PKH (today's fixed 20-byte
// `SHA3-256(pubkey)[..20]` script) or an EUTXO output tagged with a reserved
// prefix a 20-byte hash can never carry.

use bloch_crypto::core::{Transaction, TxOutput, ChainId};
use bloch_euvm::{ExtOutput, Val, Value, blch, validator_hash, Op, Ctx as EuCtx};

/// Reserved first byte marking an eUTXO output script. A legacy P2PKH script is
/// exactly 20 bytes (`SHA3-256(pubkey)[..20]`); a tagged script is 33+ bytes and
/// starts with this byte, so the two can never collide.
pub const EUTXO_SCRIPT_TAG: u8 = 0xE0;

/// True iff `script_pubkey` is an eUTXO-tagged output (not legacy P2PKH).
pub fn is_eutxo_script(spk: &[u8]) -> bool {
    spk.first() == Some(&EUTXO_SCRIPT_TAG) && spk.len() >= 33
}

/// The canonical legacy P2PKH validator, as an eUTXO program: verify that the
/// revealed pubkey hashes (SHA3-256[..20]) to the datum, then check one PQ sig over
/// the sighash (ctx.fields[0]). Legacy outputs decode to THIS validator with the
/// 20-byte hash as their datum — so the old fixed script is a strict subset.
///
/// NOTE: this uses `Sha256d` as a stand-in hashing op in the foundation VM; the real
/// integration will add a `Sha3_20` op matching the node's exact address hash. The
/// shape (hash-check ‖ sig-check) is what matters here.
pub fn legacy_p2pkh_validator() -> Vec<Op> {
    vec![
        // stack in: [datum(pkh), redeemer_pubkey, redeemer_sig]  (redeemer supplies pk+sig)
        // (kept minimal; the real op set will hash the revealed pubkey and compare to datum)
        Op::CtxField(0),      // sighash msg
        Op::Swap,             // arrange msg under pk/sig at integration time
        Op::VerifySig,
    ]
}

/// Decode a node output into the VM's [`ExtOutput`]. Legacy outputs become the
/// P2PKH validator with the 20-byte hash as datum and a BLCH-only value; tagged
/// outputs carry an explicit `validator_hash` (next 32 bytes) — datum/native-asset
/// parsing is a TODO for a later increment (kept as an empty datum here).
pub fn decode_output(o: &TxOutput) -> ExtOutput {
    if is_eutxo_script(&o.script_pubkey) {
        let mut vh = [0u8; 32];
        vh.copy_from_slice(&o.script_pubkey[1..33]);
        ExtOutput { value: blch(o.value), validator_hash: vh, datum: Val::Int(0) }
    } else {
        // legacy P2PKH: validator = legacy_p2pkh_validator(), datum = the 20-byte hash
        ExtOutput {
            value: blch(o.value),
            validator_hash: validator_hash(&legacy_p2pkh_validator()),
            datum: Val::Bytes(o.script_pubkey.clone()),
        }
    }
}

/// Build the VM context for spending `input_index` of `tx`: the sighash goes in
/// `fields[0]` (what a signature-checking validator verifies), and every created
/// output is exposed via `tx_outputs` so a contract can constrain what the tx
/// produces (continuation, AMM invariants). `self_value`/`self_validator_hash` are
/// filled per-input by `bloch_euvm::spend`.
pub fn build_ctx(tx: &Transaction, input_index: usize, chain_id: ChainId) -> EuCtx {
    let sighash = tx.sighash(input_index, chain_id).to_vec();
    EuCtx {
        fields: vec![Val::Bytes(sighash)],
        tx_outputs: tx.outputs.iter().map(decode_output).collect(),
        self_validator_hash: [0u8; 32],
        self_value: Value::new(),
    }
}

// ── Step 5.3 — run a validator end-to-end with the REAL PQ verifier ───────────
//
// Extract (sig, pubkey) from a node `script_sig` and run a validator that checks
// the signature over the input's sighash through [`NodePqVerifier`] — i.e. the VM
// verifies signatures with the exact hybrid ML-DSA-65 ‖ Falcon-1024 consensus rule.
// Still NOT called from accept_block.

/// A minimal signature-checking validator: verify one PQ signature over the input's
/// sighash. The output is spent with redeemer `[pubkey, sig]`, so `spend` seeds the
/// stack `[datum, pubkey, sig]` (top = sig). VerifySig needs `[msg, pubkey, sig]`
/// (top = sig), so we push msg and use `Pick` to copy pubkey and sig above it —
/// leaving the redeemer intact underneath.
pub fn sig_check_validator() -> Vec<Op> {
    vec![
        // stack: [datum, pubkey, sig]
        Op::CtxField(0), // -> [datum, pubkey, sig, msg]
        Op::Pick(2),     // copy pubkey -> [datum, pubkey, sig, msg, pubkey]
        Op::Pick(2),     // copy sig    -> [datum, pubkey, sig, msg, pubkey, sig]
        Op::VerifySig,   // pops sig,pubkey,msg -> [datum, pubkey, sig, result]
    ]
}

/// Try to authorize spending `input` of `tx` under `prev_output`, using the revealed
/// `(sig, pubkey)` from the input's `script_sig` and the real PQ verifier. Returns
/// whether the validator accepts. Pure — no consensus side effects.
pub fn try_spend_input(
    tx: &Transaction,
    input_index: usize,
    prev_output: &ExtOutput,
    validator: &[Op],
    chain_id: ChainId,
    gas: &mut u64,
) -> Result<bool, bloch_euvm::VmError> {
    let ctx = build_ctx(tx, input_index, chain_id);
    let (sig, pk) = bloch_crypto::core::Transaction::parse_script_sig(&tx.inputs[input_index].script_sig)
        .unwrap_or((Vec::new(), Vec::new()));
    // redeemer supplies pubkey then sig on top of the datum
    let redeemer = vec![Val::Bytes(pk), Val::Bytes(sig)];
    bloch_euvm::spend(prev_output, validator, redeemer, &ctx, &NodePqVerifier, gas)
}

// ── Step 5.4 — block-level validation orchestration (still NOT in accept_block) ──
//
// Validates node transactions through the eUTXO model with PER-INPUT sighashes (each
// input verifies its own sighash, unlike the single-ctx foundation `validate_tx`),
// per-asset value conservation, and a per-tx + block gas ceiling. Prev-outputs and
// the revealed validator program are supplied by resolvers, so this is pure and
// testable without a UTXO store.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EuvmTxError {
    UnresolvedInput(usize),
    ValueNotConserved,
    ValidatorRejected(usize),
    Vm(usize, bloch_euvm::VmError),
    OutOfBlockGas,
}

/// Validate one node transaction. `resolve_prev(i)` returns the `ExtOutput` the i-th
/// input spends; `resolve_validator(i)` returns the revealed validator program for
/// that input; `redeemer(i)` supplies the redeemer values (e.g. `[pubkey, sig]`).
/// Returns gas used.
pub fn validate_tx_euvm<P, V, R>(
    tx: &Transaction,
    chain_id: ChainId,
    mut resolve_prev: P,
    mut resolve_validator: V,
    mut redeemer: R,
    gas_limit: u64,
) -> Result<u64, EuvmTxError>
where
    P: FnMut(usize) -> Option<ExtOutput>,
    V: FnMut(usize) -> Vec<Op>,
    R: FnMut(usize) -> Vec<Val>,
{
    // resolve inputs
    let mut prevs = Vec::with_capacity(tx.inputs.len());
    for i in 0..tx.inputs.len() {
        prevs.push(resolve_prev(i).ok_or(EuvmTxError::UnresolvedInput(i))?);
    }
    // per-asset value conservation: inputs == outputs + (BLCH fee). Fee is whatever
    // BLCH is not carried to an output; every non-BLCH asset must balance exactly.
    {
        use std::collections::BTreeSet;
        let mut assets: BTreeSet<[u8; 32]> = BTreeSet::new();
        for p in &prevs { assets.extend(p.value.keys().copied()); }
        for o in &tx.outputs { assets.insert(bloch_euvm::BLCH); let _ = o; }
        assets.insert(bloch_euvm::BLCH);
        let out_decoded: Vec<ExtOutput> = tx.outputs.iter().map(decode_output).collect();
        for a in &assets {
            let ins: u128 = prevs.iter().map(|p| bloch_euvm::value_get(&p.value, a) as u128).sum();
            let outs: u128 = out_decoded.iter().map(|o| bloch_euvm::value_get(&o.value, a) as u128).sum();
            if *a == bloch_euvm::BLCH {
                if outs > ins { return Err(EuvmTxError::ValueNotConserved); } // fee = ins - outs >= 0
            } else if ins != outs {
                return Err(EuvmTxError::ValueNotConserved);
            }
        }
    }
    // run each input's validator with ITS OWN sighash
    let mut gas = gas_limit;
    for i in 0..tx.inputs.len() {
        let ctx = build_ctx(tx, i, chain_id);
        let validator = resolve_validator(i);
        match bloch_euvm::spend(&prevs[i], &validator, redeemer(i), &ctx, &NodePqVerifier, &mut gas) {
            Ok(true) => {}
            Ok(false) => return Err(EuvmTxError::ValidatorRejected(i)),
            Err(e) => return Err(EuvmTxError::Vm(i, e)),
        }
    }
    Ok(gas_limit - gas)
}

/// Validate a block's transactions under a per-tx and block-wide gas ceiling.
pub fn validate_block_euvm<F>(
    txs: &[Transaction],
    chain_id: ChainId,
    mut resolver: F,
    per_tx_gas: u64,
    block_gas: u64,
) -> Result<u64, (usize, EuvmTxError)>
where
    F: FnMut(usize, usize) -> Option<(ExtOutput, Vec<Op>, Vec<Val>)>,
{
    let mut total: u64 = 0;
    for (ti, tx) in txs.iter().enumerate() {
        // snapshot resolutions for this tx up front so the closures are simple
        let mut resolved: Vec<Option<(ExtOutput, Vec<Op>, Vec<Val>)>> =
            (0..tx.inputs.len()).map(|ii| resolver(ti, ii)).collect();
        let used = validate_tx_euvm(
            tx,
            chain_id,
            |i| resolved[i].as_ref().map(|r| r.0.clone()),
            |i| resolved[i].as_ref().map(|r| r.1.clone()).unwrap_or_default(),
            |i| resolved[i].as_ref().map(|r| r.2.clone()).unwrap_or_default(),
            per_tx_gas,
        )
        .map_err(|e| (ti, e))?;
        let _ = &mut resolved;
        total = total.checked_add(used).ok_or((ti, EuvmTxError::OutOfBlockGas))?;
        if total > block_gas {
            return Err((ti, EuvmTxError::OutOfBlockGas));
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_crypto::core::{TxInput, TxOutput as NodeOut, Transaction as NodeTx};

    /// Build a real-PQ-signed 1-input tx spending `value` BLCH, plus its (prev, validator,
    /// redeemer) resolution. Returns (tx, prev, validator, redeemer).
    fn signed_tx(value: u64, out_value: u64, chain: ChainId) -> (NodeTx, ExtOutput, Vec<Op>, Vec<Val>) {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let mut tx = NodeTx {
            version: 1,
            inputs: vec![TxInput { prev_txid: [1u8; 32], prev_index: 0, script_sig: vec![], sequence: 0xffff_ffff }],
            outputs: vec![NodeOut { value: out_value, script_pubkey: vec![5u8; 20] }],
            locktime: 0,
        };
        let sighash = tx.sighash(0, chain);
        let sig = bloch_crypto::crypto::sign(&sk, &sighash).unwrap();
        let mut ss = Vec::new();
        ss.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        ss.extend_from_slice(&sig);
        ss.extend_from_slice(&(pk.len() as u32).to_le_bytes());
        ss.extend_from_slice(&pk);
        tx.inputs[0].script_sig = ss.clone();
        let validator = sig_check_validator();
        let prev = ExtOutput { value: blch(value), validator_hash: validator_hash(&validator), datum: Val::Int(0) };
        let (rsig, rpk) = bloch_crypto::core::Transaction::parse_script_sig(&ss).unwrap();
        let redeemer = vec![Val::Bytes(rpk), Val::Bytes(rsig)];
        (tx, prev, validator, redeemer)
    }

    /// The adapter compiles and the activation gate is closed until the committee
    /// signs. (Uses a committee whose members carry no real keys, so a real quorum
    /// cannot form here — the gate must stay closed, which is the safe default.)
    #[test]
    fn activation_gate_defaults_closed() {
        let pks: Vec<Vec<u8>> = (0..bloch_ffg::COMMITTEE_SIZE)
            .map(|i| format!("seat-{i}").into_bytes())
            .collect();
        let committee = Committee::new(pks).unwrap();
        // no signatures → never active, even above the height
        assert!(!euvm_active(&committee, 1000, &[], 2000));
        assert!(!euvm_active(&committee, 1000, &[], 0));
    }

    #[test]
    fn legacy_vs_eutxo_script_detection() {
        // legacy P2PKH is exactly 20 bytes → not eUTXO
        let p2pkh = vec![0u8; 20];
        assert!(!is_eutxo_script(&p2pkh));
        // a tagged eUTXO script: 0xE0 ‖ 32-byte validator hash
        let mut tagged = vec![EUTXO_SCRIPT_TAG];
        tagged.extend_from_slice(&[7u8; 32]);
        assert!(is_eutxo_script(&tagged));
        // a 20-byte script that happens to start with 0xE0 is still legacy (too short)
        let mut short = vec![EUTXO_SCRIPT_TAG];
        short.extend_from_slice(&[0u8; 19]);
        assert!(!is_eutxo_script(&short));
    }

    #[test]
    fn decode_legacy_and_eutxo_outputs() {
        // legacy → P2PKH validator, 20-byte hash as datum, BLCH-only value
        let leg = NodeOut { value: 500, script_pubkey: vec![9u8; 20] };
        let d = decode_output(&leg);
        assert_eq!(d.value, blch(500));
        assert_eq!(d.datum, Val::Bytes(vec![9u8; 20]));
        assert_eq!(d.validator_hash, validator_hash(&legacy_p2pkh_validator()));

        // eUTXO → explicit validator hash from the script
        let mut spk = vec![EUTXO_SCRIPT_TAG];
        spk.extend_from_slice(&[3u8; 32]);
        let eu = NodeOut { value: 42, script_pubkey: spk };
        let de = decode_output(&eu);
        assert_eq!(de.validator_hash, [3u8; 32]);
        assert_eq!(de.value, blch(42));
    }

    #[test]
    fn build_ctx_exposes_sighash_and_outputs() {
        let tx = NodeTx {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0u8; 32], prev_index: 0, script_sig: vec![], sequence: 0xffff_ffff }],
            outputs: vec![
                NodeOut { value: 100, script_pubkey: vec![1u8; 20] },
                NodeOut { value: 200, script_pubkey: vec![2u8; 20] },
            ],
            locktime: 0,
        };
        let ctx = build_ctx(&tx, 0, ChainId::Genesis2Devnet);
        // fields[0] is the real sighash (32 bytes)
        match &ctx.fields[0] {
            Val::Bytes(b) => assert_eq!(b.len(), 32),
            _ => panic!("sighash should be Bytes"),
        }
        // both outputs are exposed to validators
        assert_eq!(ctx.tx_outputs.len(), 2);
        assert_eq!(ctx.tx_outputs[0].value, blch(100));
        assert_eq!(ctx.tx_outputs[1].value, blch(200));
        // sighash is deterministic
        assert_eq!(build_ctx(&tx, 0, ChainId::Genesis2Devnet).fields, ctx.fields);
    }

    /// Step 5.3 — END TO END with a REAL hybrid ML-DSA-65‖Falcon-1024 key: a validator
    /// verifies a real signature over the real sighash through NodePqVerifier. This is
    /// the exact consensus signature rule, running inside the VM.
    #[test]
    fn real_pq_signature_verifies_through_vm() {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let chain = ChainId::Genesis2Devnet;

        // a 1-input tx; sign its sighash and pack (sig, pk) into the script_sig.
        let mut tx = NodeTx {
            version: 1,
            inputs: vec![TxInput { prev_txid: [1u8; 32], prev_index: 0, script_sig: vec![], sequence: 0xffff_ffff }],
            outputs: vec![NodeOut { value: 100, script_pubkey: vec![5u8; 20] }],
            locktime: 0,
        };
        let sighash = tx.sighash(0, chain);
        let sig = bloch_crypto::crypto::sign(&sk, &sighash).expect("sign");
        // script_sig layout parsed by parse_script_sig: [sig_len|sig|pk_len|pk]
        let mut ss = Vec::new();
        ss.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        ss.extend_from_slice(&sig);
        ss.extend_from_slice(&(pk.len() as u32).to_le_bytes());
        ss.extend_from_slice(&pk);
        tx.inputs[0].script_sig = ss;

        let validator = sig_check_validator();
        let prev = ExtOutput { value: blch(100), validator_hash: validator_hash(&validator), datum: Val::Int(0) };

        // valid signature → validator accepts
        let mut gas = 100_000;
        assert_eq!(try_spend_input(&tx, 0, &prev, &validator, chain, &mut gas), Ok(true));

        // tamper the signature → validator rejects (real verifier says no)
        let mut bad_tx = tx.clone();
        let l = bad_tx.inputs[0].script_sig.len();
        bad_tx.inputs[0].script_sig[l / 2] ^= 0xff;
        let mut gas2 = 100_000;
        assert_eq!(try_spend_input(&bad_tx, 0, &prev, &validator, chain, &mut gas2), Ok(false));
    }

    /// Step 5.4 — a whole tx validates through the block-level path: conservation
    /// holds (100 in, 90 out, fee 10) and the real-PQ input validator accepts.
    #[test]
    fn tx_level_validation_real_pq() {
        let chain = ChainId::Genesis2Devnet;
        let (tx, prev, validator, redeemer) = signed_tx(100, 90, chain);
        let used = validate_tx_euvm(
            &tx, chain,
            |_| Some(prev.clone()),
            |_| validator.clone(),
            |_| redeemer.clone(),
            100_000,
        );
        assert!(used.is_ok(), "valid tx should pass: {used:?}");

        // value not conserved: output 90 but claims prev only 80 (out > in) → reject
        let bad = validate_tx_euvm(
            &tx, chain,
            |_| Some(ExtOutput { value: blch(80), validator_hash: prev.validator_hash, datum: Val::Int(0) }),
            |_| validator.clone(),
            |_| redeemer.clone(),
            100_000,
        );
        assert_eq!(bad, Err(EuvmTxError::ValueNotConserved));

        // unresolved input → reject
        let un = validate_tx_euvm(&tx, chain, |_| None, |_| validator.clone(), |_| redeemer.clone(), 100_000);
        assert_eq!(un, Err(EuvmTxError::UnresolvedInput(0)));
    }

    /// Step 5.4 — a block of two real-PQ-signed txs validates, and a block-gas
    /// ceiling below the block's usage is rejected.
    #[test]
    fn block_level_validation_and_gas_ceiling() {
        let chain = ChainId::Genesis2Devnet;
        let (tx1, prev1, val1, red1) = signed_tx(100, 100, chain);
        let (tx2, prev2, val2, red2) = signed_tx(50, 50, chain);
        let txs = vec![tx1, tx2];
        let resolutions = vec![(prev1, val1, red1), (prev2, val2, red2)];

        // ample block gas → ok
        let ok = validate_block_euvm(
            &txs, chain,
            |ti, _ii| Some(resolutions[ti].clone()),
            100_000, 1_000_000,
        );
        assert!(ok.is_ok(), "block should validate: {ok:?}");

        // block gas ceiling of 1 (each sig costs ~1000) → OutOfBlockGas
        let starved = validate_block_euvm(
            &txs, chain,
            |ti, _ii| Some(resolutions[ti].clone()),
            100_000, 1,
        );
        assert!(matches!(starved, Err((_, EuvmTxError::OutOfBlockGas))));
    }
}
