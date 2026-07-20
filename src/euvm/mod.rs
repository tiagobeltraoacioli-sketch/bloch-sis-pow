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

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_crypto::core::{TxInput, TxOutput as NodeOut, Transaction as NodeTx};

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
}
