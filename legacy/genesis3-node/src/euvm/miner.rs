//! D3 — the miner/block-builder MIRROR of the eUTXO validator.
//!
//! Purpose: the node must NEVER assemble a candidate block the acceptor
//! (`accept_block` + the D2 eUTXO hook) would reject. [`mirror_candidate_txs`]
//! runs the SAME validation entrypoint the validator uses
//! ([`crate::euvm::validate_node_block`]) over the candidate transaction list
//! BEFORE the block is finalized, excluding any transaction that fails (drop
//! and re-check until the whole set validates) — miner and validator agree by
//! construction because they execute the same code over the same inputs.
//!
//! It also mirrors the fee accounting: for every eUTXO-touching transaction
//! the coinbase claims only the post-burn miner share of the fee
//! (`bloch_euvm::fee_burn` at [`EUVM_BURN_BPS`](super::EUVM_BURN_BPS) — §5-bis,
//! EIP-1559-style). `Block::validate_coinbase_value` enforces
//! `miner_output <= subsidy + total_fees` as a CEILING, so claiming the
//! burned-down amount is valid both against today's acceptor (no burn wired)
//! and against a burn-enforcing D2 acceptor — the miner can never over-claim.
//!
//! Prevout resolution mirrors the acceptor's shape
//! (`validate_tx_in_block_with_maturity` builds a `block_utxos` map from ALL of
//! the block's own outputs, then falls back to the persistent UTXO set): here
//! the overlay is all KEPT candidate txs' outputs plus the caller-supplied
//! store lookup. The candidate coinbase is NOT in the overlay — it does not
//! exist yet when the mirror runs, and same-block coinbase spends are barred by
//! maturity anyway.
//!
//! The whole `euvm` module only compiles under `--features euvm`, and the
//! main.rs call site is additionally guarded by `euvm_active(next_height)` —
//! the default build and pre-activation behaviour are byte-for-byte unchanged.

use std::collections::HashMap;

use bloch_crypto::core::{ChainId, Transaction, TxOutput};
use bloch_euvm::{Op, Val};

use super::{is_eutxo_script, validate_node_block, EuWitness, EUVM_BURN_BPS};

// ── Gas ceilings ──────────────────────────────────────────────────────────────
//
// PMO-DEDUP: the canonical per-tx / per-block gas ceilings are the ACCEPTOR's
// (D2's accept_block hook). D2's constants were not present in this worktree at
// branch time, so matching values are defined here under the agreed names.
// These MUST stay byte-identical with the values the acceptor passes to
// `validate_node_block`, or miner and validator disagree on which blocks are
// valid — PMO must collapse the two definitions into one at merge.
//
// Sizing rationale (F2 gas schedule, crates/bloch-euvm/src/lib.rs::op_gas):
// one hybrid ML-DSA-65‖Falcon-1024 legacy input costs ~1.3k gas (VerifySig
// base 1000 + word-proportional Picks over the ~2.6 kB pubkey / ~4.6 kB sig),
// so EUVM_PER_TX_GAS = 4M covers even a MAX_TX_INPUTS (1024) legacy tx (~1.4M)
// with headroom for real contract programs, and EUVM_BLOCK_GAS = 40M bounds a
// 2000-tx template of typical 1–2-input txs (~5M) an order of magnitude below
// the ceiling while still capping adversarial blocks deterministically.

// PMO-RECONCILED: the gas ceilings are the acceptor's (D2) values — a single
// source of truth at the crate root — so miner and validator agree by
// construction. Canonical = 2_000_000 / 8_000_000 (DoS/IBD-conservative; still
// covers the ~1.4M max-input legacy tx). Do NOT redefine here.
use super::{EUVM_PER_TX_GAS, EUVM_BLOCK_GAS};

// ── Witness wire codec (pinned by PMO) ────────────────────────────────────────
//
// PMO-DEDUP: canonical is D2's `crate::euvm::decode_input_witnesses` /
// `encode_input_witness` in mod.rs (not present in this worktree at branch
// time). The functions below implement the IDENTICAL pinned wire spec and live
// here (NOT in mod.rs) purely to avoid a merge conflict with D2; PMO
// deduplicates onto D2's canonical codec at merge.
//
// Pinned spec: witnesses ride in the existing `TxInput.script_sig` (no struct
// change); parsing is driven by the SPENT PREVOUT's type:
//   eUTXO prevout  → script_sig = u32LE(validator_len)
//                                 ‖ encode_program(validator)   (validator_len bytes)
//                                 ‖ u32LE(redeemer_count)
//                                 ‖ redeemer_items
//     each redeemer item a `Val`:  Int   → 0x00 ‖ i128 LE (16 bytes)
//                                  Bytes → 0x01 ‖ u32LE(len) ‖ bytes
//   legacy prevout → existing sig‖pubkey script_sig, witness = None.

/// Encode one contract-input witness per the pinned wire spec (inverse of
/// [`decode_input_witness`]). Byte-exact and canonical.
pub fn encode_input_witness(w: &EuWitness) -> Vec<u8> {
    let prog = bloch_euvm::encode_program(&w.validator);
    let mut out = Vec::with_capacity(4 + prog.len() + 4 + 32 * w.redeemer.len());
    out.extend_from_slice(&(prog.len() as u32).to_le_bytes());
    out.extend_from_slice(&prog);
    out.extend_from_slice(&(w.redeemer.len() as u32).to_le_bytes());
    for v in &w.redeemer {
        match v {
            Val::Int(n) => {
                out.push(0x00);
                out.extend_from_slice(&n.to_le_bytes());
            }
            Val::Bytes(b) => {
                out.push(0x01);
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
            }
        }
    }
    out
}

/// Strict cursor over `buf`: the next `n` bytes or `None` (fail-closed).
fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Option<&'a [u8]> {
    if buf.len().checked_sub(*pos)? < n {
        return None;
    }
    let s = &buf[*pos..*pos + n];
    *pos += n;
    Some(s)
}

fn take_u32(buf: &[u8], pos: &mut usize) -> Option<u32> {
    Some(u32::from_le_bytes(take(buf, pos, 4)?.try_into().ok()?))
}

/// Strict inverse of `bloch_euvm::encode_program` (tag table there is the
/// source of truth). Unknown tags, truncation → `None` (fail-closed: a
/// witness carrying an undecodable program simply never validates, so the tx
/// is excluded from the candidate).
fn decode_program(bytes: &[u8]) -> Option<Vec<Op>> {
    let mut ops = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let tag = bytes[pos];
        pos += 1;
        let op = match tag {
            0x01 => Op::PushInt(i128::from_le_bytes(take(bytes, &mut pos, 16)?.try_into().ok()?)),
            0x02 => {
                let len = take_u32(bytes, &mut pos)? as usize;
                Op::PushBytes(take(bytes, &mut pos, len)?.to_vec())
            }
            0x10 => Op::Dup,
            0x11 => Op::Drop,
            0x12 => Op::Swap,
            0x13 => Op::Pick(take(bytes, &mut pos, 1)?[0]),
            0x20 => Op::Add,
            0x21 => Op::Sub,
            0x22 => Op::Mul,
            0x30 => Op::Eq,
            0x31 => Op::Lt,
            0x32 => Op::Not,
            0x40 => Op::Sha256d,
            0x41 => Op::Shake256,
            0x42 => Op::Size,
            0x50 => Op::CtxField(take(bytes, &mut pos, 1)?[0]),
            0x60 => Op::VerifySig,
            0x61 => Op::Verify,
            0x62 => Op::VerifyEcdsa,
            0x70 => Op::TxOutDatum(take(bytes, &mut pos, 1)?[0]),
            0x71 => Op::TxOutValidator(take(bytes, &mut pos, 1)?[0]),
            0x72 => Op::TxOutValue(take(bytes, &mut pos, 1)?[0]),
            0x73 => Op::SelfValidator,
            0x74 => Op::SelfAsset,
            0x75 => Op::TxOutAsset(take(bytes, &mut pos, 1)?[0]),
            _ => return None, // unknown op tag — fail closed
        };
        ops.push(op);
    }
    Some(ops)
}

/// Strictly decode one contract-input witness (pinned spec above). The WHOLE
/// `script_sig` must be consumed — trailing bytes fail closed.
fn decode_input_witness(script_sig: &[u8]) -> Option<EuWitness> {
    let mut pos = 0usize;
    let vlen = take_u32(script_sig, &mut pos)? as usize;
    let validator = decode_program(take(script_sig, &mut pos, vlen)?)?;
    let rcount = take_u32(script_sig, &mut pos)? as usize;
    // Capacity bound: each item is ≥ 1 byte on the wire, so rcount can never
    // exceed the remaining bytes — reject early instead of over-allocating.
    if rcount > script_sig.len().saturating_sub(pos) {
        return None;
    }
    let mut redeemer = Vec::with_capacity(rcount);
    for _ in 0..rcount {
        let v = match take(script_sig, &mut pos, 1)?[0] {
            0x00 => Val::Int(i128::from_le_bytes(take(script_sig, &mut pos, 16)?.try_into().ok()?)),
            0x01 => {
                let len = take_u32(script_sig, &mut pos)? as usize;
                Val::Bytes(take(script_sig, &mut pos, len)?.to_vec())
            }
            _ => return None, // unknown Val tag — fail closed
        };
        redeemer.push(v);
    }
    if pos != script_sig.len() {
        return None; // trailing bytes — fail closed
    }
    Some(EuWitness { validator, redeemer })
}

/// Per-input witnesses for `tx` given its resolved prevouts, per the pinned
/// spec: tagged (eUTXO) prevout → parse the witness out of `script_sig`
/// (parse failure → `None`, which surfaces as `EuMapError::MissingWitness`
/// downstream — fail-closed); legacy prevout → `None` (its authorization is
/// the sig‖pubkey script_sig, consumed by the legacy mapping arm).
///
/// PMO-DEDUP: canonical is D2's `crate::euvm::decode_input_witnesses`.
fn decode_input_witnesses(tx: &Transaction, prevouts: &[TxOutput]) -> Vec<Option<EuWitness>> {
    tx.inputs
        .iter()
        .zip(prevouts)
        .map(|(inp, prev)| {
            if is_eutxo_script(&prev.script_pubkey) {
                decode_input_witness(&inp.script_sig)
            } else {
                None
            }
        })
        .collect()
}

// ── The miner mirror ──────────────────────────────────────────────────────────

/// Result of mirroring the validator over a candidate transaction set.
pub struct MirroredCandidate {
    /// The surviving transactions — this exact list passes
    /// [`validate_node_block`] with [`EUVM_PER_TX_GAS`]/[`EUVM_BLOCK_GAS`]
    /// under the same prevout resolution, by construction.
    pub txs: Vec<Transaction>,
    /// Total fee value the coinbase may claim over `txs`: full fee for
    /// legacy-only txs, post-burn miner share (`fee_burn(fee, EUVM_BURN_BPS).1`)
    /// for eUTXO-touching txs. Always ≤ the acceptor's
    /// `validate_coinbase_value` fee ceiling.
    pub claimable_fees: u64,
    /// How many candidate txs were excluded.
    pub dropped: usize,
    /// Total eUTXO gas the surviving set consumes.
    pub gas_used: u64,
}

/// Outpoint → output overlay of the candidate set's OWN outputs, mirroring the
/// acceptor's `block_utxos` map (position-independent, coinbase excluded here
/// because it is built after the mirror runs).
fn candidate_overlay(txs: &[Transaction]) -> HashMap<([u8; 32], u32), TxOutput> {
    let mut overlay = HashMap::new();
    for tx in txs {
        let txid = tx.txid();
        for (j, o) in tx.outputs.iter().enumerate() {
            overlay.insert((txid, j as u32), o.clone());
        }
    }
    overlay
}

/// True iff the eUTXO fee-burn applies to this tx: it spends at least one
/// tagged prevout or creates at least one tagged output.
///
/// PMO-DEDUP: this predicate MUST match the acceptor's (D2) burn predicate
/// exactly, or miner and validator disagree on the coinbase fee ceiling the
/// moment the acceptor enforces the burn. Today's acceptor ceiling is `<=`
/// with UN-burned fees, so this (smaller) claim is valid either way.
fn tx_touches_euvm(tx: &Transaction, prevouts: &[TxOutput]) -> bool {
    prevouts.iter().any(|p| is_eutxo_script(&p.script_pubkey))
        || tx.outputs.iter().any(|o| is_eutxo_script(&o.script_pubkey))
}

/// Mirror the validator over `candidates` (non-coinbase mempool selection,
/// in template order): run [`validate_node_block`] — the SAME entrypoint the
/// acceptor's D2 hook runs — and on any failure EXCLUDE the offending tx and
/// re-check, until the whole set validates. Terminates (each round removes
/// exactly one tx). Returns the surviving set plus the mirrored, burn-aware
/// claimable fee total computed over the same prevout resolution.
///
/// `lookup` resolves an outpoint from the node's persistent UTXO set; the
/// candidate set's own outputs are overlaid on top (acceptor shape — see the
/// module docs). Any unresolvable input fails closed
/// (`EuvmTxError::UnresolvedPrevouts` → tx excluded).
pub fn mirror_candidate_txs<L>(
    mut kept: Vec<Transaction>,
    chain_id: ChainId,
    lookup: L,
) -> MirroredCandidate
where
    L: Fn(&[u8; 32], u32) -> Option<TxOutput>,
{
    let mut dropped = 0usize;
    loop {
        let overlay = candidate_overlay(&kept);
        let resolve_prevouts = |tx: &Transaction| -> Option<Vec<TxOutput>> {
            let mut prevouts = Vec::with_capacity(tx.inputs.len());
            for inp in &tx.inputs {
                let p = overlay
                    .get(&(inp.prev_txid, inp.prev_index))
                    .cloned()
                    .or_else(|| lookup(&inp.prev_txid, inp.prev_index))?;
                prevouts.push(p);
            }
            Some(prevouts)
        };

        let result = validate_node_block(
            &kept,
            chain_id,
            |_ti, tx| {
                let prevouts = resolve_prevouts(tx)?;
                let witnesses = decode_input_witnesses(tx, &prevouts);
                Some((prevouts, witnesses))
            },
            EUVM_PER_TX_GAS,
            EUVM_BLOCK_GAS,
        );

        match result {
            Ok(gas_used) => {
                // Fee mirror over the FINAL kept set, same resolution. Every
                // tx here just validated, so all prevouts resolve and every
                // fee is non-negative (mapper-enforced FeeUnderflow).
                let mut claimable: u64 = 0;
                for tx in &kept {
                    let prevouts = match resolve_prevouts(tx) {
                        Some(p) => p,
                        None => continue, // unreachable post-validation; fail closed to 0 fee
                    };
                    let in_sum: u128 = prevouts.iter().map(|p| p.value as u128).sum();
                    let out_sum: u128 = tx.outputs.iter().map(|o| o.value as u128).sum();
                    let fee = u64::try_from(in_sum.saturating_sub(out_sum)).unwrap_or(0);
                    let miner_share = if tx_touches_euvm(tx, &prevouts) {
                        bloch_euvm::fee_burn(fee, EUVM_BURN_BPS).1
                    } else {
                        fee
                    };
                    claimable = claimable.saturating_add(miner_share);
                }
                return MirroredCandidate { txs: kept, claimable_fees: claimable, dropped, gas_used };
            }
            Err((ti, e)) => {
                // Exclude the offending tx and re-check the remainder: dropping
                // a tx can orphan a child that spent its outputs (overlay
                // shrinks) or free block gas — the loop converges on a set the
                // validator accepts in toto.
                log::warn!(
                    "euvm miner-mirror: excluding tx {} from candidate (validator would reject: {})",
                    hex::encode(kept[ti].txid()),
                    e
                );
                kept.remove(ti);
                dropped += 1;
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::euvm::{
        encode_output, legacy_pubkey_hash, validate_node_tx, EutxoScript, EuvmTxError,
    };
    use bloch_crypto::core::{ChainId, Transaction as NodeTx, TxInput, TxOutput as NodeOut};
    use bloch_euvm::{blch, validator_hash, ExtOutput, BLCH};
    use std::collections::HashMap as StdHashMap;
    use std::sync::OnceLock;

    const CHAIN: ChainId = ChainId::Genesis2Devnet;

    /// One shared real hybrid ML-DSA-65 ‖ Falcon-1024 keypair (keygen is
    /// expensive in debug builds — generate once per test binary).
    fn kp() -> &'static (Vec<u8>, Vec<u8>) {
        static K: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
        K.get_or_init(bloch_crypto::crypto::generate_keypair)
    }

    fn mk_input(prev_txid: [u8; 32], prev_index: u32) -> TxInput {
        TxInput { prev_txid, prev_index, script_sig: vec![], sequence: 0xffff_ffff }
    }

    /// A UTXO-set-backed lookup closure over an explicit map.
    fn store_lookup(
        map: StdHashMap<([u8; 32], u32), NodeOut>,
    ) -> impl Fn(&[u8; 32], u32) -> Option<NodeOut> {
        move |txid, idx| map.get(&(*txid, idx)).cloned()
    }

    /// A properly-signed 1-input legacy tx spending `(prev_txid, 0)` worth
    /// `in_value`, paying `out_value`. Returns (tx, prevout).
    fn legacy_signed_tx(prev_txid: [u8; 32], in_value: u64, out_value: u64) -> (NodeTx, NodeOut) {
        let (pk, sk) = kp();
        let mut tx = NodeTx {
            version: 1,
            inputs: vec![mk_input(prev_txid, 0)],
            outputs: vec![NodeOut { value: out_value, script_pubkey: vec![5u8; 20] }],
            locktime: 0,
        };
        let sighash = tx.sighash(0, CHAIN);
        let sig = bloch_crypto::crypto::sign(sk, &sighash).expect("sign");
        tx.inputs[0].script_sig = NodeTx::build_script_sig(&sig, pk);
        let prevout = NodeOut { value: in_value, script_pubkey: legacy_pubkey_hash(pk).to_vec() };
        (tx, prevout)
    }

    /// A hash-locked contract prevout + the tx spending it with the pinned
    /// wire-format witness in `script_sig`. `good` controls whether the
    /// revealed preimage is correct.
    fn contract_tx(prev_txid: [u8; 32], good: bool) -> (NodeTx, NodeOut) {
        use sha2::{Digest as _, Sha256};
        let preimage = b"the-secret-preimage".to_vec();
        let lock = Sha256::digest(Sha256::digest(&preimage)).to_vec();
        let hashlock = vec![Op::Sha256d, Op::PushBytes(lock), Op::Eq];

        let prevout = encode_output(&ExtOutput {
            value: blch(100),
            validator_hash: validator_hash(&hashlock),
            datum: Val::Int(0),
        })
        .expect("encode prevout");
        assert!(is_eutxo_script(&prevout.script_pubkey));

        let redeemer = if good { preimage } else { b"wrong".to_vec() };
        let witness = EuWitness { validator: hashlock, redeemer: vec![Val::Bytes(redeemer)] };
        let mut tx = NodeTx {
            version: 1,
            inputs: vec![mk_input(prev_txid, 0)],
            outputs: vec![NodeOut { value: 90, script_pubkey: vec![5u8; 20] }],
            locktime: 0,
        };
        tx.inputs[0].script_sig = encode_input_witness(&witness);
        (tx, prevout)
    }

    // ── codec ──

    /// decode_program is a strict inverse of bloch_euvm::encode_program over a
    /// program exercising EVERY op tag; unknown tags and truncation fail closed.
    #[test]
    fn program_codec_round_trip_all_ops() {
        let program = vec![
            Op::PushInt(i128::MIN),
            Op::PushBytes(b"payload".to_vec()),
            Op::Dup,
            Op::Drop,
            Op::Swap,
            Op::Pick(3),
            Op::Add,
            Op::Sub,
            Op::Mul,
            Op::Eq,
            Op::Lt,
            Op::Not,
            Op::Sha256d,
            Op::Shake256,
            Op::Size,
            Op::CtxField(1),
            Op::VerifySig,
            Op::Verify,
            Op::VerifyEcdsa,
            Op::TxOutDatum(0),
            Op::TxOutValidator(1),
            Op::TxOutValue(2),
            Op::SelfValidator,
            Op::SelfAsset,
            Op::TxOutAsset(3),
        ];
        let enc = bloch_euvm::encode_program(&program);
        // Op has no PartialEq — byte-exact re-encode is the identity check
        // (encode_program is canonical: equal bytes ⟺ same instruction seq).
        let decoded = decode_program(&enc).expect("round trip");
        assert_eq!(bloch_euvm::encode_program(&decoded), enc);
        // hash identity survives the round trip — the consensus binding
        assert_eq!(validator_hash(&decoded), validator_hash(&program));
        // truncation fails closed at every cut
        for cut in 0..enc.len() {
            if cut == 0 {
                assert!(decode_program(&enc[..0]).map(|v| v.is_empty()).unwrap_or(false));
            } else {
                let d = decode_program(&enc[..cut]);
                // either fails or decodes a strict prefix — never garbage
                if let Some(ops) = d {
                    assert!(bloch_euvm::encode_program(&ops).len() <= cut);
                }
            }
        }
        // unknown tag fails closed
        assert!(decode_program(&[0xFF]).is_none());
    }

    /// The pinned witness wire format round-trips, and malformed witnesses
    /// (trailing bytes, bad tags, truncation) fail closed.
    #[test]
    fn witness_codec_round_trip_and_strictness() {
        let w = EuWitness {
            validator: vec![Op::Sha256d, Op::PushBytes(vec![9u8; 32]), Op::Eq],
            redeemer: vec![Val::Bytes(b"preimage".to_vec()), Val::Int(-7)],
        };
        let wire = encode_input_witness(&w);
        let back = decode_input_witness(&wire).expect("decode");
        // Op has no PartialEq — compare canonical encodings instead
        assert_eq!(
            bloch_euvm::encode_program(&back.validator),
            bloch_euvm::encode_program(&w.validator)
        );
        assert_eq!(back.redeemer, w.redeemer);
        // byte-exact round trip
        assert_eq!(encode_input_witness(&back), wire);

        // trailing byte → fail closed
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(decode_input_witness(&trailing).is_none());
        // every strict prefix → fail closed
        for cut in 0..wire.len() {
            assert!(decode_input_witness(&wire[..cut]).is_none(), "prefix {cut} must fail");
        }
        // bad redeemer tag → fail closed
        let bad = encode_input_witness(&EuWitness { validator: vec![], redeemer: vec![] });
        let mut bad2 = bad.clone();
        bad2.extend_from_slice(&[0x02]); // junk after a valid empty witness
        assert!(decode_input_witness(&bad2).is_none());
    }

    /// Witness extraction is driven by the PREVOUT type: legacy prevouts get
    /// None even if their script_sig happens to parse; tagged prevouts get the
    /// parsed witness (or None on parse failure — fail closed).
    #[test]
    fn witnesses_driven_by_prevout_type() {
        let (legacy_tx, legacy_prev) = legacy_signed_tx([1u8; 32], 100, 90);
        let w = decode_input_witnesses(&legacy_tx, std::slice::from_ref(&legacy_prev));
        assert_eq!(w.len(), 1);
        assert!(w[0].is_none(), "legacy prevout must yield no witness");

        let (ctx_tx, ctx_prev) = contract_tx([2u8; 32], true);
        let w = decode_input_witnesses(&ctx_tx, std::slice::from_ref(&ctx_prev));
        assert!(w[0].is_some(), "tagged prevout must yield the parsed witness");

        // corrupt the witness → None (→ MissingWitness downstream)
        let mut broken = ctx_tx.clone();
        broken.inputs[0].script_sig.push(0xAA);
        let w = decode_input_witnesses(&broken, std::slice::from_ref(&ctx_prev));
        assert!(w[0].is_none(), "unparseable witness must fail closed");
    }

    // ── the mirror itself ──

    /// A valid legacy tx and a valid contract tx are both INCLUDED; an
    /// invalid contract spend (wrong preimage) is EXCLUDED; and the surviving
    /// set re-validates through the same validator entrypoint (agreement by
    /// construction).
    #[test]
    fn mirror_includes_valid_excludes_invalid() {
        let (good_legacy, legacy_prev) = legacy_signed_tx([1u8; 32], 100, 90);
        let (good_contract, good_prev) = contract_tx([2u8; 32], true);
        let (bad_contract, bad_prev) = contract_tx([3u8; 32], false);

        let mut utxos = StdHashMap::new();
        utxos.insert(([1u8; 32], 0u32), legacy_prev.clone());
        utxos.insert(([2u8; 32], 0u32), good_prev.clone());
        utxos.insert(([3u8; 32], 0u32), bad_prev.clone());
        let lookup = store_lookup(utxos);

        // sanity: the validator itself rejects the bad spend
        let w = decode_input_witnesses(&bad_contract, std::slice::from_ref(&bad_prev));
        assert_eq!(
            validate_node_tx(&bad_contract, std::slice::from_ref(&bad_prev), &w, CHAIN, EUVM_PER_TX_GAS),
            Err(EuvmTxError::ValidatorRejected(0))
        );

        let candidates = vec![good_legacy.clone(), bad_contract.clone(), good_contract.clone()];
        let m = mirror_candidate_txs(candidates, CHAIN, &lookup);

        assert_eq!(m.dropped, 1, "exactly the invalid contract tx is excluded");
        let kept_ids: Vec<[u8; 32]> = m.txs.iter().map(|t| t.txid()).collect();
        assert!(kept_ids.contains(&good_legacy.txid()));
        assert!(kept_ids.contains(&good_contract.txid()));
        assert!(!kept_ids.contains(&bad_contract.txid()));

        // agreement by construction: the kept set passes the validator's
        // block entrypoint verbatim
        let overlay = candidate_overlay(&m.txs);
        let ok = validate_node_block(
            &m.txs,
            CHAIN,
            |_ti, tx| {
                let mut prevouts = Vec::new();
                for inp in &tx.inputs {
                    prevouts.push(
                        overlay
                            .get(&(inp.prev_txid, inp.prev_index))
                            .cloned()
                            .or_else(|| lookup(&inp.prev_txid, inp.prev_index))?,
                    );
                }
                let w = decode_input_witnesses(tx, &prevouts);
                Some((prevouts, w))
            },
            EUVM_PER_TX_GAS,
            EUVM_BLOCK_GAS,
        );
        assert!(ok.is_ok(), "surviving set must validate: {ok:?}");
        assert_eq!(ok.unwrap(), m.gas_used);
    }

    /// A tx with an unresolvable prevout is excluded (fail-closed), and
    /// dropping a parent also drops the child that spent its outputs
    /// (drop-and-re-check convergence).
    #[test]
    fn mirror_drops_unresolved_and_orphaned_children() {
        // parent: INVALID contract spend that creates a legacy output the
        // child spends — child resolves only through the in-candidate overlay.
        let (mut parent, parent_prev) = contract_tx([4u8; 32], false);
        let (pk, sk) = kp();
        parent.outputs = vec![NodeOut { value: 80, script_pubkey: legacy_pubkey_hash(pk).to_vec() }];
        // (parent's witness needs no re-sign — hashlock ignores outputs)
        let parent_id = parent.txid();

        let mut child = NodeTx {
            version: 1,
            inputs: vec![mk_input(parent_id, 0)],
            outputs: vec![NodeOut { value: 70, script_pubkey: vec![6u8; 20] }],
            locktime: 0,
        };
        let sighash = child.sighash(0, CHAIN);
        let sig = bloch_crypto::crypto::sign(sk, &sighash).expect("sign");
        child.inputs[0].script_sig = NodeTx::build_script_sig(&sig, pk);

        // completely unresolvable tx
        let (ghost, _ghost_prev) = legacy_signed_tx([9u8; 32], 50, 40);

        let mut utxos = StdHashMap::new();
        utxos.insert(([4u8; 32], 0u32), parent_prev);
        // NOTE: ghost's prevout deliberately NOT in the store
        let lookup = store_lookup(utxos);

        let m = mirror_candidate_txs(vec![parent, child, ghost], CHAIN, &lookup);
        assert_eq!(m.txs.len(), 0, "invalid parent, orphaned child and ghost all excluded");
        assert_eq!(m.dropped, 3);
        assert_eq!(m.claimable_fees, 0);
    }

    /// Fee mirror: a legacy tx's fee is claimed in full; an eUTXO-touching
    /// tx's fee is claimed at the post-burn miner share — so the total always
    /// fits under the acceptor's `<= subsidy + total_fees` coinbase ceiling.
    #[test]
    fn fee_mirror_burns_euvm_fees_only() {
        let (legacy_tx, legacy_prev) = legacy_signed_tx([1u8; 32], 100, 90); // fee 10
        let (contract_tx_, contract_prev) = contract_tx([2u8; 32], true); // fee 10

        let mut utxos = StdHashMap::new();
        utxos.insert(([1u8; 32], 0u32), legacy_prev);
        utxos.insert(([2u8; 32], 0u32), contract_prev);
        let lookup = store_lookup(utxos);

        let m = mirror_candidate_txs(vec![legacy_tx, contract_tx_], CHAIN, &lookup);
        assert_eq!(m.dropped, 0);

        let (burned, to_miner) = bloch_euvm::fee_burn(10, EUVM_BURN_BPS);
        assert_eq!(burned + to_miner, 10);
        // legacy full fee (10) + contract post-burn share
        assert_eq!(m.claimable_fees, 10 + to_miner);
        // the acceptor's ceiling counts FULL fees today — the claim is below it
        assert!(m.claimable_fees <= 20);
    }

    /// Empty candidate set is a no-op: nothing dropped, zero fees, zero gas.
    #[test]
    fn mirror_empty_set_is_noop() {
        let lookup = store_lookup(StdHashMap::new());
        let m = mirror_candidate_txs(Vec::new(), CHAIN, &lookup);
        assert!(m.txs.is_empty());
        assert_eq!(m.dropped, 0);
        assert_eq!(m.claimable_fees, 0);
        assert_eq!(m.gas_used, 0);
    }

    /// Sanity pin on the wire constants: an all-legacy candidate consumes well
    /// under the per-tx ceiling per tx, so realistic templates can never brush
    /// the PMO-DEDUP gas ceilings by accident.
    #[test]
    fn gas_ceilings_have_headroom_for_legacy_txs() {
        let (tx, prev) = legacy_signed_tx([1u8; 32], 100, 90);
        let mut utxos = StdHashMap::new();
        utxos.insert(([1u8; 32], 0u32), prev);
        let m = mirror_candidate_txs(vec![tx], CHAIN, store_lookup(utxos));
        assert_eq!(m.dropped, 0);
        assert!(m.gas_used < EUVM_PER_TX_GAS / 100, "one legacy input must be ≪ per-tx gas; got {}", m.gas_used);
    }

    /// EutxoScript import is load-bearing for the tests above via encode_output;
    /// keep a direct strict-decode pin here so a codec change surfaces loudly.
    #[test]
    fn tagged_script_still_strict() {
        let s = EutxoScript {
            validator_hash: [7u8; 32],
            datum: Val::Int(1),
            assets: Default::default(),
        };
        let enc = crate::euvm::encode_eutxo_script(&s).expect("encode");
        assert!(is_eutxo_script(&enc));
    }
}
