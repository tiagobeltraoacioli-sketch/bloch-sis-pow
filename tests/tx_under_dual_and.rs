//! LOCAL TEST — TRANSACTION validity is INVARIANT to the "Dual AND" PoW scheme.
//!
//! Claim proven here:
//!   valid(block) = sha256d_ok(header)  AND  sis_ok(header, pow_solution)
//! changes ONLY the proof-of-work predicate. Transaction format and every
//! transaction-level validation are UNTOUCHED — a block's PoW is checked by a
//! SEPARATE method (`validate_pow`) that reads only header/bits/pow_solution and
//! NEVER the `transactions`. Therefore a transaction that is valid today (pure
//! SHA-256d, empty `pow_solution`) is valid BYTE-FOR-BYTE inside a Dual-AND block
//! (SHA-256d + a bound SIS witness). Adding the SIS co-requirement creates NO
//! transaction-compatibility problem.
//!
//! This test does NOT modify consensus. It reconstructs the Dual-AND predicate
//! from the crate's EXISTING public primitives (same style as the shipped
//! `tests/dual_and_local.rs` and `examples/mine_dual_and.rs`) and drives the
//! REAL transaction-level validators on ONE block whose ONLY difference between
//! the two configs is the `pow_solution` field.
//!
//! Method (grounding: file:line in crates/bloch-crypto/src/core/mod.rs):
//!   * `Block::validate_pow`               :1480  — the ONLY PoW method; reads
//!         header/bits/pow_solution, never `transactions`.
//!   * tx-level validators, PoW-independent (read only txs/merkle_root):
//!         `validate_merkle` :1476, `validate_coinbase_format` :1532,
//!         `validate_no_duplicate_txs` :1658, `validate_dust` :1640.
//!   * signature path: `crypto::verify(&pk, &tx.sighash(0, chain_id), &sig)`
//!         over `(sig, pk) = Transaction::parse_script_sig(script_sig)`.
//!   * SHA-256d gate  : `sha256d_pow_valid` :2029 (80-byte `pow_hash()`).
//!   * SIS gate       : `pow::verify_sis_pow_testnet` over the nonce-less
//!                      `pow_preimage()` (76 B) + the full nonce.
//!
//! IMPORTANT CORRECTION vs the task grounding: `Block::validate_structure`
//! :1672 is NOT a pure tx-level check — it CALLS `validate_pow()` internally
//! (line 1674). It is the single block method where PoW enters. So it is
//! deliberately EXCLUDED from the invariant set below; the PoW predicate is
//! reconstructed separately. That exclusion IS the point: PoW is cleanly
//! factored out of transaction validation.

use bloch::core::{
    sha256d_pow_valid, Block, BlockHeader, ChainId, MerkleRoot, Transaction, TxInput, TxOutput,
};
use bloch::crypto;
use bloch::pow;
use bloch::wallet::{generate_keypair, TxBuilder};

/// Post-activation height for the (hypothetical) Dual-AND rule. Also >= the
/// SHA-256d little-endian fork height, so `sha256d_pow_valid` uses the current
/// (reversed-hash) comparison — matches `examples/mine_dual_and.rs`.
const HEIGHT: u64 = 5_000;

/// Leading zero BITS the SHA-256d hash must have. 12 => ~4096 hashes/hit, a fast
/// debug-build grind while still being a REAL (non-all-FF) SHA-256d target.
const SHA_BITS: u32 = 12;

/// Big-endian target with `bits` leading zeros then all-ones (mirrors the
/// example): hash <= target iff the hash has at least `bits` leading zero bits.
fn target_with_leading_zeros(bits: u32) -> [u8; 32] {
    let mut t = [0xFFu8; 32];
    let full = (bits / 8) as usize;
    for b in t.iter_mut().take(full) {
        *b = 0x00;
    }
    let rem = bits % 8;
    if full < 32 && rem > 0 {
        t[full] = 0xFFu8 >> rem;
    }
    t
}

/// A minimal, well-formed coinbase (1 input, prev_txid == 0, prev_index ==
/// u32::MAX) so `is_coinbase()`/`validate_coinbase_format()` accept it. Value is
/// irrelevant to the compat invariant (we don't call `validate_coinbase_value`,
/// which needs the founder/subsidy schedule).
fn make_coinbase() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_index: u32::MAX,
            script_sig: b"tx-under-dual-and local test coinbase".to_vec(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOutput {
            value: 190_500_000_000,
            script_pubkey: vec![0x11; 20],
        }],
        locktime: 0,
    }
}

/// Run EVERY PoW-independent transaction-level validation on a block and return
/// the tuple of results. This is the exact surface a transaction's validity
/// depends on. It reads only `transactions`/`merkle_root` — NEVER `pow_solution`.
fn tx_level_report(block: &Block) -> (bool, bool, bool, bool, bool) {
    // Signature check on the spend tx (index 1), exactly as the consensus
    // verifier extracts it: parse (sig,pk) out of script_sig, verify over the
    // chain-bound sighash. generate_keypair(true) yields a testnet address, so
    // TxBuilder signs under ChainId::Testnet.
    let spend = &block.transactions[1];
    let (sig, pk) = Transaction::parse_script_sig(&spend.inputs[0].script_sig)
        .expect("spend tx script_sig must parse");
    let sig_ok = crypto::verify(&pk, &spend.sighash(0, ChainId::Testnet), &sig);

    (
        block.validate_merkle(),
        block.validate_coinbase_format(),
        block.validate_no_duplicate_txs().is_ok(),
        block.validate_dust().is_ok(),
        sig_ok,
    )
}

/// THE reconstructed Dual-AND PoW predicate (cheap SHA gate first, then the
/// nonce-bound SIS witness). Identical wiring to `tests/dual_and_local.rs`.
fn dual_and_pow_ok(header: &BlockHeader, pow_solution: &[i32], sha_target: &[u8; 32], sis_bits: u32) -> bool {
    if !sha256d_pow_valid(&header.pow_hash(), sha_target, HEIGHT) {
        return false;
    }
    if pow_solution.len() != pow::SOLUTION_LEN {
        return false;
    }
    let mut s = [0i32; pow::SOLUTION_LEN];
    s.copy_from_slice(pow_solution);
    pow::verify_sis_pow_testnet(&header.pow_preimage(), header.nonce, &s, sis_bits).is_ok()
}

#[test]
fn tx_validity_is_invariant_to_dual_and_pow() {
    // ── (1) A REAL signed spend transaction (ML-DSA-65 ‖ Falcon-1024) ────────
    // Build it against a mock funding UTXO, mirroring `bloch-cli`. TxBuilder
    // signs every input with the keypair regardless of the mock UTXO's
    // script_pubkey, so no matching spendable script is required.
    let keypair = generate_keypair(true); // testnet address -> ChainId::Testnet
    let dest_hex = "aabbccddeeff00112233445566778899aabbccdd"; // 20-byte hex addr
    let funding_txid = hex::decode("11".repeat(32)).unwrap();
    let available_utxos = vec![(
        funding_txid,
        0u32,
        TxOutput { value: 1_000_000, script_pubkey: keypair.address_bytes() },
    )];
    let spend = TxBuilder::build(&keypair, &available_utxos, dest_hex, 100_000, 1_000)
        .expect("TxBuilder::build must produce a signed spend tx");

    // Sanity: the spend really carries a verifiable post-quantum signature.
    let (sig0, pk0) = Transaction::parse_script_sig(&spend.inputs[0].script_sig).unwrap();
    assert!(
        crypto::verify(&pk0, &spend.sighash(0, ChainId::Testnet), &sig0),
        "precondition: the built spend tx must have a valid signature"
    );

    // ── (2) Assemble the block: [coinbase, spend]; merkle bound to the txs ───
    let coinbase = make_coinbase();
    let transactions = vec![coinbase, spend];
    // No shielded txs => body_merkle_root == Transaction::merkle_root(txs).
    let merkle: MerkleRoot = Transaction::merkle_root(&transactions);

    let sis_bits = pow::target_to_bits(&pow::Target::MAX);
    let sha_target = target_with_leading_zeros(SHA_BITS);

    // Header committing to the REAL merkle root. pow_preimage()/pow_hash() read
    // these fields; the SIS seed and the SHA hash both bind this same header.
    let base_header = BlockHeader {
        version: 1,
        parents: vec![],
        merkle_root: merkle,
        timestamp: 1_777_000_000,
        bits: sis_bits, // easiest SIS aux target; work is the k=4 residual gate
        nonce: 0,
    };

    // ── (3) Mine ONE shared nonce clearing BOTH schemes (coupled loop) ───────
    // pow_preimage excludes the nonce (76 B) -> identical for every nonce.
    let preimage = base_header.pow_preimage();
    let (shared_nonce, witness) = {
        let mut nonce: u64 = 0;
        loop {
            let mut h = base_header.clone();
            h.nonce = nonce;
            // Cheap SHA-256d gate first.
            if sha256d_pow_valid(&h.pow_hash(), &sha_target, HEIGHT) {
                // SIS solve BOUND to THIS exact nonce (budget capped so it can't
                // wander to a different nonce -> upholds the coupling).
                if let Some((got, sol)) = pow::mine_sis_pow_testnet(&preimage, sis_bits, nonce, 8_192) {
                    assert_eq!(got, nonce, "coupling: SIS witness must bind the SHA nonce");
                    break (nonce, sol.to_vec());
                }
            }
            nonce += 1;
            assert!(nonce < (1u64 << 32), "exhausted 32-bit nonce space; lower SHA_BITS");
        }
    };
    assert!(shared_nonce < (1u64 << 32), "nonce must be < 2^32 (SHA/SIS coupling)");

    let mut header = base_header.clone();
    header.nonce = shared_nonce;

    // ── Two PoW configs of the SAME block/txs, differing ONLY in pow_solution ─
    // (a) PRE-activation SHA-256d block: empty witness (today's Genesis-2 form).
    let block_a = Block {
        header: header.clone(),
        transactions: transactions.clone(),
        blue_score: 0,
        height: HEIGHT,
        pow_solution: vec![], // <-- the only field that differs
        shielded_transactions: vec![],
    };
    // (b) DUAL-AND block: same header/txs, SIS witness attached.
    let block_b = Block {
        header: header.clone(),
        transactions: transactions.clone(),
        blue_score: 0,
        height: HEIGHT,
        pow_solution: witness.clone(), // <-- the only field that differs
        shielded_transactions: vec![],
    };

    // ── (4) THE COMPAT INVARIANT ─────────────────────────────────────────────
    // Every PoW-independent transaction-level validation returns the SAME result
    // under (a) and (b). Since the ONLY difference between the blocks is
    // `pow_solution`, equality here proves tx validity does not depend on the
    // PoW scheme.
    let report_a = tx_level_report(&block_a);
    let report_b = tx_level_report(&block_b);
    assert_eq!(
        report_a, report_b,
        "transaction-level validity MUST be identical under SHA-256d and Dual-AND"
    );
    // And it is affirmatively VALID (not merely 'equally false').
    assert_eq!(
        report_a,
        (true, true, true, true, true),
        "the transaction-level checks must all PASS: (merkle, coinbase_format, no_dup, dust, signature)"
    );

    // ── (5) The Dual-AND PoW predicate holds for block (b) ───────────────────
    assert!(
        sha256d_pow_valid(&block_b.header.pow_hash(), &sha_target, HEIGHT),
        "Dual-AND (b): SHA-256d component must pass"
    );
    let mut s_arr = [0i32; pow::SOLUTION_LEN];
    s_arr.copy_from_slice(&block_b.pow_solution);
    assert!(
        pow::verify_sis_pow_testnet(&block_b.header.pow_preimage(), block_b.header.nonce, &s_arr, sis_bits).is_ok(),
        "Dual-AND (b): SIS component must pass"
    );
    assert!(
        dual_and_pow_ok(&block_b.header, &block_b.pow_solution, &sha_target, sis_bits),
        "Dual-AND (b): the full AND predicate must hold"
    );
    // (a) is a valid PRE-activation SHA-256d block but NOT a Dual-AND block
    // (no witness) — confirming the two PoW regimes are genuinely distinct.
    assert!(
        !dual_and_pow_ok(&block_a.header, &block_a.pow_solution, &sha_target, sis_bits),
        "pre-activation (a): empty-witness block is not a Dual-AND block"
    );

    // ── (6) NEGATIVE: corrupting the SIS witness breaks Dual-AND PoW but leaves
    //         EVERY transaction-level validation unchanged (orthogonality). ────
    let mut corrupt_witness = witness.clone();
    corrupt_witness[0] = corrupt_witness[0].wrapping_add(1);
    let block_c = Block {
        header: header.clone(),
        transactions: transactions.clone(),
        blue_score: 0,
        height: HEIGHT,
        pow_solution: corrupt_witness.clone(),
        shielded_transactions: vec![],
    };
    assert!(
        !dual_and_pow_ok(&block_c.header, &block_c.pow_solution, &sha_target, sis_bits),
        "corrupting the SIS witness MUST break the Dual-AND PoW"
    );
    assert_eq!(
        tx_level_report(&block_c),
        report_a,
        "corrupting the PoW witness MUST NOT change ANY transaction-level result"
    );

    println!("shared nonce = {shared_nonce} (< 2^32: {})", shared_nonce < (1u64 << 32));
    println!("tx-level report (a)=(b)=(c) = {report_a:?}  [merkle, coinbase_fmt, no_dup, dust, sig]");
    println!("Dual-AND PoW: (a) empty-witness = false, (b) SIS-bound = true, (c) corrupt = false");
    println!("=> transaction validity is INVARIANT to the Dual AND PoW scheme.");
}
