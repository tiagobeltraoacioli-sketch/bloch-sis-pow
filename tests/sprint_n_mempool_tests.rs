//! Sprint N-min — Mempool hardening tests
//!
//! Covers:
//!   - Intra-mempool double-spend rejection (MempoolError::Conflict)
//!   - Per-tx size cap (MempoolError::Oversized)
//!   - Spent-outpoint index invariant across add / remove / remove_confirmed
//!   - Regressions on existing behaviour (Duplicate, Invalid)
//!
//! Tests construct Transactions directly without real ML-DSA signatures;
//! mempool.add() does not verify signatures — that is the validator's job
//! upstream. These tests isolate mempool-level checks.

#[cfg(test)]
mod sprint_n_tests {
    use bloch::core::{Transaction, TxInput, TxOutput};
    use bloch::mempool::{Mempool, MempoolError, MAX_TX_SIZE};

    fn make_tx(prev_txid: [u8; 32], prev_idx: u32, value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid,
                prev_index: prev_idx,
                script_sig: vec![0u8; 32], // placeholder
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOutput {
                value,
                script_pubkey: vec![1u8; 20],
            }],
            locktime: 0,
        }
    }

    fn make_multi_input_tx(inputs: Vec<([u8; 32], u32)>, value_per_output: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: inputs.into_iter().map(|(txid, idx)| TxInput {
                prev_txid: txid,
                prev_index: idx,
                script_sig: vec![0u8; 32],
                sequence: 0xffffffff,
            }).collect(),
            outputs: vec![TxOutput {
                value: value_per_output,
                script_pubkey: vec![1u8; 20],
            }],
            locktime: 0,
        }
    }

    // ─────────────────────────────────────────────────────────
    // Baseline happy path
    // ─────────────────────────────────────────────────────────

    #[test]
    fn add_accepts_normal_tx() {
        let mp = Mempool::new();
        let tx = make_tx([1; 32], 0, 1_000);
        let res = mp.add(tx, 100);
        assert!(res.is_ok());
        assert_eq!(mp.size(), 1);
    }

    #[test]
    fn add_rejects_duplicate_tx() {
        let mp = Mempool::new();
        let tx = make_tx([1; 32], 0, 1_000);
        assert!(mp.add(tx.clone(), 100).is_ok());
        let res = mp.add(tx, 100);
        assert!(matches!(res, Err(MempoolError::Duplicate)));
    }

    #[test]
    fn add_rejects_empty_inputs() {
        let mp = Mempool::new();
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput { value: 1, script_pubkey: vec![1; 20] }],
            locktime: 0,
        };
        let res = mp.add(tx, 0);
        assert!(matches!(res, Err(MempoolError::Invalid(_))));
    }

    // ─────────────────────────────────────────────────────────
    // Sprint N-min: Conflict detection
    // ─────────────────────────────────────────────────────────

    #[test]
    fn add_rejects_conflicting_tx_same_input() {
        let mp = Mempool::new();
        // tx1 and tx2 both spend outpoint ([7;32], 0) but have different outputs
        // → they produce different txids but conflict at the UTXO layer.
        let prev = [7u8; 32];
        let tx1 = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev, prev_index: 0, script_sig: vec![0; 32], sequence: 0xffffffff,
            }],
            outputs: vec![TxOutput { value: 1_000, script_pubkey: vec![1; 20] }],
            locktime: 0,
        };
        let tx2 = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev, prev_index: 0, script_sig: vec![0; 32], sequence: 0xffffffff,
            }],
            outputs: vec![TxOutput { value: 2_000, script_pubkey: vec![2; 20] }],
            locktime: 0,
        };
        assert_ne!(tx1.txid(), tx2.txid(), "test bug: txs should differ");

        let tx1_txid = tx1.txid();
        assert!(mp.add(tx1, 100).is_ok());

        let res = mp.add(tx2, 200);
        match res {
            Err(MempoolError::Conflict { outpoint_txid, outpoint_idx, existing_spender }) => {
                assert_eq!(outpoint_txid, prev);
                assert_eq!(outpoint_idx, 0);
                assert_eq!(existing_spender, tx1_txid,
                    "Conflict should point to the first-seen spender");
            }
            other => panic!("expected Conflict, got {:?}", other),
        }
        assert_eq!(mp.size(), 1, "tx2 must not have been added");
    }

    #[test]
    fn add_rejects_conflict_on_any_shared_input() {
        // tx1 uses (A, 0). tx2 uses (B, 0) + (A, 0). tx2 must be rejected even
        // though B is fresh, because A is already claimed.
        let mp = Mempool::new();
        let a = [0xaau8; 32];
        let b = [0xbbu8; 32];

        let tx1 = make_tx(a, 0, 100);
        assert!(mp.add(tx1, 100_000).is_ok());

        let tx2 = make_multi_input_tx(vec![(b, 0), (a, 0)], 200);
        let res = mp.add(tx2, 200_000);
        assert!(matches!(res, Err(MempoolError::Conflict { .. })));
        assert_eq!(mp.size(), 1);
    }

    #[test]
    fn add_accepts_non_conflicting_tx() {
        // Same prev_txid but different prev_index — those are distinct outpoints,
        // so no conflict.
        let mp = Mempool::new();
        let prev = [0x42u8; 32];
        // Fees clear the L2 minimum relay rate (1 sat/byte; make_tx ≈ 112 bytes).
        assert!(mp.add(make_tx(prev, 0, 100), 100_000).is_ok());
        assert!(mp.add(make_tx(prev, 1, 200), 100_000).is_ok());
        assert!(mp.add(make_tx(prev, 2, 300), 100_000).is_ok());
        assert_eq!(mp.size(), 3);
    }

    // ─────────────────────────────────────────────────────────
    // Sprint N-min: Spent index sync across remove/remove_confirmed
    // ─────────────────────────────────────────────────────────

    #[test]
    fn remove_frees_outpoint_for_reuse() {
        // After a tx is removed, a conflicting tx should be admissible.
        let mp = Mempool::new();
        let prev = [0x33u8; 32];

        let tx1 = make_tx(prev, 0, 100);
        let tx1_txid = tx1.txid();
        assert!(mp.add(tx1, 100_000).is_ok());

        // Conflict at this point
        let tx2 = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev, prev_index: 0, script_sig: vec![0; 32], sequence: 0xffffffff,
            }],
            outputs: vec![TxOutput { value: 500, script_pubkey: vec![9; 20] }],
            locktime: 0,
        };
        assert!(matches!(mp.add(tx2.clone(), 200_000), Err(MempoolError::Conflict { .. })));

        // Remove tx1
        assert!(mp.remove(&tx1_txid));

        // Now tx2 should succeed
        assert!(mp.add(tx2, 200_000).is_ok());
        assert_eq!(mp.size(), 1);
    }

    #[test]
    fn remove_confirmed_frees_outpoints() {
        let mp = Mempool::new();
        let prev = [0x55u8; 32];

        let tx1 = make_tx(prev, 0, 100);
        let tx1_txid = tx1.txid();
        assert!(mp.add(tx1, 100_000).is_ok());

        // Simulate block confirmation
        mp.remove_confirmed(&[tx1_txid]);
        assert_eq!(mp.size(), 0);

        // A new tx on the same outpoint must now succeed (UTXO check is
        // the caller's job; mempool is no longer blocking).
        let tx2 = make_tx(prev, 0, 200);
        assert!(mp.add(tx2, 200_000).is_ok());
    }

    // ─────────────────────────────────────────────────────────
    // Sprint N-min: Oversized tx rejection
    // ─────────────────────────────────────────────────────────

    #[test]
    fn add_rejects_oversized_tx() {
        let mp = Mempool::new();
        // Build a tx whose serialized size exceeds MAX_TX_SIZE by inflating script_sig.
        // script_sig is a Vec<u8>; fill with > MAX_TX_SIZE bytes.
        let big_script = vec![0xcdu8; MAX_TX_SIZE + 1024]; // overshoot a bit
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0x11; 32],
                prev_index: 0,
                script_sig: big_script,
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOutput {
                value: 100,
                script_pubkey: vec![1; 20],
            }],
            locktime: 0,
        };

        let res = mp.add(tx, 1);
        match res {
            Err(MempoolError::Oversized { size, max }) => {
                assert_eq!(max, MAX_TX_SIZE);
                assert!(size > MAX_TX_SIZE);
            }
            other => panic!("expected Oversized, got {:?}", other),
        }
    }

    #[test]
    fn add_accepts_large_but_within_cap() {
        let mp = Mempool::new();
        // 200 KB tx — under the 400 KB cap, should be accepted.
        let script = vec![0x77u8; 200 * 1024];
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0x22; 32],
                prev_index: 0,
                script_sig: script,
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOutput {
                value: 100,
                script_pubkey: vec![1; 20],
            }],
            locktime: 0,
        };
        assert!(mp.add(tx, 300_000).is_ok());
    }

    // ─────────────────────────────────────────────────────────
    // Sprint N-min: Coinbase rejection still works
    // ─────────────────────────────────────────────────────────

    #[test]
    fn add_still_rejects_coinbase() {
        let mp = Mempool::new();
        // A coinbase tx has a single input with prev_txid = zeros.
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0; 32],
                prev_index: 0xffffffff,
                script_sig: b"height:0".to_vec(),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOutput {
                value: 1_050_000_00000000,
                script_pubkey: vec![1; 20],
            }],
            locktime: 0,
        };
        assert!(tx.is_coinbase(), "test bug: tx should be coinbase");

        let res = mp.add(tx, 0);
        assert!(matches!(res, Err(MempoolError::Invalid(_))));
    }
}
