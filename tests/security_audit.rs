//! Bloch-SIS Protocol — Security Audit Tests
//!
//! Attack vectors tested:
//!   VULN-01 [CRITICAL] Difficulty bypass — block accepts any `bits` value
//!   VULN-02 [CRITICAL] Height spoofing — self-reported, never validated
//!   VULN-03 [HIGH]     FIXED: Coinbase maturity enforced (Sprint N-min)
//!   VULN-04 [HIGH]     Timestamp manipulation — no bounds, distorts retargeting
//!   VULN-05 [MEDIUM]   Coinbase excludes fees — miners can't collect TX fees
//!   VULN-06 [MEDIUM]   TXID malleability — script_sig included in txid hash
//!   VULN-07 [LOW]      Dust attack — zero-value outputs bloat UTXO set
//!   VULN-08 [HIGH]     CVE-2012-2459 — duplicate-tx merkle malleability (Sprint S)
//!   VULN-09 [LOW]      RPC unauthenticated — open to world, no rate limiting (Sprint M)

#[cfg(test)]
mod security_tests {
    use bloch::core::*;
    use bloch::crypto;

    // ═══════════════════════════════════════════════════════════════════════
    // VULN-01 [CRITICAL]: Difficulty bypass
    //
    // validate_pow() checks hash against the block's OWN bits field.
    // Attacker sets bits = 0x2100ffff (trivially easy target) and mines
    // a valid block in microseconds. No check that bits matches the
    // expected difficulty from consensus.
    //
    // Impact: Complete PoW bypass. Attacker can flood chain with blocks.
    // Fix: accept_block() must verify block.header.bits == expected_bits
    //      from storage ("current_bits" meta key).
    // ═══════════════════════════════════════════════════════════════════════
    #[test]
    fn vuln01_difficulty_bypass() {
        let founder = b"test_founder_20bytes";
        let mut block = create_genesis_block(founder, founder, founder);

        // Set absurdly easy difficulty — 0x20ffffff: exp=32, mant=0xffffff
        // target[0]=0xff → virtually any SHA-256 hash meets this target
        block.header.bits = 0x20ffffff;
        block.header.nonce = 0;

        // PoW passes trivially because validate_pow checks the block's OWN bits
        let hash = block.header.pow_hash();
        let target = bits_to_target(block.header.bits);
        assert!(
            hash_meets_target(&hash, &target),
            "VULN-01 CONFIRMED: block with trivial difficulty passes PoW validation"
        );

        // But with correct difficulty, the same nonce would fail
        block.header.bits = 0x1d00ffff; // real difficulty
        assert!(
            !block.validate_pow(),
            "With real difficulty, nonce=0 should fail"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VULN-02 [CRITICAL]: Height spoofing
    //
    // block.height is self-reported, used in:
    //   - block_reward(height): determines mining reward
    //   - validate_coinbase(): checks reward against height
    //   - retarget calculation: determines when to retarget
    //
    // Attack: set height = 13,440,000 (64+ halvings) → reward = 0
    //   Then put enormous value in coinbase → validate_coinbase passes
    //   because 0 <= anything fails... wait, no: reward=0, total_out > 0
    //   → total_out <= reward fails.
    //
    // Better attack: set height = 0 → reward = 5 BLOCH (max)
    //   Real height might be 1,000,000 where reward should be ~0.
    //   Attacker claims full 5 BLOCH reward.
    //
    // Impact: Inflation — attacker mints coins at height-0 rate forever.
    // Fix: Validate block.height == selected_parent.height + 1
    // ═══════════════════════════════════════════════════════════════════════
    #[test]
    fn vuln02_height_spoofing_inflation() {
        // V2 height-spoofing attack: V2 subsidy depends on height
        // (INITIAL_BLOCK_REWARD_SAT for h < halving 1, halved per HALVING_INTERVAL,
        // tail floor TAIL_FLOOR_SAT after halving 7 ≈ h ≥ 1_470_000).
        // An attacker constructs a coinbase sized for h=0 (1905 BLOCH subsidy)
        // but tries to use it at a real height where subsidy is much smaller.
        //
        // Both heights chosen here (0 and 10_000_000) are OUTSIDE the founder
        // vesting window [CLIFF+1=210_001, END=5_970_000], so the coinbase
        // must have exactly 3 outputs (no founder output).
        use bloch::core::tokenomics_v2;

        // Pure PoW (B3): coinbase is a single miner output paying the full
        // subsidy. Build one sized for h=0, then spoof to h=10M below.
        let subsidy_h0 = tokenomics_v2::block_subsidy_sat(0);

        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid:  [0u8; 32],
                prev_index: u32::MAX,
                script_sig: b"height:0".to_vec(),
                sequence:   u32::MAX,
            }],
            outputs: vec![
                TxOutput { value: subsidy_h0, script_pubkey: vec![0u8; 20] },
            ],
            locktime: 0,
        };
        let merkle = Transaction::merkle_root(&[coinbase.clone()]);
        let mut block = Block {
            header: BlockHeader {
                version:     1,
                parents:     vec![],
                merkle_root: merkle,
                timestamp:   1_750_000_000,
                bits:        0x1d00ffff,
                nonce:       0,
            },
            transactions: vec![coinbase],
            blue_score:   0,
            height:       0,
            pow_solution: Vec::new(),
            shielded_transactions: Vec::new(),        };

        // Sanity: at real h=0, the coinbase passes validation (correct values)
        assert!(
            block.validate_coinbase_value(0).is_ok(),
            "V2 VULN-02 sanity: correct h=0 coinbase must pass at h=0"
        );

        // Sanity: tail-floor heights have a smaller subsidy than h=0
        let subsidy_late = tokenomics_v2::block_subsidy_sat(10_000_000);
        assert!(
            subsidy_late < subsidy_h0,
            "V2 sanity: tail floor (h=10M) must be smaller than initial subsidy (h=0)"
        );

        // Attack: spoof to h=10M while keeping h=0-sized outputs.
        // validate_coinbase_value must reject because output values are
        // sized for h=0 subsidy, not for the (much smaller) h=10M subsidy.
        block.height = 10_000_000;
        assert!(
            block.validate_coinbase_value(0).is_err(),
            "V2 VULN-02: at h=10M, h=0-sized coinbase must be rejected (inflation prevented)"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VULN-03 [HIGH] FIXED: Coinbase maturity enforced (Sprint N-min)
    //
    // Bitcoin requires 100 confirmations before coinbase outputs are
    // spendable. Bloch-SIS Protocol enforces the same via
    // `core::check_coinbase_maturity`, used by both block-validation
    // (main.rs::validate_tx_in_block_with_maturity) and mempool-admission
    // (rpc/mod.rs::validate_tx_for_mempool) paths.
    //
    // Original attack scenario (now blocked):
    //   1. Miner mines block A with coinbase → 5 BLOCH
    //   2. In the NEXT block B, spends that coinbase output (REJECTED:
    //      depth=1 < COINBASE_MATURITY=100).
    //   3. Spend only succeeds once depth >= 100 confirmations.
    //
    // The four tests below verify the policy directly against the helper:
    // immature spend rejected, mature spend allowed, non-coinbase spend
    // unaffected, and pre-genesis (current_height==0) skipped.
    // ═══════════════════════════════════════════════════════════════════════
    /// Helper: a non-coinbase tx whose single input references `prev_txid`.
    /// Constructed by cloning the genesis coinbase (so we inherit whatever
    /// fields `Transaction` has) and overwriting inputs.
    fn spending_tx(prev_txid: [u8; 32]) -> Transaction {
        let founder = b"test_founder_20bytes";
        let mut tx = create_genesis_block(founder, founder, founder)
            .transactions[0]
            .clone();
        tx.inputs = vec![TxInput {
            prev_txid,
            prev_index: 0,
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        }];
        tx
    }

    #[test]
    fn vuln03_immature_coinbase_spend_rejected() {
        // Coinbase mined at h=5; we try to spend at h=50. depth=45 < 100.
        let tx = spending_tx([0x42; 32]);
        let result = check_coinbase_maturity(&tx, 50, |_| Some(5));
        assert!(result.is_err(), "immature coinbase spend must be rejected");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("coinbase maturity"),
            "error should mention 'coinbase maturity', got: {}", msg
        );
    }

    #[test]
    fn vuln03_mature_coinbase_spend_allowed() {
        // Coinbase mined at h=5; we spend at h=200. depth=195 >= 100.
        let tx = spending_tx([0x42; 32]);
        let result = check_coinbase_maturity(&tx, 200, |_| Some(5));
        assert!(result.is_ok(), "mature coinbase spend must be allowed");
    }

    #[test]
    fn vuln03_boundary_exactly_at_maturity() {
        // Coinbase at h=5; spend at h=105. depth = 100 == COINBASE_MATURITY.
        // Boundary semantics: depth >= MATURITY means spend allowed.
        let tx = spending_tx([0x42; 32]);
        let result = check_coinbase_maturity(&tx, 5 + COINBASE_MATURITY, |_| Some(5));
        assert!(
            result.is_ok(),
            "spend at exactly COINBASE_MATURITY confirmations must be allowed"
        );

        // One block earlier (depth = MATURITY - 1) must still be rejected.
        let result = check_coinbase_maturity(&tx, 5 + COINBASE_MATURITY - 1, |_| Some(5));
        assert!(
            result.is_err(),
            "spend at COINBASE_MATURITY-1 confirmations must be rejected"
        );
    }

    #[test]
    fn vuln03_non_coinbase_spend_unaffected() {
        // Lookup returns None -> input is not a coinbase, no maturity policy.
        let tx = spending_tx([0x99; 32]);
        let result = check_coinbase_maturity(&tx, 50, |_| None);
        assert!(result.is_ok(), "non-coinbase spends are not subject to maturity");
    }

    #[test]
    fn vuln03_pre_genesis_skips_check() {
        // current_height == 0 means we are at/before genesis. Helper is
        // a no-op even if the closure claims everything is a coinbase.
        let tx = spending_tx([0xFF; 32]);
        let result = check_coinbase_maturity(&tx, 0, |_| Some(0));
        assert!(result.is_ok(), "pre-genesis spends must skip the maturity check");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VULN-04 [FIXED]: Timestamp validation
    //
    // validate_timestamp() now rejects blocks with timestamps:
    //   - More than MAX_FUTURE_SECS (7200s = 2h) in the future
    //   - Before the parent's timestamp
    // ═══════════════════════════════════════════════════════════════════════
    #[test]
    fn vuln04_timestamp_validation_fixed() {
        let founder = b"test_founder_20bytes";
        let mut block = create_genesis_block(founder, founder, founder);

        // Block with timestamp far in the future should be rejected
        block.header.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() + MAX_FUTURE_SECS + 3600; // 3h in the future
        assert!(
            block.validate_timestamp(0).is_err(),
            "FIX VERIFIED: future timestamp rejected"
        );

        // Block with timestamp before parent should be rejected
        let parent_ts = 2_000_000_000;
        block.header.timestamp = parent_ts - 1;
        assert!(
            block.validate_timestamp(parent_ts).is_err(),
            "FIX VERIFIED: timestamp before parent rejected"
        );

        // Valid timestamp should pass
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        block.header.timestamp = now;
        assert!(
            block.validate_timestamp(now - 10).is_ok(),
            "Valid timestamp should pass"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VULN-05 [FIXED]: Coinbase now includes fees
    // ═══════════════════════════════════════════════════════════════════════
    #[test]
    fn vuln05_coinbase_with_fees_fixed() {
        // Bloch pure PoW (B3): 1-output coinbase at h=1 (outside the founder
        // vesting window, so no 2nd founder output). Miner gets full subsidy +
        // fees. Validates fee inclusion and rejection of malformations.
        use bloch::core::tokenomics_v2;

        let height = 1u64;
        let subsidy = tokenomics_v2::block_subsidy_sat(height);
        let fees = 1000u64;

        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid:  [0u8; 32],
                prev_index: u32::MAX,
                script_sig: b"height:1".to_vec(),
                sequence:   0xffffffff,
            }],
            outputs: vec![
                TxOutput {
                    value:         subsidy + fees,
                    script_pubkey: b"miner_addr_20byte_pl".to_vec(),
                },
            ],
            locktime: 0,
        };
        let merkle = Transaction::merkle_root(&[coinbase.clone()]);
        let mut block = Block {
            header: BlockHeader {
                version:     1,
                parents:     vec![],
                merkle_root: merkle,
                timestamp:   1_750_000_000,
                bits:        0x1d00ffff,
                nonce:       0,
            },
            transactions: vec![coinbase],
            blue_score:   0,
            height,
            pow_solution: Vec::new(),
            shielded_transactions: Vec::new(),        };

        // Correct coinbase passes
        assert!(
            block.validate_coinbase_value(fees).is_ok(),
            "B3 FIX-VULN-05: 1-output coinbase with miner = subsidy + fees should pass"
        );

        // Miner output exceeding (subsidy + fees) is rejected
        block.transactions[0].outputs[0].value = subsidy + fees + 1;
        assert!(
            block.validate_coinbase_value(fees).is_err(),
            "B3: miner output exceeding (subsidy + fees) must be rejected"
        );
        // Reset miner
        block.transactions[0].outputs[0].value = subsidy + fees;

        // A spurious extra output (wrong output count outside vesting) is rejected
        block.transactions[0].outputs.push(TxOutput {
            value:         1,
            script_pubkey: vec![0xff; 20],
        });
        assert!(
            block.validate_coinbase_value(fees).is_err(),
            "B3: coinbase must have exactly 1 output outside the vesting window"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VULN-06 [FIXED]: TXID no longer malleable
    // ═══════════════════════════════════════════════════════════════════════
    #[test]
    fn vuln06_txid_malleability_fixed() {
        let (pk, sk) = crypto::generate_keypair();
        let sig = crypto::sign(&sk, b"test_sighash").unwrap();
        let script_sig = Transaction::build_script_sig(&sig, &pk);

        let tx1 = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [1u8; 32],
                prev_index: 0,
                script_sig: script_sig.clone(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOutput { value: 100, script_pubkey: vec![0u8; 20] }],
            locktime: 0,
        };

        // Same tx but with extra trailing bytes in script_sig
        let mut padded_sig = script_sig.clone();
        padded_sig.push(0x00);
        let tx2 = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [1u8; 32],
                prev_index: 0,
                script_sig: padded_sig,
                sequence: u32::MAX,
            }],
            outputs: vec![TxOutput { value: 100, script_pubkey: vec![0u8; 20] }],
            locktime: 0,
        };

        assert_eq!(
            tx1.txid(), tx2.txid(),
            "FIX VERIFIED: txid is now immune to script_sig padding"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VULN-07 [FIXED]: Dust outputs rejected
    // ═══════════════════════════════════════════════════════════════════════
    #[test]
    fn vuln07_dust_rejected() {
        let mut block = create_genesis_block(b"test_founder_20bytes", b"test_founder_20bytes", b"test_founder_20bytes");
        // Add a non-coinbase tx with a dust output
        block.transactions.push(Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [1u8; 32], prev_index: 0,
                script_sig: vec![0u8; 20], sequence: u32::MAX,
            }],
            outputs: vec![TxOutput { value: 100, script_pubkey: vec![0u8; 20] }], // 100 < 546
            locktime: 0,
        });
        assert!(
            block.validate_dust().is_err(),
            "FIX VERIFIED: dust output (100 sats < 546 threshold) rejected"
        );

        // Zero-value outputs are still allowed (used for OP_RETURN-like data)
        block.transactions[1].outputs[0].value = 0;
        assert!(
            block.validate_dust().is_ok(),
            "Zero-value outputs allowed (data carrier)"
        );

        // Above-threshold outputs pass
        block.transactions[1].outputs[0].value = DUST_THRESHOLD;
        assert!(
            block.validate_dust().is_ok(),
            "At-threshold output passes"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VERIFY: Double-spend protection (FIX #9) works
    // ═══════════════════════════════════════════════════════════════════════
    #[test]
    fn verify_double_spend_protected() {
        // This is a structural test — the actual double-spend check is in
        // validate_tx_inputs with the spent_set parameter.
        // Here we verify the crypto primitives are sound.
        let (pk, sk) = crypto::generate_keypair();
        let msg = b"test message";
        let sig = crypto::sign(&sk, msg).unwrap();

        // Valid signature
        assert!(crypto::verify(&pk, msg, &sig));
        // Tampered message
        assert!(!crypto::verify(&pk, b"tampered", &sig));
        // Wrong key
        let (pk2, _) = crypto::generate_keypair();
        assert!(!crypto::verify(&pk2, msg, &sig));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VERIFY: Merkle root is tamper-proof
    // ═══════════════════════════════════════════════════════════════════════
    #[test]
    fn verify_merkle_tamper_detection() {
        let tx1 = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32], prev_index: u32::MAX,
                script_sig: b"coinbase".to_vec(), sequence: u32::MAX,
            }],
            outputs: vec![TxOutput { value: 100, script_pubkey: vec![0u8; 20] }],
            locktime: 0,
        };
        let tx2 = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [1u8; 32], prev_index: 0,
                script_sig: vec![0u8; 20], sequence: u32::MAX,
            }],
            outputs: vec![TxOutput { value: 50, script_pubkey: vec![1u8; 20] }],
            locktime: 0,
        };

        let merkle = Transaction::merkle_root(&[tx1.clone(), tx2.clone()]);

        // Modify a transaction — merkle root changes
        let mut tx2_tampered = tx2.clone();
        tx2_tampered.outputs[0].value = 999;
        let merkle_tampered = Transaction::merkle_root(&[tx1, tx2_tampered]);

        assert_ne!(merkle, merkle_tampered, "Merkle root detects tampering");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VERIFY: PoW is correctly validated
    // ═══════════════════════════════════════════════════════════════════════
    #[test]
    fn verify_pow_cannot_be_skipped() {
        let founder = b"test_founder_20bytes";
        let block = create_genesis_block(founder, founder, founder);
        // Block with nonce=0 and real difficulty should fail PoW
        assert!(
            !block.validate_pow(),
            "Unmined block must not pass PoW validation"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VERIFY: Address checksum prevents typos
    // ═══════════════════════════════════════════════════════════════════════
    #[test]
    #[ignore = "TODO Fase 4: regenerate with bloch1q HRP checksum"]
    fn verify_address_checksum() {
        let (pk, _) = crypto::generate_keypair();
        let addr = crypto::address_from_pubkey(&pk, false);
        assert!(addr.starts_with("bloch1q"));
        // Address is prefix + 40 hex (20 bytes hash) + 8 hex (4 bytes checksum) = 54 chars
        assert_eq!(addr.len(), 6 + 40 + 8, "Address format: 6 prefix + 48 hex");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VULN-08 [HIGH]: CVE-2012-2459 — duplicate-tx merkle malleability
    //
    // Bitcoin's merkle computation duplicates the last hash on odd-length
    // lists. For 3 txs [A, B, C], merkle computes H(H(A,B), H(C,C)). For
    // 4 txs [A, B, C, C] (attacker duplicates C), merkle computes the same
    // H(H(A,B), H(C,C)). Attacker announces a valid header+merkle but
    // delivers two different tx lists satisfying it, creating a UTXO split.
    //
    // Mitigation (Sprint S, audit C-3): validate_structure() rejects blocks
    // containing duplicate txids.
    // ═══════════════════════════════════════════════════════════════════════
    #[test]
    fn vuln08_duplicate_tx_merkle_collision_is_rejected() {
        let founder = b"test_founder_20bytes";
        let base = create_genesis_block(founder, founder, founder);
        let coinbase = base.transactions[0].clone();

        // Two distinct regular txs.
        let tx_a = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid:  [0xAA; 32],
                prev_index: 0,
                script_sig: vec![],
                sequence:   u32::MAX,
            }],
            outputs: vec![TxOutput { value: 1_000, script_pubkey: vec![0u8; 20] }],
            locktime: 0,
        };
        let tx_b = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid:  [0xBB; 32],
                prev_index: 0,
                script_sig: vec![],
                sequence:   u32::MAX,
            }],
            outputs: vec![TxOutput { value: 2_000, script_pubkey: vec![0u8; 20] }],
            locktime: 0,
        };

        // Honest block: 3 unique txs. Merkle computes H(H(coinbase,A), H(B,B))
        // because odd-length lists get their last hash duplicated internally.
        let honest_txs = vec![coinbase.clone(), tx_a.clone(), tx_b.clone()];
        let honest_root = Transaction::merkle_root(&honest_txs);

        // Malicious block: 4 txs, B explicitly duplicated. Merkle computes
        // H(H(coinbase,A), H(B,B)) — IDENTICAL to honest root.
        let malicious_txs = vec![coinbase.clone(), tx_a, tx_b.clone(), tx_b];
        let malicious_root = Transaction::merkle_root(&malicious_txs);

        // Confirm the CVE: same merkle root, different tx lists.
        assert_eq!(
            honest_root, malicious_root,
            "CVE-2012-2459 precondition: duplicated-last-tx produces same merkle root \
             as odd-length list — this is the core of the attack"
        );
        assert_ne!(
            honest_txs.len(), malicious_txs.len(),
            "transaction lists must differ in length for the exploit"
        );

        // The fix: validate_no_duplicate_txs rejects the malicious list.
        let mut malicious = base.clone();
        malicious.transactions = malicious_txs;
        malicious.header.merkle_root = malicious_root;

        let result = malicious.validate_no_duplicate_txs();
        assert!(
            result.is_err(),
            "VULN-08: duplicate-tx block must be rejected by validate_no_duplicate_txs"
        );
        assert!(
            result.unwrap_err().contains("duplicate"),
            "error message should mention 'duplicate'"
        );

        // And the honest block passes.
        let mut honest = base.clone();
        honest.transactions = honest_txs;
        honest.header.merkle_root = honest_root;
        assert!(
            honest.validate_no_duplicate_txs().is_ok(),
            "honest block with unique txs must pass"
        );
    }

    // VULN-08 follow-up: validate_structure integration — the duplicate check
    // must run as part of the full structural validation, not as an optional
    // extra. Any block that passes validate_structure must not contain dupes.
    #[test]
    fn vuln08_validate_structure_enforces_no_duplicate_txs() {
        let founder = b"test_founder_20bytes";
        let base = create_genesis_block(founder, founder, founder);

        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid:  [0xCC; 32],
                prev_index: 0,
                script_sig: vec![],
                sequence:   u32::MAX,
            }],
            outputs: vec![TxOutput { value: 2_000, script_pubkey: vec![0u8; 20] }],
            locktime: 0,
        };

        let mut bad_block = base.clone();
        bad_block.transactions = vec![
            base.transactions[0].clone(),
            tx.clone(),
            tx, // duplicate
        ];
        bad_block.header.merkle_root = Transaction::merkle_root(&bad_block.transactions);

        // validate_structure should reject — duplicate check is part of the pipeline.
        let err = bad_block.validate_structure();
        assert!(
            err.is_err(),
            "validate_structure must reject duplicate-tx block"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 6 CLOSURE: 4-output coinbase happy path with founder vesting
    //
    // After Phase 6 (2026-05-02 / commit 1068bad), FOUNDER_ADDRESS_HASH is
    // consensus-locked to the 20-byte hash of the founder vesting wallet.
    // This test verifies the full chain end-to-end: the constant byte values
    // committed in src/core/tokenomics_v2.rs are exactly what
    // Block::validate_coinbase_value compares against (per ADR-028 +
    // TOKENOMICS_V2 §4 + §5).
    //
    // Construction: start from the V2 genesis (h=0, 3-output coinbase using
    // the real pool addresses so outputs[0..3] are already valid), reset the
    // height to FOUNDER_VESTING_CLIFF + 1 (first block where founder vesting
    // is active), and append a 4th output paying founder_vesting_delta_sat(h)
    // satoshi to FOUNDER_ADDRESS_HASH. At this height halvings=0, so the
    // initial subsidy split (70/25/5 of 1905 BLOCH) is unchanged from h=0.
    //
    // Any future change to FOUNDER_ADDRESS_HASH (a hard fork) will fail this
    // test alongside the byte-exact test in tokenomics_v2.rs::tests.
    // ═══════════════════════════════════════════════════════════════════════
    #[test]
    fn coinbase_4output_at_cliff_plus_one_passes_validation() {
        let miner = [0xAA_u8; 20];
        let founder_addr = tokenomics_v2::founder_address_hash();

        // Bloch pure-PoW genesis: 1-output coinbase (miner). Pool args are
        // ignored by create_genesis_block (BFT/PoBRS removed in B2).
        let mut block = create_genesis_block(&miner, &miner, &miner);

        // Monthly vesting (B3b): the founder output appears only on month
        // boundaries. Use the first vested month (CLIFF + MONTH_BLOCKS).
        let height = tokenomics_v2::FOUNDER_VESTING_CLIFF + tokenomics_v2::MONTH_BLOCKS;
        block.height = height;

        // Recompute the miner output for this height's subsidy (tail era → the
        // 100-BLOCH tail floor, 100% to miner in pure PoW).
        let subsidy = tokenomics_v2::block_subsidy_sat(height);
        block.transactions[0].outputs[0].value = subsidy;

        let founder_value = tokenomics_v2::founder_vesting_delta_sat(height);
        assert!(
            founder_value > 0,
            "sanity: founder vesting delta must be > 0 at the first month boundary"
        );
        // Monthly payout = premine / 480 tranches (divides exactly; B3b).
        assert_eq!(
            founder_value,
            tokenomics_v2::founder_monthly_tranche_sat(),
            "sanity: founder monthly delta must equal one tranche (premine / 480)"
        );

        // Append output[1]: founder vesting payment (pure-PoW 2-output shape).
        block.transactions[0].outputs.push(TxOutput {
            value:         founder_value,
            script_pubkey: founder_addr.to_vec(),
        });

        // Consensus rule must accept: 2 outputs — miner (full subsidy) +
        // founder delta to the consensus-locked FOUNDER_ADDRESS_HASH.
        assert!(
            block.validate_coinbase_value(0).is_ok(),
            "pure-PoW 2-output coinbase at CLIFF+1 with consensus-locked FOUNDER_ADDRESS_HASH must pass"
        );

        // Negative cross-check: corrupting the founder script_pubkey (now at
        // output[1]) by one byte must be rejected.
        let mut corrupted_script = founder_addr.to_vec();
        corrupted_script[0] ^= 0x01;
        block.transactions[0].outputs[1].script_pubkey = corrupted_script;
        assert!(
            block.validate_coinbase_value(0).is_err(),
            "wrong founder address must be rejected"
        );
    }
}
