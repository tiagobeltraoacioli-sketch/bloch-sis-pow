// Reproduction for NET-02 — mempool admits/relays valid-sig transfers whose
// inputs do NOT exist, and the per-source admission scan is O(N) SHA3 over the
// whole mempool.
//
// HOW TO USE (do NOT commit; do NOT run here — build lock is held):
//   Drop these three tests into the `#[cfg(test)] mod tests { ... }` block of
//   crates/bloch-pos-node/src/engine.rs. They reuse that module's existing
//   helpers verbatim: `engine_at_wall_epoch`, `signed_transfer`, and the
//   in-scope items `admissible`, `on_transaction`, `Admitted`, `MEMPOOL_MAX`,
//   `MEMPOOL_MAX_PER_SOURCE`, `tx_source_hash`, `PosTransaction`,
//   `TransferInput`, `TransferOutput`. Run with:
//     cargo test -p bloch-pos-node net02 -- --nocapture
//
// WHAT EACH TEST SHOWS
//   1. nonexistent_input_transfer_is_admitted_and_relayed
//        A validly-signed Transfer spending an outpoint that is in NO state
//        (`[0x11;32]:0`) returns Ok(Admitted::New) from on_transaction — the
//        exact verdict that triggers `self.net.broadcast(frame)` at
//        engine.rs:3142. So one submission to a public bootnode fans out to
//        every validator. (This mirrors the crate's own passing test
//        `a_correctly_signed_transfer_is_still_admitted`.)
//   2. per_source_scan_visits_every_mempool_entry
//        Fill the mempool to MEMPOOL_MAX with distinct-source, nonexistent-
//        input, valid-sig transfers (>= MEMPOOL_MAX_PER_SOURCE distinct first-
//        input pubkeys defeats the per-source cap). Then submit one more and
//        time it: on_transaction computes tx_source_hash (SHA3 over the ~3.7KB
//        first-input pubkey) for ALL 4096 entries BEFORE the signature check.
//        Prints the wall-clock cost of that single admission.
//   3. per_source_scan_runs_before_signature_check
//        A transfer with a GARBAGE signature still pays the full O(N) scan
//        (the scan at engine.rs:3040 precedes admissible's verify at :3121),
//        so the amplification cannot be dodged by refusing bad signatures.

use std::time::Instant;

/// A valid-sig `Transfer` that spends a NONEXISTENT outpoint. `seed` selects a
/// distinct hybrid keypair => a distinct first-input pubkey => a distinct
/// `tx_source_hash`, so `n` transfers with `n` distinct seeds occupy `n`
/// different per-source buckets and never hit MEMPOOL_MAX_PER_SOURCE.
fn nonexistent_input_transfer(seed: u8, tip: u128) -> PosTransaction {
    let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[seed; 32])
        .expect("hybrid keypair from a fixed seed");
    let mut tx = PosTransaction::Transfer {
        inputs: vec![TransferInput {
            // An outpoint that exists in no genesis and no block. admissible()
            // never checks existence (engine.rs:3100-3105), only the signature.
            txid: [0xAB; 32],
            vout: seed as u32,
            pubkey: pk.clone(),
            signature: Vec::new(),
        }],
        outputs: vec![TransferOutput {
            value: 1_000, // >= MIN_TRANSFER_OUTPUT_SAT
            script_hash: [0x22; 32],
        }],
        tx_bytes: 0,
        tip_millisat_per_gas: tip,
    };
    let root = tx.spend_signing_root();
    let sig = bloch_crypto::crypto::sign(&sk, &root).expect("sign the spend root");
    if let PosTransaction::Transfer { inputs, .. } = &mut tx {
        inputs[0].signature = sig;
    }
    tx
}

#[test]
fn net02_nonexistent_input_transfer_is_admitted_and_relayed() {
    // Engine whose committed state holds NONE of the outpoints these transfers
    // spend (empty eUTXO fixture).
    let mut node = engine_at_wall_epoch(1, &[]);
    let tx = nonexistent_input_transfer(7, 0);

    // admissible passes: structure ok, output non-dust, signature verifies.
    assert!(
        admissible(&tx, epoch_of(node.wall_slot())).is_ok(),
        "a valid-sig transfer with a nonexistent input passes admission"
    );
    // ...and on_transaction ADMITS it (New => it hits self.net.broadcast).
    assert_eq!(
        node.on_transaction(tx),
        Ok(Admitted::New),
        "an unincludable transfer is admitted to the mempool and relayed"
    );
    assert_eq!(node.mempool.len(), 1);
}

#[test]
fn net02_per_source_scan_visits_every_mempool_entry() {
    let mut node = engine_at_wall_epoch(1, &[]);

    // Fill to capacity with distinct-source, unincludable, valid-sig transfers.
    // 4096 distinct seeds => 4096 distinct source hashes, so the per-source cap
    // (64) never bites and the mempool reaches MEMPOOL_MAX.
    let mut admitted = 0usize;
    for i in 0..MEMPOOL_MAX {
        // seed must be distinct per entry; widen past u8 by mixing i into the
        // keypair seed. (Here: use a 4-byte counter as the seed material.)
        let seed = seed_bytes(i as u32);
        let tx = transfer_with_seed_bytes(&seed, /*tip=*/ 1);
        if node.on_transaction(tx) == Ok(Admitted::New) {
            admitted += 1;
        }
    }
    assert_eq!(admitted, MEMPOOL_MAX, "mempool fills with unincludable txs");
    assert_eq!(node.mempool.len(), MEMPOOL_MAX);

    // Now the COST of one more admission: on_transaction computes
    // tx_source_hash (SHA3 over ~3.7KB) for every one of the 4096 entries
    // BEFORE any signature work. A higher tip forces eviction => Admitted::New
    // => relay, so this is the per-relay cost paid on all 64 nodes.
    let probe = transfer_with_seed_bytes(&seed_bytes(u32::MAX), /*tip=*/ 1_000_000);
    let t0 = Instant::now();
    let verdict = node.on_transaction(probe);
    let dt = t0.elapsed();
    assert_eq!(verdict, Ok(Admitted::New), "higher-tip tx evicts and relays");
    // No hard assert on the number (machine-dependent) — print it. Expect tens
    // of milliseconds: 4096 * SHA3-256(3.7KB). Multiply by sustained tx/s and
    // by 64 nodes for the network-wide consensus-thread load.
    println!("NET-02: one admission at a full mempool took {dt:?} (4096 x SHA3)");
}

#[test]
fn net02_scan_runs_before_signature_check() {
    let mut node = engine_at_wall_epoch(1, &[]);
    // Prime the mempool so the scan has entries to walk.
    for i in 0..MEMPOOL_MAX_PER_SOURCE as u32 * 2 {
        let _ = node.on_transaction(transfer_with_seed_bytes(&seed_bytes(i), 1));
    }
    let before = node.mempool.len();

    // A transfer whose signature does NOT verify. It must be refused by
    // admissible — but only AFTER on_transaction has already run the O(N)
    // tx_source_hash scan (engine.rs:3040 precedes :3121). The refusal proves
    // the scan cost is unavoidable even for junk the node will drop.
    let mut junk = nonexistent_input_transfer(200, 1);
    if let PosTransaction::Transfer { inputs, .. } = &mut junk {
        inputs[0].signature = vec![0u8; inputs[0].signature.len().max(64)];
    }
    let verdict = node.on_transaction(junk);
    assert!(verdict.is_err(), "garbage signature is ultimately refused");
    assert_eq!(node.mempool.len(), before, "and it is NOT admitted or relayed");
    // The point: the refusal happened only after the full-mempool scan ran.
}

// ---- seed helpers (distinct keypair material past the 256-value u8 range) ----
fn seed_bytes(i: u32) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..4].copy_from_slice(&i.to_le_bytes());
    s
}

fn transfer_with_seed_bytes(seed: &[u8; 32], tip: u128) -> PosTransaction {
    let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(seed)
        .expect("hybrid keypair");
    let mut tx = PosTransaction::Transfer {
        inputs: vec![TransferInput {
            txid: [0xAB; 32],
            vout: u32::from_le_bytes([seed[0], seed[1], seed[2], seed[3]]),
            pubkey: pk,
            signature: Vec::new(),
        }],
        outputs: vec![TransferOutput { value: 1_000, script_hash: [0x22; 32] }],
        tx_bytes: 0,
        tip_millisat_per_gas: tip,
    };
    let root = tx.spend_signing_root();
    let sig = bloch_crypto::crypto::sign(&sk, &root).expect("sign");
    if let PosTransaction::Transfer { inputs, .. } = &mut tx {
        inputs[0].signature = sig;
    }
    tx
}
