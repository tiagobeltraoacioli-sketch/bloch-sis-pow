//! Host driver: prove the spend statement over the guest ELF and verify the
//! RAW FRI proof (post-quantum). One-shot smoke test — build the guest first
//! (`cd ../program && cargo prove build`), then `cargo run --release` here.
//!
//! Pinned to sp1-sdk =6.5.0 (blocking API). The client is built EXPLICITLY as
//! the CPU prover — never `ProverClient::from_env()` or the old env-sensitive
//! `ProverClient::new()`: on a box with `SP1_PROVER=mock` those hand back a
//! mock prover whose "proofs" verify as valid. The load-bearing rule stands:
//! use the CORE STARK/FRI proof (`SP1ProofMode::Core`), never a Groth16/PLONK
//! wrap (elliptic curves — Shor-breakable, forbidden by COHERENCE-C1 §3).

use coherence_core::{check_spend, CommitmentTree, Note, SpendInput, SpendPublic, SpendWitness};
use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1ProofMode, SP1Stdin};
use sp1_sdk::{ProvingKey, SP1Proof};

/// The guest ELF produced by `cargo prove build` in ../program (pinned
/// toolchain: `sp1up --version v6.5.0`). This is where SP1 6.x writes it —
/// the old `../program/elf/riscv32im-succinct-zkvm-elf` path is gone.
const ELF: &[u8] = include_bytes!(
    "../../program/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/coherence-spend-program"
);

fn note(v: u64, seed: u8) -> Note {
    Note { v, pk_d: [seed; 32], rho: [seed ^ 0xAA; 32], psi: [seed ^ 0x55; 32] }
}

fn main() {
    sp1_sdk::utils::setup_logger();

    // A small REAL witness (2-in/2-out), same shape the wallet produces: the
    // public (anchor, nullifiers, output commitments, fee) and the private
    // witness (spent notes, Merkle paths, nullifier key, output notes).
    let fee: u64 = 100;
    let ins = [note(1_000, 1), note(1_100, 2)];
    let outs = [note(1_500, 100), note(500, 101)]; // 2100 - 100 fee = 2000

    let mut tree = CommitmentTree::new();
    for x in &ins {
        tree.append(x.commitment());
    }
    let anchor = tree.root();

    let nk = [0x77u8; 32];
    let witness = SpendWitness {
        inputs: ins
            .iter()
            .enumerate()
            .map(|(i, x)| SpendInput {
                note: x.clone(),
                position: i as u64,
                path: tree.path(i as u64).expect("path"),
                nk,
            })
            .collect(),
        outputs: outs.to_vec(),
    };
    let public = SpendPublic {
        anchor,
        nullifiers: ins.iter().enumerate().map(|(i, x)| x.nullifier(&nk, i as u64)).collect(),
        out_commitments: outs.iter().map(|o| o.commitment()).collect(),
        fee,
    };

    // Fail fast on the host before burning prover cycles.
    check_spend(&public, &witness).expect("spend statement violated on the host");

    let mut stdin = SP1Stdin::new();
    stdin.write(&public);
    stdin.write(&witness);

    // EXPLICIT CPU prover — deterministic, ignores SP1_PROVER.
    let client = ProverClient::builder().cpu().build();
    let pk = client.setup(Elf::Static(ELF)).expect("setup failed");

    // POST-QUANTUM: the CORE STARK/FRI proof. Do NOT call .groth16()/.plonk().
    let proof = client
        .prove(&pk, stdin)
        .mode(SP1ProofMode::Core)
        .run()
        .expect("proving failed");
    assert!(matches!(proof.proof, SP1Proof::Core(_)), "prover returned a non-Core proof");

    // FRI verification — the same check the node runs on ShieldedTx.proof.
    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("FRI verification failed");

    let bytes = bincode::serialize(&proof).expect("serialize proof");
    println!(
        "spend proof produced and FRI-verified (post-quantum path); {} bytes ({:.1} KiB) serialized",
        bytes.len(),
        bytes.len() as f64 / 1024.0
    );
    // `bytes` is what ShieldedTx.proof carries on the wire.
}
