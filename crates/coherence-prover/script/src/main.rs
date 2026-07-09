//! Host driver: build the guest ELF, prove the spend statement, and verify the
//! RAW FRI proof (post-quantum). Run with `cargo run --release`.
//!
//! API shapes follow the SP1 SDK; check the pinned SP1 version's docs, as the
//! prove/verify surface evolves. The load-bearing rule is: use the CORE
//! STARK/FRI proof (`.core()`), never a Groth16/PLONK wrap.

use sp1_sdk::{ProverClient, SP1Stdin};

/// The guest ELF produced by `cargo prove build` in ../program.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    sp1_sdk::utils::setup_logger();
    let client = ProverClient::new();

    // Build the prover inputs. In production these come from the wallet: the
    // public (anchor, nullifiers, output commitments, fee) and the private
    // witness (spent notes, Merkle paths, keys, output notes).
    let mut stdin = SP1Stdin::new();
    // stdin.write(&public);
    // stdin.write(&witness);

    let (pk, vk) = client.setup(ELF);

    // POST-QUANTUM: the CORE STARK/FRI proof. Do NOT call .groth16()/.plonk().
    let proof = client
        .prove(&pk, stdin)
        .core()
        .run()
        .expect("proving failed");

    // FRI verification — this is what the node runs on ShieldedTx.proof.
    client.verify(&proof, &vk).expect("FRI verification failed");

    println!("✅ spend proof produced and FRI-verified (post-quantum path)");
    // proof.bytes() → ShieldedTx.proof on the wire.
}
