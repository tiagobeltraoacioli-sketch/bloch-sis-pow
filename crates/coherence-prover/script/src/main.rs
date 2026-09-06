//! Host driver: build the guest ELF, prove the spend statement, and verify the
//! RAW FRI proof (post-quantum). Run with `cargo run --release`.
//!
//! The load-bearing rules (Round-2 audit P123 P-2):
//! - EXPLICIT `.cpu()` prover client — never the env-driven one, and
//!   `SP1_PROVER=mock` aborts (mock "proofs" are fabrications).
//! - The CORE STARK/FRI proof (`.core()`), never a Groth16/PLONK wrap.
//!
//! This host also prints the guest verifying-key hash (`vk.bytes32()`) and
//! writes the serialized vkey to `spend-guest.vkey.bin` — the release process
//! pins that hash into `SHIELDED_SPEND_VKEY_HASH` in the node
//! (legacy/genesis3-node/src/coherence/verifier.rs) and ships the vkey file
//! (`BLOCH_SP1_VKEY`). Finally it self-checks the two rejection properties the
//! node relies on: a tampered public-values binding does not verify, and an
//! empty/mock-shaped proof does not verify.

use sp1_sdk::{HashableKey, Prover, ProverClient, SP1Stdin};

/// The guest ELF produced by `cargo prove build` in ../program.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    sp1_sdk::utils::setup_logger();

    // Audit P123 P-2: refuse the mock-prover environment outright.
    if std::env::var("SP1_PROVER").is_ok_and(|v| v.trim().eq_ignore_ascii_case("mock")) {
        eprintln!("SP1_PROVER=mock refused: mock proofs are fabrications. Unset it.");
        std::process::exit(1);
    }
    // EXPLICIT CPU backend — never ProverClient::from_env().
    let client = ProverClient::builder().cpu().build();

    // Build the prover inputs. In production these come from the wallet: the
    // public (anchor, nullifiers, output commitments, fee) and the private
    // witness (spent notes, Merkle paths, keys, output notes).
    let stdin = SP1Stdin::new();
    // stdin.write(&public);
    // stdin.write(&witness);

    let (pk, vk) = client.setup(ELF);

    // Pinning material for the node (audit P123 P-1).
    println!("guest vkey hash (pin as SHIELDED_SPEND_VKEY_HASH): {}", vk.bytes32());
    let vk_bytes = bincode::serialize(&vk).expect("serialize vkey");
    std::fs::write("spend-guest.vkey.bin", &vk_bytes).expect("write vkey file");
    println!("vkey written to spend-guest.vkey.bin (ship as BLOCH_SP1_VKEY)");

    // POST-QUANTUM: the CORE STARK/FRI proof. Do NOT call .groth16()/.plonk().
    let proof = client.prove(&pk, &stdin).core().run().expect("proving failed");

    // FRI verification — this is what the node runs on ShieldedTx.proof.
    client.verify(&proof, &vk).expect("FRI verification failed");

    // Self-check 1: a TAMPERED public-values binding must NOT verify (the
    // proof commits a digest of its public values; flipping a byte breaks it).
    let mut tampered = proof.clone();
    let mut pv = tampered.public_values.to_vec();
    if pv.is_empty() {
        pv.push(0xFF);
    } else {
        pv[0] ^= 0x01;
    }
    tampered.public_values = sp1_sdk::SP1PublicValues::from(&pv);
    assert!(
        client.verify(&tampered, &vk).is_err(),
        "SECURITY: tampered public values verified — binding is broken"
    );

    // Self-check 2: an empty/mock-shaped core proof must NOT verify.
    let mut hollow = proof.clone();
    hollow.proof = sp1_sdk::SP1Proof::Core(vec![]);
    assert!(
        client.verify(&hollow, &vk).is_err(),
        "SECURITY: hollow (mock-shaped) proof verified"
    );

    println!("✅ spend proof produced, FRI-verified, and tamper/mock rejection self-checked");
    // proof.bytes() → ShieldedTx.proof on the wire.
}
