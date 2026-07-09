//! SP1 guest program for the Coherence shielded-pool spend proof.
//!
//! Runs INSIDE the SP1 zkVM (RISC-V). It reads the public inputs and the private
//! witness, enforces the C1 spend statement via `check_spend` (a violated
//! statement makes proving fail), and commits the public inputs so the verifier
//! is bound to them. Build with `cargo prove build`.
//!
//! Needs the lean `coherence-core` crate (see ../README.md) — it cannot depend
//! on the full `bloch` node crate.

#![no_main]
sp1_zkvm::entrypoint!(main);

use coherence_core::{check_spend, SpendPublic, SpendWitness};

pub fn main() {
    // Public inputs (bound into the proof) and the private witness (never leaves
    // the prover; the node only ever sees the resulting FRI proof).
    let public: SpendPublic = sp1_zkvm::io::read();
    let witness: SpendWitness = sp1_zkvm::io::read();

    // THE statement: opening + Merkle membership + nullifier + range + balance.
    // If it does not hold, proving aborts — an invalid spend is unprovable.
    check_spend(&public, &witness).expect("spend statement violated");

    // Commit the public inputs so the verifier ties the FRI proof to this
    // (anchor, nullifiers, output commitments, fee).
    sp1_zkvm::io::commit(&public);
}
