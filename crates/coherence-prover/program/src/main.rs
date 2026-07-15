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

    // C2 binds, mirrored in-circuit so the guest agrees with the host check
    // even if the library statement drifts: every committed public
    // out_commitment / nullifier must correspond one-for-one to a witness
    // output / input. Extra public out_commitments the balance check never
    // sees would mint unbacked notes (shielded counterfeiting).
    assert!(
        public.out_commitments.len() == witness.outputs.len(),
        "public out_commitments not bound to witness outputs"
    );
    assert!(
        public.nullifiers.len() == witness.inputs.len(),
        "public nullifiers not bound to witness inputs"
    );

    // THE statement: opening + Merkle membership + nullifier + range + balance.
    // If it does not hold, proving aborts — an invalid spend is unprovable
    // (check_spend also enforces the C2 count binds and returns a distinct
    // SpendError on mismatch).
    check_spend(&public, &witness).expect("spend statement violated");

    // Commit the public inputs so the verifier ties the FRI proof to this
    // (anchor, nullifiers, output commitments, fee).
    sp1_zkvm::io::commit(&public);
}
