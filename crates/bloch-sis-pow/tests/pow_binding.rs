//! Guards the PoW solution binding: a valid solution cannot be replayed across
//! blocks or nonces.
//!
//! Two independent bindings enforce this:
//!  - the SIS instance (A, t) is derived from `derive_pow_seed(header, nonce)`,
//!    so a solution `s` that satisfies one (header, nonce) fails the residual
//!    check for any other — a fresh instance per nonce (blocks precomputation);
//!  - the aux hash commits to (s, nonce, header) for the difficulty filter.
//!
//! This test guards the aux-hash binding (cheap + deterministic; exercising the
//! SIS-instance binding requires a mined solution and is covered by the mining
//! tests).

use bloch_sis_pow::params::N;
use bloch_sis_pow::verify::compute_aux_hash;

#[test]
fn aux_hash_binds_solution_nonce_and_header() {
    let s = [0i32; N];
    let base = compute_aux_hash(b"header-A", 1, &s);

    // A different header, nonce, or solution must change the aux hash — so a
    // valid (s, nonce) for one block cannot satisfy another block's target.
    assert_ne!(base, compute_aux_hash(b"header-B", 1, &s), "aux must bind the header");
    assert_ne!(base, compute_aux_hash(b"header-A", 2, &s), "aux must bind the nonce");

    let mut s2 = s;
    s2[0] = 1;
    assert_ne!(base, compute_aux_hash(b"header-A", 1, &s2), "aux must bind the solution");

    // Deterministic for the same triple.
    assert_eq!(base, compute_aux_hash(b"header-A", 1, &s));
}
