//! pqcrypto-internals — GroundState fork
//!
//! # Why a fork?
//!
//! The upstream `pqcrypto-internals` crate (rustpq/pqcrypto) exposes
//! `PQCRYPTO_RUST_randombytes` as the single source of randomness for all
//! PQClean-based algorithm crates (pqcrypto-mldsa, pqcrypto-kyber, etc.).
//! The upstream implementation always pulls from the OS RNG, which means
//! `mldsa65::keypair()` and similar functions are always non-deterministic
//! — there is no public seed-based API.
//!
//! GroundState needs deterministic keypair derivation from a user-controlled
//! 32-byte seed (for BIP39-style wallet recovery — see audit finding C-2,
//! documented in docs/audit/AUDIT-2026-04-20.md of the main repo). FIPS 204
//! Algorithm 6 defines ML-DSA keygen as a deterministic function of a
//! 32-byte seed xi; the underlying PQClean C code already implements this
//! correctly, but pulls xi from `randombytes()` without exposing the seeded
//! entry point.
//!
//! This fork overrides `PQCRYPTO_RUST_randombytes` to check a thread-local
//! seeded RNG before falling back to OS entropy. Callers use the
//! `with_seeded_rng` helper (or set/clear manually) to scope determinism
//! around a specific keypair generation call.
//!
//! # Semantics
//!
//! - When no thread-local seed is active: IDENTICAL to upstream
//!   (getrandom::fill). Zero change in behavior for any caller that
//!   doesn't opt in.
//! - When a thread-local seed is active: bytes are drawn from a
//!   ChaCha20-based CSPRNG keyed with the user-supplied seed. The stream
//!   is deterministic for a given seed, which is exactly what FIPS 204
//!   Algorithm 6 requires.
//! - The thread-local is scoped per-thread. Concurrent keypair generation
//!   in other threads is unaffected.
//!
//! # Caveats
//!
//! - This fork must be kept in sync with upstream (currently 0.2.11). If
//!   upstream changes the signature or semantics of
//!   `PQCRYPTO_RUST_randombytes`, this file needs a matching update.
//! - The override is a NO-OP for signing randomness if the caller doesn't
//!   set the thread-local — signing remains hedged (randomized) by
//!   default, which is the FIPS 204 recommended mode.
//! - DO NOT use `with_seeded_rng` around `sign()` unless you explicitly
//!   want deterministic signatures. Deterministic signatures are more
//!   vulnerable to fault attacks; the hedged variant is preferred.
//!   Keygen is different — keygen is inherently deterministic-from-seed
//!   by FIPS 204 design.
//!
//! # Upstream reconciliation plan
//!
//! An issue will be opened upstream (rustpq/pqcrypto) proposing a
//! `keypair_from_seed()` public API. If accepted, this fork is retired
//! and `groundstate/Cargo.toml` drops the `[patch.crates-io]` section.

use core::slice;
use std::cell::RefCell;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[allow(nonstandard_style)]
type size_t = usize;
use core::ffi::c_int;

thread_local! {
    /// Per-thread seeded RNG override for `PQCRYPTO_RUST_randombytes`.
    /// When `Some`, PQClean `randombytes` calls pull bytes from this
    /// deterministic stream instead of OS entropy. When `None`, upstream
    /// behavior (OS RNG via getrandom) is preserved.
    static SEEDED_RNG: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };
}

/// RAII guard that clears the thread-local seeded RNG when dropped.
///
/// Returned by [`with_seeded_rng`]. Hold this for the duration of any
/// PQClean call that should consume deterministic bytes.
#[must_use = "guard must remain in scope — dropping it restores OS RNG"]
pub struct SeededRngGuard {
    // Private field prevents external construction — the only way to get
    // this guard is via `with_seeded_rng` or the equivalent public API.
    _priv: (),
}

impl Drop for SeededRngGuard {
    fn drop(&mut self) {
        SEEDED_RNG.with(|cell| {
            cell.borrow_mut().take();
        });
    }
}

/// Activate deterministic bytes for PQClean calls on this thread.
///
/// Subsequent calls to `PQCRYPTO_RUST_randombytes` on this thread will
/// return bytes from a ChaCha20 CSPRNG keyed with `seed`. When the
/// returned guard is dropped, the override is cleared and OS RNG is
/// restored.
///
/// # Example
///
/// ```ignore
/// use pqcrypto_internals::with_seeded_rng;
/// use pqcrypto_mldsa::mldsa65;
///
/// let seed = [0u8; 32]; // derive this from BIP39 / HKDF / etc.
/// let (pk1, sk1) = {
///     let _guard = with_seeded_rng(&seed);
///     mldsa65::keypair()
/// };
/// let (pk2, sk2) = {
///     let _guard = with_seeded_rng(&seed);
///     mldsa65::keypair()
/// };
/// // Same seed → same keypair bytes.
/// ```
///
/// # Nesting
///
/// Calling `with_seeded_rng` while a guard is already active REPLACES the
/// active seed for the duration of the new guard. The previous guard's
/// drop will then clear the state. In practice, do not nest — it is
/// almost certainly a bug.
pub fn with_seeded_rng(seed: &[u8; 32]) -> SeededRngGuard {
    let rng = ChaCha20Rng::from_seed(*seed);
    SEEDED_RNG.with(|cell| {
        *cell.borrow_mut() = Some(rng);
    });
    SeededRngGuard { _priv: () }
}

/// Get random bytes; exposed for PQClean implementations.
///
/// # Behavior
///
/// - If a seeded RNG is active on this thread (via `with_seeded_rng`):
///   fills `buf` with deterministic bytes from that RNG.
/// - Otherwise: fills `buf` with OS entropy via `getrandom::fill` —
///   identical to upstream pqcrypto-internals.
///
/// # Safety
///
/// Assumes inputs are valid and may panic over FFI boundary if rng failed.
///
/// # Example
/// ```rust
/// use pqcrypto_internals::*;
/// let mut buf = [0u8;10];
/// unsafe {
///   PQCRYPTO_RUST_randombytes(buf.as_mut_ptr(), buf.len());
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn PQCRYPTO_RUST_randombytes(buf: *mut u8, len: size_t) -> c_int {
    let buf = slice::from_raw_parts_mut(buf, len);

    // Fast path: no seeded RNG → upstream behavior exactly.
    let used_seeded = SEEDED_RNG.with(|cell| {
        let mut opt = cell.borrow_mut();
        match opt.as_mut() {
            Some(rng) => {
                rng.fill_bytes(buf);
                true
            }
            None => false,
        }
    });

    if !used_seeded {
        getrandom::fill(buf).expect("RNG Failed");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without a seeded RNG, two consecutive calls produce different bytes
    /// (OS RNG behavior — effectively never the same for 32-byte buffers).
    #[test]
    fn default_behavior_is_random() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        unsafe {
            PQCRYPTO_RUST_randombytes(a.as_mut_ptr(), a.len());
            PQCRYPTO_RUST_randombytes(b.as_mut_ptr(), b.len());
        }
        assert_ne!(a, b, "OS RNG produced identical 32-byte buffers — impossibly rare");
    }

    /// With a seeded RNG active, bytes are deterministic for a given seed.
    #[test]
    fn seeded_is_deterministic() {
        let seed = [0x42u8; 32];

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];

        {
            let _g = with_seeded_rng(&seed);
            unsafe { PQCRYPTO_RUST_randombytes(a.as_mut_ptr(), a.len()); }
        }
        {
            let _g = with_seeded_rng(&seed);
            unsafe { PQCRYPTO_RUST_randombytes(b.as_mut_ptr(), b.len()); }
        }

        assert_eq!(a, b, "same seed must produce same bytes");
    }

    /// Different seeds produce different bytes.
    #[test]
    fn different_seeds_differ() {
        let seed_a = [0x01u8; 32];
        let seed_b = [0x02u8; 32];

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];

        {
            let _g = with_seeded_rng(&seed_a);
            unsafe { PQCRYPTO_RUST_randombytes(a.as_mut_ptr(), a.len()); }
        }
        {
            let _g = with_seeded_rng(&seed_b);
            unsafe { PQCRYPTO_RUST_randombytes(b.as_mut_ptr(), b.len()); }
        }

        assert_ne!(a, b);
    }

    /// Dropping the guard restores OS RNG behavior.
    #[test]
    fn guard_drop_restores_os_rng() {
        let seed = [0xFFu8; 32];

        let mut seeded_bytes = [0u8; 32];
        {
            let _g = with_seeded_rng(&seed);
            unsafe { PQCRYPTO_RUST_randombytes(seeded_bytes.as_mut_ptr(), 32); }
        } // guard dropped here

        // After drop, a fresh call should NOT match the seeded output
        // (except by cosmic coincidence).
        let mut after_bytes = [0u8; 32];
        unsafe { PQCRYPTO_RUST_randombytes(after_bytes.as_mut_ptr(), 32); }

        assert_ne!(seeded_bytes, after_bytes);
    }

    /// Multiple sequential calls within the same guard consume the stream
    /// continuously (not re-seeding per call).
    #[test]
    fn stream_continues_within_guard() {
        let seed = [0x77u8; 32];

        let mut first_call = [0u8; 32];
        let mut second_call = [0u8; 32];

        let _g = with_seeded_rng(&seed);
        unsafe {
            PQCRYPTO_RUST_randombytes(first_call.as_mut_ptr(), 32);
            PQCRYPTO_RUST_randombytes(second_call.as_mut_ptr(), 32);
        }

        // Two reads from the SAME stream should differ — the RNG advances.
        assert_ne!(first_call, second_call);
    }
}
