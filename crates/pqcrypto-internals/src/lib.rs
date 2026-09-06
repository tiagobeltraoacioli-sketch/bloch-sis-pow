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
    /// Per-thread seeded RNG override STACK for `PQCRYPTO_RUST_randombytes`
    /// (I-2: a LIFO stack, not a single `Option`, so nesting is well-defined
    /// — see `with_seeded_rng`'s "Nesting" section). `randombytes_fill`
    /// always draws from the TOP of the stack; empty ⇒ upstream OS-RNG
    /// behavior is preserved.
    static SEEDED_RNG_STACK: RefCell<Vec<ChaCha20Rng>> = const { RefCell::new(Vec::new()) };
}

/// RAII guard that pops this call's seeded RNG off the thread-local stack
/// when dropped, restoring whatever was active before it (I-2).
///
/// Returned by [`with_seeded_rng`]. Hold this for the duration of any
/// PQClean call that should consume deterministic bytes.
#[must_use = "guard must remain in scope — dropping it restores the previous RNG (or OS RNG)"]
pub struct SeededRngGuard {
    // Private field prevents external construction — the only way to get
    // this guard is via `with_seeded_rng` or the equivalent public API.
    _priv: (),
}

impl Drop for SeededRngGuard {
    fn drop(&mut self) {
        // Pop exactly ONE entry — the one this guard pushed. Popping (not
        // clearing) is what makes nesting a well-defined no-op for the OUTER
        // scope: the entry below it on the stack, if any, is left untouched
        // and becomes active again.
        SEEDED_RNG_STACK.with(|stack| {
            stack.borrow_mut().pop();
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
/// # Nesting (I-2)
///
/// `with_seeded_rng` PUSHES onto a per-thread stack; `randombytes_fill`
/// always reads the TOP entry; dropping a guard POPS exactly the entry it
/// pushed. So calling `with_seeded_rng` while a guard is already active is a
/// well-defined, DOCUMENTED no-op for the outer scope: the inner seed is
/// active only until the inner guard drops, at which point the outer seed's
/// stream resumes EXACTLY where it left off — the inner scope does not
/// consume any of the outer stream's bytes and does not revert the thread to
/// OS RNG. (The pre-fix implementation stored a single `Option`, so an inner
/// guard's drop unconditionally cleared it — silently reverting the OUTER
/// scope to OS entropy for anything between the inner drop and the outer
/// drop. See `nested_seeded_rng_is_a_documented_noop_for_the_outer_scope`.)
///
/// Still not recommended as a matter of style (a nested call SHOULD have a
/// reason), but it can no longer corrupt an enclosing scope's determinism.
pub fn with_seeded_rng(seed: &[u8; 32]) -> SeededRngGuard {
    let rng = ChaCha20Rng::from_seed(*seed);
    SEEDED_RNG_STACK.with(|stack| {
        stack.borrow_mut().push(rng);
    });
    SeededRngGuard { _priv: () }
}

/// Fill `buf` with random bytes — safe-Rust core of the FFI entry point.
///
/// - If a seeded RNG is active on this thread (via [`with_seeded_rng`]):
///   fills `buf` with deterministic bytes from that RNG (infallible).
/// - Otherwise: fills `buf` with OS entropy via `getrandom::fill` —
///   identical to upstream pqcrypto-internals — and propagates any OS RNG
///   failure as `Err` instead of panicking.
pub fn randombytes_fill(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    // Fast path: no seeded RNG active (empty stack) → upstream behavior
    // exactly. Otherwise draw from the TOP of the stack (I-2) — the most
    // recently pushed, still-active guard.
    let used_seeded = SEEDED_RNG_STACK.with(|stack| {
        let mut s = stack.borrow_mut();
        match s.last_mut() {
            Some(rng) => {
                rng.fill_bytes(buf);
                true
            }
            None => false,
        }
    });

    if !used_seeded {
        #[cfg(test)]
        if FORCE_RNG_FAILURE.load(core::sync::atomic::Ordering::Relaxed) {
            return Err(getrandom::Error::UNEXPECTED);
        }
        getrandom::fill(buf)?;
    }
    Ok(())
}

/// Test-only fault injection for the OS-RNG failure branch of
/// [`randombytes_fill`].
///
/// An actual `getrandom` failure cannot be provoked portably, so the
/// fail-closed regression tests flip this flag in a re-executed child
/// process and assert the process dies instead of returning. Compiled out
/// entirely outside `cfg(test)`.
#[cfg(test)]
static FORCE_RNG_FAILURE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Fail closed: report the fault on stderr, then kill the process.
///
/// This is the only correct answer at the PQClean boundary. The two
/// alternatives are both wrong:
///
/// - Returning an error code is **fail-open**: every PQClean call site
///   (`crypto_sign_keypair`, `crypto_sign_signature`, …) calls
///   `randombytes()` for its return value and discards it, so the caller
///   would go on to derive a key or a signature nonce from an unwritten
///   stack buffer.
/// - Panicking unwinds into `extern "C"` frames.
///
/// `process::abort` does neither: no unwinding crosses the FFI boundary,
/// and no key material is ever produced from unrandomized bytes.
#[cold]
#[inline(never)]
fn abort_rng_failure(what: &str) -> ! {
    use std::io::Write as _;
    // A locked-stderr `writeln!` returns its error instead of panicking, so
    // nothing on the way to abort() can unwind.
    let mut err = std::io::stderr().lock();
    let _ = writeln!(
        err,
        "FATAL: pqcrypto-internals: {what}. Aborting: PQClean discards the \
         randombytes() return code, so continuing would derive keys or \
         signature nonces from an unrandomized buffer."
    );
    let _ = err.flush();
    std::process::abort()
}

/// Get random bytes; exposed for PQClean implementations.
///
/// # Behavior
///
/// Delegates to [`randombytes_fill`] (seeded thread-local stream if active,
/// OS entropy otherwise) and returns `0` on success. It returns *only* on
/// success — every failure aborts the process.
///
/// SECURITY (audit K-H1, supersedes audit M): this function must FAIL CLOSED.
/// Upstream `pqcrypto-internals` writes `getrandom::fill(buf).expect(..)`,
/// i.e. it dies on an OS RNG failure; an earlier fork of this file relaxed
/// that to `return -1`, which is fail-OPEN, because the PQClean C sources
/// call `randombytes(buf, len);` as a statement and never inspect the result.
/// A `-1` therefore let ML-DSA keygen and hedged signing continue over an
/// unwritten stack buffer — attacker-predictable key material rather than a
/// loud crash. Both failure modes now go to [`abort_rng_failure`]:
///
/// - OS RNG failure → abort (never a partially filled or untouched `buf`).
/// - `buf` is NULL with `len > 0` → abort. Checked before any slice is
///   constructed, since `slice::from_raw_parts_mut` on NULL is itself UB.
///
/// `len == 0` is a no-op and returns `0` for any `buf`, NULL included.
///
/// # Safety
///
/// If `len > 0`, `buf` must be non-NULL, valid for writes of `len` bytes, and
/// not aliased by any Rust reference for the duration of the call.
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
    // Nothing to write: no buffer is dereferenced, so this is safe even for a
    // NULL `buf`, and no randomness is owed to the caller.
    if len == 0 {
        return 0;
    }
    // Checked BEFORE constructing a slice: `slice::from_raw_parts_mut` on a
    // NULL pointer is undefined behavior. A NULL buffer means the C side is
    // broken; there is no way to return randomness, and an error code would
    // be discarded, so fail closed.
    if buf.is_null() {
        abort_rng_failure("randombytes() called with a NULL buffer");
    }
    let buf = slice::from_raw_parts_mut(buf, len);

    match randombytes_fill(buf) {
        Ok(()) => 0,
        // Fail closed; never unwind into C, never hand back a `-1` that the
        // PQClean call site ignores.
        Err(_) => abort_rng_failure("the OS RNG failed to fill the buffer"),
    }
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

    /// Zero-length fills succeed trivially — nothing is written and no
    /// pointer is dereferenced, so even a NULL `buf` is a plain no-op rather
    /// than a fault.
    #[test]
    fn zero_length_fill_is_ok() {
        let mut buf = [0u8; 1];
        let rc = unsafe { PQCRYPTO_RUST_randombytes(buf.as_mut_ptr(), 0) };
        assert_eq!(rc, 0);

        let rc_null = unsafe { PQCRYPTO_RUST_randombytes(core::ptr::null_mut(), 0) };
        assert_eq!(
            rc_null, 0,
            "zero-length NULL fill must be a no-op, not a fault"
        );
    }

    // ---- Audit K-H1: the RNG must FAIL CLOSED --------------------------
    //
    // `abort_rng_failure` kills the process, so each failure case is driven
    // by re-executing THIS test binary against a single filtered child test,
    // with an env var selecting the case. The child prints `RETURNED_MARKER`
    // if `PQCRYPTO_RUST_randombytes` returns at all; the parent then asserts
    // the child died on SIGABRT and never printed that marker.
    //
    // Against the pre-fix code (`Err(_) => -1`, NULL → -1) both tests fail:
    // the child exits 0 with the marker on stdout, which is exactly the
    // fail-open behavior PQClean would have silently accepted.

    const ABORT_CASE_ENV: &str = "PQCRYPTO_INTERNALS_ABORT_CASE";
    const RETURNED_MARKER: &str = "RETURNED-INSTEAD-OF-ABORTING";

    fn run_abort_case(case: &str) -> std::process::Output {
        let exe = std::env::current_exe().expect("path to the running test binary");
        std::process::Command::new(exe)
            .args([
                "--exact",
                "tests::abort_case_child",
                "--include-ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ABORT_CASE_ENV, case)
            .output()
            .expect("re-exec the test binary")
    }

    fn assert_failed_closed(out: &std::process::Output, case: &str) {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);

        assert!(
            !stdout.contains(RETURNED_MARKER),
            "{case}: PQCRYPTO_RUST_randombytes RETURNED instead of aborting — \
             PQClean discards that code, so this is fail-open.\nstdout:\n{stdout}"
        );
        assert!(
            !out.status.success(),
            "{case}: child exited successfully; expected an abort.\nstdout:\n{stdout}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            assert_eq!(
                out.status.signal(),
                Some(6),
                "{case}: expected SIGABRT, got {:?}.\nstderr:\n{stderr}",
                out.status
            );
        }
        assert!(
            stderr.contains("FATAL: pqcrypto-internals"),
            "{case}: no fail-closed diagnostic on stderr:\n{stderr}"
        );
    }

    /// Child helper: re-executed by [`run_abort_case`], never run by a plain
    /// `cargo test` (no env var set → returns immediately).
    #[test]
    #[ignore = "child process helper for the fail-closed regression tests"]
    fn abort_case_child() {
        let Ok(case) = std::env::var(ABORT_CASE_ENV) else {
            return;
        };
        match case.as_str() {
            // Force the OS-RNG branch to fail, exactly as `getrandom` would
            // on a kernel entropy-source failure.
            "os_rng_failure" => {
                FORCE_RNG_FAILURE.store(true, core::sync::atomic::Ordering::SeqCst);
                let mut buf = [0u8; 32];
                let rc = unsafe { PQCRYPTO_RUST_randombytes(buf.as_mut_ptr(), buf.len()) };
                println!("{RETURNED_MARKER} rc={rc} buf={buf:?}");
            }
            "null_buffer" => {
                let rc = unsafe { PQCRYPTO_RUST_randombytes(core::ptr::null_mut(), 32) };
                println!("{RETURNED_MARKER} rc={rc}");
            }
            other => panic!("unknown abort case {other:?}"),
        }
    }

    /// Audit K-H1 REGRESSION: an OS RNG failure must abort, not return `-1`.
    #[test]
    fn os_rng_failure_aborts_instead_of_failing_open() {
        assert_failed_closed(&run_abort_case("os_rng_failure"), "os_rng_failure");
    }

    /// Audit K-H1 REGRESSION: a NULL buffer with `len > 0` must abort too —
    /// there is no way to return randomness, and an error code is discarded.
    #[test]
    fn null_buffer_aborts_instead_of_failing_open() {
        assert_failed_closed(&run_abort_case("null_buffer"), "null_buffer");
    }

    /// The injection hook itself must be inert unless a test sets it —
    /// otherwise the two abort tests above could pass vacuously.
    #[test]
    fn fault_injection_is_off_by_default() {
        assert!(!FORCE_RNG_FAILURE.load(core::sync::atomic::Ordering::SeqCst));
        let mut buf = [0u8; 32];
        assert!(randombytes_fill(&mut buf).is_ok());
    }

    /// The safe-Rust core reports success via Result (the OS-failure branch
    /// propagates `getrandom::Error` instead of panicking; an actual OS RNG
    /// failure cannot be forced in a portable test).
    #[test]
    fn randombytes_fill_returns_result() {
        let mut buf = [0u8; 32];
        assert!(randombytes_fill(&mut buf).is_ok());

        // Seeded path is deterministic and infallible.
        let _g = with_seeded_rng(&[0xA5u8; 32]);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        randombytes_fill(&mut a).unwrap();
        drop(_g);
        let _g2 = with_seeded_rng(&[0xA5u8; 32]);
        randombytes_fill(&mut b).unwrap();
        assert_eq!(a, b);
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

    /// I-2 regression: nesting `with_seeded_rng` must be a well-defined
    /// no-op for the OUTER scope — the outer stream must pick up EXACTLY
    /// where it left off once the inner guard drops, not fall back to OS
    /// entropy.
    ///
    /// Against the pre-fix single-`Option` implementation this test FAILS:
    /// the inner guard's `Drop` unconditionally cleared the thread-local, so
    /// the outer's second read went through the OS-RNG branch instead of any
    /// seeded stream, and would (with overwhelming probability) differ from
    /// the un-nested baseline.
    #[test]
    fn nested_seeded_rng_is_a_documented_noop_for_the_outer_scope() {
        let outer_seed = [0x10u8; 32];
        let inner_seed = [0x20u8; 32];

        // Baseline: two consecutive reads from the outer stream, no nesting.
        let (baseline_1, baseline_2) = {
            let _g = with_seeded_rng(&outer_seed);
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            randombytes_fill(&mut a).unwrap();
            randombytes_fill(&mut b).unwrap();
            (a, b)
        };

        // Same two reads, but with an inner nested guard in between.
        let (nested_1, nested_2, inner_bytes) = {
            let _outer = with_seeded_rng(&outer_seed);
            let mut a = [0u8; 32];
            randombytes_fill(&mut a).unwrap();

            let inner_bytes = {
                let _inner = with_seeded_rng(&inner_seed);
                let mut i = [0u8; 32];
                randombytes_fill(&mut i).unwrap();
                i
            }; // inner guard dropped here — must restore the OUTER seed, not OS RNG

            let mut b = [0u8; 32];
            randombytes_fill(&mut b).unwrap();
            (a, b, inner_bytes)
        };

        assert_eq!(baseline_1, nested_1, "the outer stream's first read is unaffected by nesting");
        assert_eq!(
            baseline_2, nested_2,
            "the outer stream must resume EXACTLY where it left off after the \
             inner guard drops — nesting must be a no-op for the outer scope"
        );
        // Sanity: the inner scope really was seeded differently (not equal to
        // either outer read), confirming the inner guard was genuinely active.
        assert_ne!(inner_bytes, baseline_1);
        assert_ne!(inner_bytes, baseline_2);
    }
}
