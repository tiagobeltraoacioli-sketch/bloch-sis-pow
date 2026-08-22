//! Cross-VM KATs (BLOCH-VM-HOST §9.1): prove the REAL bloch-euvm in-VM
//! hashing (`Op::Shake256`, `Op::Sha256d` — bloch-euvm lib.rs:424/418) and
//! this crate's `RustCryptoHost` compute the same function, byte for byte,
//! so the two hashing sites can never drift apart silently (a version bump,
//! a "cleanup", a different XOF read length — all become a red test here).
//!
//! Method: euvm's `run` only ever returns the truthiness of the top of
//! stack (lib.rs:297 doc), so the digest cannot be read out directly.
//! Instead each check runs the program `[HashOp, PushBytes(expected), Eq]`
//! over a seeded `[Bytes(input)]` stack: `Ok(true)` iff the in-VM digest
//! equals the host-side digest. The CONTROL half flips one byte of
//! `expected` and demands `Ok(false)` — proving the `Ok(true)` half is a
//! real comparison, not a program that vacuously succeeds.
//!
//! sha3_256 has NO in-VM twin (euvm has no SHA3 op; it is the SBPF syscall
//! 3 surface) — its KATs are pinned against an independent implementation
//! in src/lib.rs and gain a cross-check only when sbpf exists.

use bloch_euvm::{run, Ctx, Op, SigVerifier, Val};
use bloch_vm_host::{HostCrypto, RustCryptoHost};

/// Signature-free verifier: these programs never touch VerifySig, and a
/// default-deny verifier keeps that true fail-closed (same posture as
/// RustCryptoHost::verify_pq).
struct NoSig;
impl SigVerifier for NoSig {
    fn verify(&self, _m: &[u8], _p: &[u8], _s: &[u8]) -> bool {
        false
    }
}

/// Run `[hash_op, PushBytes(expected), Eq]` over seed `[Bytes(input)]`.
fn vm_hash_equals(hash_op: Op, input: &[u8], expected: &[u8; 32]) -> bool {
    let program = vec![hash_op, Op::PushBytes(expected.to_vec()), Op::Eq];
    let mut gas: u64 = 1_000_000;
    run(
        &program,
        vec![Val::Bytes(input.to_vec())],
        &Ctx::default(),
        &NoSig,
        &mut gas,
    )
    .expect("hash cross-check program must not fault")
}

/// Inputs spanning the classes that expose sponge/padding bugs: empty,
/// short, rate-boundary-ish (136 bytes = SHAKE-256 rate), and multi-block.
fn inputs() -> Vec<Vec<u8>> {
    vec![
        b"".to_vec(),
        b"abc".to_vec(),
        vec![0xA5; 136],
        (0u8..=255).cycle().take(1024).collect(),
    ]
}

#[test]
fn shake256_host_and_vm_agree() {
    for input in inputs() {
        let expected = RustCryptoHost.shake256_32(&input);
        assert!(
            vm_hash_equals(Op::Shake256, &input, &expected),
            "Op::Shake256 disagrees with RustCryptoHost::shake256_32 for len {}",
            input.len()
        );
    }
}

/// CONTROL: the same program with a tampered digest must answer false —
/// otherwise the positive half proves nothing.
#[test]
fn control_shake256_tampered_digest_is_rejected() {
    for input in inputs() {
        let mut tampered = RustCryptoHost.shake256_32(&input);
        tampered[0] ^= 0x01;
        assert!(
            !vm_hash_equals(Op::Shake256, &input, &tampered),
            "VM accepted a wrong shake256 digest for len {}",
            input.len()
        );
    }
}

#[test]
fn sha256d_host_and_vm_agree() {
    for input in inputs() {
        let expected = RustCryptoHost.sha256d(&input);
        assert!(
            vm_hash_equals(Op::Sha256d, &input, &expected),
            "Op::Sha256d disagrees with RustCryptoHost::sha256d for len {}",
            input.len()
        );
    }
}

/// CONTROL twin of the sha256d positive half.
#[test]
fn control_sha256d_tampered_digest_is_rejected() {
    for input in inputs() {
        let mut tampered = RustCryptoHost.sha256d(&input);
        tampered[31] ^= 0x80;
        assert!(
            !vm_hash_equals(Op::Sha256d, &input, &tampered),
            "VM accepted a wrong sha256d digest for len {}",
            input.len()
        );
    }
}

/// The two hash ops are different functions in BOTH implementations — a
/// cross-wiring (host shake vs. VM sha256d agreeing) would slip through the
/// per-function tests only if both sides made the same swap; this pins the
/// host side against the VM side crosswise.
#[test]
fn control_cross_wiring_is_rejected() {
    let input = b"abc";
    let shake = RustCryptoHost.shake256_32(input);
    let dsha = RustCryptoHost.sha256d(input);
    assert!(!vm_hash_equals(Op::Sha256d, input, &shake));
    assert!(!vm_hash_equals(Op::Shake256, input, &dsha));
}
