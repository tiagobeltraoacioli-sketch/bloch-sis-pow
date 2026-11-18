// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cross-architecture determinism of the consensus signature and hash
//! primitives (L1 hardening round 19).
//!
//! Two kinds of evidence, both from a fixed, seed-derived corpus:
//!
//! 1. **Differential** (within one run): every implementation of a primitive
//!    that this binary can execute is run on the same inputs and must give
//!    the same verdict, and the same bytes where output is deterministic.
//!    ML-DSA-65: PQClean `clean` (the consensus rule from
//!    `MLDSA_PIN_ACTIVATION_EPOCH`), the AVX2 backend on x86-64 hosts with
//!    AVX2, the AArch64/NEON backend on aarch64, the historical
//!    CPU-dispatching wrapper and the pinned wrapper. Hashes: the `sha2` /
//!    `sha3` crates (whatever backend they select on this CPU: SHA-NI, AVX2,
//!    ARMv8 extensions or portable) against a portable reference written in
//!    this file from FIPS 180-4 / FIPS 202, whose round constants are derived
//!    from the specification's definition rather than copied.
//!
//! 2. **Golden transcript** (across runs and machines): every verdict and
//!    every deterministic output is folded into one SHA3-256 digest (computed
//!    with the reference above, not with a crate) and compared with a
//!    constant recorded on x86-64. A host of another architecture that runs
//!    this file and gets `ok` has reproduced the x86-64 results bit for bit:
//!    that is the cross-architecture check, and it needs no second machine
//!    at hand. The transcript only contains architecture-independent facts
//!    (the reference verdict, not the list of backends), so the constants are
//!    the same on every target.
//!
//! What this file cannot do is run the AArch64 code on an x86-64 host; see
//! the report of the round for what was and was not executed.
use pqcrypto_mldsa::ffi;

// ───────────────────────── reference hashes ─────────────────────────────

mod reference {
    //! Portable, table-free reference implementations. Slow and simple on
    //! purpose; used as the oracle for the crates and to hash transcripts.
    use primitive_types::U256;
    use std::sync::OnceLock;

    const RC: [u64; 24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];
    const ROTC: [u32; 24] =
        [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
    const PILN: [usize; 24] =
        [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

    fn keccak_f1600(st: &mut [u64; 25]) {
        for rc in RC {
            let mut bc = [0u64; 5];
            for i in 0..5 {
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            }
            for i in 0..5 {
                let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
                for j in (0..25).step_by(5) {
                    st[j + i] ^= t;
                }
            }
            let mut t = st[1];
            for i in 0..24 {
                let j = PILN[i];
                let b = st[j];
                st[j] = t.rotate_left(ROTC[i]);
                t = b;
            }
            for j in (0..25).step_by(5) {
                let row = [st[j], st[j + 1], st[j + 2], st[j + 3], st[j + 4]];
                for i in 0..5 {
                    st[j + i] = row[i] ^ (!row[(i + 1) % 5] & row[(i + 2) % 5]);
                }
            }
            st[0] ^= rc;
        }
    }

    /// Keccak sponge: `rate` in bytes, `suffix` the domain-separation byte
    /// (0x06 SHA-3, 0x1f SHAKE, 0x01 legacy Keccak), `out_len` output bytes.
    pub fn keccak(rate: usize, suffix: u8, input: &[u8], out_len: usize) -> Vec<u8> {
        let mut st = [0u64; 25];
        let xor_byte = |st: &mut [u64; 25], pos: usize, b: u8| st[pos / 8] ^= u64::from(b) << (8 * (pos % 8));
        let mut pos = 0;
        for &b in input {
            xor_byte(&mut st, pos, b);
            pos += 1;
            if pos == rate {
                keccak_f1600(&mut st);
                pos = 0;
            }
        }
        xor_byte(&mut st, pos, suffix);
        xor_byte(&mut st, rate - 1, 0x80);
        keccak_f1600(&mut st);
        let mut out = Vec::with_capacity(out_len);
        let mut pos = 0;
        while out.len() < out_len {
            if pos == rate {
                keccak_f1600(&mut st);
                pos = 0;
            }
            out.push((st[pos / 8] >> (8 * (pos % 8))) as u8);
            pos += 1;
        }
        out
    }

    pub fn sha3_256(m: &[u8]) -> [u8; 32] {
        keccak(136, 0x06, m, 32).try_into().unwrap()
    }
    pub fn sha3_512(m: &[u8]) -> Vec<u8> {
        keccak(72, 0x06, m, 64)
    }
    pub fn keccak256(m: &[u8]) -> Vec<u8> {
        keccak(136, 0x01, m, 32)
    }
    pub fn shake128(m: &[u8], n: usize) -> Vec<u8> {
        keccak(168, 0x1f, m, n)
    }
    pub fn shake256(m: &[u8], n: usize) -> Vec<u8> {
        keccak(136, 0x1f, m, n)
    }

    fn primes(n: usize) -> Vec<u64> {
        let mut v: Vec<u64> = Vec::new();
        let mut c = 2u64;
        while v.len() < n {
            if v.iter().all(|p| c % p != 0) {
                v.push(c);
            }
            c += 1;
        }
        v
    }

    /// floor(n^(1/k)) for k = 2 or 3, by binary search.
    fn iroot(n: U256, k: u32) -> U256 {
        let (mut lo, mut hi) = (U256::zero(), U256::one() << 80);
        while lo < hi {
            let mid = (lo + hi + U256::one()) >> 1;
            let mut p = mid;
            for _ in 1..k {
                p = p * mid;
            }
            if p <= n {
                lo = mid;
            } else {
                hi = mid - U256::one();
            }
        }
        lo
    }

    /// First `bits` fractional bits of the k-th root of `p` (FIPS 180-4
    /// §4.2.2/§4.2.3 round constants with k = 3, §5.3 initial values with
    /// k = 2).
    fn frac_root(p: u64, k: u32, bits: u32) -> u64 {
        let r = iroot(U256::from(p) << (k * bits) as usize, k);
        (r & ((U256::one() << bits as usize) - U256::one())).low_u64()
    }

    pub fn sha256(m: &[u8]) -> [u8; 32] {
        static CONSTANTS: OnceLock<(Vec<u32>, Vec<u32>)> = OnceLock::new();
        let (k, iv) = CONSTANTS.get_or_init(|| {
            (
                primes(64).iter().map(|p| frac_root(*p, 3, 32) as u32).collect(),
                primes(8).iter().map(|p| frac_root(*p, 2, 32) as u32).collect(),
            )
        });
        let mut h = iv.clone();
        let mut msg = m.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&((m.len() as u64) * 8).to_be_bytes());
        for block in msg.chunks(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
            }
            let mut v: [u32; 8] = h.clone().try_into().unwrap();
            for i in 0..64 {
                let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
                let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
                let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
                let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
                let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                let t2 = s0.wrapping_add(maj);
                v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
            }
            for i in 0..8 {
                h[i] = h[i].wrapping_add(v[i]);
            }
        }
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
        }
        out
    }

    pub fn sha512(m: &[u8]) -> Vec<u8> {
        static CONSTANTS: OnceLock<(Vec<u64>, Vec<u64>)> = OnceLock::new();
        let (k, iv) = CONSTANTS.get_or_init(|| {
            (
                primes(80).iter().map(|p| frac_root(*p, 3, 64)).collect(),
                primes(8).iter().map(|p| frac_root(*p, 2, 64)).collect(),
            )
        });
        let mut h = iv.clone();
        let mut msg = m.to_vec();
        msg.push(0x80);
        while msg.len() % 128 != 112 {
            msg.push(0);
        }
        msg.extend_from_slice(&((m.len() as u128) * 8).to_be_bytes());
        for block in msg.chunks(128) {
            let mut w = [0u64; 80];
            for i in 0..16 {
                w[i] = u64::from_be_bytes(block[8 * i..8 * i + 8].try_into().unwrap());
            }
            for i in 16..80 {
                let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
                let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
                w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
            }
            let mut v: [u64; 8] = h.clone().try_into().unwrap();
            for i in 0..80 {
                let s1 = v[4].rotate_right(14) ^ v[4].rotate_right(18) ^ v[4].rotate_right(41);
                let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
                let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
                let s0 = v[0].rotate_right(28) ^ v[0].rotate_right(34) ^ v[0].rotate_right(39);
                let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                let t2 = s0.wrapping_add(maj);
                v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
            }
            for i in 0..8 {
                h[i] = h[i].wrapping_add(v[i]);
            }
        }
        h.iter().flat_map(|x| x.to_be_bytes()).collect()
    }
}

/// Golden transcript: a running reference-SHA3-256 chain, so the constant
/// does not depend on any crate under test.
struct Transcript([u8; 32], u64);
impl Transcript {
    fn new(label: &str) -> Self {
        Transcript(reference::sha3_256(label.as_bytes()), 0)
    }
    fn absorb(&mut self, data: &[u8]) {
        let mut buf = Vec::with_capacity(48 + data.len());
        buf.extend_from_slice(&self.0);
        buf.extend_from_slice(&self.1.to_le_bytes());
        buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        buf.extend_from_slice(data);
        self.0 = reference::sha3_256(&buf);
        self.1 += 1;
    }
    fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Compare with the recorded constant. `R19_DET_PRINT=1` prints the value
/// instead of failing, for recording after a deliberate corpus change.
fn check_golden(name: &str, t: &Transcript, want: &str) {
    eprintln!("r19 determinism: {name} transcript = {} ({} records) on {}", t.hex(), t.1, std::env::consts::ARCH);
    if std::env::var_os("R19_DET_PRINT").is_some() {
        return;
    }
    assert_eq!(
        t.hex(),
        want,
        "{name}: this host ({}) does not reproduce the transcript recorded on x86-64. \
         If the corpus was not changed, this is a cross-architecture or cross-backend divergence.",
        std::env::consts::ARCH
    );
}

/// Splitmix64: reproducible schedule without a dev-dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn seed32(&mut self) -> [u8; 32] {
        self.bytes(32).try_into().unwrap()
    }
}

// ───────────────────────── hashes ────────────────────────────────────────

#[test]
fn reference_hashes_match_the_published_test_vectors() {
    let h = |b: &[u8]| hex::encode(b);
    assert_eq!(h(&reference::sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(
        h(&reference::sha512(b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    assert_eq!(h(&reference::sha3_256(b"")), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    assert_eq!(h(&reference::sha3_256(b"abc")), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    assert_eq!(h(&reference::keccak256(b"")), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    assert_eq!(h(&reference::shake256(b"", 32)), "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
    assert_eq!(h(&reference::shake128(b"", 32)), "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
}

/// Which acceleration the hash crates can select on this CPU, for the log.
fn hash_cpu_features() -> String {
    #[cfg(target_arch = "x86_64")]
    {
        format!(
            "x86_64 sha-ni={} avx2={} (sha2 0.10 uses SHA-NI for SHA-256 and AVX2 for SHA-512 when present)",
            std::is_x86_feature_detected!("sha"),
            std::is_x86_feature_detected!("avx2")
        )
    }
    #[cfg(target_arch = "aarch64")]
    {
        format!(
            "aarch64 sha2={} sha3={} (used by sha2/keccak only when their `asm` feature is on)",
            std::arch::is_aarch64_feature_detected!("sha2"),
            std::arch::is_aarch64_feature_detected!("sha3")
        )
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        String::from("portable")
    }
}

const GOLDEN_HASHES: &str = "3824443b8aecb18a7b2968dbaf8f2aea8324e0fca32fe4362a657ddf72e436d2";

#[test]
fn hash_crates_match_the_portable_reference_on_this_cpu() {
    use sha2::Digest as _;
    use sha3::digest::{ExtendableOutput as _, Update as _, XofReader as _};
    eprintln!("r19 determinism: hash backends: {}", hash_cpu_features());

    let mut rng = Rng(0x5231_395f_4841_5348); // "R19_HASH"
    // Every length across the block boundaries of all seven functions
    // (rates 72, 136, 168; blocks 64, 128), then random longer inputs.
    let mut lens: Vec<usize> = (0..=345).collect();
    for _ in 0..1700 {
        lens.push(rng.below(4200));
    }
    let mut t = Transcript::new("bloch r19 hashes v1");
    let mut bytes_hashed = 0usize;
    for (n, len) in lens.iter().copied().enumerate() {
        let m = rng.bytes(len);
        let cut = if len == 0 { 0 } else { rng.below(len + 1) };
        let (a, b) = m.split_at(cut);
        bytes_hashed += len;

        // One-shot and split-update must both equal the reference.
        macro_rules! fixed {
            ($ty:ty, $reference:expr, $name:literal) => {{
                let want: Vec<u8> = $reference.to_vec();
                assert_eq!(<$ty>::digest(&m).to_vec(), want, "{} one-shot, case {n} len {len}", $name);
                let mut h = <$ty>::new();
                sha2::Digest::update(&mut h, a);
                sha2::Digest::update(&mut h, b);
                assert_eq!(h.finalize().to_vec(), want, "{} split at {cut}, case {n} len {len}", $name);
                t.absorb(&want);
            }};
        }
        fixed!(sha2::Sha256, reference::sha256(&m), "SHA-256");
        fixed!(sha2::Sha512, reference::sha512(&m), "SHA-512");
        fixed!(sha3::Sha3_256, reference::sha3_256(&m), "SHA3-256");
        fixed!(sha3::Sha3_512, reference::sha3_512(&m), "SHA3-512");
        fixed!(sha3::Keccak256, reference::keccak256(&m), "Keccak-256");

        let out_len = 1 + rng.below(400);
        macro_rules! xof {
            ($ty:ty, $reference:expr, $name:literal) => {{
                let want: Vec<u8> = $reference;
                let mut x = <$ty>::default();
                x.update(a);
                x.update(b);
                let mut rdr = x.finalize_xof();
                // Squeeze in two reads to cross the rate boundary both ways.
                let mut got = vec![0u8; out_len];
                let first = out_len / 3;
                rdr.read(&mut got[..first]);
                rdr.read(&mut got[first..]);
                assert_eq!(got, want, "{} case {n} len {len} out {out_len}", $name);
                t.absorb(&want);
            }};
        }
        xof!(sha3::Shake128, reference::shake128(&m, out_len), "SHAKE128");
        xof!(sha3::Shake256, reference::shake256(&m, out_len), "SHAKE256");
    }
    eprintln!("r19 determinism: hashes: {} inputs, {bytes_hashed} bytes, 7 functions agree with the reference", lens.len());
    check_golden("hashes", &t, GOLDEN_HASHES);
}

// ───────────────────────── ML-DSA-65 ─────────────────────────────────────

const PK: usize = 1952;
const SK: usize = 4032;
const SIG: usize = 3309;
// FIPS 204 ML-DSA-65 signature layout: c~ (48) ‖ z (5 × 256 × 20 bits) ‖ h.
const CTILDE: usize = 48;
const L: usize = 5;
const K: usize = 6;
const OMEGA: usize = 55;
const Z_POLY_BYTES: usize = 640;
const H0: usize = CTILDE + L * Z_POLY_BYTES;
const GAMMA1: i32 = 1 << 19;
const BETA: i32 = 49 * 4; // tau * eta
const _: () = assert!(H0 + OMEGA + K == SIG);

type Keypair = unsafe extern "C" fn(*mut u8, *mut u8) -> core::ffi::c_int;
type SignCtx =
    unsafe extern "C" fn(*mut u8, *mut usize, *const u8, usize, *const u8, usize, *const u8) -> core::ffi::c_int;
type VerifyCtx =
    unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize, *const u8) -> core::ffi::c_int;

struct Backend {
    name: &'static str,
    keypair: Keypair,
    sign: SignCtx,
    verify: VerifyCtx,
}

/// Every ML-DSA-65 implementation linked into this binary that this CPU can
/// run. `clean` is first and is the reference.
fn backends() -> Vec<Backend> {
    let mut v = vec![Backend {
        name: "clean",
        keypair: ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair,
        sign: ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx,
        verify: ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx,
    }];
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        v.push(Backend {
            name: "avx2",
            keypair: ffi::PQCLEAN_MLDSA65_AVX2_crypto_sign_keypair,
            sign: ffi::PQCLEAN_MLDSA65_AVX2_crypto_sign_signature_ctx,
            verify: ffi::PQCLEAN_MLDSA65_AVX2_crypto_sign_verify_ctx,
        });
    }
    #[cfg(target_arch = "aarch64")]
    v.push(Backend {
        name: "aarch64",
        keypair: ffi::PQCLEAN_MLDSA65_AARCH64_crypto_sign_keypair,
        sign: ffi::PQCLEAN_MLDSA65_AARCH64_crypto_sign_signature_ctx,
        verify: ffi::PQCLEAN_MLDSA65_AARCH64_crypto_sign_verify_ctx,
    });
    v
}

fn keypair_seeded(b: &Backend, seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (mut pk, mut sk) = (vec![0u8; PK], vec![0u8; SK]);
    // SAFETY: buffers have exactly the FIPS 204 ML-DSA-65 sizes.
    let rc = pqcrypto_internals::with_seeded_rng_scope(seed, || unsafe {
        (b.keypair)(pk.as_mut_ptr(), sk.as_mut_ptr())
    });
    assert_eq!(rc, 0, "{} keypair", b.name);
    (pk, sk)
}

fn sign_seeded(b: &Backend, sk: &[u8], msg: &[u8], ctx: &[u8], rnd_seed: &[u8; 32]) -> Vec<u8> {
    assert_eq!(sk.len(), SK);
    let mut sig = vec![0u8; SIG];
    let mut len = 0usize;
    // SAFETY: sig has SIG capacity, every input pointer carries its length.
    let rc = pqcrypto_internals::with_seeded_rng_scope(rnd_seed, || unsafe {
        (b.sign)(sig.as_mut_ptr(), &mut len, msg.as_ptr(), msg.len(), ctx.as_ptr(), ctx.len(), sk.as_ptr())
    });
    assert_eq!((rc, len), (0, SIG), "{} sign", b.name);
    sig
}

fn verify_raw(b: &Backend, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    assert_eq!(pk.len(), PK);
    // SAFETY: every pointer is passed with its length; pk length asserted.
    unsafe { (b.verify)(sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len(), ctx.as_ptr(), ctx.len(), pk.as_ptr()) == 0 }
}

fn v2_ctx(suite: u16) -> Vec<u8> {
    let mut c = bloch_crypto::crypto::SIG_V2_MLDSA_CONTEXT_PREFIX.to_vec();
    c.extend_from_slice(&suite.to_le_bytes());
    c
}

/// z coefficient `coeff` of polynomial `poly` (FIPS 204 BitPack, 20 bits,
/// stored as gamma1 - z).
fn z_get(sig: &[u8], poly: usize, coeff: usize) -> i32 {
    let bit = 20 * coeff;
    let o = CTILDE + poly * Z_POLY_BYTES + bit / 8;
    let raw = u32::from(sig[o]) | u32::from(sig[o + 1]) << 8 | u32::from(sig[o + 2]) << 16;
    GAMMA1 - ((raw >> (bit % 8)) & 0xF_FFFF) as i32
}

fn z_set(sig: &mut [u8], poly: usize, coeff: usize, z: i32) {
    let t = ((GAMMA1 - z) as u32) & 0xF_FFFF;
    let bit = 20 * coeff;
    let o = CTILDE + poly * Z_POLY_BYTES + bit / 8;
    let sh = bit % 8;
    let mut raw = u32::from(sig[o]) | u32::from(sig[o + 1]) << 8 | u32::from(sig[o + 2]) << 16;
    raw = (raw & !(0xF_FFFF << sh)) | (t << sh);
    sig[o] = raw as u8;
    sig[o + 1] = (raw >> 8) as u8;
    sig[o + 2] = (raw >> 16) as u8;
}

/// Row `i` of the hint vector occupies index bytes `[start, end)`.
fn hint_row(sig: &[u8], i: usize) -> (usize, usize) {
    let start = if i == 0 { 0 } else { sig[H0 + OMEGA + i - 1] as usize };
    (start, sig[H0 + OMEGA + i] as usize)
}

/// What a mutation guarantees about the verdict, when it guarantees anything.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Expect {
    Accept,
    /// FIPS 204 Alg. 21 (sigDecode / HintBitUnpack) or the length check must
    /// refuse this encoding whatever the key and message are.
    Reject,
    Any,
}

struct Case {
    class: u8,
    pk: Vec<u8>,
    msg: Vec<u8>,
    ctx: Vec<u8>,
    sig: Vec<u8>,
    expect: Expect,
}

const CLASSES: u8 = 20;

/// Build mutation `class` of a genuine `(pk, msg, ctx, sig)`. A class that
/// does not apply to this signature (e.g. no row with two hints) falls back
/// to a c~ bit flip, still under its own class number.
fn mutate(class: u8, rng: &mut Rng, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8], ctxs: &[Vec<u8>]) -> Case {
    let (mut p, mut m, mut c, mut s) = (pk.to_vec(), msg.to_vec(), ctx.to_vec(), sig.to_vec());
    let mut expect = Expect::Any;
    let total = s[H0 + OMEGA + K - 1] as usize;
    let rows: Vec<(usize, usize)> = (0..K).map(|i| hint_row(&s, i)).collect();
    let wide: Vec<usize> = (0..K).filter(|&i| rows[i].1 >= rows[i].0 + 2).collect();
    let mut fallback = false;
    match class {
        0 => expect = Expect::Accept,
        1 => s[rng.below(CTILDE)] ^= 1 << rng.below(8),
        2 => s[CTILDE + rng.below(L * Z_POLY_BYTES)] ^= 1 << rng.below(8),
        // z at and around the Alg. 8 bound ||z||_inf < gamma1 - beta, and at
        // the two ends of the 20-bit encoding.
        3 => {
            let bound = GAMMA1 - BETA;
            let (poly, coeff) = (rng.below(L), rng.below(256));
            let old = z_get(&s, poly, coeff);
            let choices = [bound - 1, bound, bound + 1, -(bound - 1), -bound, -(bound + 1), GAMMA1, -(GAMMA1 - 1), 0, old + 1, old - 1];
            let z = choices[rng.below(choices.len())];
            z_set(&mut s, poly, coeff, z);
            assert_eq!(z_get(&s, poly, coeff), z);
        }
        // Whole polynomial at the bound.
        4 => {
            let poly = rng.below(L);
            let z = if rng.below(2) == 0 { GAMMA1 - BETA } else { -(GAMMA1 - BETA) };
            for coeff in 0..256 {
                z_set(&mut s, poly, coeff, z);
            }
        }
        // Same hint set, non-canonical order: two neighbours swapped.
        5 if !wide.is_empty() => {
            let (a, b) = rows[wide[rng.below(wide.len())]];
            let j = a + rng.below(b - a - 1);
            s.swap(H0 + j, H0 + j + 1);
            expect = Expect::Reject;
        }
        // Repeated index.
        6 if !wide.is_empty() => {
            let (a, b) = rows[wide[rng.below(wide.len())]];
            let j = a + rng.below(b - a - 1);
            s[H0 + j + 1] = s[H0 + j];
            expect = Expect::Reject;
        }
        // Non-zero byte in the unused index positions.
        7 if total < OMEGA => {
            s[H0 + total + rng.below(OMEGA - total)] = 1 + rng.below(255) as u8;
            expect = Expect::Reject;
        }
        // Cumulative counter going down.
        8 => {
            let candidates: Vec<usize> = (1..K).filter(|&i| s[H0 + OMEGA + i - 1] > 0).collect();
            if candidates.is_empty() {
                fallback = true;
            } else {
                let i = candidates[rng.below(candidates.len())];
                s[H0 + OMEGA + i] = rng.below(s[H0 + OMEGA + i - 1] as usize) as u8;
                expect = Expect::Reject;
            }
        }
        // Counter above omega.
        9 => {
            s[H0 + OMEGA + rng.below(K)] = (OMEGA + 1 + rng.below(255 - OMEGA)) as u8;
            expect = Expect::Reject;
        }
        10 => s[H0 + OMEGA + rng.below(K)] = rng.next() as u8,
        11 => s[H0 + rng.below(OMEGA)] = rng.next() as u8,
        // One hint dropped: a well-formed encoding of a different hint set.
        12 if total > 0 => {
            let j = rng.below(total);
            s.copy_within(H0 + j + 1..H0 + OMEGA, H0 + j);
            s[H0 + OMEGA - 1] = 0;
            for i in 0..K {
                if rows[i].1 > j {
                    s[H0 + OMEGA + i] -= 1;
                }
            }
        }
        // A hint moved to the neighbouring row by shifting one row boundary.
        13 => {
            let i = rng.below(K - 1);
            let v = s[H0 + OMEGA + i];
            s[H0 + OMEGA + i] = if rng.below(2) == 0 { v.wrapping_add(1) } else { v.wrapping_sub(1) };
        }
        14 => p[rng.below(PK)] ^= 1 << rng.below(8),
        15 => match rng.below(3) {
            0 => m.push(rng.next() as u8),
            1 if !m.is_empty() => {
                let i = rng.below(m.len());
                m[i] ^= 1 << rng.below(8);
            }
            _ => m.insert(0, 0),
        },
        // Another context: the other suite, a prefix, or a longer one.
        16 => {
            c = match rng.below(4) {
                0 => ctxs[rng.below(ctxs.len())].clone(),
                1 => c[..c.len() / 2].to_vec(),
                2 => [c.as_slice(), &[0]].concat(),
                _ => {
                    let n = rng.below(256);
                    rng.bytes(n)
                }
            };
        }
        // Wrong signature length.
        17 => {
            match rng.below(3) {
                0 => s.truncate(SIG - 1),
                1 => s.push(0),
                _ => s.truncate(rng.below(SIG)),
            }
            expect = Expect::Reject;
        }
        // All-zero / all-ones regions.
        18 => {
            let fill = if rng.below(2) == 0 { 0x00 } else { 0xFF };
            let (a, b) = match rng.below(3) {
                0 => (0, CTILDE),
                1 => (CTILDE, H0),
                _ => (H0, SIG),
            };
            s[a..b].fill(fill);
        }
        // Several independent byte edits.
        19 => {
            for _ in 0..=rng.below(4) {
                let i = rng.below(SIG);
                s[i] = rng.next() as u8;
            }
        }
        _ => fallback = true,
    }
    if fallback {
        s[rng.below(CTILDE)] ^= 1 << rng.below(8);
    }
    Case { class, pk: p, msg: m, ctx: c, sig: s, expect }
}

const GOLDEN_MLDSA: &str = "3acb209bec9c91505ff13970891f73d01344f06fdfb9118f75aa0b3edae2c564";

/// Keygen, signing and verification on every backend over a fixed corpus of
/// genuine, malformed and boundary signatures.
#[test]
fn mldsa65_backends_agree_and_reproduce_the_recorded_transcript() {
    let bs = backends();
    eprintln!("r19 determinism: ML-DSA-65 backends on this host: {:?}", bs.iter().map(|b| b.name).collect::<Vec<_>>());
    let mut rng = Rng(0x5231_395f_4d4c_4453); // "R19_MLDS"
    let ctxs: Vec<Vec<u8>> = vec![Vec::new(), v2_ctx(0x0001), v2_ctx(0x0002), vec![0xA5; 255]];
    let mut t = Transcript::new("bloch r19 ml-dsa-65 v1");
    let (mut cases, mut accepted, mut forced_rejects) = (0usize, 0usize, 0usize);
    let mut per_class = [0usize; CLASSES as usize];

    for key in 0..6usize {
        // Keygen: same function of the seed on every backend.
        let seed = rng.seed32();
        let (pk, sk) = keypair_seeded(&bs[0], &seed);
        for b in &bs[1..] {
            assert_eq!(keypair_seeded(b, &seed), (pk.clone(), sk.clone()), "{} keygen differs from clean", b.name);
        }
        t.absorb(&pk);
        t.absorb(&sk);

        for (ci, ctx) in ctxs.iter().enumerate() {
            let msg = rng.bytes([0, 1, 32, 33, 64, 137, 1000, 4097][(key + 3 * ci) % 8]);
            // Signing: same bytes for the same rnd on every backend.
            let rnd = rng.seed32();
            let sig = sign_seeded(&bs[0], &sk, &msg, ctx, &rnd);
            for b in &bs[1..] {
                assert_eq!(sign_seeded(b, &sk, &msg, ctx, &rnd), sig, "{} signature differs from clean", b.name);
            }
            t.absorb(&sig);

            for n in 0..200usize {
                let class = (n % CLASSES as usize) as u8;
                let case = mutate(class, &mut rng, &pk, &msg, ctx, &sig, &ctxs);
                let reference = verify_raw(&bs[0], &case.pk, &case.msg, &case.ctx, &case.sig);
                for b in &bs[1..] {
                    assert_eq!(
                        verify_raw(b, &case.pk, &case.msg, &case.ctx, &case.sig),
                        reference,
                        "ML-DSA-65 verdict of {} differs from clean: key {key} ctx {ci} case {n} class {class}",
                        b.name
                    );
                }
                // The pinned wrapper (consensus from MLDSA_PIN_ACTIVATION_EPOCH).
                assert_eq!(
                    bloch_mldsa_clean::verify_ctx(&case.pk, &case.msg, &case.ctx, &case.sig),
                    reference && case.ctx.len() <= 255,
                    "pinned wrapper, key {key} ctx {ci} case {n} class {class}"
                );
                if case.ctx.is_empty() {
                    // The historical rule (CPU-dispatching wrapper: AVX2 on
                    // this kind of x86-64 host, NEON on aarch64) and the
                    // pinned rule, through the entry points consensus uses.
                    assert_eq!(
                        bloch_crypto::crypto::verify_mldsa65_raw(&case.pk, &case.msg, &case.sig),
                        reference,
                        "historical dispatching verifier, key {key} case {n} class {class}"
                    );
                    assert_eq!(
                        bloch_crypto::crypto::verify_mldsa65_raw_pinned(&case.pk, &case.msg, &case.sig),
                        reference,
                        "pinned verifier, key {key} case {n} class {class}"
                    );
                }
                match case.expect {
                    Expect::Accept => assert!(reference, "genuine signature refused, key {key} ctx {ci}"),
                    Expect::Reject => {
                        assert!(!reference, "non-canonical encoding accepted: key {key} ctx {ci} case {n} class {class}");
                        forced_rejects += 1;
                    }
                    Expect::Any => {}
                }
                t.absorb(&[case.class, u8::from(reference)]);
                cases += 1;
                accepted += usize::from(reference);
                per_class[class as usize] += usize::from(reference);
            }
        }
    }
    eprintln!(
        "r19 determinism: ML-DSA-65: {cases} cases, {accepted} accepted, {forced_rejects} must-reject encodings refused, \
         accepted per class {per_class:?}, {} backend(s) agree",
        bs.len()
    );
    assert!(cases >= 4800 && accepted >= 24 * 10 && accepted < cases);
    check_golden("ml-dsa-65", &t, GOLDEN_MLDSA);
}

/// A context longer than 255 bytes is refused by every backend (the C entry
/// points check it themselves; the safe wrapper never passes it down).
#[test]
fn mldsa65_backends_refuse_an_overlong_context_identically() {
    let bs = backends();
    let (pk, sk) = keypair_seeded(&bs[0], &[9u8; 32]);
    let sig = sign_seeded(&bs[0], &sk, b"m", &[7u8; 255], &[1u8; 32]);
    for b in &bs {
        assert!(verify_raw(b, &pk, b"m", &[7u8; 255], &sig), "{}", b.name);
        assert!(!verify_raw(b, &pk, b"m", &[7u8; 256], &sig), "{}", b.name);
        assert!(!verify_raw(b, &pk, b"m", &[7u8; 254], &sig), "{}", b.name);
    }
}

// ───────────────────────── hybrid (suite 0x0001) ─────────────────────────

const GOLDEN_HYBRID: &str = "706144cddcee2014edfb7c455f3af8eb1ad738d6c70588ef5bd775e48accae5e";

/// The two consensus rules for a hybrid signature — the historical one
/// (`verify`, ML-DSA half through the CPU-dispatching wrapper) and the pinned
/// one (`verify_pinned`) — give the same verdict on genuine and mutated
/// signatures, and the Falcon-1024 half (PQClean `clean`, integer-emulated
/// floating point) reproduces the recorded keys, signatures and verdicts.
#[test]
fn hybrid_rules_agree_and_falcon_reproduces_the_recorded_transcript() {
    use bloch_crypto::crypto::{self, falcon};
    let mut rng = Rng(0x5231_395f_4859_4252); // "R19_HYBR"
    let mut t = Transcript::new("bloch r19 hybrid v1");
    let (mut cases, mut accepted) = (0usize, 0usize);
    for key in 0..2usize {
        // Seeded hybrid keygen: ML-DSA through the dispatching keypair,
        // Falcon through `clean`.
        let seed = rng.seed32();
        let (pk, sk) = crypto::generate_keypair_from_seed(&seed).unwrap();
        t.absorb(&pk);
        t.absorb(&sk);
        let (_, pk_body) = crypto::split_envelope(&pk).unwrap();
        let fpk = &pk_body[PK..];

        for m in 0..3usize {
            let msg = rng.bytes([32, 0, 300][m]);
            // Seeded signing is for reproducibility of this corpus only;
            // production signing stays randomized.
            let sig = pqcrypto_internals::with_seeded_rng_scope(&rng.seed32(), || crypto::sign(&sk, &msg)).unwrap();
            t.absorb(&sig);
            assert!(crypto::verify(&pk, &msg, &sig) && crypto::verify_pinned(&pk, &msg, &sig));
            let (_, sig_body) = crypto::split_envelope(&sig).unwrap();
            let fsig = sig_body[SIG..].to_vec();
            let f0 = 4 + SIG; // envelope header + ML-DSA half
            assert!(falcon::verify(fpk, &msg, &fsig) && falcon::verify_canonical(fpk, &msg, &fsig));

            for n in 0..120usize {
                let (mut s, mut p, mut mm) = (sig.clone(), pk.clone(), msg.clone());
                match n % 12 {
                    0 => {}
                    1 => s[4 + rng.below(SIG)] ^= 1 << rng.below(8), // ML-DSA half
                    2 => s[f0] = rng.next() as u8,                     // Falcon header byte
                    3 => s[f0 + 1 + rng.below(40)] ^= 1 << rng.below(8), // Falcon nonce
                    4 => {
                        let i = f0 + 41 + rng.below(s.len() - f0 - 41); // compressed s2
                        s[i] ^= 1 << rng.below(8);
                    }
                    5 => s.push(0),                                  // one trailing zero
                    6 => s.resize(f0 + falcon::padded_signature_len(), 0), // PQClean padded form
                    7 => s.truncate(s.len() - 1),
                    8 => {
                        let extra = 1 + rng.below(8);
                        s.extend_from_slice(&rng.bytes(extra));
                    }
                    9 => {
                        let i = 4 + rng.below(p.len() - 4);
                        p[i] ^= 1 << rng.below(8);
                    }
                    10 => mm.push(1),
                    _ => {
                        let i = rng.below(4); // envelope header
                        s[i] ^= 1 << rng.below(8);
                    }
                }
                let legacy = crypto::verify(&p, &mm, &s);
                let pinned = crypto::verify_pinned(&p, &mm, &s);
                assert_eq!(legacy, pinned, "historical vs pinned hybrid rule: key {key} msg {m} case {n}");
                // Falcon half alone, when the mutated object still has one.
                let (fv, fc) = match crypto::split_envelope(&s) {
                    Some((_, body)) if body.len() > SIG && p.len() == pk.len() => {
                        let fp = &p[4 + PK..];
                        (falcon::verify(fp, &mm, &body[SIG..]), falcon::verify_canonical(fp, &mm, &body[SIG..]))
                    }
                    _ => (false, false),
                };
                assert!(!fc || fv, "canonical Falcon verdict without the plain one");
                t.absorb(&[(n % 12) as u8, u8::from(legacy), u8::from(fv), u8::from(fc)]);
                cases += 1;
                accepted += usize::from(legacy);
            }
        }
    }
    eprintln!("r19 determinism: hybrid: {cases} cases, {accepted} accepted, historical and pinned rules agree");
    assert!(accepted >= 6 && accepted < cases);
    check_golden("hybrid", &t, GOLDEN_HYBRID);
}

// ───────────────────────── SLH-DSA-SHAKE-128s ────────────────────────────

const GOLDEN_SLHDSA: &str = "c5d22746e23c0358b17ca18f035acc815ea8832153e1f73448bbaf135b7210e6";

/// SLH-DSA has one implementation (vendored pure-Rust `fips205` over the
/// `sha3` crate), so there is no second backend to compare inside one run:
/// the check is the recorded transcript (keys, deterministic signatures and
/// the verdict of every mutation), plus "every mutated signature is refused"
/// (a hash-based signature has no encoding slack). NIST's own vectors are in
/// `acvp_slhdsa.rs`.
#[test]
fn slhdsa_shake_128s_reproduces_the_recorded_transcript() {
    use bloch_crypto::crypto::slhdsa_suite::SLHDSA_SUITE_CONTEXT;
    use fips205::slh_dsa_shake_128s as p;
    use fips205::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};

    /// rand_core 0.6 RNG that must never be asked (deterministic signing).
    struct Never;
    impl rand_core::RngCore for Never {
        fn next_u32(&mut self) -> u32 { unreachable!() }
        fn next_u64(&mut self) -> u64 { unreachable!() }
        fn fill_bytes(&mut self, _: &mut [u8]) { unreachable!() }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> { unreachable!() }
    }
    impl rand_core::CryptoRng for Never {}

    let mut rng = Rng(0x5231_395f_534c_4844); // "R19_SLHD"
    let mut t = Transcript::new("bloch r19 slh-dsa-shake-128s v1");
    let (mut cases, mut accepted) = (0usize, 0usize);
    for key in 0..2usize {
        let seed = |rng: &mut Rng| <[u8; p::N]>::try_from(rng.bytes(p::N)).unwrap();
        let (pk, sk) = p::KG::keygen_with_seeds(&seed(&mut rng), &seed(&mut rng), &seed(&mut rng));
        let pk_bytes = pk.clone().into_bytes();
        t.absorb(&pk_bytes);
        t.absorb(&sk.clone().into_bytes());
        let contexts: [&[u8]; 2] = [SLHDSA_SUITE_CONTEXT, b""];
        for (ci, ctx) in contexts.iter().enumerate() {
            let msg = rng.bytes(32 + 100 * ci);
            let sig = sk.try_sign_with_rng(&mut Never, &msg, ctx, false).unwrap();
            t.absorb(&sig);
            for n in 0..500usize {
                let (mut s, mut pb, mut m, mut c) = (sig, pk_bytes, msg.clone(), ctx.to_vec());
                let genuine = n % 25 == 0;
                if !genuine {
                    match n % 5 {
                        // Randomizer R, then FORS, then the hypertree: one
                        // flipped bit anywhere in the signature.
                        0 => s[rng.below(p::N)] ^= 1 << rng.below(8),
                        1 | 2 => s[rng.below(p::SIG_LEN)] ^= 1 << rng.below(8),
                        3 => pb[rng.below(p::PK_LEN)] ^= 1 << rng.below(8),
                        _ => {
                            if rng.below(2) == 0 {
                                m.push(0)
                            } else {
                                c = contexts[1 - ci].to_vec()
                            }
                        }
                    }
                }
                let verdict = match p::PublicKey::try_from_bytes(&pb) {
                    Ok(k) => k.verify(&m, &s, &c),
                    Err(_) => false,
                };
                assert_eq!(verdict, genuine, "SLH-DSA key {key} ctx {ci} case {n}");
                t.absorb(&[u8::from(verdict)]);
                cases += 1;
                accepted += usize::from(verdict);
            }
        }
    }
    eprintln!("r19 determinism: SLH-DSA-SHAKE-128s: {cases} cases, {accepted} accepted");
    check_golden("slh-dsa-shake-128s", &t, GOLDEN_SLHDSA);
}

/// Suite 0x0003 as consensus sees it: seeded keygen is recorded, a signature
/// verifies through `verify_spend` only with the HF3 verdict set, and the
/// AND-composition refuses a damaged half.
#[test]
fn suite_0003_keygen_is_recorded_and_spend_verification_is_gated() {
    use bloch_crypto::crypto::{self, slhdsa_suite};
    let (pk, sk) = slhdsa_suite::generate_keypair_from_seed(&[0x19u8; 32]).unwrap();
    let mut t = Transcript::new("bloch r19 suite 0x0003 keygen v1");
    t.absorb(&pk);
    t.absorb(&sk);
    check_golden("suite-0x0003 keygen", &t, GOLDEN_SUITE3_KEYGEN);

    let msg = [0x42u8; 32];
    let sig = crypto::sign(&sk, &msg).unwrap();
    assert!(crypto::verify_spend(&pk, &msg, &sig, true));
    assert!(!crypto::verify_spend(&pk, &msg, &sig, false), "suite 0x0003 accepted with the HF3 verdict off");
    let mut rng = Rng(0x5231_395f_5333_0003);
    for _ in 0..40 {
        let mut s = sig.clone();
        let i = 4 + rng.below(s.len() - 4);
        s[i] ^= 1 << rng.below(8);
        assert!(!crypto::verify_spend(&pk, &msg, &s, true), "damaged suite-0x0003 signature accepted (byte {i})");
    }
}

const GOLDEN_SUITE3_KEYGEN: &str = "b594d7ab9484b5b9dd0b4bb633cd0e6f29e646cb74db0beff89b6b7fe32f4fa2";
