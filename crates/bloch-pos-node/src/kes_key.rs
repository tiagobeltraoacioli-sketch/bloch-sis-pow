// SPDX-License-Identifier: AGPL-3.0-or-later
//! The validator's forward-secure signing key (`bloch_pos_committee::kes`) on
//! disk: `<data-dir>/validator.kes`, beside `validator.key` and under the same
//! passphrase policy ([`Unlock`]).
//!
//! The file holds the public tree (depth, root, every leaf hash) in the clear
//! and, sealed, only the CURRENT leaf index and its seed. The leaf index is
//! local to the tree: on chain, leaf `i` signs global period
//! `start_period + i` (`bloch_pos_committee::kes::KesPublic::leaf_index`), and
//! the node maps one to the other from committed state. [`KesKey::evolve_to`]
//! writes the evolved state to disk (temp file, fsync, rename) **before** the
//! caller signs anything with the new leaf, then replaces it in memory. Once
//! that rename lands, no earlier seed exists anywhere this node wrote it, so
//! nothing it holds can sign an earlier period — the long-range property.
//! Operators must not keep older copies of this file: a backup of an earlier
//! state is an earlier seed.
//!
//! Rotation (HF3): the successor tree is generated in the background and
//! sealed as `validator.kes.next` ([`NEXT_FILE_NAME`]); once the chain makes
//! it the key in force, [`promote_next`] swaps it in and shreds the old file.
//!
//! ```text
//! BPOSKES2 (sealed):    magic ‖ kdf id ‖ m t p ‖ salt ‖ nonce ‖ index ‖ depth ‖ root ‖ leaves  [AAD]
//!                       ‖ len ‖ XChaCha20-Poly1305(period u64 ‖ seed 32)
//! BPOSKES1 (plaintext): magic ‖ index ‖ depth ‖ root ‖ leaves ‖ period ‖ seed   (opt-in only)
//! ```

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use bloch_pos_committee::kes::{self, KesPublic, KesSignature};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::keys::{os_random, read_keystore_file, KdfParams, Unlock, KDF_ARGON2ID};

const MAGIC_PLAIN: &[u8; 8] = b"BPOSKES1";
const MAGIC_SEALED: &[u8; 8] = b"BPOSKES2";
pub const FILE_NAME: &str = "validator.kes";
/// The rotated-in successor, written before its `KesRotate` is submitted.
pub const NEXT_FILE_NAME: &str = "validator.kes.next";
/// The replaced key during a swap; shredded right after (and at startup if
/// a crash interrupted the swap).
pub const RETIRED_FILE_NAME: &str = "validator.kes.retired";

pub struct KesKey {
    index: u32,
    public: KesPublic,
    leaves: Vec<[u8; 32]>,
    /// The leaf index (local to this tree) the key can sign with now.
    period: u64,
    seed: Zeroizing<[u8; 32]>,
    /// The sealing key derived once (Argon2id) with its salt and cost, reused
    /// by every later evolution of this file (review F-7: re-deriving 64 MiB
    /// Argon2id on every validator of a host at the same period boundary is
    /// a synchronized memory spike). The node already holds the passphrase
    /// for the process lifetime, so caching its derivative adds no exposure.
    /// Each save still uses a fresh random 24-byte XChaCha nonce.
    seal: std::cell::RefCell<Option<SealCache>>,
}

struct SealCache {
    kdf: KdfParams,
    salt: [u8; 32],
    key: Zeroizing<[u8; 32]>,
}

impl Clone for SealCache {
    fn clone(&self) -> Self {
        SealCache { kdf: self.kdf, salt: self.salt, key: Zeroizing::new(*self.key) }
    }
}

fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn leaf_keypair(seed: &[u8; 32]) -> io::Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let leaf_seed = Zeroizing::new(kes::leaf_seed(seed));
    let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&leaf_seed[..])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("KES leaf keygen: {e:?}")))?;
    Ok((pk, Zeroizing::new(sk)))
}

impl KesKey {
    /// Derive every leaf key of a fresh tree for `index` and keep only their
    /// hashes. `progress(done)` is called after each leaf: depth 10 is 1,024
    /// hybrid keypairs (under a minute); depth 12 a few minutes.
    pub fn generate(index: u32, depth: u8, mut progress: impl FnMut(u64)) -> io::Result<KesKey> {
        if !(kes::MIN_DEPTH..=kes::MAX_DEPTH).contains(&depth) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "KES depth out of range"));
        }
        let mut seed0 = Zeroizing::new([0u8; 32]);
        os_random(&mut seed0[..])?;
        let mut leaves = Vec::with_capacity(1usize << depth);
        let mut s = Zeroizing::new(*seed0);
        for i in 0..(1u64 << depth) {
            let (pk, _sk) = leaf_keypair(&s)?;
            leaves.push(kes::leaf_hash(&pk));
            *s = kes::step(&s);
            progress(i + 1);
        }
        let public = KesPublic::new(depth, kes::merkle_root(&leaves), 0);
        Ok(KesKey { index, public, leaves, period: 0, seed: seed0, seal: Default::default() })
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    /// The tree (depth and root). Its `start_period` is 0: where the tree
    /// starts is the chain's record, not the file's
    /// (`CommittedState::kes_public_at`).
    pub fn public(&self) -> KesPublic {
        self.public
    }

    /// The leaf index (local to the tree) this key can sign with now.
    pub fn period(&self) -> u64 {
        self.period
    }

    pub fn path(dir: &Path) -> PathBuf {
        dir.join(FILE_NAME)
    }

    pub fn next_path(dir: &Path) -> PathBuf {
        dir.join(NEXT_FILE_NAME)
    }

    /// Move to leaf `period`, erasing every earlier seed — on disk first,
    /// then in memory. Refuses to go back and refuses past the last leaf.
    pub fn evolve_to(&mut self, dir: &Path, unlock: &Unlock, period: u64) -> io::Result<()> {
        if period < self.period {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("KES key is at period {}; period {period} is erased", self.period),
            ));
        }
        if period >= self.public.periods() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "KES key exhausted: generate and register a new one"));
        }
        if period == self.period {
            return Ok(());
        }
        let mut seed = Zeroizing::new(*self.seed);
        for _ in self.period..period {
            *seed = kes::step(&seed);
        }
        let next = KesKey {
            index: self.index,
            public: self.public,
            leaves: self.leaves.clone(),
            period,
            seed,
            seal: std::cell::RefCell::new(self.seal.borrow().clone()),
        };
        next.save_named(dir, unlock, FILE_NAME)?;
        *self = next;
        Ok(())
    }

    /// Sign `message` — the bound `kes::leaf_message`, never a bare consensus
    /// root — with the current period's leaf (encoded `kes::KesSignature`).
    /// The caller evolves first.
    pub fn sign(&self, message: &[u8; 32]) -> io::Result<Vec<u8>> {
        let (leaf_pk, sk) = leaf_keypair(&self.seed)?;
        // Canonical, suite-bound v2 form (review F-1), matching
        // `HybridVerifier::verify_kes_leaf`.
        let sig = bloch_crypto::crypto::sign_bound(&sk, message)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("KES leaf signing: {e:?}")))?;
        let index = u32::try_from(self.period).map_err(|_| bad("KES period exceeds u32"))?;
        Ok(KesSignature { index, leaf_pk, sig, path: kes::auth_path(&self.leaves, self.period as usize) }.encode())
    }

    fn public_header(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.index.to_le_bytes());
        out.push(self.public.depth);
        out.extend_from_slice(&self.public.root);
        for leaf in &self.leaves {
            out.extend_from_slice(leaf);
        }
    }

    /// Write `dir/validator.kes` atomically (0600 temp file, fsync, rename,
    /// fsync of the directory), sealed unless plaintext was explicitly allowed.
    pub fn save(&self, dir: &Path, unlock: &Unlock) -> io::Result<()> {
        self.save_named(dir, unlock, FILE_NAME)
    }

    /// Write `dir/validator.kes.next` (the rotation successor) the same way.
    pub fn save_next(&self, dir: &Path, unlock: &Unlock) -> io::Result<()> {
        self.save_named(dir, unlock, NEXT_FILE_NAME)
    }

    fn save_named(&self, dir: &Path, unlock: &Unlock, name: &str) -> io::Result<()> {
        let mut out = Zeroizing::new(Vec::new());
        match unlock {
            Unlock::Passphrase { pass, kdf, .. } => {
                let cached = self.seal.borrow().as_ref().filter(|c| c.kdf == *kdf).cloned();
                let cache = match cached {
                    Some(cache) => cache,
                    None => {
                        let mut salt = [0u8; 32];
                        os_random(&mut salt)?;
                        let key = kdf.derive(pass, &salt)?;
                        let cache = SealCache { kdf: *kdf, salt, key };
                        *self.seal.borrow_mut() = Some(cache.clone());
                        cache
                    }
                };
                let salt = cache.salt;
                let mut nonce = [0u8; 24];
                os_random(&mut nonce)?;
                let mut header = Vec::new();
                header.extend_from_slice(MAGIC_SEALED);
                header.push(KDF_ARGON2ID);
                header.extend_from_slice(&kdf.m_cost.to_le_bytes());
                header.extend_from_slice(&kdf.t_cost.to_le_bytes());
                header.extend_from_slice(&kdf.p_cost.to_le_bytes());
                header.extend_from_slice(&salt);
                header.extend_from_slice(&nonce);
                self.public_header(&mut header);
                let mut plain = Zeroizing::new(Vec::with_capacity(40));
                plain.extend_from_slice(&self.period.to_le_bytes());
                plain.extend_from_slice(&self.seed[..]);
                let cipher = XChaCha20Poly1305::new_from_slice(cache.key.as_ref())
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "AEAD key length"))?;
                let sealed = cipher
                    .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: &header })
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "KES key sealing failed"))?;
                out.extend_from_slice(&header);
                crate::codec::put_bytes(&mut out, &sealed);
            }
            Unlock::PlaintextOptIn => {
                out.extend_from_slice(MAGIC_PLAIN);
                self.public_header(&mut out);
                out.extend_from_slice(&self.period.to_le_bytes());
                out.extend_from_slice(&self.seed[..]);
            }
        }
        fs::create_dir_all(dir)?;
        let path = dir.join(name);
        let tmp = dir.join(format!("{name}.tmp"));
        {
            use std::io::Write;
            #[cfg(unix)]
            let mut f = {
                use std::os::unix::fs::OpenOptionsExt;
                fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?
            };
            #[cfg(not(unix))]
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&out)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        fs::File::open(dir)?.sync_all()?;
        Ok(())
    }

    /// `Ok(None)` iff `dir/validator.kes` does not exist.
    pub fn load_optional(dir: &Path, unlock: &Unlock) -> io::Result<Option<KesKey>> {
        Self::load_path(&Self::path(dir), unlock)
    }

    /// `Ok(None)` iff `dir/validator.kes.next` does not exist.
    pub fn load_next(dir: &Path, unlock: &Unlock) -> io::Result<Option<KesKey>> {
        Self::load_path(&Self::next_path(dir), unlock)
    }

    fn load_path(path: &Path, unlock: &Unlock) -> io::Result<Option<KesKey>> {
        let bytes = match read_keystore_file(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        Self::decode(&bytes, unlock).map(Some)
    }

    fn decode(bytes: &[u8], unlock: &Unlock) -> io::Result<KesKey> {
        let mut r = crate::codec::Reader::new(bytes);
        let magic = r.take(8).map_err(|_| bad("truncated KES key"))?;
        let sealed = match magic {
            m if m == MAGIC_SEALED => true,
            m if m == MAGIC_PLAIN => false,
            _ => return Err(bad("not a KES key file")),
        };
        let mut kdf_salt_nonce = None;
        if sealed {
            if r.u8().map_err(|_| bad("truncated KES key"))? != KDF_ARGON2ID {
                return Err(bad("KES key uses an unknown KDF"));
            }
            let kdf = KdfParams {
                m_cost: r.u32().map_err(|_| bad("truncated KES key"))?,
                t_cost: r.u32().map_err(|_| bad("truncated KES key"))?,
                p_cost: r.u32().map_err(|_| bad("truncated KES key"))?,
            };
            let salt = r.h32().map_err(|_| bad("truncated KES key"))?;
            let nonce: [u8; 24] =
                r.take(24).map_err(|_| bad("truncated KES key"))?.try_into().map_err(|_| bad("truncated KES key"))?;
            kdf_salt_nonce = Some((kdf, salt, nonce));
        } else if !matches!(unlock, Unlock::PlaintextOptIn) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "validator.kes is PLAINTEXT; seal it or allow plaintext keystores explicitly",
            ));
        }
        let index = r.u32().map_err(|_| bad("truncated KES key"))?;
        let depth = r.u8().map_err(|_| bad("truncated KES key"))?;
        if !(kes::MIN_DEPTH..=kes::MAX_DEPTH).contains(&depth) {
            return Err(bad("KES depth out of range"));
        }
        let root = r.h32().map_err(|_| bad("truncated KES key"))?;
        let mut leaves = Vec::with_capacity(1usize << depth);
        for _ in 0..(1u64 << depth) {
            leaves.push(r.h32().map_err(|_| bad("truncated KES key"))?);
        }
        if kes::merkle_root(&leaves) != root {
            return Err(bad("KES leaves do not match the root"));
        }
        let public = KesPublic::new(depth, root, 0);
        let mut seal_cache = None;
        let (period, seed) = match kdf_salt_nonce {
            None => {
                let period = r.u64().map_err(|_| bad("truncated KES key"))?;
                let seed = Zeroizing::new(r.h32().map_err(|_| bad("truncated KES key"))?);
                r.finish().map_err(|_| bad("trailing bytes in KES key"))?;
                (period, seed)
            }
            Some((kdf, salt, nonce)) => {
                let Unlock::Passphrase { pass, kdf: write_kdf, .. } = unlock else {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "validator.kes is sealed and no passphrase is configured"));
                };
                // The node rewrites this file with its own write cost at every
                // evolution, so the header must carry exactly that cost.
                // Refused before derivation, like validator.key.
                if kdf != *write_kdf {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "validator.kes KDF header does not match this node's keystore profile; refusing before derivation",
                    ));
                }
                let header_len = bytes.len() - r.remaining();
                let sealed = r.bytes().map_err(|_| bad("truncated KES key"))?;
                r.finish().map_err(|_| bad("trailing bytes in KES key"))?;
                let key = kdf.derive(pass, &salt)?;
                let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "AEAD key length"))?;
                seal_cache = Some(SealCache { kdf, salt, key: Zeroizing::new(*key) });
                let plain = Zeroizing::new(
                    cipher
                        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &sealed, aad: &bytes[..header_len] })
                        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "validator.kes: wrong passphrase or tampered file"))?,
                );
                if plain.len() != 40 {
                    return Err(bad("KES secret state has the wrong length"));
                }
                let period = u64::from_le_bytes(plain[..8].try_into().map_err(|_| bad("KES state"))?);
                let mut seed = Zeroizing::new([0u8; 32]);
                seed.copy_from_slice(&plain[8..]);
                (period, seed)
            }
        };
        if period >= public.periods() {
            return Err(bad("KES period is beyond the tree"));
        }
        Ok(KesKey { index, public, leaves, period, seed, seal: std::cell::RefCell::new(seal_cache) })
    }
}

/// Overwrite `path` with zeros, fsync, and remove it. Best effort against
/// recovery from the file system; a copy-on-write or journaled medium may
/// still hold old blocks, which is why operators keep KES data dirs out of
/// snapshots (docs/KES-MAINNET-READINESS.md §6).
pub fn shred(path: &Path) -> io::Result<()> {
    use std::io::Write;
    let len = match fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    {
        let mut f = fs::OpenOptions::new().write(true).open(path)?;
        f.write_all(&vec![0u8; len as usize])?;
        f.sync_all()?;
    }
    fs::remove_file(path)?;
    if let Some(dir) = path.parent() {
        fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Make the rotation successor the key: `validator.kes` →
/// `validator.kes.retired`, `validator.kes.next` → `validator.kes`, then
/// shred the retired file. Each rename is atomic, so a crash leaves either
/// the old key in place with the successor beside it, or the successor in
/// place with a retired file that [`finish_interrupted_rotation`] shreds.
pub fn promote_next(dir: &Path) -> io::Result<()> {
    let current = dir.join(FILE_NAME);
    let next = dir.join(NEXT_FILE_NAME);
    let retired = dir.join(RETIRED_FILE_NAME);
    if !next.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no validator.kes.next to promote"));
    }
    if current.exists() {
        fs::rename(&current, &retired)?;
    }
    fs::rename(&next, &current)?;
    fs::File::open(dir)?.sync_all()?;
    shred(&retired)
}

/// Startup: a swap interrupted after its renames leaves
/// `validator.kes.retired`; shred it. A swap interrupted between the renames
/// leaves `validator.kes.next` and `validator.kes.retired` but no
/// `validator.kes`: finish it.
pub fn finish_interrupted_rotation(dir: &Path) -> io::Result<()> {
    let current = dir.join(FILE_NAME);
    let next = dir.join(NEXT_FILE_NAME);
    let retired = dir.join(RETIRED_FILE_NAME);
    if !current.exists() && next.exists() && retired.exists() {
        fs::rename(&next, &current)?;
        fs::File::open(dir)?.sync_all()?;
    }
    shred(&retired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::HybridVerifier;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bloch-kes-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn quick() -> Unlock {
        Unlock::passphrase_with("kes-test-passphrase-2026", KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 })
    }

    #[test]
    fn real_hybrid_leaves_sign_only_their_period_and_evolution_erases_the_past() {
        let dir = tmp("evolve");
        let unlock = quick();
        let mut key = KesKey::generate(4, 2, |_| {}).unwrap();
        key.save(&dir, &unlock).unwrap();
        let public = key.public();
        let root = [7u8; 32];
        let verifier = HybridVerifier::new();

        let sig0 = key.sign(&root).unwrap();
        assert!(kes::verify(&verifier, &public, 0, &root, &sig0));
        assert!(!kes::verify(&verifier, &public, 1, &root, &sig0));

        key.evolve_to(&dir, &unlock, 2).unwrap();
        let sig2 = key.sign(&root).unwrap();
        assert!(kes::verify(&verifier, &public, 2, &root, &sig2));
        assert!(key.evolve_to(&dir, &unlock, 1).is_err(), "cannot go back");
        assert!(key.evolve_to(&dir, &unlock, 4).is_err(), "exhausted");

        // The file on disk already holds only period 2: a reload cannot sign period 0 or 1.
        let reloaded = KesKey::load_optional(&dir, &unlock).unwrap().unwrap();
        assert_eq!(reloaded.period(), 2);
        assert_eq!(reloaded.public(), public);
        let again = reloaded.sign(&root).unwrap();
        assert!(kes::verify(&verifier, &public, 2, &root, &again));
        assert!(!kes::verify(&verifier, &public, 0, &root, &again));
        assert!(fs::read_dir(&dir).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_successor_is_promoted_atomically_and_the_old_key_shredded() {
        let dir = tmp("promote");
        let unlock = quick();
        let old = KesKey::generate(4, 1, |_| {}).unwrap();
        old.save(&dir, &unlock).unwrap();
        let next = KesKey::generate(4, 2, |_| {}).unwrap();
        next.save_next(&dir, &unlock).unwrap();
        assert_eq!(KesKey::load_next(&dir, &unlock).unwrap().unwrap().public(), next.public());
        promote_next(&dir).unwrap();
        assert_eq!(KesKey::load_optional(&dir, &unlock).unwrap().unwrap().public(), next.public());
        assert!(KesKey::load_next(&dir, &unlock).unwrap().is_none());
        assert!(!dir.join(RETIRED_FILE_NAME).exists(), "the old key is gone");
        assert!(promote_next(&dir).is_err(), "nothing left to promote");

        // A crash between the two renames: no validator.kes, a retired one
        // and the successor. Startup finishes the swap.
        let crashed = tmp("promote-crash");
        let a = KesKey::generate(4, 1, |_| {}).unwrap();
        let b = KesKey::generate(4, 1, |_| {}).unwrap();
        a.save(&crashed, &unlock).unwrap();
        fs::rename(crashed.join(FILE_NAME), crashed.join(RETIRED_FILE_NAME)).unwrap();
        b.save_next(&crashed, &unlock).unwrap();
        finish_interrupted_rotation(&crashed).unwrap();
        assert_eq!(KesKey::load_optional(&crashed, &unlock).unwrap().unwrap().public(), b.public());
        assert!(!crashed.join(RETIRED_FILE_NAME).exists());
        assert!(!crashed.join(NEXT_FILE_NAME).exists());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&crashed);
    }

    #[test]
    fn wrong_passphrase_tampering_and_plaintext_without_opt_in_are_refused() {
        let dir = tmp("seal");
        let key = KesKey::generate(1, 1, |_| {}).unwrap();
        key.save(&dir, &quick()).unwrap();
        let other = Unlock::passphrase_with("another-passphrase-2026", KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 });
        assert!(KesKey::load_optional(&dir, &other).is_err());
        let mut bytes = fs::read(KesKey::path(&dir)).unwrap();
        let n = bytes.len();
        bytes[n - 40] ^= 1;
        fs::write(KesKey::path(&dir), &bytes).unwrap();
        assert!(KesKey::load_optional(&dir, &quick()).is_err());

        let plain = tmp("plain");
        key.save(&plain, &Unlock::PlaintextOptIn).unwrap();
        assert!(KesKey::load_optional(&plain, &quick()).is_err(), "plaintext needs the opt-in");
        assert_eq!(KesKey::load_optional(&plain, &Unlock::PlaintextOptIn).unwrap().unwrap().public(), key.public());
        assert!(KesKey::load_optional(&tmp("absent"), &quick()).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&plain);
    }
}
