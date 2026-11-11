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
//! caller signs anything with the new leaf, then replaces it in memory.
//!
//! What "erased" means (review CR-7). Once the rename lands the file NAME
//! holds only the current seed, and the node then overwrites the replaced
//! file's contents in place with zeros, through a descriptor it opened before
//! the rename, and fsyncs ([`overwrite_replaced`]). On a file system that
//! writes data in place (ext4 and XFS in their default modes) on a medium
//! that does not remap writes, the earlier sealed seed is then gone from the
//! blocks this node wrote it to, so the disk alone, or the disk plus the
//! passphrase, no longer yields a seed of a past period. That is the
//! long-range property, and it is best effort below the file system:
//!
//! - a copy-on-write or log-structured file system (btrfs, ZFS, APFS, F2FS),
//!   a data-journaling mount (`data=journal`), an LVM/ZFS/cloud snapshot, or
//!   an SSD's flash translation layer can keep the old blocks until they are
//!   garbage-collected or trimmed; the overwrite cannot reach them;
//! - a crash between the rename and the overwrite's fsync leaves the old
//!   blocks released but not overwritten;
//! - a key file the operator made read-only (0400) is still replaced, but
//!   its old contents cannot be overwritten by this process (review V1-5;
//!   the node says so); keep the mode the node wrote, 0600;
//! - a backup of an earlier state is an earlier seed: operators must not
//!   keep older copies of this file, and keep KES data dirs out of snapshots.
//!
//! The sealing key is not ratcheted per period, on purpose. After a restart
//! the node has only the passphrase and the file, so whatever opens the
//! current file must be derivable from the two; any per-period key would
//! have to be stored wrapped under the passphrase-derived key beside the
//! ciphertext, and someone holding the passphrase and an old ciphertext
//! would hold the old wrapped key too. Against that attacker a ratchet
//! reduces to erasing the old file, which is what the overwrite does;
//! without the passphrase the sealing already protects every generation.
//! With `--allow-plaintext-keystore` there is no sealing and the overwrite
//! is the only protection of past seeds.
//!
//! Rotation (HF3): the successor tree is generated in the background and
//! sealed as `validator.kes.next` ([`NEXT_FILE_NAME`]); once the chain makes
//! it the key in force, [`promote_next`] swaps it in and the replaced key
//! becomes `validator.kes.retired` ([`RETIRED_FILE_NAME`]).
//!
//! The replaced key is NOT destroyed at the swap (review PER-1). The swap
//! follows the head state, which is not final: if the block that carried the
//! `KesRotate` is reorganized out, the chain names the old tree as the key
//! in force again, and a node that had destroyed it could not sign, could
//! not rotate again (a rotation is signed by the old tree's current leaf)
//! and could not be rescued by the static key until the old tree expired.
//! So the replaced key is kept until this node's finalized checkpoint
//! reaches the successor's first epoch (the including block is then an
//! ancestor of a finalized block, and the node does not reorganize below
//! its finality), or until the old tree has expired, and is shredded then.
//! If the handover is reorganized out first, [`demote_promoted`] puts it
//! back.
//!
//! What forward security means while it is kept: the retired file is evolved
//! exactly like the key in force ([`KesKey::evolve_retired_to`]: at the swap
//! to the old tree's leaf for the handover period, then once per period), so
//! it never holds a seed for a period before the handover and, on a node
//! that is running and at the head, none for a period before the current
//! one. Every seed the old key had erased stays erased. What remains on disk
//! until finality is the old tree's seed for the current and later periods:
//! the seed this node would hold anyway had the rotation not been included.
//! A signature made with it is valid only on a chain that does not contain
//! the rotation; where the rotation stands, consensus judges those periods
//! by the successor. The cost is that a host compromised between the swap
//! and its finality (normally two to three epochs) yields that seed as well
//! as the successor's; before this change it yielded the successor's alone.
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

use crate::keys::{
    abort_on_signer_fault, os_random, read_keystore_file, sign_verified_released, KdfParams, SignerFault, Unlock,
    KDF_ARGON2ID,
};

const MAGIC_PLAIN: &[u8; 8] = b"BPOSKES1";
const MAGIC_SEALED: &[u8; 8] = b"BPOSKES2";
pub const FILE_NAME: &str = "validator.kes";
/// The rotated-in successor, written before its `KesRotate` is submitted.
pub const NEXT_FILE_NAME: &str = "validator.kes.next";
/// The replaced key after a swap, kept until the handover is final (see the
/// module doc, "Rotation").
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
    /// The current leaf's keypair, derived once per leaf rather than on every
    /// signature (a Falcon-1024 keygen per duty was measurable on the duty
    /// path; rehearsal kes-1). Dropped (zeroized) when the key evolves.
    leaf: std::cell::RefCell<Option<(u64, Vec<u8>, Zeroizing<Vec<u8>>)>>,
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
        Ok(KesKey { index, public, leaves, period: 0, seed: seed0, seal: Default::default(), leaf: Default::default() })
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

    /// Move to leaf `period`, erasing every earlier seed — on disk first
    /// (new state durable under the file name, then the replaced file's
    /// contents overwritten in place; see the module doc for what that
    /// guarantees), then in memory. Refuses to go back and refuses past the
    /// last leaf.
    pub fn evolve_to(&mut self, dir: &Path, unlock: &Unlock, period: u64) -> io::Result<()> {
        self.evolve_named(dir, unlock, period, FILE_NAME)
    }

    /// [`Self::evolve_to`] for the replaced key kept as
    /// `validator.kes.retired`: same erasure, in its own file.
    pub fn evolve_retired_to(&mut self, dir: &Path, unlock: &Unlock, period: u64) -> io::Result<()> {
        self.evolve_named(dir, unlock, period, RETIRED_FILE_NAME)
    }

    fn evolve_named(&mut self, dir: &Path, unlock: &Unlock, period: u64, name: &str) -> io::Result<()> {
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
            leaf: Default::default(),
        };
        next.save_named(dir, unlock, name)?;
        *self = next;
        Ok(())
    }

    /// Sign `message` — the bound `kes::leaf_message`, never a bare consensus
    /// root — with the current period's leaf (encoded `kes::KesSignature`).
    /// The caller evolves first.
    ///
    /// Released through the same hardening as the static key
    /// (`keys::sign_verified_released`, p9e finding 2): the leaf signature is
    /// verified under the leaf public key, with the verifier the network
    /// applies (`HybridVerifier::verify_kes_leaf`), before it leaves the
    /// process; a signature that does not verify is withheld and signing is
    /// retried with fresh randomness; a signer that keeps failing aborts the
    /// process; and the latency floor applies. The leaf key is also checked
    /// against the tree before the secret is exercised.
    pub fn sign(&self, message: &[u8; 32]) -> io::Result<Vec<u8>> {
        match self.sign_with(message, bloch_crypto::crypto::sign_bound)? {
            Ok(signature) => Ok(signature),
            Err(SignerFault) => abort_on_signer_fault(self.index, "the KES leaf public key"),
        }
    }

    /// [`Self::sign`] with an explicit leaf signer. The outer `Err` is a
    /// condition under which the key was never exercised; the inner one is a
    /// signer whose every attempt failed verification (nothing released).
    fn sign_with(
        &self,
        message: &[u8; 32],
        sign_fn: impl Fn(&[u8], &[u8]) -> Result<Vec<u8>, bloch_crypto::crypto::CryptoError>,
    ) -> io::Result<Result<Vec<u8>, SignerFault>> {
        let cached = self.leaf.borrow().as_ref().filter(|(leaf, _, _)| *leaf == self.period).map(|(_, pk, sk)| (pk.clone(), Zeroizing::new(sk.to_vec())));
        let (leaf_pk, sk) = match cached {
            Some(pair) => pair,
            None => {
                let (pk, sk) = leaf_keypair(&self.seed)?;
                *self.leaf.borrow_mut() = Some((self.period, pk.clone(), Zeroizing::new(sk.to_vec())));
                (pk, sk)
            }
        };
        let index = u32::try_from(self.period).map_err(|_| bad("KES period exceeds u32"))?;
        // The Merkle half of `kes::verify`: the leaf key must be the tree's
        // leaf for this period. `leaves` hash to the registered root (checked
        // at load) and the authentication path is computed from them, so this
        // is the same condition. A seed that does not belong to the tree is
        // not a transient fault: refuse without signing, do not retry.
        if self.leaves.get(self.period as usize) != Some(&kes::leaf_hash(&leaf_pk)) {
            return Err(bad("KES leaf key does not match the tree at this period; nothing signed"));
        }
        // Canonical, suite-bound v2 form (review F-1), matching
        // `HybridVerifier::verify_kes_leaf`.
        let released = sign_verified_released(self.index, &sk, &leaf_pk, message, sign_fn, |pk, m, s| {
            bloch_crypto::crypto::verify_bound(pk, m, s)
        });
        let sig = match released {
            Ok(sig) => sig,
            Err(fault) => return Ok(Err(fault)),
        };
        Ok(Ok(KesSignature { index, leaf_pk, sig, path: kes::auth_path(&self.leaves, self.period as usize) }.encode()))
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
        // The file this write replaces, if any, held open across the rename
        // so its contents can be overwritten afterwards (review CR-7): a
        // rename only drops the name, and the old inode's blocks would be
        // released with an earlier seed still in them.
        // Unix only: elsewhere an open handle can make the rename itself
        // fail, and the atomic replace matters more than the overwrite.
        //
        // The node writes this file 0600. An operator who made it read-only
        // (0400) must not thereby stop the key from evolving (review V1-5):
        // the rename needs only the directory, and staying on an old period
        // is worse than one inode this process cannot overwrite. That case
        // is reported and the rename goes ahead.
        #[cfg(unix)]
        let replaced = match fs::OpenOptions::new().write(true).open(&path) {
            Ok(f) => Some(f),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "KES WARNING: {} is not writable by this node ({e}); it is replaced, but its old \
                     contents (an earlier seed) could NOT be overwritten in place. Keep the file mode 0600.",
                    path.display()
                );
                None
            }
            Err(e) => return Err(e),
        };
        #[cfg(not(unix))]
        let replaced: Option<fs::File> = None;
        fs::rename(&tmp, &path)?;
        fs::File::open(dir)?.sync_all()?;
        // Only now: the new state is durable under the name, so a crash
        // during the overwrite cannot leave the node without a key.
        if let Some(old) = replaced {
            overwrite_replaced(old)?;
        }
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

    /// `Ok(None)` iff `dir/validator.kes.retired` does not exist.
    pub fn load_retired(dir: &Path, unlock: &Unlock) -> io::Result<Option<KesKey>> {
        Self::load_path(&dir.join(RETIRED_FILE_NAME), unlock)
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
        Ok(KesKey { index, public, leaves, period, seed, seal: std::cell::RefCell::new(seal_cache), leaf: Default::default() })
    }
}

/// Overwrite, in place, the contents of a file whose name has just been
/// renamed over, through the descriptor opened before the rename, and fsync.
/// Best effort against recovery from the file system, with the same limits
/// as [`shred`]: a copy-on-write, log-structured or data-journaling file
/// system, a snapshot, or a remapping medium (SSD) may still hold the old
/// blocks, and a crash before the fsync leaves them released but intact.
fn overwrite_replaced(mut old: fs::File) -> io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let mut left = old.metadata()?.len();
    old.seek(SeekFrom::Start(0))?;
    let zeros = [0u8; 4096];
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        old.write_all(&zeros[..n])?;
        left -= n as u64;
    }
    old.sync_all()
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
/// `validator.kes.retired`, `validator.kes.next` → `validator.kes`. The
/// retired file is kept (review PER-1; see the module doc) until
/// [`shred_retired`]. Each rename is atomic, so a crash leaves either the
/// old key in place with the successor beside it, or the successor in place
/// with the retired file, or (between the renames) no `validator.kes`, which
/// [`finish_interrupted_rotation`] completes. A retired file left by an
/// earlier rotation is shredded first: one replaced key is kept, not a
/// history.
pub fn promote_next(dir: &Path) -> io::Result<()> {
    let current = dir.join(FILE_NAME);
    let next = dir.join(NEXT_FILE_NAME);
    let retired = dir.join(RETIRED_FILE_NAME);
    if !next.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no validator.kes.next to promote"));
    }
    if current.exists() {
        shred(&retired)?;
        fs::rename(&current, &retired)?;
    }
    fs::rename(&next, &current)?;
    fs::File::open(dir)?.sync_all()
}

/// Undo [`promote_next`] after the handover was reorganized out:
/// `validator.kes` → `validator.kes.next`, `validator.kes.retired` →
/// `validator.kes`. A crash between the renames leaves the same files as a
/// crash inside `promote_next`; startup completes that to the promoted
/// layout and the node demotes again when the chain still says so.
pub fn demote_promoted(dir: &Path) -> io::Result<()> {
    let current = dir.join(FILE_NAME);
    let next = dir.join(NEXT_FILE_NAME);
    let retired = dir.join(RETIRED_FILE_NAME);
    if !retired.exists() || !current.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no retired KES key to put back"));
    }
    if next.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "validator.kes.next exists; refusing to overwrite a sealed successor",
        ));
    }
    fs::rename(&current, &next)?;
    fs::rename(&retired, &current)?;
    fs::File::open(dir)?.sync_all()
}

/// Destroy the replaced key once its handover is final (or it has expired).
pub fn shred_retired(dir: &Path) -> io::Result<()> {
    shred(&dir.join(RETIRED_FILE_NAME))
}

/// Startup: a swap interrupted between its renames leaves
/// `validator.kes.next` and `validator.kes.retired` but no `validator.kes`:
/// finish it. A `validator.kes.retired` beside `validator.kes` is the
/// replaced key awaiting finality and is left for the node to load.
pub fn finish_interrupted_rotation(dir: &Path) -> io::Result<()> {
    let current = dir.join(FILE_NAME);
    let next = dir.join(NEXT_FILE_NAME);
    let retired = dir.join(RETIRED_FILE_NAME);
    if !current.exists() && next.exists() && retired.exists() {
        fs::rename(&next, &current)?;
        fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
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

    /// HF2 x HF3 integration (review F-1): a KES leaf signature must verify
    /// under EVERY consensus signature policy a block or gossip wrapper can
    /// apply — before and after `SIG_CANONICAL_ACTIVATION_EPOCH` — because KES
    /// leaves are signed in the bound (v2) form from the first signature and
    /// every policy wrapper forwards `verify_kes_leaf` unchanged. If the
    /// signer and the leaf verifier ever drift to mismatched forms (a v1 leaf
    /// signer, or a wrapper that judges leaves under its own policy), every
    /// KES validator would lose the ability to sign in one epoch; this test
    /// fails first.
    #[test]
    fn kes_leaves_verify_under_every_consensus_signature_policy() {
        use bloch_pos_committee::attestation::SignatureVerifier;
        use bloch_pos_committee::{PolicyVerifier, SignaturePolicy};
        let key = KesKey::generate(4, 2, |_| {}).unwrap();
        let public = key.public();
        let root = [0x5Au8; 32];
        let sig = key.sign(&root).unwrap();
        let inner = HybridVerifier::new();
        assert!(kes::verify(&inner, &public, 0, &root, &sig));
        for policy in [
            SignaturePolicy::Compatible,
            SignaturePolicy::CompatiblePinned,
            SignaturePolicy::CanonicalUnbound,
            SignaturePolicy::Bound,
        ] {
            let wrapped = PolicyVerifier::new(&inner, policy);
            assert!(kes::verify(&wrapped, &public, 0, &root, &sig), "KES leaf refused under {policy:?}");
            // Both gates armed at early test epochs: the consensus policy of
            // any epoch accepts the leaf.
            for epoch in [0u64, 1, 6_460, 6_550, 6_562] {
                let consensus = PolicyVerifier::consensus(&inner, epoch);
                assert!(kes::verify(&consensus, &public, 0, &root, &sig), "epoch {epoch}");
            }
        }
        // The leaf verifier is the bound form: a v1 leaf signature over the
        // same message is refused, so a signer regression to v1 is caught.
        let decoded = bloch_pos_committee::kes::KesSignature::decode(&sig).expect("decodes");
        let (_, leaf_sk) = leaf_keypair(&key.seed).unwrap();
        let v1 = bloch_crypto::crypto::sign(&leaf_sk, &root).unwrap();
        assert!(!inner.verify_kes_leaf(&decoded.leaf_pk, &root, &v1), "a v1 leaf must not verify");
        assert!(inner.verify_kes_leaf(&decoded.leaf_pk, &root, &decoded.sig));
    }

    /// CR-6: a KES duty signature goes through verify-before-release. A leaf
    /// signer whose output does not verify under the leaf key releases
    /// nothing (production then aborts), and a seed that is not the tree's is
    /// refused before the key is exercised.
    #[test]
    fn a_faulted_leaf_signature_is_withheld_and_a_foreign_seed_is_never_exercised() {
        let key = KesKey::generate(4, 1, |_| {}).unwrap();
        let root = [0x33u8; 32];
        let attempts = std::cell::Cell::new(0u32);
        let faulted = |sk: &[u8], m: &[u8]| {
            attempts.set(attempts.get() + 1);
            let mut sig = bloch_crypto::crypto::sign_bound(sk, m)?;
            let last = sig.len() - 1;
            sig[last] ^= 1;
            Ok(sig)
        };
        assert!(key.sign_with(&root, faulted).unwrap().is_err(), "a faulted leaf signature must be withheld");
        assert_eq!(attempts.get(), crate::keys::SIGN_VERIFY_ATTEMPTS);
        // A signer in the wrong form (v1) is withheld by the same check.
        assert!(key.sign_with(&root, bloch_crypto::crypto::sign).unwrap().is_err());
        // The honest signer is released and is what the network accepts.
        let sig = key.sign(&root).unwrap();
        assert!(kes::verify(&HybridVerifier::new(), &key.public(), 0, &root, &sig));

        let mut foreign = KesKey::generate(4, 1, |_| {}).unwrap();
        foreign.leaves = key.leaves.clone();
        foreign.public = key.public;
        let signed = std::cell::Cell::new(false);
        let out = foreign.sign_with(&root, |sk, m| {
            signed.set(true);
            bloch_crypto::crypto::sign_bound(sk, m)
        });
        assert!(out.is_err(), "a seed outside the tree must be refused");
        assert!(!signed.get(), "and the leaf key must not have been exercised");
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

    /// CR-7: evolution overwrites the replaced file's contents, not only its
    /// name. A second hard link stands in for "the old inode's blocks": after
    /// the evolution it must hold no byte of the earlier sealed state, for
    /// sealed and plaintext keystores alike, and the key must still reload.
    #[cfg(unix)]
    #[test]
    fn evolution_overwrites_the_replaced_file_in_place() {
        for (name, unlock) in [("overwrite-sealed", quick()), ("overwrite-plain", Unlock::PlaintextOptIn)] {
            let dir = tmp(name);
            let mut key = KesKey::generate(4, 2, |_| {}).unwrap();
            key.save(&dir, &unlock).unwrap();
            let before = fs::read(KesKey::path(&dir)).unwrap();
            let old_inode = dir.join("old-inode");
            fs::hard_link(KesKey::path(&dir), &old_inode).unwrap();

            key.evolve_to(&dir, &unlock, 1).unwrap();

            let after = fs::read(&old_inode).unwrap();
            assert_eq!(after.len(), before.len(), "overwritten in place, not truncated");
            assert!(after.iter().all(|b| *b == 0), "the earlier state must be overwritten");
            // The live file is a different inode holding only period 1.
            let reloaded = KesKey::load_optional(&dir, &unlock).unwrap().unwrap();
            assert_eq!(reloaded.period(), 1);
            assert_eq!(*reloaded.seed, kes::step(&KesKey::decode(&before, &unlock).unwrap().seed));
            // A second evolution overwrites the period-1 file the same way.
            let mid = dir.join("mid-inode");
            fs::hard_link(KesKey::path(&dir), &mid).unwrap();
            key.evolve_to(&dir, &unlock, 3).unwrap();
            assert!(fs::read(&mid).unwrap().iter().all(|b| *b == 0));
            assert_eq!(KesKey::load_optional(&dir, &unlock).unwrap().unwrap().period(), 3);
            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// Review V1-5: a key file the operator made read-only does not block
    /// evolution. The new state is published by the rename (which needs the
    /// directory only); the old inode is left as it was and that is reported.
    #[cfg(unix)]
    #[test]
    fn a_read_only_key_file_does_not_block_evolution() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("read-only");
        let unlock = quick();
        let mut key = KesKey::generate(4, 2, |_| {}).unwrap();
        key.save(&dir, &unlock).unwrap();
        fs::set_permissions(KesKey::path(&dir), fs::Permissions::from_mode(0o400)).unwrap();
        if fs::OpenOptions::new().write(true).open(KesKey::path(&dir)).is_ok() {
            // Running as root: the mode does not restrict this process.
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        key.evolve_to(&dir, &unlock, 1).unwrap();
        assert_eq!(key.period(), 1);
        let reloaded = KesKey::load_optional(&dir, &unlock).unwrap().unwrap();
        assert_eq!(reloaded.period(), 1, "the evolved state is what the name holds");
        assert_eq!(fs::metadata(KesKey::path(&dir)).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    /// The first save has nothing to overwrite, and a failed evolution
    /// (refused period) leaves the file untouched.
    #[test]
    fn a_refused_evolution_leaves_the_file_untouched() {
        let dir = tmp("refused");
        let unlock = quick();
        let mut key = KesKey::generate(4, 1, |_| {}).unwrap();
        key.save(&dir, &unlock).unwrap();
        key.evolve_to(&dir, &unlock, 1).unwrap();
        let bytes = fs::read(KesKey::path(&dir)).unwrap();
        assert!(key.evolve_to(&dir, &unlock, 0).is_err());
        assert!(key.evolve_to(&dir, &unlock, 2).is_err());
        assert_eq!(fs::read(KesKey::path(&dir)).unwrap(), bytes);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_successor_is_promoted_atomically_and_the_old_key_kept_until_shredded() {
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
        // Review PER-1: the replaced key survives the swap, still loadable,
        // and can be put back if the handover is reorganized out.
        assert_eq!(KesKey::load_retired(&dir, &unlock).unwrap().unwrap().public(), old.public());
        assert!(promote_next(&dir).is_err(), "nothing left to promote");
        demote_promoted(&dir).unwrap();
        assert_eq!(KesKey::load_optional(&dir, &unlock).unwrap().unwrap().public(), old.public());
        assert_eq!(KesKey::load_next(&dir, &unlock).unwrap().unwrap().public(), next.public());
        assert!(!dir.join(RETIRED_FILE_NAME).exists());
        assert!(demote_promoted(&dir).is_err(), "nothing retired to put back");
        // Promoted again and final: the old key is destroyed.
        promote_next(&dir).unwrap();
        let old_inode = dir.join("old-inode");
        fs::hard_link(dir.join(RETIRED_FILE_NAME), &old_inode).unwrap();
        shred_retired(&dir).unwrap();
        assert!(!dir.join(RETIRED_FILE_NAME).exists(), "the old key is gone");
        assert!(fs::read(&old_inode).unwrap().iter().all(|b| *b == 0), "and overwritten");
        fs::remove_file(&old_inode).unwrap();
        assert!(demote_promoted(&dir).is_err());

        // The retired key evolves in its own file and erases as the live one.
        let kept = tmp("retired-evolve");
        let mut a = KesKey::generate(4, 2, |_| {}).unwrap();
        a.save(&kept, &unlock).unwrap();
        KesKey::generate(4, 1, |_| {}).unwrap().save_next(&kept, &unlock).unwrap();
        promote_next(&kept).unwrap();
        let live = fs::read(KesKey::path(&kept)).unwrap();
        a.evolve_retired_to(&kept, &unlock, 2).unwrap();
        assert_eq!(KesKey::load_retired(&kept, &unlock).unwrap().unwrap().period(), 2);
        assert_eq!(fs::read(KesKey::path(&kept)).unwrap(), live, "the key in force is untouched");
        assert!(a.evolve_retired_to(&kept, &unlock, 1).is_err(), "cannot go back");
        let _ = fs::remove_dir_all(&kept);

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
        assert_eq!(KesKey::load_retired(&crashed, &unlock).unwrap().unwrap().public(), a.public(), "kept, not shredded");
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
