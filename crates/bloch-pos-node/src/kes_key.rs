// SPDX-License-Identifier: AGPL-3.0-or-later
//! The validator's forward-secure signing key (`bloch_pos_committee::kes`) on
//! disk: `<data-dir>/validator.kes`, beside `validator.key` and under the same
//! passphrase policy ([`Unlock`]).
//!
//! The file holds the public tree (depth, root, every leaf hash) in the clear
//! and, sealed, only the CURRENT period and its seed. [`KesKey::evolve_to`]
//! writes the evolved state to disk (temp file, fsync, rename) **before** the
//! caller signs anything in the new period, then replaces it in memory. Once
//! that rename lands, no earlier seed exists anywhere this node wrote it, so
//! nothing it holds can sign an earlier period — the long-range property.
//! Operators must not keep older copies of this file: a backup of an earlier
//! state is an earlier seed.
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

pub struct KesKey {
    index: u32,
    public: KesPublic,
    leaves: Vec<[u8; 32]>,
    period: u64,
    seed: Zeroizing<[u8; 32]>,
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
        let public = KesPublic { depth, root: kes::merkle_root(&leaves) };
        Ok(KesKey { index, public, leaves, period: 0, seed: seed0 })
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn public(&self) -> KesPublic {
        self.public
    }

    /// The period whose leaf this key can sign with now.
    pub fn period(&self) -> u64 {
        self.period
    }

    pub fn path(dir: &Path) -> PathBuf {
        dir.join(FILE_NAME)
    }

    /// Move to `period`, erasing every earlier seed — on disk first, then in
    /// memory. Refuses to go back and refuses past the last leaf.
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
        let next = KesKey { index: self.index, public: self.public, leaves: self.leaves.clone(), period, seed };
        next.save(dir, unlock)?;
        *self = next;
        Ok(())
    }

    /// Sign `message` — the bound `kes::leaf_message`, never a bare consensus
    /// root — with the current period's leaf (encoded `kes::KesSignature`).
    /// The caller evolves first.
    pub fn sign(&self, message: &[u8; 32]) -> io::Result<Vec<u8>> {
        let (leaf_pk, sk) = leaf_keypair(&self.seed)?;
        let sig = bloch_crypto::crypto::sign(&sk, message)
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
        let mut out = Zeroizing::new(Vec::new());
        match unlock {
            Unlock::Passphrase { pass, kdf, .. } => {
                let mut salt = [0u8; 32];
                os_random(&mut salt)?;
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
                let key = kdf.derive(pass, &salt)?;
                let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
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
        let path = Self::path(dir);
        let tmp = dir.join(format!("{FILE_NAME}.tmp"));
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
        let bytes = match read_keystore_file(&Self::path(dir)) {
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
        let public = KesPublic { depth, root };
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
        Ok(KesKey { index, public, leaves, period, seed })
    }
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
