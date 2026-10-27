// SPDX-License-Identifier: AGPL-3.0-or-later

//! Post-quantum authentication and encryption for the devnet TCP mesh
//! (`--mesh-security`).
//!
//! ## Why this exists
//!
//! The devnet mesh in `net.rs` is what the fleet actually runs, and on the
//! wire it is `u32 length ‖ type ‖ payload` in the clear: anything that can
//! reach the port can read every frame, inject frames, and impersonate any
//! peer. Consensus objects are still signed (ML-DSA-65 ‖ Falcon-1024) and
//! checked by every node, so a network attacker cannot forge a block — but it
//! can observe and map the validator set, splice itself into connections, and
//! feed a node frames under someone else's address. The libp2p stack fixes
//! the authentication half with Noise, but its key exchange is X25519 only.
//!
//! This module closes both gaps on the transport the fleet already runs,
//! without a flag day.
//!
//! ## Handshake (version 1)
//!
//! ```text
//! I → R  msg1 = "BPQ1" ‖ 0x01 ‖ network(32) ‖ x25519_i(32) ‖ mlkem768_ek(1184) ‖ nonce_i(32)
//! R → I  msg2 = "BPQ1" ‖ 0x01 ‖ x25519_r(32) ‖ mlkem768_ct(1088) ‖ nonce_r(32)
//!        h    = SHA3-256(DOMAIN ‖ msg1 ‖ msg2)
//!        ikm  = ML-KEM-768 shared secret ‖ X25519 shared secret
//!        keys = HKDF-SHA3-256(salt = h, ikm) → k_i2r, k_r2i
//! R → I  seal(k_r2i): R_pk(ML-DSA-65) ‖ Sign(R_sk, h, ctx = "…/responder")
//! I → R  seal(k_i2r): I_pk(ML-DSA-65) ‖ Sign(I_sk, h, ctx = "…/initiator")
//! ```
//!
//! - **Hybrid key exchange.** The session keys stay secret if *either*
//!   ML-KEM-768 (FIPS 203) or X25519 holds: a harvest-now-decrypt-later
//!   adversary has to break ML-KEM, and a flaw in the young ML-KEM
//!   implementation still leaves classical X25519 in front of it.
//! - **Post-quantum mutual authentication.** Each side signs the transcript
//!   hash with an ML-DSA-65 transport identity, so a man in the middle who
//!   substitutes either ephemeral key cannot produce a matching signature.
//!   The two contexts differ, so a responder signature cannot be reflected
//!   back as an initiator one.
//! - **Network binding.** `network` is the genesis id. A node from another
//!   chain (a devnet dialling mainnet by mistake) is refused before any key
//!   material is spent on it.
//! - **Records.** Every frame after the handshake is
//!   `u32 LE ciphertext length ‖ ChaCha20-Poly1305(frame) ‖ tag`, the length
//!   bound as associated data, the nonce a per-direction counter that is
//!   never reused (the connection closes before it could wrap).
//!
//! ## Transport identity
//!
//! `mesh_identity.bin` in the data dir: an ML-DSA-65 key pair created on
//! first start, written private (0600). **It is not a validator key and signs
//! nothing of value** — the same status as libp2p's `p2p_identity.bin`. Its
//! id, `SHA3-256(public key)`, is printed at startup; collect those ids into
//! a `--mesh-allow` file to turn authentication into admission control.
//!
//! ## Modes and the rollout
//!
//! - `plain` (default): byte-for-byte the old transport. Nothing changes for a
//!   node that does not opt in.
//! - `offer`: dials with the handshake and falls back to plain against a peer
//!   that does not speak it; accepts both, telling them apart by the first
//!   four bytes (`"BPQ1"` read as a legacy length is 827 MB, far above
//!   [`crate::codec::MAX_FIELD_LEN`], so a legacy node refuses it and closes,
//!   and no legacy frame can start with it). **Offer is a migration state**:
//!   an active attacker can still force plain, exactly as on today's mesh.
//! - `require`: handshake or nothing, both directions. With `--mesh-allow`,
//!   only listed identities get past the handshake.
//!
//! Rollout: every node `plain → offer`, one at a time; when every peer of a
//! node is upgraded its connections are already sealed; then
//! `offer → require` (optionally with an allow-list), again one at a time.
//!
//! ## What this does not cover
//!
//! - `submit-tx` and the equivocation injector (`net::send_transaction`,
//!   `net::send_block`) still speak plain frames; a `require` node refuses
//!   them. Submit through the JSON-RPC instead.
//! - The libp2p stack keeps its Noise/X25519 handshake.
//! - Traffic analysis: frame sizes and timing are visible.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hkdf::Hkdf;
use pqcrypto_mldsa::mldsa65;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

/// First four bytes of a handshake. Read as a legacy length prefix this is
/// 0x3151_5042 = 827,412,546, which every legacy node refuses.
pub const MAGIC: [u8; 4] = *b"BPQ1";
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"bloch-mesh-pq/v1";
const CTX_RESPONDER: &[u8] = b"bloch-mesh-pq/v1/responder";
const CTX_INITIATOR: &[u8] = b"bloch-mesh-pq/v1/initiator";
const NONCE_LEN: usize = 32;
const X25519_LEN: usize = 32;
const TAG_LEN: usize = 16;

/// Whole-handshake budget. Generous for a trans-oceanic RTT and an ML-DSA
/// signature on a loaded host; short enough that a peer which connects and
/// says nothing cannot hold a slot for long.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long an `offer` listener waits for the first four bytes before it
/// decides the dialer is a legacy node that has nothing to say yet. A
/// handshaking dialer sends `msg1` immediately after connecting.
const SNIFF_TIMEOUT: Duration = Duration::from_secs(3);

const IDENTITY_FILE: &str = "mesh_identity.bin";
const IDENTITY_MAGIC: &[u8; 12] = b"BLOCHMESHID1";

fn msg1_len() -> usize {
    4 + 1 + 32 + X25519_LEN + mlkem768::public_key_bytes() + NONCE_LEN
}

fn msg2_len() -> usize {
    4 + 1 + X25519_LEN + mlkem768::ciphertext_bytes() + NONCE_LEN
}

fn auth_len() -> usize {
    mldsa65::public_key_bytes() + mldsa65::signature_bytes()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Plain,
    Offer,
    Require,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "plain" => Ok(Mode::Plain),
            "offer" => Ok(Mode::Offer),
            "require" => Ok(Mode::Require),
            other => Err(format!("--mesh-security must be `plain`, `offer` or `require`, not `{other}`")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Mode::Plain => "plain",
            Mode::Offer => "offer",
            Mode::Require => "require",
        }
    }
}

/// `SHA3-256` of an ML-DSA-65 transport public key.
pub type PeerId = [u8; 32];

pub fn peer_id(pk: &[u8]) -> PeerId {
    Sha3_256::digest(pk).into()
}

struct Identity {
    pk: mldsa65::PublicKey,
    sk: mldsa65::SecretKey,
    id: PeerId,
}

/// Everything the mesh needs to secure a connection. Built once at startup
/// and shared by every connection thread.
pub struct MeshSecurity {
    mode: Mode,
    network: [u8; 32],
    identity: Option<Identity>,
    allow: Option<HashSet<PeerId>>,
}

impl fmt::Debug for MeshSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MeshSecurity")
            .field("mode", &self.mode)
            .field("identity", &self.identity.as_ref().map(|i| crate::codec::hex(&i.id)))
            .field("allow", &self.allow.as_ref().map(HashSet::len))
            .finish()
    }
}

impl MeshSecurity {
    /// The old transport, unchanged.
    pub fn plain() -> Self {
        MeshSecurity { mode: Mode::Plain, network: [0; 32], identity: None, allow: None }
    }

    /// Load (or create) the transport identity under `data_dir` and the
    /// optional allow-list. `plain` loads nothing and creates no file.
    pub fn load(
        mode: Mode,
        network: [u8; 32],
        data_dir: &Path,
        allow_path: Option<&Path>,
    ) -> io::Result<Self> {
        if mode == Mode::Plain {
            if allow_path.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--mesh-allow needs --mesh-security offer or require",
                ));
            }
            return Ok(Self::plain());
        }
        std::fs::create_dir_all(data_dir)?;
        let identity = load_or_create_identity(&data_dir.join(IDENTITY_FILE))?;
        let allow = allow_path.map(read_allow_list).transpose()?;
        Ok(MeshSecurity { mode, network, identity: Some(identity), allow })
    }

    /// An in-memory identity, for tests.
    #[cfg(test)]
    pub fn ephemeral(mode: Mode, network: [u8; 32], allow: Option<HashSet<PeerId>>) -> Self {
        let (pk, sk) = mldsa65::keypair();
        let id = peer_id(pk.as_bytes());
        MeshSecurity { mode, network, identity: Some(Identity { pk, sk, id }), allow }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    #[cfg(test)]
    pub fn identity_id(&self) -> Option<PeerId> {
        self.identity.as_ref().map(|i| i.id)
    }

    /// One line for the boot log.
    pub fn summary(&self) -> String {
        match (&self.identity, self.mode) {
            (None, _) | (_, Mode::Plain) => {
                "plain (no authentication, no encryption)".to_string()
            }
            (Some(id), mode) => format!(
                "{} (ML-KEM-768+X25519, ML-DSA-65 identity {}{})",
                mode.name(),
                crate::codec::hex(&id.id),
                match &self.allow {
                    Some(a) => format!(", allow-list of {}", a.len()),
                    None => String::new(),
                }
            ),
        }
    }

    fn identity(&self) -> io::Result<&Identity> {
        self.identity.as_ref().ok_or_else(|| io::Error::other("mesh: no transport identity loaded"))
    }

    fn admit(&self, id: &PeerId) -> io::Result<()> {
        match &self.allow {
            Some(allow) if !allow.contains(id) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("mesh: peer identity {} is not on the allow-list", crate::codec::hex(id)),
            )),
            _ => Ok(()),
        }
    }
}

fn load_or_create_identity(path: &Path) -> io::Result<Identity> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            let pk_len = mldsa65::public_key_bytes();
            let sk_len = mldsa65::secret_key_bytes();
            let bad = || io::Error::new(io::ErrorKind::InvalidData, format!("{}: not a mesh identity", path.display()));
            if bytes.len() != IDENTITY_MAGIC.len() + pk_len + sk_len || !bytes.starts_with(IDENTITY_MAGIC) {
                return Err(bad());
            }
            let body = &bytes[IDENTITY_MAGIC.len()..];
            let pk = mldsa65::PublicKey::from_bytes(&body[..pk_len]).map_err(|_| bad())?;
            let sk = mldsa65::SecretKey::from_bytes(&body[pk_len..]).map_err(|_| bad())?;
            // A file whose halves do not belong together would authenticate
            // nobody and fail every handshake with a misleading error.
            let probe = mldsa65::detached_sign_ctx(DOMAIN, CTX_INITIATOR, &sk);
            if mldsa65::verify_detached_signature_ctx(&probe, DOMAIN, CTX_INITIATOR, &pk).is_err() {
                return Err(bad());
            }
            let id = peer_id(pk.as_bytes());
            Ok(Identity { pk, sk, id })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let (pk, sk) = mldsa65::keypair();
            let mut out = Zeroizing::new(Vec::with_capacity(IDENTITY_MAGIC.len() + pk.as_bytes().len() + sk.as_bytes().len()));
            out.extend_from_slice(IDENTITY_MAGIC);
            out.extend_from_slice(pk.as_bytes());
            out.extend_from_slice(sk.as_bytes());
            crate::store::atomic_private_write(path, &out)?;
            let id = peer_id(pk.as_bytes());
            Ok(Identity { pk, sk, id })
        }
        Err(e) => Err(e),
    }
}

/// One hex peer id (64 characters) per line; `#` starts a comment.
fn read_allow_list(path: &Path) -> io::Result<HashSet<PeerId>> {
    let text = std::fs::read_to_string(path)?;
    parse_allow_list(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display())))
}

fn parse_allow_list(text: &str) -> Result<HashSet<PeerId>, String> {
    let mut out = HashSet::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let bytes = crate::codec::unhex(line).map_err(|_| format!("line {}: not hex", n + 1))?;
        let id: PeerId = bytes.try_into().map_err(|_| format!("line {}: a peer id is 32 bytes", n + 1))?;
        out.insert(id);
    }
    if out.is_empty() {
        return Err("allow-list is empty; it would refuse every peer".to_string());
    }
    Ok(out)
}

// ── Record layer ────────────────────────────────────────────────────────────

fn nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(n)
}

/// One direction's sealing state. Never cloned: two sealers on one key would
/// reuse nonces.
pub struct Sealer {
    aead: ChaCha20Poly1305,
    counter: u64,
}

impl Sealer {
    fn new(key: &[u8; 32]) -> Self {
        Sealer { aead: ChaCha20Poly1305::new(Key::from_slice(key)), counter: 0 }
    }

    /// Seal `parts` (concatenated) as one record and write it.
    pub fn write_record<W: Write>(&mut self, w: &mut W, parts: &[&[u8]]) -> io::Result<()> {
        let plain_len = parts.iter().try_fold(0usize, |acc, p| acc.checked_add(p.len()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "frame length overflow"))?;
        if plain_len == 0 || plain_len > crate::codec::MAX_FIELD_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad frame length"));
        }
        if self.counter == u64::MAX {
            return Err(io::Error::other("mesh: send counter exhausted"));
        }
        let len = u32::try_from(plain_len + TAG_LEN)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame length exceeds u32"))?
            .to_le_bytes();
        let mut buf = Vec::with_capacity(4 + plain_len + TAG_LEN);
        buf.extend_from_slice(&len);
        for p in parts {
            buf.extend_from_slice(p);
        }
        let tag = self.aead
            .encrypt_in_place_detached(&nonce(self.counter), &len, &mut buf[4..])
            .map_err(|_| io::Error::other("mesh: seal failed"))?;
        self.counter += 1;
        buf.extend_from_slice(&tag);
        w.write_all(&buf)
    }
}

/// One direction's opening state.
pub struct Opener {
    aead: ChaCha20Poly1305,
    counter: u64,
}

impl Opener {
    fn new(key: &[u8; 32]) -> Self {
        Opener { aead: ChaCha20Poly1305::new(Key::from_slice(key)), counter: 0 }
    }

    /// Read and open one record before `deadline`. Any failure is fatal for
    /// the connection: after a bad tag the stream cannot be trusted again.
    pub fn read_record(&mut self, sock: &mut TcpStream, deadline: Instant) -> io::Result<Vec<u8>> {
        let mut len4 = [0u8; 4];
        crate::net::read_exact_until(sock, &mut len4, deadline)?;
        let len = u32::from_le_bytes(len4) as usize;
        if len <= TAG_LEN || len > crate::codec::MAX_FIELD_LEN + TAG_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad record length"));
        }
        let mut buf = vec![0u8; len];
        crate::net::read_exact_until(sock, &mut buf, deadline)?;
        if self.counter == u64::MAX {
            return Err(io::Error::other("mesh: receive counter exhausted"));
        }
        let body_len = len - TAG_LEN;
        let tag = Tag::clone_from_slice(&buf[body_len..]);
        buf.truncate(body_len);
        self.aead
            .decrypt_in_place_detached(&nonce(self.counter), &len4, &mut buf, &tag)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mesh: record authentication failed"))?;
        self.counter += 1;
        Ok(buf)
    }
}

/// What a connection runs on after the handshake step. `peer` is the
/// authenticated identity; the allow-list has already been applied to it.
#[cfg_attr(not(test), allow(dead_code))]
pub enum Session {
    Plain,
    Sealed { sealer: Sealer, opener: Opener, peer: PeerId },
}

// ── Handshake ───────────────────────────────────────────────────────────────

fn handshake_deadline() -> io::Result<Instant> {
    Instant::now()
        .checked_add(HANDSHAKE_TIMEOUT)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "deadline out of range"))
}

fn random_nonce() -> io::Result<[u8; NONCE_LEN]> {
    let mut n = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut n).map_err(|e| io::Error::other(format!("mesh: no randomness: {e}")))?;
    Ok(n)
}

fn transcript(msg1: &[u8], msg2: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DOMAIN);
    h.update(msg1);
    h.update(msg2);
    h.finalize().into()
}

fn derive_keys(h: &[u8; 32], kem: &[u8], dh: &[u8]) -> io::Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(kem.len() + dh.len()));
    ikm.extend_from_slice(kem);
    ikm.extend_from_slice(dh);
    let hk = Hkdf::<Sha3_256>::new(Some(h), &ikm);
    let mut i2r = Zeroizing::new([0u8; 32]);
    let mut r2i = Zeroizing::new([0u8; 32]);
    hk.expand(b"bloch-mesh-pq/v1 i2r", &mut *i2r).map_err(|_| io::Error::other("mesh: hkdf"))?;
    hk.expand(b"bloch-mesh-pq/v1 r2i", &mut *r2i).map_err(|_| io::Error::other("mesh: hkdf"))?;
    Ok((i2r, r2i))
}

fn x25519_shared(secret: x25519_dalek::EphemeralSecret, their: &[u8]) -> io::Result<Zeroizing<[u8; 32]>> {
    let their: [u8; 32] = their.try_into().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mesh: bad x25519 key"))?;
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(their));
    // A low-order point gives an all-zero secret the peer did not need to
    // know anything to compute. The KEM half would still protect the session,
    // but a peer that sends one is not following the protocol.
    if !shared.was_contributory() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "mesh: non-contributory x25519 key"));
    }
    Ok(Zeroizing::new(*shared.as_bytes()))
}

fn auth_payload(id: &Identity, h: &[u8; 32], ctx: &[u8]) -> Vec<u8> {
    let sig = mldsa65::detached_sign_ctx(h, ctx, &id.sk);
    let mut out = Vec::with_capacity(auth_len());
    out.extend_from_slice(id.pk.as_bytes());
    out.extend_from_slice(sig.as_bytes());
    out
}

fn check_auth(payload: &[u8], h: &[u8; 32], ctx: &[u8]) -> io::Result<PeerId> {
    let bad = || io::Error::new(io::ErrorKind::PermissionDenied, "mesh: peer authentication failed");
    if payload.len() != auth_len() {
        return Err(bad());
    }
    let (pk, sig) = payload.split_at(mldsa65::public_key_bytes());
    let pk = mldsa65::PublicKey::from_bytes(pk).map_err(|_| bad())?;
    let sig = mldsa65::DetachedSignature::from_bytes(sig).map_err(|_| bad())?;
    mldsa65::verify_detached_signature_ctx(&sig, h, ctx, &pk).map_err(|_| bad())?;
    Ok(peer_id(pk.as_bytes()))
}

fn write_all_until(sock: &mut TcpStream, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "mesh: handshake deadline exceeded"))?;
    sock.set_write_timeout(Some(remaining))?;
    sock.write_all(bytes)
}

/// Run the initiator side on a freshly connected socket. `Plain` mode returns
/// `Session::Plain` without touching the socket.
pub fn handshake_outbound(sock: &mut TcpStream, sec: &MeshSecurity) -> io::Result<Session> {
    if sec.mode == Mode::Plain {
        return Ok(Session::Plain);
    }
    let me = sec.identity()?;
    let deadline = handshake_deadline()?;

    let x_secret = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
    let x_public = x25519_dalek::PublicKey::from(&x_secret);
    let (ek, dk) = mlkem768::keypair();
    let mut msg1 = Vec::with_capacity(msg1_len());
    msg1.extend_from_slice(&MAGIC);
    msg1.push(VERSION);
    msg1.extend_from_slice(&sec.network);
    msg1.extend_from_slice(x_public.as_bytes());
    msg1.extend_from_slice(ek.as_bytes());
    msg1.extend_from_slice(&random_nonce()?);
    write_all_until(sock, &msg1, deadline)?;

    let mut msg2 = vec![0u8; msg2_len()];
    crate::net::read_exact_until(sock, &mut msg2, deadline)?;
    if msg2[..4] != MAGIC || msg2[4] != VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "mesh: bad handshake reply"));
    }
    let x_r = &msg2[5..5 + X25519_LEN];
    let ct = &msg2[5 + X25519_LEN..5 + X25519_LEN + mlkem768::ciphertext_bytes()];
    let ct = mlkem768::Ciphertext::from_bytes(ct)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mesh: bad ML-KEM ciphertext"))?;
    let kem = mlkem768::decapsulate(&ct, &dk);
    let dh = x25519_shared(x_secret, x_r)?;
    let h = transcript(&msg1, &msg2);
    let (i2r, r2i) = derive_keys(&h, kem.as_bytes(), &*dh)?;
    let mut sealer = Sealer::new(&i2r);
    let mut opener = Opener::new(&r2i);

    let theirs = opener.read_record(sock, deadline)?;
    let peer = check_auth(&theirs, &h, CTX_RESPONDER)?;
    sec.admit(&peer)?;
    let mine = auth_payload(me, &h, CTX_INITIATOR);
    let remaining = deadline.checked_duration_since(Instant::now()).unwrap_or_default();
    sock.set_write_timeout(Some(remaining.max(Duration::from_millis(1))))?;
    sealer.write_record(sock, &[&mine])?;
    Ok(Session::Sealed { sealer, opener, peer })
}

/// Wait until four bytes are readable without consuming them, or `deadline`.
/// `Ok(None)` is "nothing arrived in time".
fn sniff(sock: &mut TcpStream, deadline: Instant) -> io::Result<Option<[u8; 4]>> {
    let mut buf = [0u8; 4];
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) else {
            return Ok(None);
        };
        sock.set_read_timeout(Some(remaining))?;
        match sock.peek(&mut buf) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "mesh: closed before speaking")),
            Ok(4) => return Ok(Some(buf)),
            // Fewer than four bytes so far: the rest is in flight.
            Ok(_) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Run the responder side on an accepted socket. `Plain` mode returns
/// `Session::Plain` without touching the socket; `offer` lets a legacy
/// dialer through as `Session::Plain`; `require` refuses it.
pub fn handshake_inbound(sock: &mut TcpStream, sec: &MeshSecurity) -> io::Result<Session> {
    if sec.mode == Mode::Plain {
        return Ok(Session::Plain);
    }
    let me = sec.identity()?;
    let deadline = handshake_deadline()?;
    let sniff_deadline = match sec.mode {
        Mode::Offer => Instant::now() + SNIFF_TIMEOUT,
        _ => deadline,
    };
    match sniff(sock, sniff_deadline)? {
        Some(first) if first == MAGIC => {}
        _ if sec.mode == Mode::Offer => return Ok(Session::Plain),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "mesh: peer did not start the post-quantum handshake (mesh-security require)",
            ))
        }
    }

    let mut msg1 = vec![0u8; msg1_len()];
    crate::net::read_exact_until(sock, &mut msg1, deadline)?;
    if msg1[4] != VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "mesh: unsupported handshake version"));
    }
    if msg1[5..37] != sec.network {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "mesh: peer is on another network (genesis mismatch)"));
    }
    let x_i = &msg1[37..37 + X25519_LEN];
    let ek = mlkem768::PublicKey::from_bytes(&msg1[37 + X25519_LEN..37 + X25519_LEN + mlkem768::public_key_bytes()])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mesh: bad ML-KEM key"))?;
    let (kem, ct) = mlkem768::encapsulate(&ek);
    let x_secret = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
    let x_public = x25519_dalek::PublicKey::from(&x_secret);
    let dh = x25519_shared(x_secret, x_i)?;

    let mut msg2 = Vec::with_capacity(msg2_len());
    msg2.extend_from_slice(&MAGIC);
    msg2.push(VERSION);
    msg2.extend_from_slice(x_public.as_bytes());
    msg2.extend_from_slice(ct.as_bytes());
    msg2.extend_from_slice(&random_nonce()?);
    let h = transcript(&msg1, &msg2);
    let (i2r, r2i) = derive_keys(&h, kem.as_bytes(), &*dh)?;
    let mut sealer = Sealer::new(&r2i);
    let mut opener = Opener::new(&i2r);

    write_all_until(sock, &msg2, deadline)?;
    let mine = auth_payload(me, &h, CTX_RESPONDER);
    sealer.write_record(sock, &[&mine])?;
    let theirs = opener.read_record(sock, deadline)?;
    let peer = check_auth(&theirs, &h, CTX_INITIATOR)?;
    sec.admit(&peer)?;
    Ok(Session::Sealed { sealer, opener, peer })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::Arc;

    const NET: [u8; 32] = [7; 32];

    fn pair(
        client: Arc<MeshSecurity>,
        server: Arc<MeshSecurity>,
    ) -> (io::Result<(Session, TcpStream)>, io::Result<(Session, TcpStream)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            handshake_inbound(&mut s, &server).map(|x| (x, s))
        });
        let mut c = TcpStream::connect(addr).unwrap();
        // A failed client drops its socket here, which is what unblocks a
        // server still waiting on it.
        let cli = handshake_outbound(&mut c, &client).map(|x| (x, c));
        (cli, srv.join().unwrap())
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn sealed_sessions_authenticate_both_sides_and_carry_frames() {
        let a = Arc::new(MeshSecurity::ephemeral(Mode::Require, NET, None));
        let b = Arc::new(MeshSecurity::ephemeral(Mode::Require, NET, None));
        let (cli, srv) = pair(a.clone(), b.clone());
        let (Session::Sealed { sealer: mut cs, opener: mut co, peer: cp }, mut csock) = cli.unwrap() else { panic!("client not sealed") };
        let (Session::Sealed { sealer: mut ss, opener: mut so, peer: sp }, mut ssock) = srv.unwrap() else { panic!("server not sealed") };
        assert_eq!(cp, b.identity_id().unwrap());
        assert_eq!(sp, a.identity_id().unwrap());
        cs.write_record(&mut csock, &[&[0x02], b"attestation"]).unwrap();
        assert_eq!(so.read_record(&mut ssock, far()).unwrap(), b"\x02attestation");
        ss.write_record(&mut ssock, &[b"\x01block"]).unwrap();
        ss.write_record(&mut ssock, &[b"\x01block2"]).unwrap();
        assert_eq!(co.read_record(&mut csock, far()).unwrap(), b"\x01block");
        assert_eq!(co.read_record(&mut csock, far()).unwrap(), b"\x01block2");
    }

    #[test]
    fn records_are_not_plaintext_and_tampering_is_fatal() {
        let a = Arc::new(MeshSecurity::ephemeral(Mode::Require, NET, None));
        let b = Arc::new(MeshSecurity::ephemeral(Mode::Require, NET, None));
        let (cli, srv) = pair(a, b);
        let (Session::Sealed { sealer: mut cs, .. }, _c) = cli.unwrap() else { panic!() };
        let (Session::Sealed { opener: mut so, .. }, _s) = srv.unwrap() else { panic!() };
        let mut wire = Vec::new();
        cs.write_record(&mut wire, &[b"\x02secret-attestation"]).unwrap();
        assert!(!wire.windows(6).any(|w| w == b"secret"), "payload visible on the wire");
        let last = wire.len() - 1;
        wire[last] ^= 1;
        // Feed the tampered record through a loopback socket.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut w = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut r, _) = l.accept().unwrap();
        w.write_all(&wire).unwrap();
        assert!(so.read_record(&mut r, far()).is_err());
    }

    #[test]
    fn allow_list_refuses_unknown_identities_on_both_sides() {
        let stranger = Arc::new(MeshSecurity::ephemeral(Mode::Require, NET, None));
        let known = MeshSecurity::ephemeral(Mode::Require, NET, None);
        let gate = Arc::new(MeshSecurity::ephemeral(
            Mode::Require,
            NET,
            Some(HashSet::from([known.identity_id().unwrap()])),
        ));
        let (_cli, srv) = pair(stranger.clone(), gate.clone());
        assert_eq!(srv.err().unwrap().kind(), io::ErrorKind::PermissionDenied);
        let (cli, _srv) = pair(gate.clone(), stranger);
        assert_eq!(cli.err().unwrap().kind(), io::ErrorKind::PermissionDenied);
        let (cli, srv) = pair(Arc::new(known), gate);
        assert!(cli.is_ok() && srv.is_ok());
    }

    #[test]
    fn another_network_is_refused() {
        let a = Arc::new(MeshSecurity::ephemeral(Mode::Require, [1; 32], None));
        let b = Arc::new(MeshSecurity::ephemeral(Mode::Require, [2; 32], None));
        let (cli, srv) = pair(a, b);
        assert!(cli.is_err());
        assert_eq!(srv.err().unwrap().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn offer_lets_a_legacy_dialer_through_and_require_does_not() {
        for (mode, plain_ok) in [(Mode::Offer, true), (Mode::Require, false)] {
            let sec = Arc::new(MeshSecurity::ephemeral(mode, NET, None));
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let srv = std::thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                handshake_inbound(&mut s, &sec).map(|x| matches!(x, Session::Plain))
            });
            let mut c = TcpStream::connect(addr).unwrap();
            // A legacy frame: length 9, get-blocks after slot 0.
            c.write_all(&9u32.to_le_bytes()).unwrap();
            c.write_all(&[0x03, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
            let got = srv.join().unwrap();
            assert_eq!(got.as_ref().ok().copied(), if plain_ok { Some(true) } else { None }, "{mode:?}");
        }
    }

    #[test]
    fn legacy_listener_refuses_the_handshake_magic_as_a_length() {
        assert!(u32::from_le_bytes(MAGIC) as usize > crate::codec::MAX_FIELD_LEN);
    }

    #[test]
    fn plain_mode_touches_nothing() {
        let sec = MeshSecurity::plain();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut s, _) = listener.accept().unwrap();
        assert!(matches!(handshake_outbound(&mut c, &sec).unwrap(), Session::Plain));
        assert!(matches!(handshake_inbound(&mut s, &sec).unwrap(), Session::Plain));
    }

    #[test]
    fn identity_file_round_trips_and_rejects_garbage() {
        let dir = std::env::temp_dir().join(format!("mesh-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = MeshSecurity::load(Mode::Offer, NET, &dir, None).unwrap();
        let again = MeshSecurity::load(Mode::Offer, NET, &dir, None).unwrap();
        assert_eq!(first.identity_id(), again.identity_id());
        std::fs::write(dir.join(IDENTITY_FILE), b"nope").unwrap();
        assert!(MeshSecurity::load(Mode::Offer, NET, &dir, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allow_list_parsing() {
        let id = [0xab; 32];
        let text = format!("# fleet\n{}  # n01\n\n", crate::codec::hex(&id));
        assert_eq!(parse_allow_list(&text).unwrap(), HashSet::from([id]));
        assert!(parse_allow_list("# nothing\n").is_err());
        assert!(parse_allow_list("abcd\n").is_err());
    }
}
