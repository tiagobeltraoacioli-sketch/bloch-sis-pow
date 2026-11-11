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
//! - **Post-quantum proof of key possession.** Each side signs the transcript
//!   hash with an ML-DSA-65 transport identity, so the session is bound to
//!   the two identities that were presented, and a man in the middle who
//!   substitutes either ephemeral key cannot produce a signature *under the
//!   identity the other side expects*. That last clause carries the whole
//!   property: the handshake proves which key the peer holds, not that the
//!   key is one this node has any reason to trust. A node that expects no
//!   particular identity (no allow-list, no pin) accepts whatever key is
//!   presented, and an on-path party can then complete one handshake with
//!   each side under keys it generated a moment ago. Whether a connection is
//!   *authenticated* is therefore decided by the configuration below, not by
//!   the handshake alone. The two contexts differ, so a responder signature
//!   cannot be reflected back as an initiator one.
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
//! id, `SHA3-256(public key)`, is printed at startup (`mesh security:`).
//! Those ids are what the operator hands to the *other* nodes, in one of two
//! forms:
//!
//! - **Allow-list** (`--mesh-allow <file>`): a set of ids. Any listed id is
//!   accepted on any connection, inbound or outbound. Right for a closed
//!   fleet under one operator; a listed key can stand in for any other
//!   listed node, so the list is only as strong as its weakest member.
//! - **Pin** (`--peers host:port=<id>`): the id this node expects to find at
//!   one dialed address. The dialer checks it before it sends its own
//!   signature and refuses anything else, even an id that is on the
//!   allow-list. A pin is sufficient for its own address: the pinned id
//!   does not also have to be on the allow-list. Each mesh pair dials in
//!   both directions and an inbound connection has no address to pin, so
//!   the pinned ids are also admitted inbound, exactly as if they were on
//!   the allow-list.
//!
//! Once either is configured, every sealed connection must present an id
//! that is pinned or listed. Without an allow-list every `--peers` entry
//! must then carry a pin (the node refuses to start otherwise: an unpinned
//! entry could never be admitted), and a node that only dials in must be
//! put on the allow-list.
//!
//! There is deliberately no trust on first use: a first connection made
//! through an on-path party would pin that party.
//!
//! ## Modes, what each one guarantees, and the rollout
//!
//! - `plain` (default): byte-for-byte the old transport. No encryption, no
//!   authentication. Nothing changes for a node that does not opt in.
//! - `offer`: dials with the handshake and falls back to plain against a peer
//!   that does not speak it; accepts both, telling them apart by the first
//!   four bytes (`"BPQ1"` read as a legacy length is 827 MB, far above
//!   [`crate::codec::MAX_FIELD_LEN`], so a legacy node refuses it and closes,
//!   and no legacy frame can start with it). **Offer is a migration state
//!   and guarantees nothing against an active attacker**, who can still
//!   force plain, exactly as on today's mesh. Sealed connections are
//!   confidential against a passive observer, and an allow-list or pins are
//!   applied to them, but a plain inbound connection bypasses both. The one
//!   firm rule: a dial to a *pinned* address never falls back to plain (a
//!   pin says the peer is upgraded).
//! - `require` with neither allow-list nor pins: **encryption only.**
//!   Handshake or nothing, in both directions, so a passive observer
//!   (including harvest-now-decrypt-later) reads nothing, and a frame cannot
//!   be injected into an established session. But no peer is authenticated:
//!   anything that can reach the port, or sits on the path, can complete the
//!   handshake under a fresh key and read, drop or inject frames as a peer.
//!   The node says so at boot, loudly, and `--mesh-require-authenticated`
//!   turns that warning into a refusal to start.
//! - `require` with `--mesh-allow`: authenticated against the closed set.
//!   Only listed (or pinned) ids get past the handshake in either direction;
//!   an on-path party without a listed key gets nothing. Any listed key is
//!   accepted at any address.
//! - `require` with pins: authenticated per peer. A dialed address is
//!   accepted only under exactly its pinned id; inbound connections only
//!   under a pinned or listed id.
//!
//! Rollout: every node `plain → offer`, one at a time; when every peer of a
//! node is upgraded its connections are already sealed; then
//! `offer → require`, again one at a time; then add pins and/or an
//! allow-list (ids are stable once `mesh_identity.bin` exists, so they can
//! be collected during `offer`), and finally `--mesh-require-authenticated`
//! so a later configuration slip cannot silently drop back to
//! encryption-only.
//!
//! ## What this does not cover
//!
//! - `submit-tx` and the equivocation injector (`net::send_transaction`,
//!   `net::send_block`) still speak plain frames; a `require` node refuses
//!   them. Submit through the JSON-RPC instead.
//! - The libp2p stack keeps its Noise/X25519 handshake.
//! - Traffic analysis: frame sizes and timing are visible.

use std::collections::{HashMap, HashSet};
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
    /// Dialed address (exactly as given in `--peers`) → the only identity
    /// accepted there.
    pins: HashMap<String, PeerId>,
}

/// Split `--peers` entries of the form `host:port=<64 hex id>` into the bare
/// dial addresses (every entry, in order) and the pins. An entry without `=`
/// is an unpinned address, as before.
pub fn split_peer_pins(entries: &[String]) -> Result<(Vec<String>, Vec<(String, PeerId)>), String> {
    let mut addrs = Vec::with_capacity(entries.len());
    let mut pins: Vec<(String, PeerId)> = Vec::new();
    for entry in entries {
        let Some((addr, id)) = entry.split_once('=') else {
            addrs.push(entry.clone());
            continue;
        };
        if addr.is_empty() {
            return Err(format!("--peers entry `{entry}`: no address before `=`"));
        }
        let id: PeerId = crate::codec::unhex(id)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| format!(
                "--peers entry `{entry}`: the pin after `=` must be a mesh identity, 64 hex digits \
                 (the peer prints it at startup as `mesh security: ... identity <id>`)"
            ))?;
        if pins.iter().any(|(a, pinned)| a == addr && *pinned != id) {
            return Err(format!("--peers pins `{addr}` to two different identities"));
        }
        addrs.push(addr.to_string());
        pins.push((addr.to_string(), id));
    }
    Ok((addrs, pins))
}

impl fmt::Debug for MeshSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MeshSecurity")
            .field("mode", &self.mode)
            .field("identity", &self.identity.as_ref().map(|i| crate::codec::hex(&i.id)))
            .field("allow", &self.allow.as_ref().map(HashSet::len))
            .field("pins", &self.pins.len())
            .finish()
    }
}

impl MeshSecurity {
    /// The old transport, unchanged.
    pub fn plain() -> Self {
        MeshSecurity { mode: Mode::Plain, network: [0; 32], identity: None, allow: None, pins: HashMap::new() }
    }

    /// Load (or create) the transport identity under `data_dir`, the
    /// optional allow-list, and the pins for the dialed `peers`. `plain`
    /// loads nothing and creates no file.
    ///
    /// `require_authenticated` (`--mesh-require-authenticated`) refuses any
    /// configuration in which a peer could connect without presenting an
    /// identity this node was told to expect.
    pub fn load(
        mode: Mode,
        network: [u8; 32],
        data_dir: &Path,
        allow_path: Option<&Path>,
        peers: &[String],
        pins: &[(String, PeerId)],
        require_authenticated: bool,
    ) -> io::Result<Self> {
        let refuse = |why: &str| Err(io::Error::new(io::ErrorKind::InvalidInput, why.to_string()));
        if require_authenticated && mode != Mode::Require {
            return refuse(
                "--mesh-require-authenticated needs --mesh-security require: \
                 plain authenticates nothing and offer still accepts plain connections",
            );
        }
        if mode == Mode::Plain {
            if allow_path.is_some() {
                return refuse("--mesh-allow needs --mesh-security offer or require");
            }
            if !pins.is_empty() {
                return refuse("a pinned --peers entry (host:port=<identity>) needs --mesh-security offer or require");
            }
            return Ok(Self::plain());
        }
        let allow = allow_path.map(read_allow_list).transpose()?;
        let pins: HashMap<String, PeerId> = pins.iter().cloned().collect();
        if allow.is_none() && !pins.is_empty() {
            // Once anything is pinned, an identity must be pinned or listed
            // to be admitted, so an unpinned dial could never succeed. Say
            // so at boot instead of refusing that peer forever at runtime.
            if let Some(unpinned) = peers.iter().find(|addr| !pins.contains_key(*addr)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "--peers pins some peers but not `{unpinned}`, and there is no --mesh-allow: \
                         pin every peer (host:port=<identity>) or list the others in --mesh-allow"
                    ),
                ));
            }
        }
        if require_authenticated && allow.is_none() && pins.is_empty() {
            return refuse(
                "--mesh-require-authenticated: no --mesh-allow and no pinned --peers \
                 (host:port=<identity>), so no peer would be authenticated",
            );
        }
        std::fs::create_dir_all(data_dir)?;
        let identity = load_or_create_identity(&data_dir.join(IDENTITY_FILE))?;
        Ok(MeshSecurity { mode, network, identity: Some(identity), allow, pins })
    }

    /// An in-memory identity, for tests.
    #[cfg(test)]
    pub fn ephemeral(mode: Mode, network: [u8; 32], allow: Option<HashSet<PeerId>>) -> Self {
        let (pk, sk) = mldsa65::keypair();
        let id = peer_id(pk.as_bytes());
        MeshSecurity { mode, network, identity: Some(Identity { pk, sk, id }), allow, pins: HashMap::new() }
    }

    /// Pin a dialed address, for tests.
    #[cfg(test)]
    pub fn with_pin(mut self, addr: &str, id: PeerId) -> Self {
        self.pins.insert(addr.to_string(), id);
        self
    }

    /// True when a dial to `addr` must end in exactly one identity. The
    /// `offer` dialer uses it to refuse the plain fallback for such a peer.
    pub fn is_pinned(&self, addr: &str) -> bool {
        self.pins.contains_key(addr)
    }

    /// True when every sealed connection must present an identity this node
    /// was configured to expect (an allow-list, pins, or both).
    fn checks_identities(&self) -> bool {
        self.allow.is_some() || !self.pins.is_empty()
    }

    /// What the operator must be told at every boot, beyond [`Self::summary`].
    /// Empty when the mode delivers what its name suggests.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.mode == Mode::Require && !self.checks_identities() {
            out.push(
                "ENCRYPTION ONLY, PEERS ARE NOT AUTHENTICATED. `--mesh-security require` without \
                 --mesh-allow and without pinned --peers (host:port=<identity>) accepts ANY peer \
                 identity: it stops a passive observer, but anything that can reach the mesh port \
                 or sits on the path can complete the handshake under a fresh key and act as a \
                 peer. Pin the peers or give an allow-list, then add --mesh-require-authenticated \
                 so this state refuses to start instead of warning."
                    .to_string(),
            );
        }
        out
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
                "{} (ML-KEM-768+X25519, ML-DSA-65 identity {}{}{}{})",
                mode.name(),
                crate::codec::hex(&id.id),
                match &self.allow {
                    Some(a) => format!(", allow-list of {}", a.len()),
                    None => String::new(),
                },
                match self.pins.len() {
                    0 => String::new(),
                    n => format!(", {n} pinned peer address(es)"),
                },
                match (mode, self.checks_identities()) {
                    (Mode::Require, false) => "; ENCRYPTION ONLY: no allow-list, no pins, peers not authenticated",
                    (Mode::Require, true) => "; peers authenticated",
                    _ => "; migration state: plain connections still accepted, peers not authenticated",
                },
            ),
        }
    }

    fn identity(&self) -> io::Result<&Identity> {
        self.identity.as_ref().ok_or_else(|| io::Error::other("mesh: no transport identity loaded"))
    }

    /// Decide whether the identity a peer proved is one this node expects.
    /// `dialed` is the `--peers` address for an outbound connection and
    /// `None` for an inbound one.
    ///
    /// - A pinned dialed address admits exactly its pin, nothing else.
    /// - Otherwise, with an allow-list or any pin configured, the identity
    ///   must be listed or be one of the pinned identities.
    /// - With neither configured there is nothing to check it against, and
    ///   the connection is encrypted but unauthenticated (see
    ///   [`Self::warnings`]).
    fn admit(&self, id: &PeerId, dialed: Option<&str>) -> io::Result<()> {
        let denied = |why: String| Err(io::Error::new(io::ErrorKind::PermissionDenied, why));
        if let Some((addr, pin)) = dialed.and_then(|addr| self.pins.get(addr).map(|pin| (addr, pin))) {
            if pin == id {
                return Ok(());
            }
            return denied(format!(
                "mesh: peer at {addr} presented identity {} but is pinned to {}",
                crate::codec::hex(id),
                crate::codec::hex(pin),
            ));
        }
        if !self.checks_identities() {
            return Ok(());
        }
        let listed = self.allow.as_ref().is_some_and(|allow| allow.contains(id));
        if listed || self.pins.values().any(|pin| pin == id) {
            return Ok(());
        }
        denied(format!(
            "mesh: peer identity {} is not on the allow-list{}",
            crate::codec::hex(id),
            if self.pins.is_empty() { "" } else { " and is not a pinned identity" },
        ))
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
        self.read_record_of(sock, deadline, None)
    }

    /// The handshake's identity record: the only valid one is exactly
    /// [`auth_len`] bytes of plaintext, so any other length is refused
    /// before a buffer is allocated for it (review CRY-8). Nothing is
    /// authenticated at this point, and the general bound would let any
    /// peer hold `MAX_FIELD_LEN` bytes per half-open handshake.
    fn read_auth_record(&mut self, sock: &mut TcpStream, deadline: Instant) -> io::Result<Vec<u8>> {
        self.read_record_of(sock, deadline, Some(auth_len()))
    }

    fn read_record_of(&mut self, sock: &mut TcpStream, deadline: Instant, exact_plain: Option<usize>) -> io::Result<Vec<u8>> {
        let mut len4 = [0u8; 4];
        crate::net::read_exact_until(sock, &mut len4, deadline)?;
        let len = u32::from_le_bytes(len4) as usize;
        if len <= TAG_LEN || len > crate::codec::MAX_FIELD_LEN + TAG_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad record length"));
        }
        if exact_plain.is_some_and(|plain| len != plain + TAG_LEN) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "mesh: bad authentication record length"));
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
/// identity the peer proved it holds; the pin and the allow-list, if any,
/// have already been applied to it. With neither configured it is whatever
/// key the peer chose to present.
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
/// `Session::Plain` without touching the socket. `dialed` is the `--peers`
/// address the socket was connected to: if it is pinned, the responder must
/// prove exactly that identity, and it is checked before this side sends its
/// own signature.
pub fn handshake_outbound(sock: &mut TcpStream, sec: &MeshSecurity, dialed: &str) -> io::Result<Session> {
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

    let theirs = opener.read_auth_record(sock, deadline)?;
    let peer = check_auth(&theirs, &h, CTX_RESPONDER)?;
    sec.admit(&peer, Some(dialed))?;
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
    let theirs = opener.read_auth_record(sock, deadline)?;
    let peer = check_auth(&theirs, &h, CTX_INITIATOR)?;
    sec.admit(&peer, None)?;
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
        pair_with(|_| client, server)
    }

    /// Like [`pair`], but the client is built once the listener's address is
    /// known, so it can pin that address.
    fn pair_with(
        client: impl FnOnce(&str) -> Arc<MeshSecurity>,
        server: Arc<MeshSecurity>,
    ) -> (io::Result<(Session, TcpStream)>, io::Result<(Session, TcpStream)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let dialed = addr.to_string();
        let client = client(&dialed);
        let srv = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            handshake_inbound(&mut s, &server).map(|x| (x, s))
        });
        let mut c = TcpStream::connect(addr).unwrap();
        // A failed client drops its socket here, which is what unblocks a
        // server still waiting on it.
        let cli = handshake_outbound(&mut c, &client, &dialed).map(|x| (x, c));
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
        assert!(matches!(handshake_outbound(&mut c, &sec, "127.0.0.1:1").unwrap(), Session::Plain));
        assert!(matches!(handshake_inbound(&mut s, &sec).unwrap(), Session::Plain));
    }

    #[test]
    fn identity_file_round_trips_and_rejects_garbage() {
        let dir = std::env::temp_dir().join(format!("mesh-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = MeshSecurity::load(Mode::Offer, NET, &dir, None, &[], &[], false).unwrap();
        let again = MeshSecurity::load(Mode::Offer, NET, &dir, None, &[], &[], false).unwrap();
        assert_eq!(first.identity_id(), again.identity_id());
        std::fs::write(dir.join(IDENTITY_FILE), b"nope").unwrap();
        assert!(MeshSecurity::load(Mode::Offer, NET, &dir, None, &[], &[], false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review CRY-8: the identity record has one valid length. A peer that
    /// announces a larger one is refused at once, before any buffer of that
    /// size exists and without waiting for the bytes (the read would
    /// otherwise run to the handshake deadline).
    #[test]
    fn an_oversized_authentication_record_is_refused_before_it_is_read() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut w = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut r, _) = l.accept().unwrap();
        // Within the general record bound, far above the identity record.
        w.write_all(&(1u32 << 20).to_le_bytes()).unwrap();
        let started = Instant::now();
        let err = Opener::new(&[9; 32]).read_auth_record(&mut r, far()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(err.to_string().contains("authentication record length"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(2), "refused on the length alone");
        // One byte short or long is refused the same way; the general
        // reader still takes such a length (and then waits for the body).
        for len in [auth_len() + TAG_LEN - 1, auth_len() + TAG_LEN + 1] {
            w.write_all(&(len as u32).to_le_bytes()).unwrap();
            let err = Opener::new(&[9; 32]).read_auth_record(&mut r, far()).unwrap_err();
            assert!(err.to_string().contains("authentication record length"), "{err}");
        }
        drop(w);
    }

    #[test]
    fn allow_list_parsing() {
        let id = [0xab; 32];
        let text = format!("# fleet\n{}  # n01\n\n", crate::codec::hex(&id));
        assert_eq!(parse_allow_list(&text).unwrap(), HashSet::from([id]));
        assert!(parse_allow_list("# nothing\n").is_err());
        assert!(parse_allow_list("abcd\n").is_err());
    }

    #[test]
    fn pinned_dial_refuses_a_different_identity_and_accepts_the_pinned_one() {
        let server = Arc::new(MeshSecurity::ephemeral(Mode::Require, NET, None));
        let server_id = server.identity_id().unwrap();
        let other_id = MeshSecurity::ephemeral(Mode::Require, NET, None).identity_id().unwrap();

        // The peer at the pinned address holds a different key: refused by
        // the dialer, which names both identities.
        let (cli, _srv) = pair_with(
            |addr| Arc::new(MeshSecurity::ephemeral(Mode::Require, NET, None).with_pin(addr, other_id)),
            server.clone(),
        );
        let err = cli.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let text = err.to_string();
        assert!(text.contains(&crate::codec::hex(&server_id)) && text.contains(&crate::codec::hex(&other_id)), "{text}");

        // The matching pin is accepted and the session is with that identity.
        let (cli, srv) = pair_with(
            |addr| Arc::new(MeshSecurity::ephemeral(Mode::Require, NET, None).with_pin(addr, server_id)),
            server,
        );
        let (Session::Sealed { peer, .. }, _c) = cli.unwrap() else { panic!("client not sealed") };
        assert_eq!(peer, server_id);
        assert!(srv.is_ok());
    }

    #[test]
    fn a_pin_overrides_the_allow_list_for_its_address() {
        // Both identities are on the allow-list, but the dialed address is
        // pinned to one of them: the other listed key is refused there.
        let server = Arc::new(MeshSecurity::ephemeral(Mode::Require, NET, None));
        let server_id = server.identity_id().unwrap();
        let other_id = [0x5a; 32];
        let allow = HashSet::from([server_id, other_id]);
        let (cli, _srv) = pair_with(
            |addr| Arc::new(MeshSecurity::ephemeral(Mode::Require, NET, Some(allow.clone())).with_pin(addr, other_id)),
            server.clone(),
        );
        assert_eq!(cli.err().unwrap().kind(), io::ErrorKind::PermissionDenied);
        // A pin is sufficient on its own address: the pinned identity need
        // not be on the allow-list as well.
        let (cli, _srv) = pair_with(
            |addr| Arc::new(MeshSecurity::ephemeral(Mode::Require, NET, Some(HashSet::from([other_id]))).with_pin(addr, server_id)),
            server,
        );
        assert!(cli.is_ok());
    }

    #[test]
    fn pins_admit_only_pinned_identities_inbound() {
        // A node whose only configuration is a pin no longer accepts an
        // arbitrary identity on its listener; the pinned peer dialling back
        // is admitted.
        let pinned = Arc::new(MeshSecurity::ephemeral(Mode::Require, NET, None));
        let gate = Arc::new(
            MeshSecurity::ephemeral(Mode::Require, NET, None).with_pin("192.0.2.1:9000", pinned.identity_id().unwrap()),
        );
        let stranger = Arc::new(MeshSecurity::ephemeral(Mode::Require, NET, None));
        let (_cli, srv) = pair(stranger, gate.clone());
        assert_eq!(srv.err().unwrap().kind(), io::ErrorKind::PermissionDenied);
        let (cli, srv) = pair(pinned, gate);
        assert!(cli.is_ok() && srv.is_ok());
    }

    #[test]
    fn require_without_identities_warns_and_strict_refuses() {
        let dir = std::env::temp_dir().join(format!("mesh-strict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let id = [0xab; 32];
        let allow_path = dir.join("allow.txt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&allow_path, format!("{}\n", crate::codec::hex(&id))).unwrap();
        let peer = "192.0.2.1:9000".to_string();
        let peers = [peer.clone()];
        let pins = [(peer.clone(), id)];

        // Default: starts, and says in the warning and in the summary that
        // nobody is authenticated.
        let open = MeshSecurity::load(Mode::Require, NET, &dir, None, &peers, &[], false).unwrap();
        let warnings = open.warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("NOT AUTHENTICATED") && warnings[0].contains("--mesh-require-authenticated"));
        assert!(open.summary().contains("ENCRYPTION ONLY"));

        // Strict: the same configuration refuses to start.
        let err = MeshSecurity::load(Mode::Require, NET, &dir, None, &peers, &[], true).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        // Strict makes no sense where plain connections are still accepted.
        assert!(MeshSecurity::load(Mode::Offer, NET, &dir, Some(&allow_path), &peers, &[], true).is_err());
        assert!(MeshSecurity::load(Mode::Plain, NET, &dir, None, &peers, &[], true).is_err());

        // An allow-list or pins satisfy strict and silence the warning.
        for (allow, pins) in [(Some(allow_path.as_path()), &[][..]), (None, &pins[..]), (Some(allow_path.as_path()), &pins[..])] {
            for strict in [false, true] {
                let sec = MeshSecurity::load(Mode::Require, NET, &dir, allow, &peers, pins, strict).unwrap();
                assert!(sec.warnings().is_empty());
                assert!(sec.summary().contains("peers authenticated"), "{}", sec.summary());
            }
        }
        // `offer` and `plain` keep booting without a warning, as before.
        assert!(MeshSecurity::load(Mode::Offer, NET, &dir, None, &peers, &[], false).unwrap().warnings().is_empty());
        assert!(MeshSecurity::plain().warnings().is_empty());

        // Pins without an allow-list must cover every dialed peer; with an
        // allow-list the unpinned peer is checked against the list instead.
        let two = [peer.clone(), "192.0.2.2:9000".to_string()];
        assert!(MeshSecurity::load(Mode::Require, NET, &dir, None, &two, &pins, false).is_err());
        assert!(MeshSecurity::load(Mode::Require, NET, &dir, Some(&allow_path), &two, &pins, false).is_ok());
        // Pins mean nothing on the plain transport.
        assert!(MeshSecurity::load(Mode::Plain, NET, &dir, None, &peers, &pins, false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_pin_parsing() {
        let id = [0xcd; 32];
        let hex = crate::codec::hex(&id);
        let entries = ["10.0.0.1:9000".to_string(), format!("10.0.0.2:9000={hex}"), format!("[::1]:9000={hex}")];
        let (addrs, pins) = split_peer_pins(&entries).unwrap();
        assert_eq!(addrs, ["10.0.0.1:9000", "10.0.0.2:9000", "[::1]:9000"]);
        assert_eq!(pins, [("10.0.0.2:9000".to_string(), id), ("[::1]:9000".to_string(), id)]);
        // Unpinned lists pass through untouched.
        let plain = ["a:1".to_string(), "b:2".to_string()];
        assert_eq!(split_peer_pins(&plain).unwrap(), (plain.to_vec(), Vec::new()));
        for bad in ["10.0.0.1:9000=", "10.0.0.1:9000=abcd", "10.0.0.1:9000=zz", &format!("={hex}")] {
            assert!(split_peer_pins(&[bad.to_string()]).is_err(), "{bad}");
        }
        let other = crate::codec::hex(&[0xce; 32]);
        assert!(split_peer_pins(&[format!("a:1={hex}"), format!("a:1={other}")]).is_err());
        assert!(split_peer_pins(&[format!("a:1={hex}"), format!("a:1={hex}")]).is_ok());
    }
}
