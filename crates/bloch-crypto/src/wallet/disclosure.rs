//! P4.3 — TRANSPARENT selective disclosure ("view/audit key", MatRiCT-Au-style).
//!
//! A `DisclosureBundle` is a USER-SIDE, OPT-IN artifact: the wallet owner picks
//! a subset of their diversified receive indices and produces a signed statement
//! disclosing (index, address, pubkey) for exactly that subset — nothing more.
//! An auditor/verifier can then:
//!
//!   1. Verify OFFLINE that the discloser controls every listed address
//!      (each entry's pubkey hashes to its address, and each entry carries a
//!      hybrid ML-DSA-65 ‖ Falcon-1024 signature over the whole bundle made
//!      with THAT entry's secret key).
//!   2. Run WATCH-ONLY balance/history queries over the existing public
//!      per-address RPC (`getbalance` / `getutxos` / `listtransactions`) —
//!      see [`watch_summary`] (feature `node`).
//!
//! # What verification PROVES — and what it does NOT (read before claiming)
//!
//! PROVES, cryptographically:
//!   - Every disclosed address is the SHA3-256 hash of the disclosed pubkey
//!     (so the balance the verifier sums really belongs to these keys).
//!   - Whoever created the bundle held the secret key of EVERY disclosed
//!     address at creation time (one signature per entry, all over one digest).
//!   - The bundle is tamper-evident as a whole: adding, removing or reordering
//!     an entry, or editing `purpose` / `audience` / `created_at`, breaks every
//!     signature (they all cover the full canonical digest).
//!
//! Does NOT prove (inherent to transparent selective disclosure — do not
//! oversell this in any UI or document):
//!   - COMPLETENESS: the bundle cannot show these are ALL of the wallet's
//!     addresses. That is the feature (selective!), but it means "audited
//!     total balance" here means "total over the disclosed subset" only.
//!     A completeness claim needs protocol-level viewing keys (the shielded
//!     ivk scaffold, gated on P1 + the C4/P2 external audit).
//!   - SAME-SEED ORIGIN: diversified keypairs are cryptographically
//!     independent by design (that is the unlinkability property), so the
//!     bundle cannot prove all entries derive from one master seed.
//!
//! # Never a protocol backdoor
//!
//! Everything in a bundle is data the user already owns (their own pubkeys and
//! addresses) plus signatures they choose to make. Consensus, the P2P layer and
//! the node are completely untouched; a user who discloses nothing reveals
//! nothing; revocation = simply never disclosing further indices. Bundles
//! already handed out remain verifiable for what they disclosed — disclosure
//! of past data is not un-sayable, and callers must be told so.
//!
//! Replay note: a bundle proves key control to WHOEVER HOLDS IT. To stop a
//! third party re-presenting someone else's bundle as their own, the digest
//! binds an `audience` string; verifiers MUST check `audience` names them.
//!
//! # AUDIT GATE (stated per the rule of engagement)
//!
//! The signature scheme and address hashing reused here are the chain's
//! existing primitives, but the DISCLOSURE-PROOF CLAIM itself ("this bundle
//! proves control of exactly these addresses and leaks nothing else") is
//! UNAUDITED until the independent third-party review (S2 / Coherence P2).
//! Ship the tool; do not market the claim as audited.
//!
//! # Index convention (matches the P4.1 `Wallet::address_at` deliverable)
//!
//! index 0  == the wallet's BASE keypair (`generate_keypair_from_seed(seed[..32])`,
//!             i.e. today's `Wallet::from_seed` address) — back-compat.
//! index N>0 == `crypto::diversified_keypair(master_seed, N)`.

use crate::address::{Address, Network};
use crate::crypto;
use sha3::{Sha3_256, Digest};
use serde::{Serialize, Deserialize};
use zeroize::Zeroizing;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use thiserror::Error;

/// Bundle format version. Bump on any change to the canonical digest layout.
pub const DISCLOSURE_VERSION: u32 = 1;

/// Domain-separation tag folded into the signed digest. Distinct from every
/// other signing domain in the codebase (tx sighash binds a chain-id; keyfile
/// AAD uses "bloch-kf"), so a disclosure signature can never be replayed as a
/// transaction signature or vice versa.
const DOMAIN_TAG: &[u8] = b"bloch:disclosure:v1";

/// DoS bound: refuse to build or verify absurdly large bundles.
pub const MAX_DISCLOSURE_ENTRIES: usize = 1024;
/// DoS bound on free-text fields bound into the digest.
pub const MAX_TEXT_LEN: usize = 4096;
/// Upper bound on a b64-decoded pubkey (hybrid enveloped pk is ~3.8 KB).
const MAX_PUBKEY_LEN: usize = 8 * 1024;
/// Upper bound on a b64-decoded signature (hybrid enveloped sig is ~4.6 KB).
const MAX_SIG_LEN: usize = 16 * 1024;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// One disclosed receive index. All fields are PUBLIC data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureEntry {
    /// Diversified receive index (0 = base address, see module docs).
    pub index: u32,
    /// The user-facing address string ("bloch1q…" / "bloch1t…").
    pub address: String,
    /// The enveloped hybrid public key, base64.
    pub pubkey_b64: String,
    /// Signature over the bundle's canonical digest, made with THIS index's
    /// secret key. Base64.
    pub sig_b64: String,
}

/// A signed selective-disclosure statement. Serialize with `serde_json` for
/// file exchange; the JSON field order is irrelevant (verification recomputes
/// the canonical digest from the typed fields, never from the JSON bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureBundle {
    pub version: u32,
    /// "mainnet" | "testnet" — bound into the digest (no cross-net replay).
    pub network: String,
    /// Free-text statement of what this disclosure is for. Digest-bound.
    pub purpose: String,
    /// WHO this disclosure is addressed to. Digest-bound; verifiers MUST
    /// check this names them (anti-replay, see module docs).
    pub audience: String,
    /// RFC 3339 creation time. Digest-bound (informational; the verifier has
    /// no way to check wall-clock truth and must not treat it as proven).
    pub created_at: String,
    /// Disclosed entries, strictly ascending by index (canonical order).
    pub entries: Vec<DisclosureEntry>,
}

/// The outcome of a successful [`DisclosureBundle::verify`].
#[derive(Debug, Clone)]
pub struct VerifiedDisclosure {
    pub network: Network,
    pub purpose: String,
    pub audience: String,
    pub created_at: String,
    /// (index, parsed address) for every verified entry.
    pub addresses: Vec<(u32, Address)>,
}

#[derive(Debug, Error)]
pub enum DisclosureError {
    #[error("invalid bundle: {0}")]
    Invalid(String),
    #[error("unsupported disclosure version: {0}")]
    UnsupportedVersion(u32),
    #[error("duplicate or unsorted index: {0}")]
    BadIndexOrder(u32),
    #[error("entry {index}: address does not match disclosed pubkey")]
    AddressMismatch { index: u32 },
    #[error("entry {index}: signature verification failed")]
    SignatureInvalid { index: u32 },
    #[error("cryptographic error: {0}")]
    Crypto(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Derivation helper (index convention shared with P4.1)
// ─────────────────────────────────────────────────────────────────────────────

/// Keypair at `index` under the shared wallet convention:
/// 0 = base keypair (`seed[..32]`, i.e. `Wallet::from_seed`); N>0 = diversified.
///
/// `master_seed` is the 64-byte BIP39 seed (`SeedPhrase::to_seed_bytes()`);
/// any `&[u8]` of length >= 32 is accepted.
pub fn keypair_at(master_seed: &[u8], index: u32)
    -> Result<(Vec<u8>, Vec<u8>), crypto::CryptoError>
{
    if index == 0 {
        crypto::generate_keypair_from_seed(&master_seed[..32.min(master_seed.len())])
    } else {
        crypto::diversified_keypair(master_seed, index)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical digest
// ─────────────────────────────────────────────────────────────────────────────

/// The one digest every entry signs. Length-prefixed, domain-tagged, and
/// covering the FULL entry set, so no entry can be spliced in or out without
/// breaking every signature.
fn bundle_digest(
    network: Network,
    purpose: &str,
    audience: &str,
    created_at: &str,
    entries: &[(u32, Vec<u8>)], // (index, pubkey) in final (ascending) order
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DOMAIN_TAG);
    h.update(DISCLOSURE_VERSION.to_le_bytes());
    h.update([match network { Network::Testnet => 1u8, Network::Mainnet => 0u8 }]);
    for text in [purpose, audience, created_at] {
        h.update((text.len() as u64).to_le_bytes());
        h.update(text.as_bytes());
    }
    h.update((entries.len() as u32).to_le_bytes());
    for (index, pk) in entries {
        h.update(index.to_le_bytes());
        h.update((pk.len() as u32).to_le_bytes());
        h.update(pk);
    }
    h.finalize().into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Create / verify
// ─────────────────────────────────────────────────────────────────────────────

impl DisclosureBundle {
    /// Build and sign a disclosure over `indices` (deduplicated, sorted
    /// ascending). Derives each keypair from `master_seed`, signs the canonical
    /// digest once per entry, and zeroizes every derived secret before return.
    ///
    /// `master_seed` is the 64-byte BIP39 seed; NO part of it, and no secret
    /// key, ever enters the bundle.
    pub fn create(
        master_seed: &[u8],
        indices: &[u32],
        network: Network,
        purpose: &str,
        audience: &str,
    ) -> Result<Self, DisclosureError> {
        if master_seed.len() < 32 {
            return Err(DisclosureError::Crypto("master seed too short (need >= 32 bytes)".into()));
        }
        if indices.is_empty() {
            return Err(DisclosureError::Invalid("no indices to disclose".into()));
        }
        if purpose.len() > MAX_TEXT_LEN || audience.len() > MAX_TEXT_LEN {
            return Err(DisclosureError::Invalid("purpose/audience too long".into()));
        }
        let mut sorted: Vec<u32> = indices.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() > MAX_DISCLOSURE_ENTRIES {
            return Err(DisclosureError::Invalid(format!(
                "too many entries: {} > {}", sorted.len(), MAX_DISCLOSURE_ENTRIES)));
        }

        // Derive all keypairs first (secrets in Zeroizing so any early-return
        // path still wipes them).
        let mut keyed: Vec<(u32, Vec<u8>, Zeroizing<Vec<u8>>)> = Vec::with_capacity(sorted.len());
        for &index in &sorted {
            let (pk, sk) = keypair_at(master_seed, index)
                .map_err(|e| DisclosureError::Crypto(e.to_string()))?;
            keyed.push((index, pk, Zeroizing::new(sk)));
        }

        let created_at = chrono::Utc::now().to_rfc3339();
        let digest_input: Vec<(u32, Vec<u8>)> =
            keyed.iter().map(|(i, pk, _)| (*i, pk.clone())).collect();
        let digest = bundle_digest(network, purpose, audience, &created_at, &digest_input);

        let is_testnet = matches!(network, Network::Testnet);
        let mut entries = Vec::with_capacity(keyed.len());
        for (index, pk, sk) in &keyed {
            let sig = crypto::sign(sk, &digest)
                .map_err(|e| DisclosureError::Crypto(e.to_string()))?;
            entries.push(DisclosureEntry {
                index: *index,
                address: crypto::address_from_pubkey(pk, is_testnet),
                pubkey_b64: B64.encode(pk),
                sig_b64: B64.encode(&sig),
            });
        }
        // `keyed` drops here; every Zeroizing<sk> wipes.

        Ok(DisclosureBundle {
            version: DISCLOSURE_VERSION,
            network: if is_testnet { "testnet" } else { "mainnet" }.into(),
            purpose: purpose.into(),
            audience: audience.into(),
            created_at,
            entries,
        })
    }

    /// Verify the bundle OFFLINE. On success, returns the verified address set.
    ///
    /// Checks, in order: version; entry-count and text-length bounds; strictly
    /// ascending indices; per-entry — bounded b64 decode, address parse +
    /// network match + checksum, address == SHA3-256(pubkey)[..20], and the
    /// hybrid signature over the recomputed canonical digest.
    ///
    /// See the module docs for what a successful verify does and does NOT
    /// prove (no completeness, no same-seed claim).
    pub fn verify(&self) -> Result<VerifiedDisclosure, DisclosureError> {
        if self.version != DISCLOSURE_VERSION {
            return Err(DisclosureError::UnsupportedVersion(self.version));
        }
        if self.entries.is_empty() {
            return Err(DisclosureError::Invalid("bundle has no entries".into()));
        }
        if self.entries.len() > MAX_DISCLOSURE_ENTRIES {
            return Err(DisclosureError::Invalid(format!(
                "too many entries: {} > {}", self.entries.len(), MAX_DISCLOSURE_ENTRIES)));
        }
        if self.purpose.len() > MAX_TEXT_LEN
            || self.audience.len() > MAX_TEXT_LEN
            || self.created_at.len() > MAX_TEXT_LEN
        {
            return Err(DisclosureError::Invalid("purpose/audience/created_at too long".into()));
        }
        let network = match self.network.as_str() {
            "mainnet" => Network::Mainnet,
            "testnet" => Network::Testnet,
            other => return Err(DisclosureError::Invalid(format!("unknown network: {}", other))),
        };

        // Decode + structural checks, building the digest input as we go.
        let mut digest_input: Vec<(u32, Vec<u8>)> = Vec::with_capacity(self.entries.len());
        let mut addresses: Vec<(u32, Address)> = Vec::with_capacity(self.entries.len());
        let mut last_index: Option<u32> = None;
        for e in &self.entries {
            // Canonical order: strictly ascending (also rejects duplicates).
            if let Some(prev) = last_index {
                if e.index <= prev {
                    return Err(DisclosureError::BadIndexOrder(e.index));
                }
            }
            last_index = Some(e.index);

            let pk = B64.decode(&e.pubkey_b64)
                .map_err(|err| DisclosureError::Invalid(format!("entry {}: bad pubkey b64: {}", e.index, err)))?;
            if pk.is_empty() || pk.len() > MAX_PUBKEY_LEN {
                return Err(DisclosureError::Invalid(format!(
                    "entry {}: pubkey length {} out of bounds", e.index, pk.len())));
            }

            let addr = Address::parse(&e.address)
                .map_err(|err| DisclosureError::Invalid(format!("entry {}: bad address: {}", e.index, err)))?;
            if addr.network() != network {
                return Err(DisclosureError::Invalid(format!(
                    "entry {}: address network does not match bundle network", e.index)));
            }
            // The load-bearing link: the disclosed address must BE the hash of
            // the disclosed pubkey, or the balance the verifier sums belongs
            // to someone else's key.
            let derived = Address::from_pubkey(&pk, network);
            if derived != addr {
                return Err(DisclosureError::AddressMismatch { index: e.index });
            }

            digest_input.push((e.index, pk));
            addresses.push((e.index, addr));
        }

        // One digest over everything; every entry must have signed exactly it.
        let digest = bundle_digest(
            network, &self.purpose, &self.audience, &self.created_at, &digest_input);
        for (e, (_, pk)) in self.entries.iter().zip(&digest_input) {
            let sig = B64.decode(&e.sig_b64)
                .map_err(|err| DisclosureError::Invalid(format!("entry {}: bad sig b64: {}", e.index, err)))?;
            if sig.is_empty() || sig.len() > MAX_SIG_LEN {
                return Err(DisclosureError::Invalid(format!(
                    "entry {}: signature length {} out of bounds", e.index, sig.len())));
            }
            if !crypto::verify(pk, &digest, &sig) {
                return Err(DisclosureError::SignatureInvalid { index: e.index });
            }
        }

        Ok(VerifiedDisclosure {
            network,
            purpose: self.purpose.clone(),
            audience: self.audience.clone(),
            created_at: self.created_at.clone(),
            addresses,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Watch-only summary (feature `node`) — verify, then sum over public RPC
// ─────────────────────────────────────────────────────────────────────────────

/// Per-address line of a watch-only summary.
#[cfg(feature = "node")]
#[derive(Debug, Clone)]
pub struct WatchLine {
    pub index: u32,
    pub address: String,
    pub confirmed: u64,
    pub pending_incoming: u64,
    pub pending_outgoing: u64,
}

/// Aggregate watch-only summary over a VERIFIED bundle.
#[cfg(feature = "node")]
#[derive(Debug, Clone)]
pub struct WatchSummary {
    pub purpose: String,
    pub audience: String,
    /// Sum of confirmed balances over the DISCLOSED subset (see module docs:
    /// this is not, and cannot be, a whole-wallet total).
    pub total_confirmed: u64,
    pub total_pending_incoming: u64,
    pub lines: Vec<WatchLine>,
}

/// Verify `bundle`, then query `getbalance`/`getaddressinfo` for every
/// disclosed address via the existing public RPC and sum. Read-only: needs no
/// secret material, so an auditor can run it with nothing but the bundle and a
/// node endpoint.
#[cfg(feature = "node")]
pub async fn watch_summary(
    client: &super::client::WalletClient,
    bundle: &DisclosureBundle,
) -> Result<WatchSummary, super::errors::WalletError> {
    let verified = bundle.verify()
        .map_err(|e| super::errors::WalletError::Parse(format!("disclosure verify failed: {}", e)))?;

    let mut lines = Vec::with_capacity(verified.addresses.len());
    let mut total_confirmed: u64 = 0;
    let mut total_pending_in: u64 = 0;
    for (index, addr) in &verified.addresses {
        let bal = client.balance(addr).await?;
        total_confirmed = total_confirmed.saturating_add(bal.confirmed);
        total_pending_in = total_pending_in.saturating_add(bal.pending_incoming);
        lines.push(WatchLine {
            index: *index,
            address: addr.to_string(),
            confirmed: bal.confirmed,
            pending_incoming: bal.pending_incoming,
            pending_outgoing: bal.pending_outgoing,
        });
    }

    Ok(WatchSummary {
        purpose: verified.purpose,
        audience: verified.audience,
        total_confirmed,
        total_pending_incoming: total_pending_in,
        lines,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic 64-byte "BIP39 seed" for tests (keygen is slow — keep
    // index sets small; each index costs one hybrid ML-DSA+Falcon keygen).
    const SEED: [u8; 64] = [7u8; 64];

    fn make_bundle() -> DisclosureBundle {
        DisclosureBundle::create(
            &SEED, &[0, 2, 5], Network::Testnet,
            "2026 audit of operating float", "Acme Auditors LLP",
        ).unwrap()
    }

    #[test]
    fn create_verify_roundtrip_and_addresses_match_derivation() {
        let bundle = make_bundle();
        assert_eq!(bundle.entries.len(), 3);

        let verified = bundle.verify().expect("fresh bundle must verify");
        assert_eq!(verified.network, Network::Testnet);
        assert_eq!(verified.addresses.len(), 3);

        // Entry addresses must equal the wallet-side derivations at each index.
        // Index 0 = BASE keypair (P4.1 convention), N>0 = diversified.
        let (pk0, _) = crypto::generate_keypair_from_seed(&SEED[..32]).unwrap();
        assert_eq!(bundle.entries[0].address, crypto::address_from_pubkey(&pk0, true));
        assert_eq!(bundle.entries[1].address, crypto::diversified_address(&SEED, 2, true).unwrap());
        assert_eq!(bundle.entries[2].address, crypto::diversified_address(&SEED, 5, true).unwrap());

        // JSON file-exchange roundtrip still verifies.
        let json = serde_json::to_string_pretty(&bundle).unwrap();
        let back: DisclosureBundle = serde_json::from_str(&json).unwrap();
        back.verify().expect("serde roundtrip must still verify");
    }

    #[test]
    fn bundle_contains_no_secret_material() {
        let bundle = make_bundle();
        let json = serde_json::to_string(&bundle).unwrap();
        for &index in &[0u32, 2, 5] {
            let (_, sk) = keypair_at(&SEED, index).unwrap();
            assert!(!json.contains(&B64.encode(&sk)),
                "serialized bundle must not contain the index-{} secret key", index);
            assert!(!json.contains(&hex::encode(&sk)),
                "serialized bundle must not contain the index-{} secret key (hex)", index);
        }
        assert!(!json.contains(&B64.encode(SEED)), "bundle must not contain the master seed");
        assert!(!json.contains(&hex::encode(SEED)), "bundle must not contain the master seed (hex)");
    }

    #[test]
    fn tampered_address_is_rejected() {
        let mut bundle = make_bundle();
        // Swap entry 0's address for entry 1's (both well-formed testnet
        // addresses, so this exercises the pubkey-hash link, not the parser).
        bundle.entries[0].address = bundle.entries[1].address.clone();
        assert!(matches!(bundle.verify(),
            Err(DisclosureError::AddressMismatch { index: 0 })));
    }

    #[test]
    fn tampered_pubkey_is_rejected() {
        let mut bundle = make_bundle();
        let mut pk = B64.decode(&bundle.entries[1].pubkey_b64).unwrap();
        pk[100] ^= 0x01;
        bundle.entries[1].pubkey_b64 = B64.encode(&pk);
        // Flipped pubkey no longer hashes to the disclosed address.
        assert!(matches!(bundle.verify(),
            Err(DisclosureError::AddressMismatch { index: 2 })));
    }

    #[test]
    fn excised_entry_breaks_every_remaining_signature() {
        let mut bundle = make_bundle();
        // Remove the middle entry: the remaining entries signed a digest that
        // covered all three, so verification must fail on the FIRST entry.
        bundle.entries.remove(1);
        assert!(matches!(bundle.verify(),
            Err(DisclosureError::SignatureInvalid { index: 0 })));
    }

    #[test]
    fn tampered_purpose_audience_or_network_breaks_signatures() {
        let base = make_bundle();

        let mut b = base.clone();
        b.purpose = "totally different purpose".into();
        assert!(matches!(b.verify(), Err(DisclosureError::SignatureInvalid { .. })));

        let mut b = base.clone();
        b.audience = "someone else entirely".into();
        assert!(matches!(b.verify(), Err(DisclosureError::SignatureInvalid { .. })));

        // Cross-net replay: flipping the network label also breaks the
        // address-network match (testnet addresses under a "mainnet" label).
        let mut b = base;
        b.network = "mainnet".into();
        assert!(b.verify().is_err());
    }

    #[test]
    fn flipped_signature_byte_is_rejected() {
        let mut bundle = make_bundle();
        let mut sig = B64.decode(&bundle.entries[0].sig_b64).unwrap();
        let mid = sig.len() / 2;
        sig[mid] ^= 0x01;
        bundle.entries[0].sig_b64 = B64.encode(&sig);
        assert!(matches!(bundle.verify(),
            Err(DisclosureError::SignatureInvalid { index: 0 })));
    }

    #[test]
    fn unsorted_or_duplicate_entries_rejected_on_verify() {
        let bundle = make_bundle();

        let mut b = bundle.clone();
        b.entries.swap(0, 1);
        assert!(matches!(b.verify(), Err(DisclosureError::BadIndexOrder(_))));

        let mut b = bundle;
        let dup = b.entries[0].clone();
        b.entries.insert(1, dup);
        assert!(matches!(b.verify(), Err(DisclosureError::BadIndexOrder(_))));
    }

    #[test]
    fn create_input_validation() {
        // Empty index set.
        assert!(matches!(
            DisclosureBundle::create(&SEED, &[], Network::Testnet, "p", "a"),
            Err(DisclosureError::Invalid(_))));
        // Short seed.
        assert!(matches!(
            DisclosureBundle::create(&[1u8; 16], &[1], Network::Testnet, "p", "a"),
            Err(DisclosureError::Crypto(_))));
        // Oversized purpose.
        let long = "x".repeat(MAX_TEXT_LEN + 1);
        assert!(matches!(
            DisclosureBundle::create(&SEED, &[1], Network::Testnet, &long, "a"),
            Err(DisclosureError::Invalid(_))));
        // Duplicate input indices are deduplicated, not an error.
        let b = DisclosureBundle::create(&SEED, &[3, 3], Network::Testnet, "p", "a").unwrap();
        assert_eq!(b.entries.len(), 1);
        b.verify().unwrap();
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut bundle = make_bundle();
        bundle.version = 999;
        assert!(matches!(bundle.verify(), Err(DisclosureError::UnsupportedVersion(999))));
    }

    #[test]
    fn selective_disclosure_reveals_nothing_about_other_indices() {
        // Disclosing indices {2} must not let a verifier link index 4's
        // address to this wallet: the bundle simply does not contain it, and
        // the addresses are independently derived (unlinkable by design).
        let bundle = DisclosureBundle::create(
            &SEED, &[2], Network::Testnet, "partial", "auditor").unwrap();
        let hidden = crypto::diversified_address(&SEED, 4, true).unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(!json.contains(&hidden));
    }
}
