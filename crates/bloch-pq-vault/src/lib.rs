//! # bloch-pq-vault — experimental Bitcoin vault and PQ anchor primitives
//!
//! Experimental primitives associated with
//! `docs/specs/PQ-SHIELD-NONCUSTODIAL-NATIVE.md`: a **commit-delay-reveal P2WSH vault**
//! on stock Bitcoin, plus a hashlocked classical clawback and a separate PQ-signed
//! commitment. It composes the repo's building blocks:
//!
//! - [`bloch_btc_wallet`] — one seed → BTC (secp256k1) + companion PQ key
//!   (ML-DSA-65 ‖ Falcon-1024). Reused for the hybrid identity and the anchor guard.
//! - [`bloch_crypto`] — `generate_keypair_from_seed` / `sign` / `verify` (the PQ half).
//! - [`bloch_euvm`] `modules` — the `Custody` (hybrid 2-of-2) / `Governance` (n-of-m)
//!   validators the anchor's guard program reuses.
//! - the `bitcoin` crate — real P2WSH scripts, transactions, BIP-143 sighashes.
//!
//! Modules:
//! - [`preimage`] — `r = HKDF(pq_sk, "pq-shield/v1" ‖ vault_id)` and `H(r) = SHA256(r)`.
//! - [`vault`]    — the P2WSH deposit/trigger scripts, addresses, and the unvault /
//!   branch-A / clawback transactions with real sighash handling.
//! - [`anchor`]   — the `PqShieldAnchor` record: serialize/deserialize, PQ sign/verify,
//!   and its `bloch-euvm` guard program.
//! - [`script_eval`] — a narrow, honestly-scoped evaluator used by the tests to *prove*
//!   the clawback hash-lock + CSV delay behave (NOT a consensus engine — see its docs).
//!
//! ---
//! # HONEST LIMITS (mandatory reading — spec §0, §2.0, §9)
//!
//! This is **NOT unconditional quantum immunity.** It is **transition-era
//! defense-in-depth** (the spec's option (C)). Precisely:
//!
//! 1. **Spend-window protection + PQ recovery only.** A CRQC that compromises an exposed
//!    key **and** wins the branch-A/branch-B fee race within Δ, **or** simply strikes
//!    while the owner/watchtower is offline, still steals the coin. We reduce the odds;
//!    we do not zero them.
//! 2. **The covenant caveat is structural.** Stock Bitcoin has no covenant opcode
//!    (`OP_CTV`/`OP_VAULT` are unshippable soft-fork proposals). The commit-delay-reveal
//!    shape is not enforced by these scripts. Historical parameters reuse the retained
//!    hot key for the deposit and therefore retain a direct bypass. An experimental
//!    separate-key construction allows a pre-sign/delete ceremony, but this crate
//!    cannot verify deletion, and quantum signature forgery can still bypass it.
//! 3. **Taproot is not quantum-safe at rest.** We use **P2WSH** for the deposit (the
//!    whole script, hence every pubkey, is behind `SHA256`). A Taproot instantiation
//!    would protect the spend window only. We do not repeat the false "unspent Taproot is
//!    quantum-safe" claim.
//! 4. **The clawback destination MUST be a fresh, unexposed (hidden-pubkey) address.**
//!    Clawing back to a reused/Taproot address just moves the same exposure.
//! 5. **Address reuse defeats the whole thing.** An already-revealed pubkey is already
//!    exposed; the delay protects nothing.
//! 6. **Requires the owner or a watchtower online during Δ.** Offline + no watchtower =
//!    no defense in the window. Watchtowers add a *griefing* surface (funds → the owner's
//!    own cold address), never theft (spec §4.1).
//! 7. **Hashlock preimage front-running is unsolved here** — same class of risk as
//!    Lightning HTLCs; mitigation is an operational fee-race, not a crypto guarantee.
//! 8. **`T_shor` is unbounded.** If a CRQC forges signatures instantly and cheaply, the
//!    whole window approach collapses; only a PQ soft fork (BIP-360) or never exposing
//!    the key helps.
//! 9. **Foundational, unaudited, unbuilt.** Not consensus-wired; the Bloch-side PQ
//!    enforcement depends on `bloch-euvm` (its own "not consensus-wired" disclaimer). The
//!    real fix is BIP-360 (P2QRH); this is a stopgap on unmodified Bitcoin. Designed ≠
//!    built ≠ booted.

//! ## Construction and recovery audit follow-up
//!
//! Historical `VaultParams` uses the same seed-derived hot key for deposit and
//! branch A: deleting a copy while retaining that seed cannot remove the bypass.
//! [`construction::SeparatedDepositV1`] is a separate, opt-in NEW construction
//! with a distinct deposit public key; independence remains a caller assumption. Existing V1/V2/V3 key derivations,
//! scripts and addresses remain unchanged. See `CONSTRUCTION-AUDIT.md` for its
//! operational, quantum-race and validation limitations. For existing recovery
//! preimages, [`preimage::restore_recovery_secret_v1`] checks the supplied backup
//! context against the already committed hash without changing the derivation.

#![forbid(unsafe_code)]

pub mod anchor;
pub mod construction;
pub mod preimage;
pub mod script_eval;
pub mod vault;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, NetworkKind, PublicKey};
use std::str::FromStr;
use zeroize::{Zeroize, Zeroizing};

/// A4-M-5: which BIP-32 branch derives a vault's `hot`/`recovery` keys.
///
/// The pre-fix derivation reused `bloch_btc_wallet`'s ordinary BIP-84 receive
/// chain (`m/84'/coin'/0'/0/{0,1}`) — `hot_pubkey` IS the wallet's normal
/// first receive address (`derive_identity`'s `btc_p2wpkh`), and `recovery_pubkey`
/// is the SECOND address the wallet hands out next. The vault's own HONEST
/// LIMITS (§4/§9.4) require the recovery key to be "distinct, unexposed" —
/// contradicted by deriving it from a chain any wallet UI will show the user
/// receive funds on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultKeyDerivation {
    /// Pre-A4-M-5 (default, for compatibility with existing vaults/callers):
    /// `m/84'/coin'/0'/0/{0,1}` — the SAME path as the wallet's ordinary BIP-84
    /// receive chain. Kept so an EXISTING vault keeps deriving the keys it was
    /// built with; never used for a new vault going forward.
    V1SharedReceiveChain,
    /// Historical A4-M-5 branch isolation: a dedicated hardened BRANCH no ordinary receive/change
    /// address ever touches — `m/1998'/coin'/0'/0/{0,1}`. Purpose `1998'` is
    /// not assigned by any BIP (the `*_44/49/84/86` family are the only
    /// purpose values `bloch_btc_wallet` or any standard wallet UI derives
    /// under). The final role children are NOT hardened: a leaked hot private
    /// key plus the branch xpub exposes recovery. Restore existing V2 vaults
    /// with this scheme; use V3 for new vaults.
    V2DedicatedHardenedBranch,
    /// New vaults: independent hardened role children at
    /// `m/1999'/coin'/0'/{0',1'}`. A hot private key plus an ancestor
    /// xpub cannot recover the parent or derive the recovery sibling.
    V3HardenedRoles,
}

/// Purpose field for [`VaultKeyDerivation::V2DedicatedHardenedBranch`] —
/// documented here as the single source of truth for the path.
const VAULT_PURPOSE_V2: &str = "1998'";

/// The on-chain (secp256k1) and post-quantum keys a vault owner derives from ONE seed.
/// The BTC `hot`/`recovery` keys guard the Bitcoin spend paths; the PQ key produces the
/// preimage `r` and signs the Bloch anchor. Same seed → both, per the hybrid-identity
/// model of [`bloch_btc_wallet`].
#[derive(Clone)]
pub struct VaultKeys {
    /// Hot spend key (deposit spend + trigger branch A).
    pub hot_sk: SecretKey,
    pub hot_pubkey: PublicKey,
    /// Recovery key (trigger branch B clawback).
    pub recovery_sk: SecretKey,
    pub recovery_pubkey: PublicKey,
    /// Enveloped ML-DSA-65 ‖ Falcon-1024 public key (PQ identity / anchor key).
    pub pq_pubkey: Vec<u8>,
    /// Enveloped PQ secret key — produces `r` and signs the anchor. Keep secret.
    pub pq_secret: Vec<u8>,
    /// A4-M-5: which BIP-32 branch produced `hot_sk`/`recovery_sk`. Carried so
    /// a caller that persists vault key material also records how to
    /// re-derive it — a vault built under one version must always be
    /// re-derived under that SAME version.
    pub key_derivation: VaultKeyDerivation,
}

// Wipe the owned PQ allocation, including every explicitly cloned instance.
// SecretKey is Copy: the library's erase is best effort and cannot wipe copies
// already held by callers, registers or third-party key-generation internals.
impl Zeroize for VaultKeys {
    fn zeroize(&mut self) {
        self.pq_secret.zeroize();
        self.hot_sk.non_secure_erase();
        self.recovery_sk.non_secure_erase();
    }
}
impl Drop for VaultKeys {
    fn drop(&mut self) { self.zeroize(); }
}

/// Derive [`VaultKeys`] from a seed under [`VaultKeyDerivation::V1SharedReceiveChain`]
/// (the historical, UNVERSIONED derivation — BTC hot key at BIP-84 index 0,
/// recovery at index 1, both on the wallet's ordinary receive chain). The PQ
/// keypair is `bloch_crypto::generate_keypair_from_seed(seed)` (the exact
/// companion key [`bloch_btc_wallet::derive_identity`]'s default, V1, PQ
/// derivation exposes the public half of).
///
/// A4-M-5: kept EXACTLY as-is (including panicking on a malformed seed) for
/// compatibility with existing callers and vaults built under it — see
/// [`derive_vault_keys_v3`] for hardened role separation for new vaults.
pub fn derive_vault_keys(seed: &[u8], mainnet: bool) -> VaultKeys {
    derive_vault_keys_versioned(seed, mainnet, VaultKeyDerivation::V1SharedReceiveChain)
        .expect("valid legacy vault seed")
}

/// Fallible restoration entry point. The stored derivation version is mandatory:
/// never guess a different family when restoring an existing funded vault.
/// V1/V2/V3 valid inputs retain their existing key bytes and derivation domains.
pub fn derive_vault_keys_versioned(seed: &[u8], mainnet: bool, version: VaultKeyDerivation) -> Result<VaultKeys, String> {
    match version {
        VaultKeyDerivation::V2DedicatedHardenedBranch => return derive_vault_keys_v2(seed, mainnet),
        VaultKeyDerivation::V3HardenedRoles => return derive_vault_keys_v3(seed, mainnet),
        VaultKeyDerivation::V1SharedReceiveChain => {}
    }
    if seed.len() < 32 { return Err("legacy vault seed must contain at least 32 bytes".into()); }
    let secp = Secp256k1::new();
    let net = if mainnet { NetworkKind::Main } else { NetworkKind::Test };
    let coin = if mainnet { "0'" } else { "1'" };
    let master = Xpriv::new_master(net, seed).map_err(|e| format!("bip32 master: {e}"))?;
    let derive = |idx: u32| -> Result<(SecretKey, PublicKey), String> {
        let path = DerivationPath::from_str(&format!("m/84'/{coin}/0'/0/{idx}"))
            .map_err(|e| format!("bip32 path: {e}"))?;
        let xpriv = master.derive_priv(&secp, &path).map_err(|e| format!("bip32 derive: {e}"))?;
        let sk = xpriv.private_key;
        Ok((sk, PublicKey::new(sk.public_key(&secp))))
    };
    let (hot_sk, hot_pubkey) = derive(0)?;
    let (recovery_sk, recovery_pubkey) = derive(1)?;
    let (pq_pubkey, pq_secret) = bloch_crypto::crypto::generate_keypair_from_seed(seed)
        .map_err(|e| format!("pq keygen: {e}"))?;
    Ok(VaultKeys { hot_sk, hot_pubkey, recovery_sk, recovery_pubkey, pq_pubkey, pq_secret,
        key_derivation: VaultKeyDerivation::V1SharedReceiveChain })
}

/// A4-M-5 fix: derive [`VaultKeys`] on a DEDICATED hardened branch
/// (`m/1998'/coin'/0'/0/{0,1}` — see [`VaultKeyDerivation::V2DedicatedHardenedBranch`])
/// that no ordinary wallet receive/change address ever touches, so `hot_pubkey`
/// and especially `recovery_pubkey` are never the same key a wallet UI shows
/// the user as a deposit address. The PQ keypair also uses
/// `bloch_btc_wallet::PqSeedKdf::V2DomainSeparated` (I-13), so the vault's PQ
/// identity no longer shares raw seed material with the BTC leg either.
///
/// Fails closed (`Err`) on a malformed seed instead of panicking — new code,
/// no back-compat constraint to preserve the old `.expect()` behavior.
pub fn derive_vault_keys_v2(seed: &[u8], mainnet: bool) -> Result<VaultKeys, String> {
    // I-13/A4-M-5: reject a too-short seed up front. `Xpriv::new_master`
    // (HMAC-SHA512 over arbitrary-length input) and the SHA3-256 domain
    // separator for the PQ leg would both formally "succeed" on a tiny seed,
    // silently deriving low-entropy keys — fail closed instead, matching
    // `generate_keypair_from_seed`'s own >=32-byte floor.
    const MIN_SEED_LEN: usize = 32;
    if seed.len() < MIN_SEED_LEN {
        return Err(format!("seed too short: {} bytes (need at least {})", seed.len(), MIN_SEED_LEN));
    }

    let secp = Secp256k1::new();
    let net = if mainnet { NetworkKind::Main } else { NetworkKind::Test };
    let coin = if mainnet { "0'" } else { "1'" };
    let master = Xpriv::new_master(net, seed).map_err(|e| format!("bip32 master: {e}"))?;

    let derive = |idx: u32| -> Result<(SecretKey, PublicKey), String> {
        let path = DerivationPath::from_str(&format!("m/{VAULT_PURPOSE_V2}/{coin}/0'/0/{idx}"))
            .map_err(|e| format!("bip32 path: {e}"))?;
        let xpriv = master.derive_priv(&secp, &path).map_err(|e| format!("bip32 derive: {e}"))?;
        let sk = xpriv.private_key;
        let pk = PublicKey::new(sk.public_key(&secp));
        Ok((sk, pk))
    };
    let (hot_sk, hot_pubkey) = derive(0)?;
    let (recovery_sk, recovery_pubkey) = derive(1)?;

    // Validate seed length + BTC-side reachability the same way
    // `derive_identity_versioned` does, then derive the PQ keypair directly —
    // `derive_identity*` deliberately exposes only the PUBLIC half (it is an
    // identity helper), and the vault needs the secret key too. Sharing
    // `pq_seed_for` (rather than re-hashing the domain tag here) keeps this
    // byte-for-byte identical to `derive_identity_versioned`'s PQ pubkey.
    let pq_seed = Zeroizing::new(bloch_btc_wallet::pq_seed_for(seed, bloch_btc_wallet::PqSeedKdf::V2DomainSeparated)
        .ok_or_else(|| format!("seed too short: {} bytes (need at least {})", seed.len(), MIN_SEED_LEN))?);
    let (pq_pubkey, pq_secret) = bloch_crypto::crypto::generate_keypair_from_seed(&pq_seed[..])
        .map_err(|e| format!("pq keygen: {e}"))?;

    Ok(VaultKeys {
        hot_sk, hot_pubkey, recovery_sk, recovery_pubkey, pq_pubkey, pq_secret,
        key_derivation: VaultKeyDerivation::V2DedicatedHardenedBranch,
    })
}

/// Derive a new vault using hardened role separation (BV-04).
///
/// This is an explicit opt-in format: persist `V3HardenedRoles` with the vault
/// backup. Never use it to restore a V1/V2 vault. Existing derivation functions
/// and their outputs are unchanged. Compromise of the master seed still exposes
/// both roles; hardened derivation protects against child-key plus xpub leakage.
pub fn derive_vault_keys_v3(seed: &[u8], mainnet: bool) -> Result<VaultKeys, String> {
    use sha2::{Digest, Sha256};
    if !(32..=64).contains(&seed.len()) {
        return Err("V3 seed must contain 32 to 64 bytes".into());
    }
    let secp = Secp256k1::new();
    let net = if mainnet { NetworkKind::Main } else { NetworkKind::Test };
    let coin = if mainnet { "0'" } else { "1'" };
    let master = Xpriv::new_master(net, seed).map_err(|e| format!("bip32 master: {e}"))?;
    let derive = |role: u32| -> Result<(SecretKey, PublicKey), String> {
        let path = DerivationPath::from_str(&format!("m/1999'/{coin}/0'/{role}'"))
            .map_err(|e| format!("bip32 path: {e}"))?;
        let child = master.derive_priv(&secp, &path).map_err(|e| format!("bip32 derive: {e}"))?;
        Ok((child.private_key, PublicKey::new(child.private_key.public_key(&secp))))
    };
    let (hot_sk, hot_pubkey) = derive(0)?;
    let (recovery_sk, recovery_pubkey) = derive(1)?;
    let mut hash = Sha256::new();
    hash.update(b"BLOCH-PQ-VAULT-V3-PQ-KEY");
    hash.update([u8::from(mainnet)]);
    hash.update(seed);
    let pq_seed = Zeroizing::new(<[u8; 32]>::from(hash.finalize()));
    let (pq_pubkey, pq_secret) = bloch_crypto::crypto::generate_keypair_from_seed(&pq_seed[..])
        .map_err(|e| format!("pq keygen: {e}"))?;
    Ok(VaultKeys { hot_sk, hot_pubkey, recovery_sk, recovery_pubkey, pq_pubkey, pq_secret,
        key_derivation: VaultKeyDerivation::V3HardenedRoles })
}

/// Produce a Bitcoin `<DER-sig ‖ SIGHASH_ALL>` witness push: sign `sighash` with `sk`.
pub fn ecdsa_witness_sig(sighash: &[u8; 32], sk: &SecretKey) -> Vec<u8> {
    let secp = Secp256k1::new();
    let msg = bitcoin::secp256k1::Message::from_digest(*sighash);
    let sig = secp.sign_ecdsa(&msg, sk);
    let mut out = sig.serialize_der().to_vec();
    out.push(bitcoin::sighash::EcdsaSighashType::All as u8);
    out
}

/// Validate that `s` is a well-formed bech32 address on `network` (the clawback
/// `designated_safe_dest` MUST be a valid, network-correct, fresh address — spec §9.4/9.6).
/// Returns the checked [`Address`] or an error string.
pub fn validate_destination(
    s: &str,
    network: bitcoin::Network,
) -> Result<Address, String> {
    let unchecked = Address::from_str(s).map_err(|e| format!("parse: {e}"))?;
    unchecked
        .require_network(network)
        .map_err(|e| format!("wrong network: {e}"))
}

/// Non-secret convenience: the Bloch eUTXO `validator_hash` of the anchor's `Governance`
/// 1-of-1 guard over `pq_recovery_pubkey` (see [`anchor::anchor_guard_governance`]). This
/// hash addresses the guarded anchor output on Bloch. Takes ONLY the public PQ key — no
/// secret material — so it is safe to expose from a public (server-side) endpoint.
pub fn anchor_guard_governance_hash(pq_recovery_pubkey: &[u8]) -> [u8; 32] {
    bloch_euvm::validator_hash(&anchor::anchor_guard_governance(pq_recovery_pubkey))
}

/// Non-secret convenience: the `validator_hash` of the anchor's `Custody` 2-of-2 guard
/// (BTC pubkey AND PQ pubkey — see [`anchor::anchor_guard_custody`]). Both inputs are
/// PUBLIC keys; no secret material is involved.
pub fn anchor_guard_custody_hash(btc_pubkey: &[u8], pq_recovery_pubkey: &[u8]) -> [u8; 32] {
    bloch_euvm::validator_hash(&anchor::anchor_guard_custody(btc_pubkey, pq_recovery_pubkey))
}

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use crate::anchor::*;
    use crate::preimage::*;
    use crate::script_eval::*;
    use crate::vault::*;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Network, OutPoint, Sequence};

    const NET: Network = Network::Regtest;
    const DELTA: u16 = 144;

    fn seed() -> Vec<u8> {
        // canonical BIP-39 "abandon…about" 64-byte seed (same as bloch-btc-wallet tests)
        let s = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
                 9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        hex::decode(s.replace(char::is_whitespace, "")).unwrap()
    }

    /// Build a vault + its keys + preimage for a given vault id.
    fn setup(vault_id: &[u8]) -> (VaultKeys, VaultParams, [u8; 32]) {
        let keys = derive_vault_keys(&seed(), false);
        let (r, hr) = derive_recovery(&keys.pq_secret, vault_id);
        let p = VaultParams {
            hot_pubkey: keys.hot_pubkey,
            recovery_pubkey: keys.recovery_pubkey,
            recovery_hash: hr,
            csv_delay: DELTA,
            network: NET,
        };
        (keys, p, r)
    }

    #[test]
    fn deposit_spend_needs_correct_preimage_and_hot_sig() {
        let secp = Secp256k1::new();
        let (keys, p, r) = setup(b"deposit-vault");
        let dep_script = deposit_script(&p.recovery_hash, &p.hot_pubkey);
        // fund a fake deposit and build the unvault tx U
        let deposit_op = OutPoint::null();
        let u = build_unvault_tx(&p, deposit_op, 100_000, 500);
        let sh = p2wsh_sighash(&u, 0, &dep_script, 100_000);
        let sig = ecdsa_witness_sig(&sh, &keys.hot_sk);

        let ctx = EvalCtx {
            input_sequence: u.input[0].sequence,
            confirmations: 0,
            tx_version: u.version.0,
            sighash: sh,
        };
        // correct r + hot sig → spends
        assert_eq!(
            eval(&secp, &dep_script, vec![sig.clone(), r.to_vec()], &ctx),
            Ok(true)
        );
        // wrong preimage → hash-lock aborts
        assert_eq!(
            eval(&secp, &dep_script, vec![sig, vec![0u8; 32]], &ctx),
            Err(EvalError::EqualVerifyFailed)
        );
    }

    #[test]
    fn clawback_branch_b_spends_only_with_correct_preimage_and_recovery_sig() {
        let secp = Secp256k1::new();
        let (keys, p, r) = setup(b"clawback-vault");
        let trig_script = trigger_script(&p);
        let trigger_op = OutPoint::null();
        let claw = build_clawback_tx(trigger_op, 99_500, &safe_dest(), 500);
        let sh = p2wsh_sighash(&claw, 0, &trig_script, 99_500);
        let sig_rec = ecdsa_witness_sig(&sh, &keys.recovery_sk);

        // branch B is immediate: no CSV, sequence is RBF-enabled
        let ctx = EvalCtx {
            input_sequence: claw.input[0].sequence,
            confirmations: 0, // during the delay window
            tx_version: claw.version.0,
            sighash: sh,
        };
        // witness bottom→top: [sigB, r, <false selector = empty>]
        assert_eq!(
            eval(&secp, &trig_script, vec![sig_rec.clone(), r.to_vec(), vec![]], &ctx),
            Ok(true),
            "correct r + recovery sig clears branch B"
        );
        // wrong preimage → EQUALVERIFY aborts
        assert_eq!(
            eval(&secp, &trig_script, vec![sig_rec.clone(), vec![9u8; 32], vec![]], &ctx),
            Err(EvalError::EqualVerifyFailed)
        );
        // correct r but WRONG signer (hot key, not recovery) → CHECKSIG false → not truthy
        let sig_hot = ecdsa_witness_sig(&sh, &keys.hot_sk);
        assert_eq!(
            eval(&secp, &trig_script, vec![sig_hot, r.to_vec(), vec![]], &ctx),
            Ok(false)
        );
    }

    #[test]
    fn branch_a_requires_the_csv_delay() {
        let secp = Secp256k1::new();
        let (keys, p, _r) = setup(b"delay-vault");
        let trig_script = trigger_script(&p);
        let trigger_op = OutPoint::null();
        let dest = safe_dest();

        // properly built branch-A tx: nSequence encodes Δ
        let a = build_branch_a_tx(&p, trigger_op, 99_500, &dest, 500);
        let sh = p2wsh_sighash(&a, 0, &trig_script, 99_500);
        let sig_hot = ecdsa_witness_sig(&sh, &keys.hot_sk);
        let witness = || vec![sig_hot.clone(), vec![1u8]]; // [sigA, <true selector>]

        // before Δ: immature → rejected
        let before = EvalCtx {
            input_sequence: a.input[0].sequence,
            confirmations: (DELTA - 1) as u32,
            tx_version: a.version.0,
            sighash: sh,
        };
        assert_eq!(eval(&secp, &trig_script, witness(), &before), Err(EvalError::Immature));

        // at/after Δ: valid
        let after = EvalCtx { confirmations: DELTA as u32, ..reeval(&before) };
        assert_eq!(eval(&secp, &trig_script, witness(), &after), Ok(true));

        // A signer can choose a sequence above the script minimum. BIP-68
        // maturity follows that actual sequence, not merely the CSV operand.
        let mut longer = a.clone();
        longer.input[0].sequence = Sequence::from_height(288);
        let longer_hash = p2wsh_sighash(&longer, 0, &trig_script, 99_500);
        let longer_sig = ecdsa_witness_sig(&longer_hash, &keys.hot_sk);
        let longer_ctx = EvalCtx { input_sequence: longer.input[0].sequence,
            confirmations: 144, tx_version: longer.version.0, sighash: longer_hash };
        for confirmations in [144, 287] {
            let ctx = EvalCtx { confirmations, ..reeval(&longer_ctx) };
            assert_eq!(eval(&secp, &trig_script, vec![longer_sig.clone(), vec![1]], &ctx), Err(EvalError::Immature));
        }
        let mature = EvalCtx { confirmations: 288, ..reeval(&longer_ctx) };
        assert_eq!(eval(&secp, &trig_script, vec![longer_sig, vec![1]], &mature), Ok(true));

        // a branch-A spend whose nSequence does NOT encode the delay (RBF-final) fails CSV
        let mut a_bad = a.clone();
        a_bad.input[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
        let sh_bad = p2wsh_sighash(&a_bad, 0, &trig_script, 99_500);
        let sig_bad = ecdsa_witness_sig(&sh_bad, &keys.hot_sk);
        let ctx_bad = EvalCtx {
            input_sequence: a_bad.input[0].sequence,
            confirmations: 10_000, // even fully matured
            tx_version: a_bad.version.0,
            sighash: sh_bad,
        };
        assert_eq!(
            eval(&secp, &trig_script, vec![sig_bad, vec![1u8]], &ctx_bad),
            Err(EvalError::CsvUnsatisfied)
        );
    }

    /// Full scenario (spec §4): derive hybrid identity → build vault → anchor the PQ
    /// commitment → an attacker unvaults during the window → the owner claws back to the
    /// designated safe destination.
    #[test]
    fn end_to_end_attack_then_clawback() {
        let secp = Secp256k1::new();
        let vault_id = b"e2e-scenario-0";
        let (keys, p, r) = setup(vault_id);

        // (1) hybrid identity is real: same seed → the wallet's PQ pubkey matches ours
        let id = bloch_btc_wallet::derive_identity(&seed(), false).unwrap();
        assert_eq!(id.pq_pubkey, keys.pq_pubkey);

        // (2) build the vault
        let dep_addr = deposit_address(&p);
        assert!(dep_addr.to_string().starts_with("bcrt1q"));
        let trig_script = trigger_script(&p);

        // (3) anchor the PQ commitment binding {vault addr, H(r), pq pk, safe dest, Δ}
        let safe = safe_dest();
        let anchor = PqShieldAnchor {
            version: ANCHOR_VERSION,
            target_chain: TargetChain::Bitcoin,
            btc_vault_address: dep_addr.to_string().into_bytes(),
            recovery_hash: p.recovery_hash,
            pq_recovery_pubkey: keys.pq_pubkey.clone(),
            designated_safe_dest: safe.to_string().into_bytes(),
            csv_delay: DELTA,
            policy: b"e2e-watchtower".to_vec(),
        };
        let signed = sign_anchor(&anchor, &keys.pq_secret).expect("PQ sign");
        // verified against the PQ key of the hybrid identity we already trust (§3), not
        // against whatever key the anchor happens to carry
        assert!(
            verify_anchor(&signed, &keys.pq_pubkey).is_ok(),
            "anchor must be PQ-authentic under the OWNER's key"
        );
        // the anchor's Δ agrees with the on-chain branch-A delay (spec §3.1 invariant);
        // both are u16, so this comparison cannot be papered over by a truncating cast
        assert_eq!(signed.anchor.csv_delay, p.csv_delay);

        // (4) attacker broadcasts the unvault U, creating the trigger T (window opens)
        let deposit_op = OutPoint::null();
        let u = build_unvault_tx(&p, deposit_op, 100_000, 500);
        let trigger_op = OutPoint { txid: u.compute_txid(), vout: 0 };
        let trigger_amount = u.output[0].value.to_sat();
        assert_eq!(u.output[0].script_pubkey, trigger_address(&p).script_pubkey());

        // during the delay window the attacker CANNOT use branch A (immature)
        let a = build_branch_a_tx(&p, trigger_op, trigger_amount, &attacker_dest(), 500);
        let sh_a = p2wsh_sighash(&a, 0, &trig_script, trigger_amount);
        // attacker doesn't even have the hot key; but even WITH a valid-looking sig it is immature
        let sig_a = ecdsa_witness_sig(&sh_a, &keys.hot_sk);
        let ctx_a = EvalCtx {
            input_sequence: a.input[0].sequence,
            confirmations: 5, // well inside Δ
            tx_version: a.version.0,
            sighash: sh_a,
        };
        assert_eq!(
            eval(&secp, &trig_script, vec![sig_a, vec![1u8]], &ctx_a),
            Err(EvalError::Immature),
            "branch A is CSV-locked for everyone during the window"
        );

        // (5) the owner claws back via branch B to the anchored safe destination — now
        let claw = build_clawback_tx(trigger_op, trigger_amount, &safe, 500);
        // the clawback pays EXACTLY the anchored designated_safe_dest
        assert_eq!(
            claw.output[0].script_pubkey.to_string(),
            {
                let checked = validate_destination(
                    std::str::from_utf8(&signed.anchor.designated_safe_dest).unwrap(),
                    NET,
                )
                .unwrap();
                checked.script_pubkey().to_string()
            }
        );
        let sh_c = p2wsh_sighash(&claw, 0, &trig_script, trigger_amount);
        let sig_c = ecdsa_witness_sig(&sh_c, &keys.recovery_sk);
        let ctx_c = EvalCtx {
            input_sequence: claw.input[0].sequence,
            confirmations: 5,
            tx_version: claw.version.0,
            sighash: sh_c,
        };
        assert_eq!(
            eval(&secp, &trig_script, vec![sig_c, r.to_vec(), vec![]], &ctx_c),
            Ok(true),
            "PQ-authorized clawback succeeds to the safe destination within Δ"
        );
    }

    #[test]
    fn destination_address_validation() {
        // a real regtest P2WSH deposit address round-trips through validation
        let (_k, p, _r) = setup(b"addr-check");
        let good = deposit_address(&p).to_string();
        assert!(validate_destination(&good, NET).is_ok());
        // wrong network (mainnet string on regtest) is rejected
        assert!(validate_destination("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", NET).is_err());
        // garbage is rejected
        assert!(validate_destination("not-an-address", NET).is_err());
    }

    // ── A4-M-5: vault key derivation versioning ─────────────────────────────

    /// A4-M-5 KAT: `derive_vault_keys` (V1) must remain byte-for-byte what it
    /// always was for the canonical seed — the SAME hot/recovery pubkeys the
    /// pre-fix code produced. Pins the exact BIP-84 receive-chain keys so an
    /// existing vault built under V1 never silently re-derives to different
    /// keys.
    #[test]
    fn v1_vault_keys_are_pinned_and_unchanged() {
        let keys = derive_vault_keys(&seed(), false);
        assert_eq!(keys.key_derivation, VaultKeyDerivation::V1SharedReceiveChain);
        assert_eq!(
            keys.hot_pubkey.to_string(),
            "02e7ab2537b5d49e970309aae06e9e49f36ce1c9febbd44ec8e0d1cca0b4f9c319",
            "V1 hot key must stay pinned to the historical BIP-84 m/84'/1'/0'/0/0 derivation"
        );
        assert_eq!(
            keys.recovery_pubkey.to_string(),
            "03eeed205a69022fed4a62a02457f3699b19c06bf74bf801acc6d9ae84bc16a9e1",
            "V1 recovery key must stay pinned to m/84'/1'/0'/0/1"
        );
    }

    /// A4-M-5: V1 (shared receive chain) and V2 (dedicated hardened branch)
    /// must derive DIFFERENT hot/recovery keys for the identical seed — this
    /// is the entire point of the fix (the vault's recovery key must not be
    /// the wallet's ordinary next receive address).
    #[test]
    fn v1_and_v2_vault_keys_diverge() {
        let v1 = derive_vault_keys(&seed(), false);
        let v2 = derive_vault_keys_v2(&seed(), false).unwrap();
        assert_eq!(v2.key_derivation, VaultKeyDerivation::V2DedicatedHardenedBranch);
        assert_ne!(v1.hot_pubkey, v2.hot_pubkey, "hot key must differ between V1 and V2");
        assert_ne!(v1.recovery_pubkey, v2.recovery_pubkey, "recovery key must differ between V1 and V2");
        assert_ne!(v1.hot_pubkey, v1.recovery_pubkey);
        assert_ne!(v2.hot_pubkey, v2.recovery_pubkey);
        // The PQ leg also diverges (I-13's domain-separated seed for V2).
        assert_ne!(v1.pq_pubkey, v2.pq_pubkey);
    }

    /// A4-M-5: V2's hot/recovery keys must NOT equal the wallet's ordinary
    /// BIP-84 receive-chain keys (index 0/1) that `bloch_btc_wallet::derive_identity`
    /// and V1 both expose — the concrete "distinct, unexposed" requirement
    /// the finding reported as violated.
    #[test]
    fn v2_vault_keys_are_not_the_wallet_receive_chain() {
        let v2 = derive_vault_keys_v2(&seed(), false).unwrap();
        let identity = bloch_btc_wallet::derive_identity(&seed(), false).unwrap();
        // The wallet's normal first receive address's pubkey is exactly V1's
        // hot_pubkey (compressed secp256k1 bytes) — confirm V2 is different.
        assert_ne!(v2.hot_pubkey.to_bytes(), identity.btc_pubkey);
    }

    /// A4-M-5: `derive_vault_keys_v2` must fail closed on a short seed rather
    /// than panic — new code, no back-compat panic behavior to preserve.
    #[test]
    fn v2_fails_closed_on_short_seed() {
        assert!(derive_vault_keys_v2(&[0x11u8; 8], false).is_err());
    }

    // ── helpers ──
    fn safe_dest() -> Address {
        // a fresh, unexposed P2WSH cold destination (spec §9.4)
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x33; 32]).unwrap();
        let pk = PublicKey::new(sk.public_key(&secp));
        let s = bitcoin::script::Builder::new()
            .push_key(&pk)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        Address::p2wsh(&s, NET)
    }
    fn attacker_dest() -> Address {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x44; 32]).unwrap();
        let pk = PublicKey::new(sk.public_key(&secp));
        let s = bitcoin::script::Builder::new()
            .push_key(&pk)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        Address::p2wsh(&s, NET)
    }
    /// Rebuild an EvalCtx borrowing another's fixed fields (confirmations overwritten).
    fn reeval(c: &EvalCtx) -> EvalCtx {
        EvalCtx {
            input_sequence: c.input_sequence,
            confirmations: c.confirmations,
            tx_version: c.tx_version,
            sighash: c.sighash,
        }
    }
}

#[cfg(test)]
mod audit_hardened_roles {
    use super::*;
    use bitcoin::bip32::Xpub;

    #[test]
    fn v3_roles_cannot_be_derived_from_the_shared_public_parent() {
        let seed = [42; 32];
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(NetworkKind::Test, &seed).unwrap();
        let parent = master.derive_priv(&secp,
            &DerivationPath::from_str("m/1999'/1'/0'").unwrap()).unwrap();
        let public = Xpub::from_priv(&secp, &parent);
        let keys = derive_vault_keys_v3(&seed, false).unwrap();
        for (role, expected) in [(0, keys.hot_sk), (1, keys.recovery_sk)] {
            let path = DerivationPath::from_str(&format!("m/{role}'")).unwrap();
            assert!(public.derive_pub(&secp, &path).is_err());
            assert_eq!(parent.derive_priv(&secp, &path).unwrap().private_key, expected);
        }
        let old = derive_vault_keys_v2(&seed, false).unwrap();
        assert_ne!(keys.hot_sk, keys.recovery_sk);
        assert_ne!(keys.hot_sk, old.hot_sk);
        assert_ne!(keys.recovery_sk, old.recovery_sk);
        assert_ne!(keys.pq_pubkey, old.pq_pubkey);
        assert_eq!(keys.hot_sk, derive_vault_keys_v3(&seed, false).unwrap().hot_sk);
        assert_ne!(keys.hot_sk, derive_vault_keys_v3(&seed, true).unwrap().hot_sk);
    }

    #[test]
    fn v3_refuses_invalid_seed_lengths() {
        for len in [0, 1, 31, 65, 4096] {
            assert!(derive_vault_keys_v3(&vec![42; len], false).is_err());
        }
    }
}

#[cfg(test)]
mod audit_secret_ownership {
    use super::*;
    #[test]
    fn explicit_wipe_clears_owned_pq_storage_without_changing_public_identity() {
        let mut keys = derive_vault_keys_v3(&[42;32], false).unwrap();
        let public = keys.pq_pubkey.clone();
        let cloned = keys.clone();
        assert!(!keys.pq_secret.is_empty());
        keys.zeroize();
        assert!(keys.pq_secret.is_empty());
        assert_eq!(keys.pq_pubkey, public);
        assert!(!cloned.pq_secret.is_empty(), "an independent clone owns its own allocation");
        // Both objects run the same wiping path on drop. This test deliberately
        // does not read freed memory or claim to inspect compiler-created copies.
    }
}

#[cfg(test)]
mod audit_versioned_restore {
    use super::*;
    #[test]
    fn explicit_restore_preserves_each_existing_derivation_and_refuses_short_seeds() {
        let seed = [42;32];
        for (version, original) in [
            (VaultKeyDerivation::V1SharedReceiveChain, derive_vault_keys(&seed, false)),
            (VaultKeyDerivation::V2DedicatedHardenedBranch, derive_vault_keys_v2(&seed, false).unwrap()),
            (VaultKeyDerivation::V3HardenedRoles, derive_vault_keys_v3(&seed, false).unwrap()),
        ] {
            let restored = derive_vault_keys_versioned(&seed, false, version).unwrap();
            assert_eq!(restored.hot_sk, original.hot_sk);
            assert_eq!(restored.recovery_sk, original.recovery_sk);
            assert_eq!(restored.pq_pubkey, original.pq_pubkey);
            assert_eq!(restored.pq_secret, original.pq_secret);
            for len in [0,1,31] {
                assert!(derive_vault_keys_versioned(&vec![42;len], false, version).is_err());
            }
        }
    }
}
