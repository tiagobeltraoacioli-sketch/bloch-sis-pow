//! # bloch-pq-vault — a non-custodial, native, opt-in post-quantum *defensive vault*
//!
//! > **Nothing here is deployed, on either Bloch chain.** The Bitcoin-side
//! > scripts are real and tested, but the Bloch-side anchor depends on
//! > [`bloch_euvm`], a Genesis-3-era crate that was never wired into
//! > consensus. The proof-of-work chain it was designed against stopped
//! > permanently at height 39,918 on 2026-08-13; the live chain is
//! > **Genesis-4, proof of stake**, which has no contract VM and no anchoring
//! > path for this record. Unaudited. See HONEST LIMITS below.
//!
//! FOUNDATION. Implements the **achievable, honest** scope of
//! `docs/specs/PQ-SHIELD-NONCUSTODIAL-NATIVE.md`: a **commit-delay-reveal P2WSH vault**
//! on stock Bitcoin, plus a **PQ-gated clawback**, anchored on Bloch by a PQ-signed
//! commitment. It composes the repo's building blocks:
//!
//! - [`bloch_btc_wallet`] — one seed → BTC (secp256k1) + companion PQ key
//!   (ML-DSA-65 ‖ Falcon-1024). Reused for the hybrid identity and the anchor guard.
//! - [`bloch_crypto`] — `generate_keypair_from_seed` / `sign` / `verify` (the PQ half).
//! - [`bloch_euvm`] `modules` — the `Custody` (hybrid 2-of-2) / `Governance` (n-of-m)
//!   validators the anchor's guard program reuses.
//! - the `bitcoin` crate — real P2WSH scripts, transactions, BIP-143 sighashes.
//!
//! Three modules:
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
//!    shape is enforced by **pre-signed transactions + secure deletion of the deposit
//!    bypass key** (Revault-style) — an *operational* trust assumption, not consensus.
//!    This crate builds and signs those txs; it cannot make anyone delete a key.
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

pub mod anchor;
pub mod preimage;
pub mod script_eval;
pub mod vault;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, NetworkKind, PublicKey};
use std::str::FromStr;

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
}

/// Derive [`VaultKeys`] from a seed. The BTC hot key is BIP-84 index 0, the recovery key
/// index 1 (a distinct, unexposed key — spec §9.4), on the same account; the PQ keypair
/// is `bloch_crypto::generate_keypair_from_seed(seed)` (the exact companion key
/// [`bloch_btc_wallet::derive_identity`] exposes the public half of).
pub fn derive_vault_keys(seed: &[u8], mainnet: bool) -> VaultKeys {
    let secp = Secp256k1::new();
    let net = if mainnet { NetworkKind::Main } else { NetworkKind::Test };
    let coin = if mainnet { "0'" } else { "1'" };
    let master = Xpriv::new_master(net, seed).expect("valid master seed");

    let derive = |idx: u32| -> (SecretKey, PublicKey) {
        let path = DerivationPath::from_str(&format!("m/84'/{coin}/0'/0/{idx}")).expect("path");
        let xpriv = master.derive_priv(&secp, &path).expect("derive");
        let sk = xpriv.private_key;
        let pk = PublicKey::new(sk.public_key(&secp));
        (sk, pk)
    };
    let (hot_sk, hot_pubkey) = derive(0);
    let (recovery_sk, recovery_pubkey) = derive(1);

    let (pq_pubkey, pq_secret) =
        bloch_crypto::crypto::generate_keypair_from_seed(seed).expect("pq keygen from seed");

    VaultKeys { hot_sk, hot_pubkey, recovery_sk, recovery_pubkey, pq_pubkey, pq_secret }
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
        let id = bloch_btc_wallet::derive_identity(&seed(), false);
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
            csv_delay: DELTA as u32,
            policy: b"e2e-watchtower".to_vec(),
        };
        let signed = sign_anchor(&anchor, &keys.pq_secret).expect("PQ sign");
        assert!(verify_anchor(&signed).is_ok(), "anchor must be PQ-authentic");
        // the anchor's Δ agrees with the on-chain branch-A delay (spec §3.1 invariant)
        assert_eq!(signed.anchor.csv_delay as u16, p.csv_delay);

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
