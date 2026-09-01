// SPDX-License-Identifier: AGPL-3.0-or-later

//! Payees, script hashes, and the hot wallet key.
//!
//! ## One derivation, and it is not in this file
//!
//! A Genesis-4 output is locked by 32 bytes, and there is exactly one way to
//! compute those bytes for a key you hold:
//! `bloch_pos_committee::script_hash::from_pubkey` — `SHA3-256(hybrid pubkey)`,
//! all 32. This crate calls it and does not re-implement it. Read that module
//! before changing anything here.
//!
//! ## What this crate used to do, and why it was wrong
//!
//! It derived every script hash — its own wallet's, its change, and every
//! recipient's — from a `bloch1q…` address: the 20 bytes the address encodes,
//! zero-extended to 32. That shape is real; it is how the Genesis-3 carryover
//! sits in the eUTXO set. But applied to a **native Genesis-4 key** it produces
//! a different UTXO-set key from the one the key's coins actually live under,
//! and consensus opens both (`script_hash::owns`), so nothing anywhere
//! complains. The two failures that follow are:
//!
//! 1. **A funded wallet that reads as empty.** Coins paid to
//!    `SHA3-256(pubkey)` are invisible to `listunspent` on
//!    `SHA3-256(pubkey)[..20] ‖ 0×12`. This crate polled the second and would
//!    have reported an empty hot wallet on a funded one.
//! 2. **A silent security downgrade for every payee.** The truncated form is
//!    protected by 160 bits of preimage resistance instead of 256 — the tier
//!    the carryover has because taking it away would freeze the opening
//!    ledger, handed to keys that never needed it.
//!
//! ## Networks
//!
//! The client is configured for ONE network and refuses payees from the other.
//! Mainnet is the default and every refusal that existed for it still fires;
//! testnet is an explicit opt-in ([`crate::withdraw::Config::network`]) so that
//! an exchange can rehearse the whole path on a chain where the coins are
//! worthless. A `script_hash` carries no network marker — it cannot, it is a
//! hash — so the network check applies to addresses only, and the isolation
//! that matters is outpoint disjointness, not string prefixes
//! (`deploy/testnet/REPLAY-ISOLATION.md`).

use bloch_crypto::address::{Address, Network};
use bloch_pos_committee::script_hash;

pub use bloch_crypto::address::Network as PayeeNetwork;
/// Consensus's ownership rule, from the consensus crate. This crate used to
/// carry a verbatim copy; a copied consensus rule is a second implementation
/// waiting to drift.
pub use bloch_pos_committee::script_hash::owns;

/// A 32-byte eUTXO locking key.
pub type ScriptHash = [u8; 32];

/// How a payee was named. Kept on the record because the two forms have
/// different security properties and an operator is entitled to know which one
/// a payment used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayeeForm {
    /// A 64-hex `script_hash` — the native Genesis-4 identifier.
    ScriptHash,
    /// A `bloch1q…`/`bloch1t…` address, accepted only under
    /// [`crate::withdraw::Config::allow_carryover_address`]. Pays the carried
    /// 20-byte shape, at the Genesis-3 security tier.
    CarryoverAddress,
}

/// Parse a payee into the 32 bytes its output will be locked to.
///
/// The accepted form is a **64-hex `script_hash`**, which is what
/// `bloch-pos spendkey` prints and the only identifier a native Genesis-4 key
/// has. It carries no network marker, so it is accepted on either network —
/// see the module docs for why that is not the isolation boundary.
///
/// An **address** is refused unless `allow_carryover_address` is set, and even
/// then only when its network matches `network`:
///
/// * On a mainnet-configured client a `bloch1t…` is refused, exactly as before.
///   That refusal is not weakened by anything here.
/// * On a testnet-configured client a `bloch1q…` is now refused too — the
///   symmetric guard the old code did not have.
/// * An address on the RIGHT network is still refused by default, because the
///   client cannot tell a Genesis-3 carryover holder (for whom the truncated
///   shape is correct) from someone who simply pasted the address form of a
///   native key (for whom it silently splits their balance across two keys and
///   drops them to 160-bit protection).
pub fn parse_payee(
    s: &str,
    network: Network,
    allow_carryover_address: bool,
) -> Result<(ScriptHash, PayeeForm), String> {
    let t = s.trim();
    if let Some(h) = crate::hex32(t) {
        return Ok((h, PayeeForm::ScriptHash));
    }
    let addr = Address::parse(t).map_err(|e| {
        format!(
            "not a payee: expected a 64-hex script_hash (what `bloch-pos spendkey` prints); \
             parsing it as an address also failed: {e}"
        )
    })?;
    if addr.network() != network {
        return Err(format!(
            "that is a {} address and this client is configured for {}. Refusing.",
            net_name(addr.network()),
            net_name(network),
        ));
    }
    if !allow_carryover_address {
        return Err(
            "Genesis-4 names a payee by a 32-byte script_hash, not by an address. An address \
             carries 20 bytes, and locking an output to those 20 bytes zero-extended is a \
             DIFFERENT key in the UTXO set from SHA3-256(their pubkey): a native-key holder \
             paid this way sees a zero balance where they expected the coins, and gets 160 \
             bits of preimage resistance instead of 256. Ask the payee for their script_hash. \
             If they are a Genesis-3 carryover holder — the one case where the 20-byte form is \
             genuinely theirs — set `allow_carryover_address`."
                .into(),
        );
    }
    Ok((
        script_hash::carried_from_g3_hash160(addr.hash_bytes()),
        PayeeForm::CarryoverAddress,
    ))
}

fn net_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet (bloch1q…)",
        Network::Testnet => "testnet (bloch1t…)",
    }
}

/// The hot wallet's hybrid keypair (suite-enveloped ML-DSA-65 ‖ Falcon-1024,
/// as bloch-crypto produces it). Secret bytes never leave this struct and it
/// implements neither `Debug` nor `Clone` on purpose.
pub struct KeyMaterial {
    pubkey: Vec<u8>,
    secret: Vec<u8>,
}

impl KeyMaterial {
    /// Deterministic keypair from a >=32-byte seed. The seed IS the wallet:
    /// generate and store it with the discipline of BLOCH-GENESIS-KEYS.md
    /// (air-gapped, human-held), not in the process that runs this client's
    /// polling loop, if you can avoid it.
    pub fn from_seed(seed: &[u8]) -> Result<KeyMaterial, String> {
        let (pubkey, secret) =
            bloch_crypto::crypto::generate_keypair_from_seed(seed).map_err(|e| e.to_string())?;
        Ok(KeyMaterial { pubkey, secret })
    }

    /// Fresh keypair from OS entropy.
    pub fn generate() -> KeyMaterial {
        let (pubkey, secret) = bloch_crypto::crypto::generate_keypair();
        KeyMaterial { pubkey, secret }
    }

    /// Wrap already-generated suite-enveloped key bytes (e.g. loaded from an
    /// external keystore). No validation beyond signing being able to fail
    /// later — the envelope is bloch-crypto's to judge.
    pub fn from_parts(pubkey: Vec<u8>, secret: Vec<u8>) -> KeyMaterial {
        KeyMaterial { pubkey, secret }
    }

    /// The suite-enveloped public key — the bytes that go into a transfer's
    /// witness, and the bytes whose SHA3-256 an output's script hash commits
    /// to.
    pub fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    /// This wallet's address on `network`, for display only.
    ///
    /// Genesis-4 does not pay to addresses and neither does this crate; the
    /// address is a 20-byte truncation of the same hash and exists here so an
    /// operator can eyeball a wallet in a log. Do not derive a script hash
    /// from it — that is the bug this module's docs are about.
    pub fn address(&self, network: Network) -> Address {
        Address::from_pubkey(&self.pubkey, network)
    }

    /// The script hash this wallet's coins live under: `SHA3-256(pubkey)`, the
    /// one derivation, from the consensus crate.
    ///
    /// This is the value to hand to `getbalance` / `listunspent`, and the one
    /// change outputs are locked to. It has no network: a hash is a hash.
    pub fn script_hash(&self) -> ScriptHash {
        script_hash::from_pubkey(&self.pubkey)
    }

    /// Hybrid signature over a 32-byte signing root, both halves.
    pub fn sign(&self, signing_root: &[u8; 32]) -> Result<Vec<u8>, String> {
        bloch_crypto::crypto::sign(&self.secret, signing_root).map_err(|e| e.to_string())
    }
}

/// SHA3-256 of a public key. Identical to
/// [`bloch_pos_committee::script_hash::from_pubkey`] and kept only as the
/// familiar name for the left operand of [`owns`].
pub fn key_hash(pubkey: &[u8]) -> [u8; 32] {
    script_hash::from_pubkey(pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wallet watches the hash its coins are actually under. The old
    /// version of this test asserted the OPPOSITE — `&sh[20..] == [0u8; 12]`,
    /// "address-derived form must be zero-padded" — which is precisely the bug:
    /// it pinned the wallet to a UTXO-set key that a faucet or a counterparty
    /// paying `SHA3-256(pubkey)` never touches.
    #[test]
    fn the_wallet_watches_the_hash_its_coins_are_under() {
        let key = KeyMaterial::from_seed(&[7u8; 32]).unwrap();
        let sh = key.script_hash();
        assert_eq!(
            sh,
            bloch_pos_committee::script_hash::from_pubkey(key.pubkey()),
            "the wallet's script hash IS the canonical derivation, not a re-derivation"
        );
        assert!(owns(&key_hash(key.pubkey()), &sh));
        assert!(
            !bloch_pos_committee::script_hash::is_carried_shape(&sh),
            "a native key's hash is 32 bytes of digest, not 20 and twelve zeroes"
        );
    }

    /// The whole point of the change: the two forms are different keys, and the
    /// client must not quietly pay the weaker one.
    #[test]
    fn the_address_form_of_a_native_key_is_a_different_key() {
        let key = KeyMaterial::from_seed(&[7u8; 32]).unwrap();
        let printed = key.address(Network::Mainnet).to_string();
        let (from_addr, form) = parse_payee(&printed, Network::Mainnet, true).unwrap();
        assert_eq!(form, PayeeForm::CarryoverAddress);
        assert_ne!(
            from_addr,
            key.script_hash(),
            "if these are ever equal the two forms have been collapsed and every balance moved"
        );
        // Both are spendable by the same key — which is exactly why the split
        // is silent rather than loud.
        assert!(owns(&key_hash(key.pubkey()), &from_addr));
        assert!(owns(&key_hash(key.pubkey()), &key.script_hash()));
    }

    /// THE MAINNET REFUSAL, UNCHANGED. A mainnet-configured client still
    /// refuses a `bloch1t…` payee, with or without the carryover opt-in.
    #[test]
    fn a_mainnet_client_still_refuses_a_testnet_address() {
        let addr = Address::from_hash([9u8; 20], Network::Testnet).to_string();
        assert!(parse_payee(&addr, Network::Mainnet, false).is_err());
        assert!(
            parse_payee(&addr, Network::Mainnet, true).is_err(),
            "the carryover opt-in must not be a way around the network check"
        );
    }

    /// The new, symmetric refusal the old code did not have.
    #[test]
    fn a_testnet_client_refuses_a_mainnet_address() {
        let addr = Address::from_hash([9u8; 20], Network::Mainnet).to_string();
        assert!(parse_payee(&addr, Network::Testnet, true).is_err());
    }

    /// A well-formed address on the right network is STILL refused by default.
    #[test]
    fn an_address_is_refused_by_default_even_on_the_right_network() {
        let addr = Address::from_hash([9u8; 20], Network::Mainnet).to_string();
        let e = parse_payee(&addr, Network::Mainnet, false).unwrap_err();
        assert!(e.contains("script_hash"), "the refusal must say what to ask for instead: {e}");
    }

    /// And this is the fix for the defect: a script_hash works on the testnet.
    #[test]
    fn a_script_hash_payee_is_accepted_on_both_networks() {
        let sh = "ab".repeat(32);
        for net in [Network::Mainnet, Network::Testnet] {
            let (h, form) = parse_payee(&sh, net, false).expect("64-hex script_hash is the payee form");
            assert_eq!(form, PayeeForm::ScriptHash);
            assert_eq!(h, [0xabu8; 32]);
        }
    }

    #[test]
    fn bad_checksum_refused() {
        let mut s = Address::from_hash([9u8; 20], Network::Mainnet).to_string();
        let flip = if s.ends_with('0') { "1" } else { "0" };
        s.replace_range(s.len() - 1.., flip);
        assert!(parse_payee(&s, Network::Mainnet, true).is_err());
    }

    /// Neither a truncated nor an over-long hex string may slip through as a
    /// script_hash and then be reinterpreted as an address.
    #[test]
    fn near_miss_hex_is_refused_rather_than_reinterpreted() {
        for bad in ["ab".repeat(31), "ab".repeat(33), "zz".repeat(32)] {
            assert!(parse_payee(&bad, Network::Mainnet, true).is_err(), "{bad} must not parse");
        }
    }
}
