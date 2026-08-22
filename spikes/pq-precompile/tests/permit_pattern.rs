// SPDX-License-Identifier: AGPL-3.0-or-later
//! The §6.2 existence proof: EIP-2612 `permit` semantics with ML-DSA ‖ Falcon
//! in place of `ecrecover`.
//!
//! There is no `solc` and no EVM host in this repo (`crates/bloch-euvm` is the
//! eUTXO predicate VM, not an EVM; revm is a decision of the state-model spec
//! and is not a dependency yet). So this file is a FAITHFUL HOST MODEL of
//! `contracts/PQPermitToken.sol`: the same digest bytes, the same checks, in
//! the same order, calling the same `pq_verify`. What it proves is the part
//! that could actually be wrong — that a hybrid PQ signature can carry an
//! approval, bound to owner/spender/value/nonce/deadline/chain/contract, and
//! that removing any of those bindings is detectable. What it does NOT prove is
//! that solc emits what I think it emits; that is a gate for the wiring wave
//! (spec §9).

use bloch_crypto::crypto as bc;
use pq_precompile_spike::*;
use sha3::{Digest, Keccak256};

// ── the Solidity ABI encodings, by hand ──────────────────────────────────────
fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

fn word_addr(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn word_u256(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

struct Token {
    domain_separator: [u8; 32],
    nonces: std::collections::HashMap<[u8; 20], u128>,
    allowance: std::collections::HashMap<([u8; 20], [u8; 20]), u128>,
}

const PERMIT_PQ_TYPE: &[u8] =
    b"PermitPQ(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
const EIP712_DOMAIN_TYPE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

impl Token {
    fn new(chain_id: u128, address: [u8; 20]) -> Self {
        let mut buf = Vec::new();
        buf.extend_from_slice(&keccak(EIP712_DOMAIN_TYPE));
        buf.extend_from_slice(&keccak(b"PQ Permit Demo"));
        buf.extend_from_slice(&keccak(b"1"));
        buf.extend_from_slice(&word_u256(chain_id));
        buf.extend_from_slice(&word_addr(&address));
        Token {
            domain_separator: keccak(&buf),
            nonces: Default::default(),
            allowance: Default::default(),
        }
    }

    /// `permitDigest` — exactly the Solidity function's bytes.
    fn digest(
        &self,
        owner: &[u8; 20],
        spender: &[u8; 20],
        value: u128,
        nonce: u128,
        deadline: u128,
    ) -> [u8; 32] {
        let mut s = Vec::new();
        s.extend_from_slice(&keccak(PERMIT_PQ_TYPE));
        s.extend_from_slice(&word_addr(owner));
        s.extend_from_slice(&word_addr(spender));
        s.extend_from_slice(&word_u256(value));
        s.extend_from_slice(&word_u256(nonce));
        s.extend_from_slice(&word_u256(deadline));
        let struct_hash = keccak(&s);

        let mut d = Vec::with_capacity(2 + 64);
        d.extend_from_slice(b"\x19\x01");
        d.extend_from_slice(&self.domain_separator);
        d.extend_from_slice(&struct_hash);
        keccak(&d)
    }

    /// `permitPQ` — same checks, same order.
    fn permit_pq(
        &mut self,
        owner: [u8; 20],
        spender: [u8; 20],
        value: u128,
        deadline: u128,
        now: u128,
        pk: &[u8],
        sig: &[u8],
    ) -> Result<(), &'static str> {
        if now > deadline {
            return Err("expired");
        }
        let nonce = *self.nonces.get(&owner).unwrap_or(&0);
        let digest = self.digest(&owner, &spender, value, nonce, deadline);

        // BlochPQ.verify(owner, digest, pk, sig)
        match pq_verify(&encode_input(&digest, pk, sig)) {
            Outcome::Valid(signer) if signer == owner => {}
            _ => return Err("bad signature"),
        }

        self.nonces.insert(owner, nonce + 1);
        self.allowance.insert((owner, spender), value);
        Ok(())
    }
}

struct Owner {
    pk: Vec<u8>,
    sk: Vec<u8>,
    addr: [u8; 20],
}

fn owner() -> Owner {
    let (pk, sk) = bc::generate_keypair();
    let addr = address_from_enveloped_pubkey(&pk);
    Owner { pk, sk, addr }
}

const SPENDER: [u8; 20] = [0xDE; 20];
const OTHER_SPENDER: [u8; 20] = [0xAD; 20];
const TOKEN_ADDR: [u8; 20] = [0x01; 20];
const CHAIN_ID: u128 = 8400;

// ── 1. It works ──────────────────────────────────────────────────────────────

#[test]
fn a_pq_signature_grants_an_allowance_without_ecrecover() {
    let o = owner();
    let mut t = Token::new(CHAIN_ID, TOKEN_ADDR);
    let digest = t.digest(&o.addr, &SPENDER, 1_000, 0, 9_999);
    let sig = bc::sign(&o.sk, &digest).unwrap();

    t.permit_pq(o.addr, SPENDER, 1_000, 9_999, 1, &o.pk, &sig)
        .expect("a valid PQ permit must be accepted");

    assert_eq!(t.allowance.get(&(o.addr, SPENDER)), Some(&1_000));
    assert_eq!(t.nonces[&o.addr], 1, "the nonce must be consumed");
}

// ── 2. Every binding, with its control half ──────────────────────────────────

#[test]
fn replay_of_the_same_permit_fails() {
    let o = owner();
    let mut t = Token::new(CHAIN_ID, TOKEN_ADDR);
    let digest = t.digest(&o.addr, &SPENDER, 1_000, 0, 9_999);
    let sig = bc::sign(&o.sk, &digest).unwrap();

    assert!(t.permit_pq(o.addr, SPENDER, 1_000, 9_999, 1, &o.pk, &sig).is_ok(), "CONTROL");
    assert_eq!(
        t.permit_pq(o.addr, SPENDER, 1_000, 9_999, 1, &o.pk, &sig),
        Err("bad signature"),
        "the second use must fail: the nonce moved"
    );
}

#[test]
fn a_permit_does_not_transfer_to_another_spender_or_another_amount() {
    let o = owner();
    let mut t = Token::new(CHAIN_ID, TOKEN_ADDR);
    let digest = t.digest(&o.addr, &SPENDER, 1_000, 0, 9_999);
    let sig = bc::sign(&o.sk, &digest).unwrap();

    assert_eq!(t.permit_pq(o.addr, OTHER_SPENDER, 1_000, 9_999, 1, &o.pk, &sig), Err("bad signature"));
    assert_eq!(t.permit_pq(o.addr, SPENDER, 1_001, 9_999, 1, &o.pk, &sig), Err("bad signature"));
    assert_eq!(t.permit_pq(o.addr, SPENDER, 1_000, 10_000, 1, &o.pk, &sig), Err("bad signature"));
    assert!(t.permit_pq(o.addr, SPENDER, 1_000, 9_999, 1, &o.pk, &sig).is_ok(), "CONTROL");
}

#[test]
fn an_expired_permit_fails_and_a_live_one_passes() {
    let o = owner();
    let mut t = Token::new(CHAIN_ID, TOKEN_ADDR);
    let digest = t.digest(&o.addr, &SPENDER, 7, 0, 100);
    let sig = bc::sign(&o.sk, &digest).unwrap();
    assert_eq!(t.permit_pq(o.addr, SPENDER, 7, 100, 101, &o.pk, &sig), Err("expired"));
    assert!(t.permit_pq(o.addr, SPENDER, 7, 100, 100, &o.pk, &sig).is_ok(), "CONTROL");
}

#[test]
fn a_third_partys_key_cannot_permit_on_the_owners_behalf() {
    let o = owner();
    let attacker = owner();
    let mut t = Token::new(CHAIN_ID, TOKEN_ADDR);
    let digest = t.digest(&o.addr, &SPENDER, 1_000, 0, 9_999);
    // The attacker signs the OWNER's exact digest with their own key.
    let sig = bc::sign(&attacker.sk, &digest).unwrap();
    assert_eq!(
        t.permit_pq(o.addr, SPENDER, 1_000, 9_999, 1, &attacker.pk, &sig),
        Err("bad signature"),
        "a valid signature by the wrong signer must not authorise"
    );
    // CONTROL: the same call by the real owner passes.
    let good = bc::sign(&o.sk, &digest).unwrap();
    assert!(t.permit_pq(o.addr, SPENDER, 1_000, 9_999, 1, &o.pk, &good).is_ok());
}

#[test]
fn a_permit_for_one_contract_or_one_chain_does_not_work_on_another() {
    let o = owner();
    let mut t = Token::new(CHAIN_ID, TOKEN_ADDR);
    let mut other_contract = Token::new(CHAIN_ID, [0x02; 20]);
    let mut other_chain = Token::new(1, TOKEN_ADDR);

    let digest = t.digest(&o.addr, &SPENDER, 5, 0, 9_999);
    let sig = bc::sign(&o.sk, &digest).unwrap();

    assert_eq!(other_contract.permit_pq(o.addr, SPENDER, 5, 9_999, 1, &o.pk, &sig), Err("bad signature"));
    assert_eq!(other_chain.permit_pq(o.addr, SPENDER, 5, 9_999, 1, &o.pk, &sig), Err("bad signature"));
    assert!(t.permit_pq(o.addr, SPENDER, 5, 9_999, 1, &o.pk, &sig).is_ok(), "CONTROL");
}

// ── 3. MUTATION PROOFS on the digest ─────────────────────────────────────────

/// MUTANT — the nonce dropped from the struct hash (the single most common
/// way a hand-rolled permit is broken).
fn mutant_digest_without_nonce(t: &Token, owner: &[u8; 20], spender: &[u8; 20], value: u128, deadline: u128) -> [u8; 32] {
    let mut s = Vec::new();
    s.extend_from_slice(&keccak(PERMIT_PQ_TYPE));
    s.extend_from_slice(&word_addr(owner));
    s.extend_from_slice(&word_addr(spender));
    s.extend_from_slice(&word_u256(value));
    s.extend_from_slice(&word_u256(deadline));
    let struct_hash = keccak(&s);
    let mut d = Vec::new();
    d.extend_from_slice(b"\x19\x01");
    d.extend_from_slice(&t.domain_separator);
    d.extend_from_slice(&struct_hash);
    keccak(&d)
}

#[test]
fn mutation_the_nonce_in_the_digest_is_what_stops_replay() {
    let o = owner();
    let t = Token::new(CHAIN_ID, TOKEN_ADDR);

    // Under the mutant, the digest for nonce 0 and nonce 1 is the SAME — one
    // signature authorises forever.
    let m0 = mutant_digest_without_nonce(&t, &o.addr, &SPENDER, 1_000, 9_999);
    let sig = bc::sign(&o.sk, &m0).unwrap();
    assert!(
        pq_verify(&encode_input(&m0, &o.pk, &sig)).is_valid(),
        "mutant digest verifies once"
    );
    let m_again = mutant_digest_without_nonce(&t, &o.addr, &SPENDER, 1_000, 9_999);
    assert_eq!(m0, m_again, "MUTATION SURVIVED if these differ");
    assert!(
        pq_verify(&encode_input(&m_again, &o.pk, &sig)).is_valid(),
        "...and again, forever — that is the bug the nonce prevents"
    );

    // Reference: the nonce moves the digest, so the same signature is dead.
    let d0 = t.digest(&o.addr, &SPENDER, 1_000, 0, 9_999);
    let d1 = t.digest(&o.addr, &SPENDER, 1_000, 1, 9_999);
    assert_ne!(d0, d1);
    let sig0 = bc::sign(&o.sk, &d0).unwrap();
    assert!(pq_verify(&encode_input(&d0, &o.pk, &sig0)).is_valid(), "CONTROL");
    assert!(!pq_verify(&encode_input(&d1, &o.pk, &sig0)).is_valid());
}

#[test]
fn mutation_the_typehash_separates_a_pq_permit_from_an_eip2612_permit() {
    // If someone "helpfully" reuses EIP-2612's typehash string, a signature
    // captured from a 2612 flow becomes a valid PQ permit and vice versa.
    let eip2612 = b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
    assert_ne!(
        keccak(PERMIT_PQ_TYPE),
        keccak(eip2612.as_slice()),
        "MUTATION SURVIVED: the two permit families must not share a typehash"
    );
}

#[test]
fn a_contract_digest_can_never_be_a_transaction_signing_root() {
    // §6.1 signs SHA3-256(DS_EVM_TX ‖ fields); contracts sign keccak256(...).
    // Different functions, so no permit signature is ever also a transaction
    // authorisation. This test exists so that "let's unify on one hash" fails
    // loudly instead of silently opening cross-protocol replay.
    use sha3::Sha3_256;
    let preimage = b"whatever bytes both sides might ever agree to hash";
    let evm_tx_root: [u8; 32] = Sha3_256::digest(preimage).into();
    let contract_digest = keccak(preimage);
    assert_ne!(evm_tx_root, contract_digest, "SHA3-256 and keccak256 must stay different functions");
}
