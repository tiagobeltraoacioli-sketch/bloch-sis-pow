// SPDX-License-Identifier: AGPL-3.0-or-later
//! §6.2 (c) — a `permit` that authorizes by ML-DSA-65 ‖ Falcon-1024 instead
//! of `ecrecover`, proving the contract pattern is possible at all.
//!
//! # What this is, and what it is not
//!
//! There is no pinned `solc` and no EVM in this repository, so these tests
//! are a HOST MODEL of `contracts/PQPermitToken.sol`: the same EIP-712 digest
//! bytes (`keccak256`, chain id, verifying contract), the same checks in the
//! same order, the same `pq_verify` call. That is enough to prove the
//! pattern, the digest binding, and the replay properties. It is NOT
//! execution: compiling the Solidity with a pinned solc and re-running this
//! file against a pinned EVM is an activation gate, listed as one.
//!
//! Every rejection test has its control half.

mod common;
use common::{alice, mallory, strip, Signer};

use bloch_evm_pq_precompile::*;
use sha3::{Digest, Keccak256};

// ── The host model of PQPermitToken.sol ─────────────────────────────────────

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
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

const NAME: &[u8] = b"PQ Permit Demo";
const VERSION: &[u8] = b"1";

struct PqPermitToken {
    address: [u8; 20],
    chain_id: u128,
    balance: std::collections::HashMap<[u8; 20], u128>,
    allowance: std::collections::HashMap<([u8; 20], [u8; 20]), u128>,
    nonces: std::collections::HashMap<[u8; 20], u128>,
}

#[derive(Debug, PartialEq, Eq)]
enum Revert {
    Expired,
    BadSignature,
    WrongSigner,
}

impl PqPermitToken {
    fn new(address: [u8; 20], chain_id: u128) -> Self {
        Self {
            address,
            chain_id,
            balance: Default::default(),
            allowance: Default::default(),
            nonces: Default::default(),
        }
    }

    fn domain_typehash() -> [u8; 32] {
        keccak(&[b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"])
    }

    /// NOT `Permit(...)`. Deliberately a different type, so no signature can
    /// cross between the EIP-2612 family and this one.
    fn permit_pq_typehash() -> [u8; 32] {
        keccak(&[b"PermitPQ(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"])
    }

    fn domain_separator(&self) -> [u8; 32] {
        keccak(&[
            &Self::domain_typehash(),
            &keccak(&[NAME]),
            &keccak(&[VERSION]),
            &word_u256(self.chain_id),
            &word_addr(&self.address),
        ])
    }

    fn permit_digest(
        &self,
        owner: &[u8; 20],
        spender: &[u8; 20],
        value: u128,
        nonce: u128,
        deadline: u128,
    ) -> [u8; 32] {
        let struct_hash = keccak(&[
            &Self::permit_pq_typehash(),
            &word_addr(owner),
            &word_addr(spender),
            &word_u256(value),
            &word_u256(nonce),
            &word_u256(deadline),
        ]);
        keccak(&[b"\x19\x01", &self.domain_separator(), &struct_hash])
    }

    #[allow(clippy::too_many_arguments)]
    fn permit_pq(
        &mut self,
        now: u128,
        owner: [u8; 20],
        spender: [u8; 20],
        value: u128,
        deadline: u128,
        pk: &[u8],
        sig: &[u8],
    ) -> Result<(), Revert> {
        if now > deadline {
            return Err(Revert::Expired);
        }
        let nonce = *self.nonces.get(&owner).unwrap_or(&0);
        let digest = self.permit_digest(&owner, &spender, value, nonce, deadline);

        // BlochPQ.recover — the one line the whole pattern rests on.
        let out = pq_verify_raw(&encode_input(&digest, pk, sig));
        if out == REJECTED {
            return Err(Revert::BadSignature);
        }
        let mut signer = [0u8; 20];
        signer.copy_from_slice(&out[12..]);
        if signer != owner {
            return Err(Revert::WrongSigner);
        }

        *self.nonces.entry(owner).or_insert(0) += 1;
        self.allowance.insert((owner, spender), value);
        Ok(())
    }

    fn transfer_from(&mut self, from: [u8; 20], caller: [u8; 20], to: [u8; 20], value: u128) -> bool {
        let a = *self.allowance.get(&(from, caller)).unwrap_or(&0);
        let b = *self.balance.get(&from).unwrap_or(&0);
        if a < value || b < value {
            return false;
        }
        self.allowance.insert((from, caller), a - value);
        self.balance.insert(from, b - value);
        *self.balance.entry(to).or_insert(0) += value;
        true
    }
}

// ── Fixtures ────────────────────────────────────────────────────────────────

const TOKEN: [u8; 20] = [0xC0; 20];
const SPENDER: [u8; 20] = [0xDE; 20];
const OTHER_SPENDER: [u8; 20] = [0xAD; 20];
const CHAIN_ID: u128 = 8400;
const NOW: u128 = 1_000_000;
const DEADLINE: u128 = 1_000_100;
const VALUE: u128 = 42_000;

fn signed_permit(
    token: &PqPermitToken,
    signer: &Signer,
    owner: &[u8; 20],
    spender: &[u8; 20],
    value: u128,
    nonce: u128,
    deadline: u128,
) -> Vec<u8> {
    let digest = token.permit_digest(owner, spender, value, nonce, deadline);
    signer.sign(&digest)
}

// ── The pattern works ───────────────────────────────────────────────────────

#[test]
fn a_pq_signature_grants_an_allowance_and_the_allowance_spends() {
    let a = alice();
    let owner = a.address20();
    let mut t = PqPermitToken::new(TOKEN, CHAIN_ID);
    t.balance.insert(owner, 100_000);

    let sig = signed_permit(&t, a, &owner, &SPENDER, VALUE, 0, DEADLINE);
    assert_eq!(t.permit_pq(NOW, owner, SPENDER, VALUE, DEADLINE, &a.pk, &sig), Ok(()));
    assert_eq!(t.allowance.get(&(owner, SPENDER)), Some(&VALUE));
    assert_eq!(t.nonces.get(&owner), Some(&1));

    // The allowance is real: the spender can move the owner's balance.
    assert!(t.transfer_from(owner, SPENDER, OTHER_SPENDER, 1_000));
    assert_eq!(t.balance.get(&owner), Some(&99_000));
    assert_eq!(t.allowance.get(&(owner, SPENDER)), Some(&(VALUE - 1_000)));
}

// ── Replay ──────────────────────────────────────────────────────────────────

#[test]
fn the_same_permit_cannot_be_replayed() {
    let a = alice();
    let owner = a.address20();
    let mut t = PqPermitToken::new(TOKEN, CHAIN_ID);
    let sig = signed_permit(&t, a, &owner, &SPENDER, VALUE, 0, DEADLINE);
    assert_eq!(t.permit_pq(NOW, owner, SPENDER, VALUE, DEADLINE, &a.pk, &sig), Ok(()));
    assert_eq!(
        t.permit_pq(NOW, owner, SPENDER, VALUE, DEADLINE, &a.pk, &sig),
        Err(Revert::BadSignature),
        "the nonce moved, so the replayed bytes sign a digest nobody signed"
    );
    // control: a permit for the NEW nonce is accepted.
    let sig2 = signed_permit(&t, a, &owner, &SPENDER, 7, 1, DEADLINE);
    assert_eq!(t.permit_pq(NOW, owner, SPENDER, 7, DEADLINE, &a.pk, &sig2), Ok(()));
    assert_eq!(t.allowance.get(&(owner, SPENDER)), Some(&7));
}

#[test]
fn a_permit_does_not_replay_onto_another_contract() {
    let a = alice();
    let owner = a.address20();
    let t1 = PqPermitToken::new(TOKEN, CHAIN_ID);
    let mut t2 = PqPermitToken::new([0xBB; 20], CHAIN_ID);
    let sig = signed_permit(&t1, a, &owner, &SPENDER, VALUE, 0, DEADLINE);
    assert_eq!(
        t2.permit_pq(NOW, owner, SPENDER, VALUE, DEADLINE, &a.pk, &sig),
        Err(Revert::BadSignature)
    );
    // control: at the contract it was signed for, it works.
    let mut t1 = t1;
    assert_eq!(t1.permit_pq(NOW, owner, SPENDER, VALUE, DEADLINE, &a.pk, &sig), Ok(()));
}

#[test]
fn a_permit_does_not_replay_onto_another_chain() {
    let a = alice();
    let owner = a.address20();
    let t1 = PqPermitToken::new(TOKEN, CHAIN_ID);
    let mut t_other = PqPermitToken::new(TOKEN, CHAIN_ID + 1);
    let sig = signed_permit(&t1, a, &owner, &SPENDER, VALUE, 0, DEADLINE);
    assert_eq!(
        t_other.permit_pq(NOW, owner, SPENDER, VALUE, DEADLINE, &a.pk, &sig),
        Err(Revert::BadSignature)
    );
    let mut t1 = t1;
    assert_eq!(t1.permit_pq(NOW, owner, SPENDER, VALUE, DEADLINE, &a.pk, &sig), Ok(()));
}

// ── Every signed field actually binds ───────────────────────────────────────

#[test]
fn each_signed_field_binds_the_authorization() {
    let a = alice();
    let owner = a.address20();
    let base = PqPermitToken::new(TOKEN, CHAIN_ID);
    let sig = signed_permit(&base, a, &owner, &SPENDER, VALUE, 0, DEADLINE);

    // spender
    let mut t = PqPermitToken::new(TOKEN, CHAIN_ID);
    assert_eq!(
        t.permit_pq(NOW, owner, OTHER_SPENDER, VALUE, DEADLINE, &a.pk, &sig),
        Err(Revert::BadSignature)
    );
    // value
    let mut t = PqPermitToken::new(TOKEN, CHAIN_ID);
    assert_eq!(
        t.permit_pq(NOW, owner, SPENDER, VALUE + 1, DEADLINE, &a.pk, &sig),
        Err(Revert::BadSignature)
    );
    // deadline
    let mut t = PqPermitToken::new(TOKEN, CHAIN_ID);
    assert_eq!(
        t.permit_pq(NOW, owner, SPENDER, VALUE, DEADLINE + 1, &a.pk, &sig),
        Err(Revert::BadSignature)
    );
    // nonce (pre-advanced)
    let mut t = PqPermitToken::new(TOKEN, CHAIN_ID);
    t.nonces.insert(owner, 1);
    assert_eq!(
        t.permit_pq(NOW, owner, SPENDER, VALUE, DEADLINE, &a.pk, &sig),
        Err(Revert::BadSignature)
    );
    // control: untouched, it is accepted
    let mut t = PqPermitToken::new(TOKEN, CHAIN_ID);
    assert_eq!(t.permit_pq(NOW, owner, SPENDER, VALUE, DEADLINE, &a.pk, &sig), Ok(()));
}

#[test]
fn an_expired_permit_is_refused_at_the_boundary() {
    let a = alice();
    let owner = a.address20();
    let mut t = PqPermitToken::new(TOKEN, CHAIN_ID);
    let sig = signed_permit(&t, a, &owner, &SPENDER, VALUE, 0, DEADLINE);
    assert_eq!(
        t.permit_pq(DEADLINE + 1, owner, SPENDER, VALUE, DEADLINE, &a.pk, &sig),
        Err(Revert::Expired)
    );
    // control: `now == deadline` is still inside.
    assert_eq!(t.permit_pq(DEADLINE, owner, SPENDER, VALUE, DEADLINE, &a.pk, &sig), Ok(()));
}

// ── Signer identity ─────────────────────────────────────────────────────────

#[test]
fn a_signature_from_another_key_cannot_permit_your_balance() {
    // The attack the `signer == owner` check exists for: Mallory signs a
    // perfectly valid permit naming Alice as owner. The signature verifies —
    // it is Mallory's, over these exact fields — and must still be refused.
    let a = alice();
    let m = mallory();
    let owner = a.address20();
    let mut t = PqPermitToken::new(TOKEN, CHAIN_ID);
    let sig = signed_permit(&t, m, &owner, &SPENDER, VALUE, 0, DEADLINE);
    assert_eq!(
        t.permit_pq(NOW, owner, SPENDER, VALUE, DEADLINE, &m.pk, &sig),
        Err(Revert::WrongSigner),
        "verification succeeded; the identity check is what stops this"
    );
    assert!(t.allowance.get(&(owner, SPENDER)).is_none());
    // control: Mallory may permit her OWN balance with the same key.
    let m_owner = m.address20();
    let sig2 = signed_permit(&t, m, &m_owner, &SPENDER, VALUE, 0, DEADLINE);
    assert_eq!(t.permit_pq(NOW, m_owner, SPENDER, VALUE, DEADLINE, &m.pk, &sig2), Ok(()));
}

#[test]
fn the_stripped_envelope_does_not_open_a_second_permit_encoding() {
    // The malleability rule reaching the contract layer: the same
    // authorization must not have two byte strings, or a contract that
    // de-duplicates by signature hash can be made to accept it twice.
    let a = alice();
    let owner = a.address20();
    let mut t = PqPermitToken::new(TOKEN, CHAIN_ID);
    let sig = signed_permit(&t, a, &owner, &SPENDER, VALUE, 0, DEADLINE);
    let raw = strip(&sig);
    assert_eq!(
        t.permit_pq(NOW, owner, SPENDER, VALUE, DEADLINE, &a.pk, &raw),
        Err(Revert::BadSignature)
    );
    assert_eq!(t.permit_pq(NOW, owner, SPENDER, VALUE, DEADLINE, &a.pk, &sig), Ok(()));
}

// ── The incompatibility, asserted rather than promised ──────────────────────

#[test]
fn this_is_not_eip_2612() {
    // If these two ever collide, an EIP-2612 signature would authorize a PQ
    // permit or the reverse.
    let ours = PqPermitToken::permit_pq_typehash();
    let eip2612 = keccak(&[
        b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)",
    ]);
    assert_ne!(ours, eip2612, "the type must not be EIP-2612's");
}

#[test]
fn a_hybrid_signature_does_not_fit_the_eip_2612_argument_shape() {
    // (v, r, s) is 65 bytes. This is the arithmetic behind "MetaMask never
    // works" at the contract layer, not only the wallet layer.
    let a = alice();
    let sig = a.sign(&[0u8; 32]);
    assert!(sig.len() > 65 * 60, "hybrid signature is {} bytes", sig.len());
    assert_eq!(a.pk.len(), ENVELOPED_PK_LEN, "and a pubkey must travel with it");
}
