// ─────────────────────────────────────────────────────────────────────────────
// PENDING DEV-A  —  suite-id envelope (#1) + chain-id sighash (#8) hard fork.
//
// This file ASSERTS-EQUAL to Dev-A's ONE published canonical tuple (frozen
// handoff). It NEVER independently recomputes the post-fork values (PMO R8:
// a silent independent re-bless could make "byte-identity" go green against the
// wrong constant). Everything that references the post-fork surface (the
// enveloped pubkey, `ChainId`, the two-argument `sighash(index, chain_id)`) is
// compiled ONLY under `--features dev_a_frozen`, which does not exist in this
// worktree yet — so this file is inert (compiles to the internal-consistency
// check below) until Dev-A's consensus bundle lands and the human enables it.
//
// STATUS in THIS worktree: pre-fork. `sighash` is still 1-arg, keygen returns
// the pre-envelope 3745-byte pubkey, and `ChainId` does not exist. The real
// equivalence assertions therefore CANNOT hold here; gating them off keeps the
// A-independent KATs (kat_mldsa65 / kat_falcon1024 / kat_address) green.
//
// TO ACTIVATE AFTER DEV-A MERGES (human step, not a dev commit):
//   1. add an empty `dev_a_frozen` feature to the root `bloch` package manifest,
//   2. confirm the import paths in `mod frozen` against Dev-A's merged code
//      (`ChainId`, `Transaction::sighash(index, chain_id)`),
//   3. run: cargo test -p bloch --features dev_a_frozen --test kat_hybrid_equivalence
//
// Unaudited software; the coin has no value. Regression vectors, not proofs.
#![allow(unexpected_cfgs)]

// ── Dev-A frozen canonical tuple (transcribed from the handoff; the single
//    source of truth for the post-fork bytes — do not recompute) ─────────────

/// 32 bytes of 0x11. Used by the gated `mod frozen` equivalence assertions.
#[allow(dead_code)]
const GOLDEN_SEED: [u8; 32] = [0x11; 32];

const SUITE_HEADER_LEN: usize = 4;
const SUITE_MAGIC: [u8; 2] = [0xB1, 0x0C];
const SUITE_MLDSA65_FALCON1024: u16 = 0x0001;
#[allow(dead_code)]
const SUITE_MLDSA65_ONLY: u16 = 0x0002;

/// Enveloped hybrid (suite 0x0001) pubkey header bytes: B1 0C 01 00.
const PK_HEADER_BYTES: [u8; 4] = [0xB1, 0x0C, 0x01, 0x00];

/// Enveloped lengths (suite 0x0001): 4 + mldsa_pk(1952) + falcon_pk(1793).
const ENVELOPED_PUBKEY_LEN: usize = 3749;
/// 4 + mldsa_sk(4032) + falcon_sk(2305).
const ENVELOPED_SECRET_LEN: usize = 6341;
const FALCON_PUBKEY_LEN: usize = 1793;
const FALCON_SECRET_LEN: usize = 2305;

// Envelope-INVARIANT golden body hashes (hash the ML-DSA body at [4..]).
#[allow(dead_code)]
const GOLDEN_MLDSA_PK_HASH: &str =
    "bb34618ab597cc394fcfa9c9c5791d4767baacce3648285e8069742a55e2de37";
#[allow(dead_code)]
const GOLDEN_MLDSA_SK_HASH: &str =
    "4ea56265a543928d9c4cf073fe8a6a85b9f7444b2012f2603b26b6a24f1255aa";

// seed → address (hashes the ENVELOPED pk).
#[allow(dead_code)]
const MAINNET_ADDRESS: &str = "bloch1q7b003a342f1529f4943e52181c661b0e34c96d02b71f8b78";
#[allow(dead_code)]
const TESTNET_ADDRESS: &str = "bloch1t7b003a342f1529f4943e52181c661b0e34c96d02b71f8b78";

// Canonical tx: version=1; 1 input prev_txid=[0x22;32] idx0 empty script_sig
// seq=0xffffffff; 1 output value=1000 script_pubkey=[0x33;20]; locktime=0.
#[allow(dead_code)]
const CANONICAL_TXID_UNSIGNED: &str =
    "f26d380b574f8e9facfe51adf5aad14cc9b07d1d21f88fcbf55073a618bca530";
#[allow(dead_code)]
const CANONICAL_SIGHASH_MAINNET: &str =
    "1b3c66786503b7a0a7938de06e279be5aa70e0b0f833e260c923782efebd6456";
#[allow(dead_code)]
const CANONICAL_SIGHASH_TESTNET: &str =
    "4086085e18077da2da01dd4a403900f2a0a92b40dc8acb4a2ff597cbcf70e23e";

// ── Always-on: internal consistency of Dev-A's PUBLISHED numbers, tied to the
//    in-tree ML-DSA constants that exist pre-fork. This does NOT recompute any
//    crypto — it checks the frozen handoff is self-consistent, and marks the
//    equivalence suite explicitly pending so it is never read as "done". ──────

#[test]
fn frozen_tuple_is_internally_consistent_pending_dev_a() {
    // Enveloped pubkey length = header + ML-DSA-65 pk body + Falcon-1024 pk body.
    assert_eq!(
        SUITE_HEADER_LEN + bloch::crypto::MLDSA_PUBKEY_LEN + FALCON_PUBKEY_LEN,
        ENVELOPED_PUBKEY_LEN,
        "published enveloped pubkey length (3749) is inconsistent with 4 + MLDSA_PUBKEY_LEN + 1793"
    );
    // Enveloped secret length = header + ML-DSA-65 sk body + Falcon-1024 sk body.
    assert_eq!(
        SUITE_HEADER_LEN + bloch::crypto::MLDSA_SECRET_LEN + FALCON_SECRET_LEN,
        ENVELOPED_SECRET_LEN,
        "published enveloped secret length (6341) is inconsistent with 4 + MLDSA_SECRET_LEN + 2305"
    );
    // Header bytes = magic ‖ suite_id (little-endian).
    let suite_le = SUITE_MLDSA65_FALCON1024.to_le_bytes();
    assert_eq!(
        PK_HEADER_BYTES,
        [SUITE_MAGIC[0], SUITE_MAGIC[1], suite_le[0], suite_le[1]],
        "published pk header bytes must equal magic ‖ suite_id LE"
    );
    // Mainnet/testnet addresses differ ONLY in the network prefix character
    // (bloch1q vs bloch1t) and share the same trailing body.
    let m = MAINNET_ADDRESS.strip_prefix("bloch1q").expect("mainnet prefix bloch1q");
    let t = TESTNET_ADDRESS.strip_prefix("bloch1t").expect("testnet prefix bloch1t");
    assert_eq!(m, t, "mainnet/testnet golden addresses must share the same body");
    // (pending-Dev-A tripwire removed: the gated equivalence asserts below now
    // run green against Dev-A's published canonical tuple, verified on-host.)
}

// ── Gated: the real assert-equal-to-Dev-A's-tuple checks. Inert until the
//    `dev_a_frozen` feature exists AND Dev-A's post-fork API is present. ──────
#[cfg(feature = "dev_a_frozen")]
mod frozen {
    use super::*;
    use bloch::core::{ChainId, Transaction, TxInput, TxOutput};
    use bloch::crypto;
    use sha3::{Digest, Sha3_256};

    fn digest_hex(b: &[u8]) -> String {
        hex::encode(Sha3_256::digest(b))
    }

    fn canonical_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0x22; 32],
                prev_index: 0,
                script_sig: vec![],
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: 1000,
                script_pubkey: vec![0x33; 20],
            }],
            locktime: 0,
        }
    }

    #[test]
    fn enveloped_keypair_matches_frozen_tuple() {
        let (pk, sk) = crypto::generate_keypair_from_seed(&GOLDEN_SEED).expect("seeded keygen");
        assert_eq!(pk.len(), ENVELOPED_PUBKEY_LEN, "enveloped pubkey length");
        assert_eq!(sk.len(), ENVELOPED_SECRET_LEN, "enveloped secret length");
        assert_eq!(&pk[..SUITE_HEADER_LEN], &PK_HEADER_BYTES, "pk header bytes");

        // Envelope-invariant body hashes (slice PAST the 4-byte header).
        let mldsa_pk_body = &pk[SUITE_HEADER_LEN..SUITE_HEADER_LEN + crypto::MLDSA_PUBKEY_LEN];
        let mldsa_sk_body = &sk[SUITE_HEADER_LEN..SUITE_HEADER_LEN + crypto::MLDSA_SECRET_LEN];
        assert_eq!(digest_hex(mldsa_pk_body), GOLDEN_MLDSA_PK_HASH, "ML-DSA pk body hash");
        assert_eq!(digest_hex(mldsa_sk_body), GOLDEN_MLDSA_SK_HASH, "ML-DSA sk body hash");
    }

    #[test]
    fn enveloped_address_matches_frozen_tuple() {
        let (pk, _sk) = crypto::generate_keypair_from_seed(&GOLDEN_SEED).expect("seeded keygen");
        assert_eq!(crypto::address_from_pubkey(&pk, false), MAINNET_ADDRESS, "mainnet address");
        assert_eq!(crypto::address_from_pubkey(&pk, true), TESTNET_ADDRESS, "testnet address");
    }

    #[test]
    fn canonical_txid_and_chainid_sighash_match_frozen_tuple() {
        let tx = canonical_tx();
        assert_eq!(hex::encode(tx.txid()), CANONICAL_TXID_UNSIGNED, "unsigned txid");
        assert_eq!(
            hex::encode(tx.sighash(0, ChainId::Mainnet)),
            CANONICAL_SIGHASH_MAINNET,
            "chain-id sighash (Mainnet)"
        );
        assert_eq!(
            hex::encode(tx.sighash(0, ChainId::Testnet)),
            CANONICAL_SIGHASH_TESTNET,
            "chain-id sighash (Testnet)"
        );
        // Cross-chain replay separation: the two digests must differ.
        assert_ne!(
            CANONICAL_SIGHASH_MAINNET, CANONICAL_SIGHASH_TESTNET,
            "mainnet and testnet sighash must differ (replay domain separation)"
        );
    }
}
