// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared machinery for the Coherence merge-gate suite (DEV-15).
//!
//! Not a test target itself — `tests/coherence_*.rs` include it via
//! `mod coherence_harness;`. Everything here goes through the PUBLIC surface
//! of `bloch-pos-committee`, never through `#[cfg(test)]` helpers of the
//! crate under test: this suite is the wave's merge gate, so it must judge
//! the same API the node binary consumes, from the outside.
//!
//! ## The one posture this harness must never drift from
//!
//! The genesis it builds mirrors what the LIVE loader committed
//! (`crates/bloch-pos-node/src/genesis.rs`, `Manifest::genesis_state` /
//! `genesis_header`): the three carried roots are **`[0u8; 32]`, loaded, not
//! derived** — taint, Coherence accumulator, Coherence nullifier set — and
//! the EVM segment is all zeros. That is the PMO finding this whole wave
//! hangs on: the live chain's every `state_root` commits those loaded zeros,
//! and every child header's `coherence_root` is
//! `coherence_binding([0;32], [0;32])`. A patch that starts *deriving* those
//! roots (empty-tree roots instead of loaded zeros) without an epochal gate
//! moves both values on every block since genesis and forks production at
//! deploy. The KATs in `coherence_replay_identity.rs` pin the values this
//! harness produces so that exactly that change cannot land silently.

#![allow(dead_code)]

use bloch_pos_committee::attestation::{Attestation, SignatureVerifier};
use bloch_pos_committee::beacon::{mix_in, RandaoChain};
use bloch_pos_committee::header::{BlockHeaderV4, BlockId, VERSION_G4};
use bloch_pos_committee::interfaces::{ProposalEnvelope, StateReader, StateTransition};
use bloch_pos_committee::state_root::{EutxoEntry, EvmCommitment};
use bloch_pos_committee::transition::{
    CommittedState, GenesisValidator, PosTransaction, Transition, TransferInput, TransferOutput,
};
use bloch_pos_committee::{epoch_of, fee_market, schedule, tokenomics_v4};
use sha3::{Digest, Sha3_256};

/// Accept-everything verifier: the suite exercises replay identity, the
/// coherence binding, epoch gating and reorg/finality rules — never the PQ
/// stack, which has its own KATs. Same posture as the pure crate's own tests.
pub struct OkVerifier;
impl SignatureVerifier for OkVerifier {
    fn verify(&self, _v: u32, _root: &[u8; 32], _sig: &[u8]) -> bool {
        true
    }
    fn verify_with_key(&self, _pk: &[u8], _root: &[u8; 32], _sig: &[u8]) -> bool {
        true
    }
}

pub fn sat(bloch: u128) -> u128 {
    bloch * tokenomics_v4::SAT_PER_BLOCH
}

/// The spender's key bytes and the script hash an output commits to.
/// `script_hash = SHA3-256(pubkey)` is the transfer rule's `owns` relation.
pub fn owner_key(tag: u8) -> Vec<u8> {
    vec![tag; 9]
}
pub fn script_of(pubkey: &[u8]) -> [u8; 32] {
    Sha3_256::digest(pubkey).into()
}

/// One opening-balance output locked to `owner`.
pub fn opening(txid_tag: u8, vout: u32, value: u64, owner: &[u8]) -> EutxoEntry {
    EutxoEntry { txid: [txid_tag; 32], vout, value, script_hash: script_of(owner) }
}

/// The LIVE genesis header, field for field (`genesis.rs::genesis_header`):
/// every root zero, slot 0, proposer 0, `GENESIS_MIX = [0;32]`. Its id is a
/// pure function of these constants — the same id the mainnet chain carries.
pub fn live_genesis_header() -> BlockHeaderV4 {
    BlockHeaderV4 {
        version: VERSION_G4,
        parent: [0u8; 32],
        state_root: [0u8; 32],
        body_root: [0u8; 32],
        slot: 0,
        proposer_index: 0,
        randao_reveal: [0u8; 32],
        randao_mix: [0u8; 32],
        justified_root: [0u8; 32],
        finalized_root: [0u8; 32],
        attestation_root: [0u8; 32],
        coherence_root: [0u8; 32],
    }
}

/// The test validators' RANDAO chains, regenerable from their seeds.
///
/// `RandaoChain` is deliberately not `Clone`, and a chain whose reveal was
/// consumed for a block that never applied is desynchronised from committed
/// state forever. This set instead tracks how many reveals each validator's
/// COMMITTED state has consumed and regenerates the chain to that position
/// on demand — so a *speculative* block (built to be rejected, never
/// applied) can peek a reveal without burning it.
pub struct ChainSet {
    seeds: Vec<[u8; 32]>,
    used: Vec<u32>,
}

impl ChainSet {
    pub fn new(n: u32) -> Self {
        let seeds = (0..n)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = i as u8;
                seed[1] = 0xC0;
                seed
            })
            .collect();
        ChainSet { seeds, used: vec![0; n as usize] }
    }

    /// The public commitment `c_0` — what genesis registers.
    pub fn commitment(&self, v: u32) -> [u8; 32] {
        RandaoChain::generate(self.seeds[v as usize]).commitment()
    }

    /// The reveal validator `v` would use next, given everything the chain
    /// has already committed. `consume` records it as spent — pass `true`
    /// exactly when the block carrying it will be applied.
    pub fn reveal(&mut self, v: u32, consume: bool) -> [u8; 32] {
        let mut chain = RandaoChain::generate(self.seeds[v as usize]);
        for _ in 0..self.used[v as usize] {
            chain.next_reveal().expect("test chain spent");
        }
        let r = chain.peek_reveal().expect("test chain spent");
        if consume {
            self.used[v as usize] += 1;
        }
        r
    }
}

/// A devnet-shaped genesis with the LIVE loader's carried-root posture.
///
/// `n` validators with deterministic RANDAO chains, plus `opening_balances`.
/// The three carried roots and the EVM segment are all zeros — LOADED, the
/// way `Manifest::genesis_state` commits them on mainnet. Deterministic in
/// every input, which is what lets the identity tests pin its roots.
pub fn genesis_fixture(
    n: u32,
    opening_balances: &[EutxoEntry],
) -> (Transition<OkVerifier>, CommittedState, ChainSet) {
    let chains = ChainSet::new(n);
    let mut vals = Vec::new();
    for i in 0..n {
        vals.push(GenesisValidator {
            index: i,
            pubkey: vec![i as u8; 8],
            staked_sat: sat(200_000),
            randao_commitment: chains.commitment(i),
            withdrawal_credentials: vec![i as u8; 4],
            commission_bps: 500,
        });
    }
    let genesis_id = BlockId::of(&live_genesis_header());
    let st = CommittedState::genesis(
        genesis_id,
        [0u8; 32], // GENESIS_MIX, the live value
        &vals,
        &[],
        // The three carried roots, exactly as the live loader commits them:
        // LOADED zeros (genesis.rs:970-977). Not empty-tree roots. This is
        // the posture the whole suite defends.
        [0u8; 32],
        [0u8; 32],
        [0u8; 32],
        EvmCommitment {
            account_root: [0u8; 32],
            receipts_root: [0u8; 32],
            gas_used: 0,
            base_fee_per_gas: 0,
        },
        opening_balances,
    );
    (Transition::new(OkVerifier), st, chains)
}

/// Build a valid block at `slot` on top of `pre` — the same walk a validator
/// client does, through public API only.
///
/// The coherence root is stamped from `pre.coherence_root()`, i.e. the
/// binding over the parent's CARRIED roots — the live rule (§6.6.1). If the
/// transition ever starts expecting something else without a gate, blocks
/// this builder produces stop applying and every test that chains them
/// fails loudly, which is intended.
pub fn build_block(
    t: &Transition<OkVerifier>,
    pre: &CommittedState,
    slot: u64,
    txs: &[PosTransaction],
    chains: &mut ChainSet,
) -> ProposalEnvelope {
    build_block_inner(t, pre, slot, txs, chains, true)
}

/// [`build_block`] without consuming the proposer's reveal: for blocks built
/// to be REJECTED (or otherwise never applied). Using the consuming form for
/// such a block would desynchronise the test chains from committed state and
/// fail the next honest build with `BadRandaoReveal` — for the wrong reason.
pub fn speculative_block(
    t: &Transition<OkVerifier>,
    pre: &CommittedState,
    slot: u64,
    txs: &[PosTransaction],
    chains: &mut ChainSet,
) -> ProposalEnvelope {
    build_block_inner(t, pre, slot, txs, chains, false)
}

fn build_block_inner(
    t: &Transition<OkVerifier>,
    pre: &CommittedState,
    slot: u64,
    txs: &[PosTransaction],
    chains: &mut ChainSet,
    consume: bool,
) -> ProposalEnvelope {
    // Roll the builder's context over any epoch boundaries the block crosses,
    // exactly as `apply_block` will. In a linear chain the state's epoch is
    // `epoch_of(state.slot())` after every apply, so the roll count is
    // derivable without private accessors.
    let mut ctx = pre.clone();
    let mut ctx_epoch = epoch_of(ctx.slot());
    while ctx_epoch < epoch_of(slot) {
        ctx = t.process_epoch(&ctx).expect("close_epoch is infallible");
        ctx_epoch += 1;
    }
    let roster = ctx.active_validators();
    let seed = ctx.seed_for_epoch(ctx_epoch);
    let p = schedule::proposer(&seed, slot, &roster).expect("no eligible proposer");
    let reveal = chains.reveal(p, consume);
    let mix = mix_in(&ctx.randao_mix(), &reveal);
    let fin = ctx.finality();
    let tx_bytes: Vec<Vec<u8>> = txs.iter().map(PosTransaction::canonical_bytes).collect();
    let mut header = BlockHeaderV4 {
        version: VERSION_G4,
        parent: *pre.head().as_bytes(),
        state_root: [0u8; 32],
        body_root: bloch_pos_committee::derive::body_root(&tx_bytes),
        slot,
        proposer_index: p,
        randao_reveal: reveal,
        randao_mix: mix,
        justified_root: fin.justified.root,
        finalized_root: fin.finalized.root,
        attestation_root: bloch_pos_committee::derive::attestation_root(&[]),
        coherence_root: pre.coherence_root(),
    };
    let probe = ProposalEnvelope { header, proposer_sig: vec![0u8; 8] };
    let atts: [Attestation; 0] = [];
    let post = t
        .compute_post_state(pre, &probe, &atts, txs)
        .expect("builder produced an untransitionable block");
    header.state_root = post.state_root();
    ProposalEnvelope { header, proposer_sig: vec![0u8; 8] }
}

/// Apply a block built by [`build_block`], panicking with context on refusal.
pub fn apply(
    t: &Transition<OkVerifier>,
    pre: &CommittedState,
    env: &ProposalEnvelope,
    txs: &[PosTransaction],
) -> CommittedState {
    t.apply_block(pre, env, &[], txs).unwrap_or_else(|e| {
        panic!("valid block at slot {} refused: {e:?}", env.header.slot)
    })
}

/// A transfer spending `(txid, vout, value)` (owned by `owner`) entirely to
/// `to_script`, with the fee derived from the same market call the
/// transition charges — conservation exact by construction.
///
/// `parent` must be the state the containing block will be applied to, and
/// `block_slot` the block's slot: the price is
/// `parent.next_base_fee_at(epoch_of(block_slot))`, the §4.4 rule.
pub fn transfer(
    parent: &CommittedState,
    block_slot: u64,
    owner: &[u8],
    input: ([u8; 32], u32, u64),
    to_script: [u8; 32],
) -> PosTransaction {
    let (txid, vout, value) = input;
    let probe = PosTransaction::Transfer {
        inputs: vec![TransferInput {
            txid,
            vout,
            pubkey: owner.to_vec(),
            signature: vec![0u8; 8],
        }],
        outputs: vec![TransferOutput { value: 0, script_hash: to_script }],
        tx_bytes: 0,
        tip_millisat_per_gas: 0,
    };
    // Canonical length is independent of the u64 values it carries
    // (fixed-width encoding), so one probe sizes the real transaction.
    let len = probe.canonical_bytes().len() as u64;
    let base_fee = parent.next_base_fee_at(epoch_of(block_slot));
    let charge = fee_market::charge(
        fee_market::TxClass::Eutxo { inputs: 1 },
        len,
        base_fee,
        0,
    );
    let fee = charge.base_fee_sat + charge.priority_fee_sat;
    let out_value = (value as u128)
        .checked_sub(fee)
        .expect("fixture input too small for the derived fee") as u64;
    PosTransaction::Transfer {
        inputs: vec![TransferInput {
            txid,
            vout,
            pubkey: owner.to_vec(),
            signature: vec![0u8; 8],
        }],
        outputs: vec![TransferOutput { value: out_value, script_hash: to_script }],
        tx_bytes: len,
        tip_millisat_per_gas: 0,
    }
}

// ── A blocks.log-shaped fixture file ────────────────────────────────────────
//
// The node's `Store` frames `u32 LE length ‖ envelope bytes` and replays the
// decoded envelopes through the same `Transition` that accepted them live.
// This mirror keeps the framing and the replay discipline while carrying the
// suite's own envelope encoding (the node's `codec` lives in the binary
// crate and is deliberately unreachable from `tests/` — re-implementing it
// here would create a second consensus codec, the twin-derivation defect).

pub struct LoggedBlock {
    pub envelope: ProposalEnvelope,
    pub txs: Vec<PosTransaction>,
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

fn take_bytes<'a>(b: &'a [u8], at: &mut usize) -> &'a [u8] {
    let len = u32::from_le_bytes(b[*at..*at + 4].try_into().unwrap()) as usize;
    *at += 4;
    let s = &b[*at..*at + len];
    *at += len;
    s
}

/// One frame: header (canonical 304 bytes) ‖ sig ‖ tx count ‖ txs, all
/// length-prefixed, the whole payload behind a `u32 LE` frame length — the
/// same outer framing as the node's `blocks.log`.
pub fn encode_log(blocks: &[LoggedBlock]) -> Vec<u8> {
    let mut log = Vec::new();
    for b in blocks {
        let mut payload = Vec::new();
        payload.extend_from_slice(&b.envelope.header.canonical_serialize());
        put_bytes(&mut payload, &b.envelope.proposer_sig);
        payload.extend_from_slice(&(b.txs.len() as u32).to_le_bytes());
        for tx in &b.txs {
            put_bytes(&mut payload, &tx.canonical_bytes());
        }
        log.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        log.extend_from_slice(&payload);
    }
    log
}

/// Strict inverse of [`encode_log`]. A truncated trailing frame is DROPPED
/// (the node's crash rule); a corrupt frame body panics the test, which is
/// the right severity for a fixture this suite wrote itself.
pub fn decode_log(bytes: &[u8]) -> Vec<LoggedBlock> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 4 <= bytes.len() {
        let len = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        if at + 4 + len > bytes.len() {
            break; // truncated trailing frame: crash mid-append, drop it
        }
        let payload = &bytes[at + 4..at + 4 + len];
        at += 4 + len;
        let mut p = 0usize;
        let header = BlockHeaderV4::canonical_deserialize(
            &payload[p..p + BlockHeaderV4::ENCODED_LEN],
        )
        .expect("fixture header decodes");
        p += BlockHeaderV4::ENCODED_LEN;
        let sig = take_bytes(payload, &mut p).to_vec();
        let ntx = u32::from_le_bytes(payload[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        let mut txs = Vec::with_capacity(ntx);
        for _ in 0..ntx {
            let raw = take_bytes(payload, &mut p);
            txs.push(
                PosTransaction::from_canonical_bytes(raw).expect("fixture tx decodes"),
            );
        }
        assert_eq!(p, payload.len(), "trailing bytes inside a fixture frame");
        out.push(LoggedBlock {
            envelope: ProposalEnvelope { header, proposer_sig: sig },
            txs,
        });
    }
    out
}

pub fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
