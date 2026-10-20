//! # HF3 wire-tag allocation table (2026-10-20) — the single record
//!
//! One table for every transaction tag, state-root tag, local-cache section
//! and finality-leaf extension marker that is live on mainnet
//! (`b4a21fb6`) or claimed by a branch pending for hard forks 1/2/3. The
//! prose twin is `docs/WIRE-NAMESPACE-REGISTRY.md`, section
//! "HF3 allocation 2026-10-20".
//!
//! **Stable.** The values below are frozen as of their first commit on
//! `codex/hf3-tags-20261020`. Other HF3 lines (KES `codex/hf3-kes-20261020`,
//! wallet `codex/hf-wallet-20261020`, SLH-DSA `codex/hf3-slhdsa-20261020`)
//! read this table; a byte is never re-pointed here, only appended.
//!
//! ## The clash this resolves
//!
//! Three drafts claimed overlapping transaction bytes:
//!
//! * KES registration `0x17` — live on devnet4 (`codex/native-kes-20261014`),
//!   carried by the KES mainnet port (`codex/bloch-kes-port-20261019`,
//!   `codex/hf3-kes-20261020`). **Keeps `0x17`.**
//! * PQ suite migration (`codex/bloch-p9d-migration-20261019`, `104d8a94`)
//!   drafted credential rotation `0x17`, rescue `0x18`/`0x19`; the
//!   2026-10-19 allocation (`codex/bloch-tag-alloc-20261019`, `61ac024d`)
//!   moved it to `0x18`/`0x19`/`0x1A`, and `codex/hf-wallet-20261020`
//!   already merged that. **Keeps `0x18`–`0x1A`.**
//! * `KesRotate`, proposed at `0x18` in `docs/KES-MAINNET-READINESS.md`
//!   (`codex/bloch-p8b-kesmainnet-20261019`, `7175b3ec`) — a design note with
//!   no code on any ref. **Moves to `0x1B`.** Moving the only claimant that
//!   has no code is the allocation that re-points no implemented byte.
//!
//! State-root tags: `0x22` KES root and `0x23` light-client roster (both
//! live on devnet4) keep their bytes; PQ rescue commitments take `0x24`.
//!
//! ## Sweep
//!
//! 2026-10-20, every `refs/heads` + `refs/remotes` tip (371 refs, distinct
//! commits): every `*_TAG: u8` / `TAG_*: u8` constant under `crates/`, and
//! every arm of the `PosTransaction` decoder `match`. Beyond the mainnet set
//! the only tx claimants >= `0x17` are KES `REGISTER_TAG = 0x17` and the
//! PQ trio; the only state claimants >= `0x22` are `TAG_KES_ROOT = 0x22`,
//! `TAG_LC_ROSTER = 0x23` and `TAG_PQ_RESCUE_COMMIT` (`0x22` draft, `0x24`).
//! Stale pre-mainnet rivals below `0x17`/`0x22` (e.g. `NATIVE_TRANSFER_TAG =
//! 0x0E` on `feat/native-usdt-custody`, `TAG_SHIELDED_POOL = 0x17/0x18`) are
//! superseded by the released assignments and recorded in the registry doc.

/// `PosTransaction` wire tags — first byte of `canonical_bytes`.
pub mod tx {
    /// Released on mainnet.
    pub const TRANSFER: u8 = 0x01;
    pub const DEPOSIT: u8 = 0x02;
    pub const EXIT: u8 = 0x03;
    pub const DELEGATE: u8 = 0x04;
    pub const SLASHING_EVIDENCE: u8 = 0x05;
    pub const TRANSFER_V2: u8 = 0x06;
    /// ADR-041 permanent tombstones. Never assign.
    pub const TOMBSTONED: [u8; 3] = [0x07, 0x08, 0x09];
    pub const RANDAO_RECOMMIT: u8 = 0x0A;
    pub const FUNDED_DEPOSIT: u8 = 0x0B;
    pub const EXIT_V2: u8 = 0x0C;
    pub const WITHDRAW: u8 = 0x0D;
    pub const FUNDED_DELEGATE: u8 = 0x0E;
    pub const FUNDED_UNDELEGATE: u8 = 0x0F;
    pub const FUNDED_DELEGATION_WITHDRAW: u8 = 0x10;
    pub const VALIDATOR_COMMISSION_UPDATE: u8 = 0x11;
    pub const L2_SETTLEMENT: u8 = 0x12;
    pub const L2_SETTLEMENT_ASYNC: u8 = 0x13;
    pub const L2_DEPOSIT: u8 = 0x14;
    pub const L2_DATA_AVAILABILITY: u8 = 0x15;
    pub const L2_WITHDRAW_CLAIM: u8 = 0x16;

    /// HF3: KES registration (same byte devnet4 runs).
    pub const KES_REGISTER: u8 = 0x17;
    /// HF3: PQ migration — withdrawal-credential rotation.
    pub const WITHDRAWAL_CREDENTIAL_ROTATION: u8 = 0x18;
    /// HF3: PQ migration — lattice-break rescue, commit phase.
    pub const RESCUE_COMMIT: u8 = 0x19;
    /// HF3: PQ migration — lattice-break rescue, reveal phase.
    pub const RESCUE_REVEAL: u8 = 0x1A;
    /// HF3: KES leaf-authorised rotation (p8b proposal, moved from 0x18).
    pub const KES_ROTATE: u8 = 0x1B;

    /// Next unallocated transaction tag.
    pub const NEXT_FREE: u8 = 0x1C;
}

/// State-root component tags — key prefix in the state SMT.
pub mod state {
    /// Highest tag released on mainnet (`TAG_L2_SETTLEMENT`); `0x01`..=this
    /// are all assigned, see `state_root::STATE_COMPONENT_TAGS`.
    pub const MAINNET_HIGHEST: u8 = 0x21;
    /// HF3: KES root registry (devnet4 byte).
    pub const KES_ROOT: u8 = 0x22;
    /// Light-client roster (devnet4 byte, `codex/bloch-lc-20261014`).
    pub const LC_ROSTER: u8 = 0x23;
    /// HF3: PQ rescue commitments (moved from the 0x22 draft).
    pub const PQ_RESCUE_COMMIT: u8 = 0x24;
    /// Next unallocated state-root tag.
    pub const NEXT_FREE: u8 = 0x25;
}

/// Local state-cache sections (16-byte markers, parsed by sequential prefix
/// stripping in `transition::local_cache`). Merge order is this order.
pub mod local_cache {
    /// Mainnet.
    pub const L2: &[u8; 16] = b"BPOSST01:L2:v1\0\0";
    /// Pending: `codex/native-claim-finality-20261019` (L2 checkpoint roots).
    pub const L2_CHECKPOINTS: &[u8; 16] = b"BPOSST01:L2CP:v1";
    /// HF3 KES (`v2`: entries with start periods and the enforcement bind
    /// epoch; the devnet lineage's `v1` section is not accepted).
    pub const KES: &[u8; 16] = b"BPOSST01:KES:v2\0";
    /// HF3 PQ rescue commitments.
    pub const PQ: &[u8; 16] = b"BPOSST01:PQ:v1\0\0";
    /// HF1 frozen finality set (p1a).
    pub const FINALITY_SET: &[u8; 16] = b"BPOSST01:FSET:v1";
    /// HF1 own-target checkpoints (p2a).
    pub const OWN_CHECKPOINTS: &[u8; 16] = b"BPOSST01:FFGO:v1";
    /// Fixed merge/parse order.
    pub const ORDER: [&[u8; 16]; 6] = [L2, L2_CHECKPOINTS, KES, PQ, FINALITY_SET, OWN_CHECKPOINTS];
}

/// Trailing extensions of the finality leaf (state tag `0x09`). Absent while
/// empty; merge order FSET then OWN-CHECKPOINTS.
pub mod finality_leaf {
    pub const FINALITY_SET: &[u8] = b"BLOCH-FFG-FSETv1";
    pub const OWN_CHECKPOINTS: &[u8] = b"BLOCH:FINALITY:OWN-CHECKPOINTS:1";
}

/// Allocation status of one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Decoded by the mainnet release.
    Mainnet,
    /// ADR-041 tombstone; never assign.
    Tombstoned,
    /// Allocated to a pending hard-fork line; consensus-inert until its gate.
    Pending { gate: &'static str, branch: &'static str },
}

/// One row of the transaction-tag table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    pub tag: u8,
    pub name: &'static str,
    pub status: Status,
}

const fn mainnet(tag: u8, name: &'static str) -> Row {
    Row { tag, name, status: Status::Mainnet }
}

/// Every allocated transaction tag, ascending.
pub const TX_TABLE: &[Row] = &[
    mainnet(tx::TRANSFER, "Transfer"),
    mainnet(tx::DEPOSIT, "Deposit"),
    mainnet(tx::EXIT, "Exit"),
    mainnet(tx::DELEGATE, "Delegate"),
    mainnet(tx::SLASHING_EVIDENCE, "SlashingEvidence"),
    mainnet(tx::TRANSFER_V2, "TransferV2"),
    Row { tag: 0x07, name: "(tombstone)", status: Status::Tombstoned },
    Row { tag: 0x08, name: "(tombstone)", status: Status::Tombstoned },
    Row { tag: 0x09, name: "(tombstone)", status: Status::Tombstoned },
    mainnet(tx::RANDAO_RECOMMIT, "RandaoRecommit"),
    mainnet(tx::FUNDED_DEPOSIT, "FundedDeposit"),
    mainnet(tx::EXIT_V2, "ExitV2"),
    mainnet(tx::WITHDRAW, "Withdraw"),
    mainnet(tx::FUNDED_DELEGATE, "FundedDelegate"),
    mainnet(tx::FUNDED_UNDELEGATE, "FundedUndelegate"),
    mainnet(tx::FUNDED_DELEGATION_WITHDRAW, "FundedDelegationWithdraw"),
    mainnet(tx::VALIDATOR_COMMISSION_UPDATE, "ValidatorCommissionUpdate"),
    mainnet(tx::L2_SETTLEMENT, "L2Settlement"),
    mainnet(tx::L2_SETTLEMENT_ASYNC, "L2SettlementAsync"),
    mainnet(tx::L2_DEPOSIT, "L2Deposit"),
    mainnet(tx::L2_DATA_AVAILABILITY, "L2DataAvailability"),
    mainnet(tx::L2_WITHDRAW_CLAIM, "L2WithdrawClaim"),
    Row {
        tag: tx::KES_REGISTER,
        name: "KesRegister",
        status: Status::Pending { gate: "HF3_KES_EPOCH", branch: "codex/hf3-kes-20261020" },
    },
    Row {
        tag: tx::WITHDRAWAL_CREDENTIAL_ROTATION,
        name: "WithdrawalCredentialRotation",
        status: Status::Pending { gate: "HF3_PQ_MIGRATION_EPOCH", branch: "codex/hf3-tags-20261020" },
    },
    Row {
        tag: tx::RESCUE_COMMIT,
        name: "RescueCommit",
        status: Status::Pending { gate: "HF3_PQ_MIGRATION_EPOCH", branch: "codex/hf3-tags-20261020" },
    },
    Row {
        tag: tx::RESCUE_REVEAL,
        name: "RescueReveal",
        status: Status::Pending { gate: "HF3_PQ_MIGRATION_EPOCH", branch: "codex/hf3-tags-20261020" },
    },
    Row {
        tag: tx::KES_ROTATE,
        name: "KesRotate",
        status: Status::Pending { gate: "HF3_KES_EPOCH", branch: "codex/hf3-kes-20261020" },
    },
];

/// State-root tags allocated beyond the mainnet range, ascending.
pub const STATE_TABLE_HF3: &[(u8, &str, &str)] = &[
    (state::KES_ROOT, "TAG_KES_ROOT", "codex/hf3-kes-20261020"),
    (state::LC_ROSTER, "TAG_LC_ROSTER", "codex/bloch-lc-20261014 (devnet4)"),
    (state::PQ_RESCUE_COMMIT, "TAG_PQ_RESCUE_COMMIT", "codex/hf3-tags-20261020"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn tx_table_is_strictly_ascending_and_unique() {
        for pair in TX_TABLE.windows(2) {
            assert!(pair[0].tag < pair[1].tag, "{:#04x} then {:#04x}", pair[0].tag, pair[1].tag);
        }
        let names: BTreeSet<&str> =
            TX_TABLE.iter().filter(|r| r.status != Status::Tombstoned).map(|r| r.name).collect();
        assert_eq!(names.len(), TX_TABLE.len() - 3, "a name is allocated twice");
        assert_eq!(TX_TABLE.last().unwrap().tag + 1, tx::NEXT_FREE);
        assert_eq!(TX_TABLE.len(), 0x1B, "0x01..=0x1B allocated without gaps");
    }

    /// The 2026-10-20 ruling, pinned byte by byte. Changing any line here
    /// re-points a byte another HF3 line already reads.
    #[test]
    fn hf3_ruling_is_frozen() {
        assert_eq!(tx::KES_REGISTER, 0x17);
        assert_eq!(tx::WITHDRAWAL_CREDENTIAL_ROTATION, 0x18);
        assert_eq!(tx::RESCUE_COMMIT, 0x19);
        assert_eq!(tx::RESCUE_REVEAL, 0x1A);
        assert_eq!(tx::KES_ROTATE, 0x1B);
        assert_eq!(tx::NEXT_FREE, 0x1C);
        assert_eq!(state::KES_ROOT, 0x22);
        assert_eq!(state::LC_ROSTER, 0x23);
        assert_eq!(state::PQ_RESCUE_COMMIT, 0x24);
        assert_eq!(state::NEXT_FREE, 0x25);
    }

    /// The mainnet rows agree with the constants the decoder dispatches on.
    #[test]
    fn hf3_kes_rows_match_the_decoder_constants() {
        assert_eq!(crate::kes::REGISTER_TAG, tx::KES_REGISTER);
        assert_eq!(crate::kes::ROTATE_TAG, tx::KES_ROTATE);
        assert!(crate::state_root::STATE_COMPONENT_TAGS.contains(&("TAG_KES_ROOT", state::KES_ROOT)));
    }

    #[test]
    fn mainnet_rows_match_the_decoder_constants() {
        use crate::transition::{funded, funded_delegation, l2_claim, l2_da, l2_deposit};
        assert_eq!(funded::FUNDED_DEPOSIT_TAG, tx::FUNDED_DEPOSIT);
        assert_eq!(funded_delegation::FUNDED_DELEGATE_TAG, tx::FUNDED_DELEGATE);
        assert_eq!(funded_delegation::FUNDED_UNDELEGATE_TAG, tx::FUNDED_UNDELEGATE);
        assert_eq!(funded_delegation::FUNDED_DELEGATION_WITHDRAW_TAG, tx::FUNDED_DELEGATION_WITHDRAW);
        assert_eq!(funded_delegation::VALIDATOR_COMMISSION_UPDATE_TAG, tx::VALIDATOR_COMMISSION_UPDATE);
        assert_eq!(crate::l2_settlement::WIRE_TAG, tx::L2_SETTLEMENT);
        assert_eq!(crate::l2_settlement::ASYNC_WIRE_TAG, tx::L2_SETTLEMENT_ASYNC);
        assert_eq!(l2_deposit::L2_DEPOSIT_TAG, tx::L2_DEPOSIT);
        assert_eq!(l2_da::L2_DATA_AVAILABILITY_TAG, tx::L2_DATA_AVAILABILITY);
        assert_eq!(l2_claim::L2_WITHDRAW_CLAIM_TAG, tx::L2_WITHDRAW_CLAIM);
    }

    /// Every state tag in the live registry is at or below the mainnet
    /// ceiling, and no HF3 state allocation collides with it.
    #[test]
    fn state_allocations_clear_the_live_registry() {
        let live: BTreeSet<u8> =
            crate::state_root::STATE_COMPONENT_TAGS.iter().map(|(_, t)| *t).collect();
        for (tag, name, _) in STATE_TABLE_HF3 {
            if *tag <= state::MAINNET_HIGHEST {
                panic!("{name} {tag:#04x} is inside the mainnet range");
            }
            // Present only once the owning line is merged; never under another name.
            if live.contains(tag) {
                let owner = crate::state_root::STATE_COMPONENT_TAGS
                    .iter()
                    .find(|(_, t)| t == tag)
                    .map(|(n, _)| *n)
                    .unwrap();
                assert_eq!(owner, *name, "{tag:#04x} registered under a different name");
            }
        }
        assert!(live.iter().all(|t| *t < state::NEXT_FREE), "a state tag past NEXT_FREE is unallocated");
        for pair in STATE_TABLE_HF3.windows(2) {
            assert!(pair[0].0 < pair[1].0);
        }
        assert_eq!(STATE_TABLE_HF3.last().unwrap().0 + 1, state::NEXT_FREE);
    }

    #[test]
    fn local_cache_sections_and_finality_markers_are_distinct() {
        let set: BTreeSet<&[u8; 16]> = local_cache::ORDER.iter().copied().collect();
        assert_eq!(set.len(), local_cache::ORDER.len());
        for s in local_cache::ORDER {
            assert!(s.starts_with(b"BPOSST01:"));
        }
        assert_ne!(finality_leaf::FINALITY_SET, finality_leaf::OWN_CHECKPOINTS);
    }
}
