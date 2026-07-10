//! bloch-pool — a REFERENCE, open-source mining pool for Bloch-SIS-PoW.
//!
//! READ THIS FIRST (the honest part)
//! =================================
//!
//! * **This exists so there can be MANY pools, not one.** A pool that
//!   controls >51% of network hashrate IS a 51%-attack vector and
//!   centralizes what should be decentralized. The healthy outcome is
//!   several independent small pools plus solo miners. Fork this, run
//!   your own.
//! * **The coin is worth nothing by design.** Bloch is mainnet-beta:
//!   unaudited, young, 51%-attackable. This pool is for coordination
//!   and testing, not profit.
//! * **Solo mining stays the default** (`bloch --mine`) and needs no
//!   pool. Pooling is strictly opt-in.
//! * **The PoW is NOT lattice-hard.** Bloch-SIS-PoW is a SHAKE-256
//!   cumulative-work hashcash with a Module-SIS *structural gate*
//!   (small-k residual check). Shares here are plain hash-difficulty
//!   shares on the SHAKE-256 aux hash. No lattice bit-security number
//!   attaches to any of this (see `crates/bloch-sis-pow` crate docs).
//!
//! Why a SIS-native dialect instead of the node's stratum
//! ======================================================
//!
//! The node ships a Bitcoin-style Stratum V1/V2 server
//! (`src/stratum{,_v2}`), but it **refuses to start** under Module-SIS
//! (main.rs, Sprint B5f): the classic `mining.submit` params
//! `[user, job, extranonce2, ntime, nonce]` have no field for the
//! 256-coefficient solution vector `s` that every valid block must
//! carry (`Block::pow_solution`). This pool is the "SIS-native share
//! protocol" that B5f defers: it keeps Stratum V1's framing, method
//! names, session state machine and error codes (mirroring
//! `src/stratum/protocol.rs`), but the job/submit params carry the
//! 76-byte PoW preimage and the encoded solution vector.
//!
//! Architecture
//! ============
//!
//! ```text
//!   Bloch node (bloch --mine ... --rpc-port 16210)
//!     ▲  JSON-RPC: getblocktemplate / submitblock  (B5f pool seam)
//!     │
//!   bloch-pool
//!     ├── upstream   — RPC client; template polling; block submission;
//!     │                canonical-hash maturity checks
//!     ├── job        — template → coinbase(pool addr) → Block skeleton
//!     │                → 76-byte PoW preimage (BlockHeader::pow_preimage)
//!     ├── stratum    — miner-facing TCP server (SIS-native V1 dialect,
//!     │                address-ownership proof at authorize)
//!     ├── shares     — per-miner weighted share ledger + PPLNS window,
//!     │                JSONL-journaled; blocks credit only on maturity
//!     ├── payout     — pure payout math (PPLNS, fee_bps, default 0%)
//!     └── dashboard  — self-contained HTTP dashboard + /api/stats
//!                      (incl. honest luck / share-of-network panel)
//!     ▲
//!     │  stratum+tcp (newline JSON), default :3335
//!   miners (reference CPU miner: `bloch-pool-miner`)
//! ```
//!
//! Payout scheme (PPLNS) — documented in payout.rs and the README.

pub mod protocol;
pub mod keyshard;
pub mod upstream;
pub mod job;
pub mod shares;
pub mod payout;
pub mod state;
pub mod stratum;
pub mod dashboard;
