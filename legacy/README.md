<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# `legacy/` — the Genesis-3 record

This folder is the written record of **Genesis-3**: the proof-of-work chain
Bloch ran from 2026-07-29 until it stopped itself. Genesis-3 does not fade
out and it is not switched off by an operator — it ends by consensus rule at
a terminal height, after which every node rejects every further block. The
decided terminal height is **50,000** (founder decision, 2026-08-12, lowered
from 80,000). Genesis-4 is proof of stake and launches separately, from a
signed snapshot taken at that height.

The documents here are not deprecated in the sense of "wrong". They are
**closed**: they describe a machine that ran, in production, with real
hashrate against it, and then stopped on schedule.

## Why this is kept and not deleted

Three reasons, in descending order of how much they would cost to lose.

1. **Genesis-4 is built on Genesis-3's output.** The launch inputs are a
   signed datadir snapshot taken at the terminal height and the carryover
   UTXO set. Those artifacts are only meaningful if the rules that produced
   them are still readable: the emission curve that paid every coinbase in
   them (`specs/TOKENOMICS_V3.md`), the carryover offset arithmetic, the
   flag-days that changed validity mid-chain. A balance you cannot explain
   is a balance an auditor will not accept.
2. **Auditability is a property of the record, not of the current head.**
   An auditor asked to accept the Genesis-4 opening distribution will ask
   where it came from. "We deleted that" is not an answer. Deleting the
   losing branch of your own history is exactly how a project stops being
   auditable — the remaining documents all agree with each other because the
   disagreeing ones are gone.
3. **Some of it was expensive to learn.** The proof-of-work hardness
   research (`specs/POW-HARDNESS.md`, `research/POW-CANONICAL-frontier.md`)
   concluded that a trapdoorless PoW cannot be simultaneously lattice-hard
   and mineable — the secure and mineable parameter regimes are disjoint.
   That is a negative result, it cost real work, and it is the reason the
   PoW security claim was always stated as hashcash cumulative work rather
   than lattice hardness. It should not have to be rediscovered.

## What is still true in here, and what is not

**Still true.**

- The *historical* facts. Genesis-3 ran SHA-256d proof-of-work over a
  GhostDAG-Q BlockDAG; merged mining with Bitcoin (AuxPoW) activated at
  local height 8,500; the difficulty-from-ancestry flag-day activated at
  30,030; Emission V3 cut the block reward at local height 40,000. Those
  events happened and the documents describing them are accurate about them.
- The *arithmetic*. The carryover offset (`emission_height = local_height +
  413,743`), the per-height subsidy, the founder-premine vesting schedule as
  it applied on Genesis-3. Anyone reconstructing a Genesis-3 balance needs
  these and they do not change retroactively.
- The *negative results*. The PoW hardness conclusion above, and the
  post-incident findings in the Era-1 documents, are about mathematics and
  engineering, not about which consensus algorithm is in fashion.

**No longer true, and misleading if read as current.**

- **Everything forward-looking.** Anything here that says "will", "roadmap",
  "next sprint", "pending activation" is describing a future that was
  cancelled. Stratum V2 (`legacy/gips/GIP-0003-stratum-v2.md`), pool mode with
  PPLNS payout, the k=8 PoW re-activation, the FFG-BFT overlay elected by
  hashrate: none of these will happen. There is no mining on Genesis-4.
- **The tokenomics.** V1, V2 and V3 are all superseded. The current
  authority is `crates/bloch-pos-committee/src/tokenomics_v4.rs` (the code,
  not prose) and `docs/specs/BLOCH-TOKENOMICS-V4.md`. Do not quote a supply
  or emission figure from this folder as a current number.
- **The "ownerless" framing.** Retracted by
  `docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`. Several
  documents here still assert it. Read those assertions as dated.
- **The stated terminal height.** Documents written before 2026-08-12 say
  Genesis-3 halts at **80,000**. The decision is **50,000**. Where the two
  disagree, 50,000 is correct and the document is stale.
- **The consensus mechanisms themselves.** GhostDAG-Q blue-set ordering,
  ASERT-Lattice difficulty retargeting, the 80-byte Bitcoin-layout mining
  header, the Module-SIS structural gate, PoW-depth finality. Genesis-4 is a
  linear chain with slot/epoch timing and Casper-style finality. None of the
  above carries over.

## Layout

Paths mirror where each document used to live under `docs/`, so a reference
of the form `docs/X` from before this move reads as `legacy/X` now.

**`genesis3-node/` is the exception: it is code, not a document.** On
2026-08-13, when Genesis-4 went live, the Genesis-3 node moved here from the
repository root. It had been the workspace's *root package*, which meant a
bare `cargo build` produced the proof-of-work node and offered it as the
repository's default output — a fair description of the project in July and a
false one now. It is a plain workspace member at `legacy/genesis3-node/`
today, it still compiles, and `cargo build --release --workspace` still
produces `bloch`, `bloch-cli`, `bloch-calibrate` and `bloch-wallet`.

Two things did not move with it, and deliberately: `crates/bloch-sis-pow` and
`crates/coherence-core`. They read as proof-of-work crates and they are not
exclusively that — `bloch-crypto`, which is on the **Genesis-4** consensus
path, depends on both. Filing them under `legacy/` would have been a tidier
directory and a false statement about the live chain's dependency graph.

**Reproducing a published Genesis-3 binary: do not build from this path.**
`REPRO.md` and `repro-manifest.sh` assume the package sits at the repository
root, because it did when every published binary was cut. Check out the
`genesis3-node-*` tag for the release you are verifying, or the branch
`deploy/g3-terminal-50000`. The move changed no bytes of the program; it did
change paths, and reproducibility is checked against paths.

**The terminal height in this folder is stale in two directions.** Documents
here say 80,000; the constant on the trunk says 50,000; the chain stopped at
**39,918**. See the note at the top of the root `README.md`.

| Path | What it is |
| --- | --- |
| `genesis3-node/` | **Code.** The Genesis-3 proof-of-work node — `src/`, its integration tests, and its examples. Ran mainnet from 2026-07-29 to height 39,918. Kept buildable because Genesis-4's opening ledger is this node's output. |
| `MERGED-MINING.md`, `MERGED-MINING-ACTIVATION.md` | AuxPoW / merged mining with Bitcoin: the protocol and the flag-day runbook, including the honest note that merged mining only secures Bloch with the fraction of BTC hashrate that opts in. |
| `MIGRATION-TOKENOMICS-V1-TO-V2.md` | The completed 2026-05 code migration off V1 tokenomics. Its embedded shell transcripts and before/after listings are preserved verbatim as a record of what was run; the `docs/specs/…` paths inside those fenced blocks are the paths *as they were then*, deliberately not rewritten. |
| `MAINNET-DEV-CHECKLIST.md`, `STRESS-TEST-PLAN.md`, `INTERNAL-AUDIT-PLAN.md` | The 2026-05 pre-mainnet gate trilogy. Scoped to subsystems that are gone (Stratum V1/V2, DKG, BLS FFG). |
| `BLOCH-UPGRADE-REACHABILITY.md` | Durable reachability index for GhostDAG coloring. Never activated (`CORRECTED_COLORING_ACTIVATION_HEIGHT = u64::MAX`); the flag-day it needed can no longer be taken. |
| `CALL-FOR-REVIEW.md` | The reviewers-and-testers call. Its ask was PoW cryptanalysis. |
| `BLOCH_DEVELOPMENT_PLAN.md` | The founding fork-divergence plan. Its decision D2 — "remove Casper-FFG finality and the validator committee; Bloch is pure PoW" — is exactly what Genesis-4 reverses. |
| `FEATURES.md` | Genesis-2 feature summary. Superseded twice: by Genesis-3, then by the PoS relaunch. |
| `specs/TOKENOMICS_V2.md`, `specs/TOKENOMICS_V3.md`, `specs/historical/TOKENOMICS_V1_SUPERSEDED.md` | The three PoW emission schedules, in order. V3 was the live Genesis-3 schedule. |
| `specs/POW-HARDNESS.md`, `research/POW-CANONICAL-frontier.md` | The Module-SIS PoW hardness analysis and the parameter-frontier sweep. A mutually-citing pair; the negative result is the durable content. |
| `architecture/mining-header.md` | The 80-byte Bitcoin-layout mining-header projection that made SHA-256d ASIC mining possible. |
| `design/CHAIN-SYNC-MODEL.md`, `design/CHAIN-SYNC-MODEL-PHASE2-SHIPPED.md` | Headers-first IBD and DAG-frontier reconciliation with a blue_work-verified latch. Tied to the BlockDAG. |
| `implementation/sprint-aa1-plan.md`, `implementation/sprint-aa1-pt3-plan.md` | Stratum V1 server implementation plans. |
| `operations/stratum.md` | Operator guide for running a Stratum V1 mining server. |
| `operations/UPGRADE-ghostdag-reachability.md` | The coordinated soft-fork runbook for the reachability fix. |
| `operations/v0.6.0-reset.md` | Era-1 chain-reset runbook: calibrate genesis difficulty from measured hashrate, rebuild, redeploy the miner fleet. |
| `portal/` | The five-page developer portal, written for the PoW chain. Its RPC mechanics are partly salvageable; its framing ("pure-PoW UTXO L1", "no VM", "PoW-depth finality", "ownerless") is falsified point by point by Genesis-4. The replacement surface is `docs/specs/BLOCH-RPC-V4.md`. |
| `gips/GIP-0002-stratum.md`, `gips/GIP-0003-stratum-v2.md` | Stratum V1 and V2 as GIPs. **They remain part of the numbered GIP series and their numbers are not reusable** — the process itself still lives in `gips/GIP-0001.md`. They are filed here because their subject is a mining interface, not because they were withdrawn. |
| `rfc/RFC-001-ffg-signature-scheme.md` | The BLS12-381 ‖ ML-DSA-65 FFG attestation scheme, over a committee elected by hashrate. Genesis-4's finality uses neither BLS nor hashrate weighting. |

## Known loose ends in this folder

Stated rather than hidden, because an auditor will find them anyway.

- **Stale terminal height.** Several documents here (and several still in
  `docs/`) say 80,000. See above: 50,000 is the decision. This was not
  bulk-corrected, because in some places 80,000 is quoted as the historical
  value that was later lowered, and a blind replace would falsify that.
- **Code comments still point at the old paths.** Doc comments in `src/`,
  `crates/`, `deploy/` and `apps/` cite paths such as
  `docs/research/POW-CANONICAL-frontier.md`, `docs/specs/POW-HARDNESS.md`,
  `docs/specs/TOKENOMICS_V2.md`, `docs/operations/stratum.md`,
  `docs/architecture/mining-header.md`, `docs/operations/v0.6.0-reset.md`
  and `docs/MERGED-MINING.md`. Those trees were deliberately not edited:
  the Genesis-3 binary running on mainnet was built from them and must keep
  compiling byte-for-byte-comparably until the terminal height. Read
  `docs/…` in a code comment as `legacy/…`. The full list is in the move
  report; the fix belongs in the same change that retires the PoW code.
- **`MAINNET-DEV-CHECKLIST.md` references `operations/stratum-v2.md`**,
  which never existed — it was a to-do that was never done.
- **Pre-existing broken links** unrelated to this move (for example
  `docs/audit/AUDIT-2026-04-20.md`, whose real name is
  `AUDIT-2026-04-20_ERA1.md`) were left alone.

## What deliberately stayed in `docs/`

Not everything that mentions proof of work moved. Three categories stayed:

- **Things Genesis-4 consumes.** `docs/CARRYOVER.md` and
  `docs/SNAPSHOT-BOOTSTRAP.md` describe the two artifacts the PoS launch is
  built from. They are Genesis-3-specific in every detail and still
  operationally load-bearing today.
- **Decision records.** All ADRs stayed in `docs/adr/`. A superseded
  decision is still a decision, the series is cross-referenced by number,
  and an ADR that is wrong is evidence of *when* it became wrong. Which ones
  are dead is marked in `docs/README.md`.
- **The historical record readers go looking for.** Release notes, the two
  Era-1 audits, the IBD-reorg post-mortem. These describe the PoW era as
  history of something that ran, which is more useful filed where a reader
  expects release notes and audits than exiled here.
