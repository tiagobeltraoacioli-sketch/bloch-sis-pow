<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Fleet brief — 2026-08-11

> **Historical — dated brief, superseded in part.** Written 2026-08-11 as
> binding instruction for that wave. Two things have happened since: the
> tokenomics went from 21 B to a **100,000,000,000 BLOCH hard cap** (pure
> ×100/21 split, decided 2026-08-12), and **Genesis-3 halted permanently at
> height 39,918 on 2026-08-13**, with **Genesis-4 live under proof of stake
> from 21:31:19 UTC the same day**. The stale figures below have been
> corrected in place and marked; the reasoning and the working rules still
> hold. Do not cite this brief for a number — cite
> `crates/bloch-pos-committee/src/tokenomics_v4.rs`.

Shared context for every agent on this wave. Read it before starting; do not
re-derive what is settled here, and do not contradict it silently — if your
work says something here is wrong, say so explicitly in your report.

## Where things stand

- Repo: `~/dev/BlochPOS`, branch `integration/pos-modules`. The PoS crate is
  `crates/bloch-pos-committee` (its own workspace — `cargo test` must be run
  from inside the crate directory, not the repo root).
- 270 tests green as of `f6299a3`.
- **Licence: AGPL-3.0-or-later.** Decided 2026-08-11. New files carry
  `SPDX-License-Identifier: AGPL-3.0-or-later`.

## Settled, not up for re-litigation

*(Settled as of 2026-08-11. Items 1 and 4 have since been overtaken by events;
corrected in place below.)*

1. ~~**The Genesis-3 chain halts at height 80,000.**~~ **Superseded twice, then
   overtaken.** The terminal height was lowered from 80,000 to 50,000 on
   2026-08-12, and the chain in fact stopped permanently at **height 39,918**
   on 2026-08-13 (terminal DAG block count **50,690** — height and block count
   are different measurements in a DAG, and 50,690 is not the 50,000 ceiling).
   The "~6 months with no miners" projection therefore never ran: **Genesis-4
   went live under proof of stake at 21:31:19 UTC on 2026-08-13**, from the
   signed terminal snapshot. There was no hybrid PoW/PoS phase — that part
   held. Live params: 30 s slots, 32 slots/epoch, `COMMITTEE_SIZE` 128,
   `SLOT_SUBCOMMITTEE_SIZE` 8, 64 genesis validators, Casper justification and
   finalisation **by epoch** (~32 min typical, ~48 min worst case). Finality,
   not confirmation depth, is the settlement rule.
2. **The signature suite is unchanged**: `SUITE_MLDSA65_FALCON1024 = 0x0001`,
   ML-DSA-65 ‖ Falcon-1024 hybrid, both must verify. Escape hatch
   `SUITE_MLDSA65_ONLY = 0x0002`. Falcon signs exclusively through the
   constant-time `clean` path (pinned by a symbol test and a CI guard).
3. **The Coherence shielded pool is C1-frozen**: SHAKE-256 commitments and
   nullifiers, SP1 raw FRI-STARK, no elliptic-curve ZK. Leaf positions are
   consensus.
4. **Tokenomics V4** — *every figure in the original text of this item was
   stale by the next day; corrected here.* The total is
   **100,000,000,000 BLOCH, hard-capped** (not 21 B — a pure ×100/21 split
   decided 2026-08-12: every bucket scales, every percentage is unchanged,
   nobody is diluted). The **terminal carryover is 18,146,400,000 BLOCH,
   measured at Genesis-3 height 39,918 over 452,726 outputs**, from a
   Genesis-3-side total of 3,810,744,000 BLOCH — the two sides of the same
   split, the same coins. It crosses as one undifferentiated set, liquid at
   genesis. Founder grant **10,000,000,000** (10%). VC 10%, team 10%,
   marketing 4%, liquidity 5%. Validator emission **42,853,600,000 (42.85%)**
   over 40 years, issued rather than granted at genesis; genesis itself issues
   **57,146,400,000**. Fees burn during emission, then 100% to validators.
   Superseded figures you may still find in older text and must not reuse:
   3,773,884,800 · 3,475,441,200 · 17,970,880,000 · 3,805,746,000 /
   18,122,600,000, and 9,036,115,200 or 43,029,120,000 for validator emission.
   The label "height 43,172" is doubly wrong: 43,172 was a **block count**
   mislabelled as a height, and the total it went with is superseded. The
   authority is `crates/bloch-pos-committee/src/tokenomics_v4.rs` — never
   restate a number, import the constant.
5. **Governance is not ownerless.** Two-entity foundation structure
   (`BLOCH-ENTITY-STRUCTURE.md`). The founder allocates the genesis validator
   cohort and is bound by a consensus rule taking that cohort under one third
   within a year (`genesis_cohort.rs`).
6. **Churn**: `WARMUP_RATE_BPS = 25` (was 900). Floor `MIN_CHURN_SAT =
   MIN_DEPOSIT_SAT`.
7. **A carried-over balance that is liquid is also stakeable.** Founder
   decision, 2026-08-11 — and it is a statement about the *design*, not about
   what the live chain accepts today. On Genesis-4 as it runs now, **`Deposit`
   and `Delegate` are refused at every node's mempool**
   (`crates/bloch-pos-node/src/engine.rs:1900-1906`) because bonding is not yet
   funded from the UTXO set. Nobody can stake a carried balance in practice
   until that changes. Say "stakeable by design, refused in practice today" —
   not "stakeable" unqualified.

## The two new directions on this wave

### EVM at L1, no L2

The founder's instruction is that Bloch runs EVM **at the base layer**, not as
a rollup. `bloch-l2-evm` (chainId 8400), currently a separate service, is the
thing being replaced — not extended.

**A premise correction you must not repeat.** The instruction came with
"Solana is natively EVM". It is not: Solana runs the SVM over SBF bytecode,
with programs written in Rust/C, and EVM on Solana exists only through Neon
EVM, a separate deployed program. What Solana *does* have, and what the
instruction actually means, is **one global state machine at L1 with no
rollups** — everything native, one fee market, one state. Design to that, and
do not cite Solana as EVM precedent in any document.

**The hard problem, stated up front so nobody discovers it in week three.**
EVM tooling — MetaMask, Ledger, `eth_sendRawTransaction`, every wallet and
every deployment script — signs secp256k1 and recovers the sender address from
the signature. Bloch's base is ML-DSA-65 ‖ Falcon-1024, which is not
recoverable, is ~4.6 KB per signature, and no hardware wallet implements it.
"EVM at L1" therefore forces an explicit choice, and each option costs
something real:

- Accept secp256k1 accounts at L1 for EVM transactions. Cheapest for adoption;
  it means the chain has a quantum-vulnerable authorisation path, which is the
  one thing the whole project exists to avoid. If this is proposed, the
  security note must be blunt about what it gives up.
- PQ-only accounts, EVM semantics but not EVM tooling. Keeps the thesis; means
  MetaMask never works and every tool needs porting.
- Both, with the fee/consensus consequences of a dual authorisation model made
  explicit — including what a quantum adversary can steal from the secp256k1
  side and whether that contaminates the PQ side.

Nobody is authorised to pick silently. Price all three; recommend one; the
founder decides.

Second-order questions that are yours to answer, not to defer: how an
account-model state coexists with the eUTXO base and the shielded pool; what
this does to the closed list of `state_root` leaves; gas versus the V4 fee
model; and whether `crates/bloch-euvm` (the eUTXO VM, consensus-wired at
Genesis-3 height 0) survives, is absorbed, or dies.

### Ustav at L1

**Ustav** is the token-charter standard (PSTRN-1), and **Kirpich** is its
fail-closed charter-audit gate. Today both are described publicly as *Postern
tooling built on `bloch-euvm`* — "reference/tooling, not consensus rules". The
instruction is to promote Ustav to L1, i.e. to make the charter a consensus
object rather than a convention.

That is a genuine change of kind, not a port. A charter enforced by consensus
means every node validates charter rules, which makes charter semantics part
of the fork-choice-relevant state and makes a charter bug a chain bug. Say
what is gained (a charter that cannot be bypassed by talking to the contract
directly) and what is bought with it (consensus surface, upgrade rigidity,
the fact that a token issuer's mistake becomes everyone's validation cost).

## How to work

- You get your own git worktree. **Commit your work in it before you finish.**
  Every previous wave left everything uncommitted and the PMO had to commit on
  their behalf; twice, work was nearly lost.
- Read before writing. `docs/specs/` has the normative design
  (`BLOCH-POS-SHA3-LATTICE-MIGRATION.md`), the two threat models, the
  interfaces contract, and the node-integration plan.
- Never restate a constant. Import it. `tools/doc-sweep/check_stale.py` exists
  because five tokenomics revisions left stale numbers in prose that the
  founder caught by reading the PDF.
- One derivation path. The crate has a property test
  (`header.rs::single_derivation_path`) that scans `src/` and fails if block
  identity can be derived a second way. At integration on 2026-08-11 it caught
  two `BlockId` types, two `BlockHeaderV4` types and three copies of the
  canonical header serialisation, written by three agents who each thought
  they were the only one. If you need a derivation that exists, call it.
- Report honestly. A finding you are unsure of, labelled unsure, is worth more
  than a confident one that is wrong. If you did not run it, do not say it
  passes. If the task is bigger than the time you had, say what you did not
  do — do not narrow the task silently and report success.
