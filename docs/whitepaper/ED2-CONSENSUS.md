<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Institutional Dossier — Edition 2

## The Consensus Chapters: Genesis-3, Its End, and the Proof-of-Stake Chain That Replaced It

```
Document:   ED2-CONSENSUS
Edition:    2 · 2026
Supersedes: Edition 1, Chapters 5–8 (Consensus I — Proof of Work;
            Consensus II — The BlockDAG & GhostDAG; The Genesis-2 Hard Fork;
            Finality & the Dropped FFG)
Repository: bloch-pos (gitlab.com/blochsispow-group/bloch-pos)
License:    AGPL-3.0-or-later
Revised:    2026-08-14. The transition this chapter was drafted in
            anticipation of has happened; the text is re-tensed against it.
```

> **The one fact that governs every tense in this chapter.** Genesis-3, the
> proof-of-work chain, **stopped permanently at height 39,918 on 2026-08-13**.
> It never reached the announced terminal heights of 80,000 or 50,000.
> **Genesis-4, proof of stake, has been live since 21:31:19 UTC on
> 2026-08-13** — 30-second slots, 32-slot epochs, Casper-style justification
> and finalisation by epoch, the hybrid ML-DSA-65 ‖ Falcon-1024 suite on every
> consensus path. Public read RPC: `https://posternlabs.com/g4rpc`.
>
> The planned pause of roughly six months between the two chains, for code
> review and an external audit, **did not occur**. There has been no external
> audit. The distribution gates G1–G4 were not met. Chapter 5 states the live
> chain's honest status, and it is not the status this chapter originally
> anticipated.

**Honest status, inherited and enforced.** Edition 1 adopted a mantra and this
edition keeps it: **designed ≠ built ≠ booted**. Having a specification, having
code that implements it, and having that code running as the consensus-enforced
rule on a live network are three different states, and every capability in
these chapters is labelled with which of the three it has reached. Conflating
them is the single most common way a technical dossier misleads a reader, and
Edition 1 was written to avoid it systematically. So is this one — which
matters more this time, because Edition 2 must document a consensus that went
from specification to live mainnet inside a fortnight, and must also document a
reversal: a finality mechanism Edition 1 correctly described as dropped is now
the center of the design and is finalising checkpoints on a public network.
That reversal is explained in Chapter 4, honestly, including what changed in
the reasoning and what has *not* changed in the facts.

Three status vocabularies used throughout:

- **Designed** — specified in a reviewed document; no claim that code exists.
- **Built** — implemented and tested as code; no claim that it runs anywhere
  that matters.
- **Booted** — running as an enforced rule on a network; the only state that
  constitutes a property of a live chain.

**And a fourth thing, which is not a status but a standing caveat, because on
this chain "booted" is easy to over-read.** Genesis-4 is a mainnet, and it is
operated end to end by one entity: **64 of 64 validators**. Its live transport
is a point-to-point TCP full mesh with **a fixed peer list, no discovery and no
authentication**, which is the mechanical reason a third party cannot join.
`Deposit` and `Delegate` transactions are **refused at every node's mempool**,
because bonding is not yet funded from the UTXO set, so no outside party can
bond stake even if it could connect. And no third party has audited any of it.
Every "booted" label below inherits all four sentences.

---

# 1. Genesis-3 — the consensus that ran until 2026-08-13

> **Historical — Genesis-3.** This chapter describes the proof-of-work chain
> that stopped permanently at height 39,918 on 2026-08-13. The live chain is
> **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by
> epoch), described in Chapter 3. This chapter is kept because Genesis-4's
> opening ledger is derived from it. It is not what runs.

Edition 1 documented Genesis-2, the live chain of mid-2026. On 2026-07-29 the
network relaunched as **Genesis-3**: not a fork of Genesis-2 but a brand-new
chain starting at height 0 with its own genesis block and a distinct chain
identifier, ingesting the same carried-over ledger as opening balances. This
chapter documents what Genesis-3 ran — booted, on mainnet, for the fifteen
days of its life — and Chapter 2 documents the unusual fact that distinguishes
this edition from every ordinary protocol dossier: the chain had a
consensus-encoded final block, and it reached it.

All statuses in this chapter read **"Booted (Genesis-3, ended 2026-08-13)"**;
where the text below says "booted" it means booted then, not now.

## 1.1 Chain identity and lineage

Genesis-3 is registered as `ChainId::Genesis3Mainnet = 0xB10C_0004`
(`crates/bloch-crypto/src/core/mod.rs:179`). The registry comment is explicit
about what it is and is not: "a brand-new chain that starts at height 0 with
its OWN genesis block (distinct coinbase banner ⇒ distinct genesis hash — NOT
a fork of Genesis-2), ingests the SAME carry-over ledger as Genesis-2 as its
opening balances" (`mod.rs:170-178`). The chain-id is folded into every
transaction sighash for replay domain separation (`mod.rs:139-151`), so a
Genesis-2 signature cannot be replayed on Genesis-3 or vice versa.

The carryover is not optional equipment. `chain_requires_carryover`
(`mod.rs:396-411`) makes the snapshot flag mandatory at node start for
Genesis-3, for a fail-closed reason stated at the match arm: a node started
without it "would produce a chain with the right rules and an empty ledger —
every balance silently gone, and nothing in the protocol objecting"
(`mod.rs:400-405`).

**Status: booted (Genesis-3).** Genesis-3 mainnet produced blocks from
2026-07-29 until its terminal block at height 39,918 on 2026-08-13.

## 1.2 SHA-256d, ASIC-native from height zero

The proof-of-work function is SHA-256d over an 80-byte Bitcoin-layout mining
header, exactly as Edition 1 described for Genesis-2. The chain-id → PoW
mapping is a single exhaustive function, `pow_algorithm` (`mod.rs:199-207`),
with `ChainId::Genesis3Mainnet => PowAlgorithm::Sha256d` (`mod.rs:205`) —
miner and validator both route through it, so they provably agree.

One defect Edition 1 spent a chapter on is structurally absent here. Genesis-2
needed a height-gated hard fork (`SHA256D_LE_FORK_HEIGHT = 2400`,
`mod.rs:2473`) to correct a big-endian target comparison that rejected all
standard ASIC work. Genesis-3 validates little-endian **from height 0**:
`sha256d_le_fork_height_for(ChainId::Genesis3Mainnet)` returns `0`
(`mod.rs:2489-2496`), with the rationale in place — "a fresh chain has no
legacy big-endian blocks to grandfather, so ASIC shares validate from block 1"
(`mod.rs:2485-2488`). The endianness lesson of Edition 1's Chapter 7 was paid
for once and encoded permanently.

**Status: booted (Genesis-3).**

## 1.3 Difficulty — and the incident that rewrote how it is validated

The target block interval is 30 seconds (`TARGET_BLOCK_TIME`, `mod.rs:262`,
sourced from `tokenomics_v2.rs:82`), with a Bitcoin-style retarget every 60
blocks (`GENESIS3_RETARGET_WINDOW = 60`, `mod.rs:2281`, compile-time asserted
equal to the Genesis-2 window at `mod.rs:2288`).

Edition 1 described difficulty retargeting as "a purely mechanical,
deterministic adjustment computed identically by every full node from the same
on-chain history." On Genesis-3 that sentence was, for a period, false in a
way this dossier is obliged to record. The legacy validation path derived
expected difficulty from **node-local mutable state** — a `current_bits` meta
key rewritten on every accepted block, and a timestamp column keyed by height
alone, which in a DAG is last-write-wins. Two nodes running an *identical
binary* could disagree purely because they accepted blocks in a different
order, and every follower froze permanently at the first retarget boundary
where its cache had diverged. The consequence is stated in the code, not
softened: "The chain effectively had one producer and no independent
validator" (`mod.rs:32-44`).

The fix is `DIFFICULTY_ANCESTRY_FORK_HEIGHT = 30_030` (`mod.rs:125`): at and
above that height, expected bits are a pure function of the block's own
selected-parent ancestry, computed at one height-gated choke point shared by
the validator and every template producer, with ancestry-incomplete cases
failing closed (`mod.rs:102-111`). The 90-line comment above the constant
preserves the full post-mortem, including a first activation attempt that was
itself wrong (a distant flag-day at 30,000 "is not a safety margin at all: it
is a guarantee that no follower ever reaches the fix", `mod.rs:56-65`) and an
emergency intermediate raise after a halt at height 28,080 where the producer's
own template and its own validator disagreed (`mod.rs:72-100`).

**Status: booted (Genesis-3)** — active above 30,030 for the remainder of the chain's life.

> **Note.** This incident matters beyond its mechanics, and it recurs in
> Chapters 3 and 4. It is the clearest evidence in the project's record for
> two claims this edition relies on: first, that Genesis-3's practical
> security posture was weaker than "young PoW chain" already implies — for
> stretches of its life the network had one block producer and no independent
> validation; second, that consensus values derived from node-local mutable
> state are how identical honest nodes split. The proof-of-stake design in
> Chapter 3 treats the second claim as a design axiom
> (`crates/bloch-pos-committee/src/transition.rs:14-29`).

## 1.4 GhostDAG ordering

Genesis-3 remains a BlockDAG ordered by GhostDAG, as Edition 1's Chapter 6
described: blocks may cite multiple parents, and the canonical total order is
computed over the blue set by accumulated blue work rather than by a single
longest chain. The anticone parameter is `GHOSTDAG_K = 10` (`mod.rs:251`).
Everything in Edition 1's structural account — tips, blue/red classification,
`blue_score` as the DAG analogue of height, parallel-block absorption instead
of orphaning — carries over unchanged and is not re-derived here.

One measured fact is worth adding: with a 30-second target and DAG
parallelism, the observed cadence at the time of writing is faster than
target — 21.57 s/block measured on 2026-08-12 (commit `38258aa`, branch
`deploy/g3-terminal-50000`). The DAG absorbs the parallel production, exactly
as the structure is designed to.

**Status: booted (Genesis-3).**

## 1.5 Merged mining with Bitcoin (AuxPoW)

Since Edition 1, Genesis-3 gained merged mining: because Bloch's PoW is
SHA-256d exactly like Bitcoin's, the same hash can secure both chains. A miner
hashes a Bitcoin block whose coinbase carries a commitment to a Bloch block;
if that single hash meets Bloch's (lower) target, an AuxPoW proof lets Bloch
accept the block — "no extra hashing, no new ASICs"
(`crates/bloch-crypto/src/core/auxpow.rs:1-17`). The verifier is faithful to
the standard Bitcoin/Namecoin `CAuxPow` format — parent-header PoW against
Bloch's `bits`, coinbase proven at index 0 in the parent merkle root, and the
`fa be 6d 6d` merge-mining marker carrying the aux root (`auxpow.rs:10-17`) —
so existing merge-mining pool tooling applies. Bloch's merged-mining chain id
is `AUXPOW_CHAIN_ID = 0x0B10` (`auxpow.rs:36`).

Activation followed the project's established flag-day idiom: the verifier
shipped inert with the activation height at `u64::MAX`, then a coordinated
fleet upgrade set `AUXPOW_ACTIVATION_HEIGHT = 8500`, activated 2026-08-01
(`mod.rs:16-22`). A block carrying an `auxpow` below the height is invalid,
fail-closed; the validation arm is height-gated at `mod.rs:1756`.

The honest caveat ships in the module documentation and this dossier repeats
it rather than paraphrasing it away: "merged mining only secures Bloch with
the FRACTION of BTC hashrate that opts in, and lets a large BTC miner attack
at ~zero marginal cost — for a young chain this can worsen the 51% risk, not
fix it. It is a bootstrap lever, not a security guarantee"
(`auxpow.rs:23-26`).

**Status: booted (Genesis-3)** — active at and above height 8,500; merged
blocks were accepted on Genesis-3 mainnet from 2026-08-01 until the halt.

## 1.6 What Genesis-3 is, in one table

| Component | Mechanism | Source | Status |
|---|---|---|---|
| Chain identity | `0xB10C_0004`, fresh genesis, carryover opening balances | `mod.rs:179`, `mod.rs:396-411` | Booted (ended 2026-08-13) |
| Proof of work | SHA-256d, 80-byte Bitcoin-layout header, little-endian from height 0 | `mod.rs:199-207`, `mod.rs:2489-2496` | Booted (ended 2026-08-13) |
| Difficulty | 30 s target, 60-block retarget; ancestry-derived bits above h30,030 | `mod.rs:262`, `mod.rs:2281`, `mod.rs:125` | Booted (ended 2026-08-13) |
| Ordering | GhostDAG over a BlockDAG, K = 10 | `mod.rs:251` | Booted (ended 2026-08-13) |
| Merged mining | Namecoin-style AuxPoW under Bitcoin, active at h8,500 | `auxpow.rs`, `mod.rs:22`, `mod.rs:1756` | Booted (ended 2026-08-13) |
| Finality gadget | None — PoW depth only, exactly as Edition 1 stated for Genesis-2 | Ch. 4 below | n/a — never existed on this chain |
| Terminal height | Chain ends at a fixed height; blocks above are consensus-invalid | Ch. 2 below | **Fired — the chain stopped at height 39,918 on 2026-08-13** |

None of the above describes the network today. For that, see Chapter 3.

---

# 2. The terminal height — why Genesis-3 ended

This is the chapter Edition 1 could not have contained. Genesis-3 had a
consensus-encoded last block, and it reached it: **the chain stopped
permanently at height 39,918 on 2026-08-13.** At that height a signed balance
snapshot was taken; the snapshot — not the chain — is the canonical record; and
Genesis-4, a proof-of-stake chain, launched from that artifact **the same day,
at 21:31:19 UTC**. Nothing about this was framed as an upgrade of the running
chain. The chain was not continued. It was ended, deliberately, and the
protocol's own constants said so.

Three facts about how this differed from the plan, stated here rather than
discovered later, because a dossier that only records the plan is worth
nothing:

1. **The chain stopped below every height ever published.** The constant was
   introduced at 80,000, lowered to 50,000 on 2026-08-12, and the chain in
   fact stopped at 39,918.
2. **The planned ~six-month pause between the chains did not happen.**
   Genesis-4 opened within hours. §2.3 and §5.3 below were written for that
   pause; they are corrected in place.
3. **The external audit the pause existed for has not happened**, and the
   Go/No-Go distribution gates were not met before launch. Chapter 5 carries
   this as the live chain's honest status.

## 2.1 The rule

`GENESIS3_TERMINAL_HEIGHT` is the last valid height on the Genesis-3 mainnet;
blocks **above** it are invalid (`mod.rs:437-438`). The terminal height itself
is valid — "it is the last block, and the height the snapshot is taken at"
(`is_past_terminal_height`, `mod.rs:457-466`). The per-chain lookup is
exhaustive with no wildcard arm, the same fail-closed idiom used for the
carryover requirement: adding a chain-id without deciding whether it
terminates is a compile error, "instead of silently inheriting 'runs forever'"
(`mod.rs:440-455`). A unit test pins that only Genesis-3 terminates
(`mod.rs:3064-3071`) and another pins that the terminal block itself remains
valid (`mod.rs:3074-3086`).

The rule is wired at every point where a block could be born or accepted:

- **Block acceptance** rejects anything past the terminal height before any
  other validation work: "this chain has ended; Genesis-4 launches from the
  snapshot" (`src/main.rs:2537-2544`).
- **The internal miner** stops assembling rounds and idles rather than
  grinding PoW its own node would reject (`src/main.rs:1820-1835`).
- **Stratum V1** template production refuses past-terminal templates
  (`src/stratum/session.rs:102`), and **Stratum V2** likewise
  (`src/stratum_v2/template_adapter.rs:55`) — so ASICs are never handed work
  on a chain that has ended.

## 2.2 The value: 80,000, then 50,000 — and a chain that stopped at 39,918

The constant was introduced at 80,000 on 2026-08-11 (commit `ced885d`; the
value on this repository's integration branch, `mod.rs:438`). On 2026-08-12
the founder lowered it to **50,000**, shipped as a single-constant diff on the
dedicated branch `deploy/g3-terminal-50000` (commit `38258aa`) against the
exact tree already running fleet-wide — the commit message states the
discipline plainly: a three-day flag day is not the place to ship a month of
work with no mainnet soak. At the measured 21.57 s/block cadence, height 50,000
was roughly three days from that commit, and every node had to be running the
50,000 binary before it arrived. The commit is equally plain about the failure
mode: "A node still on the 80,000 binary keeps accepting blocks above 50,000,
and the moment one does, the halt itself becomes the fork."

**Neither value is what happened.** Genesis-3's last block is height
**39,918**, on 2026-08-13 — below both published heights. The terminal
snapshot taken there is the authority for every carryover figure in this
edition: **452,726 outputs, 18,146,400,000 BLOCH**, with the SHAKE-256 set root
and both file digests pinned in
`crates/bloch-pos-committee/src/tokenomics_v4.rs`
(`CARRYOVER_MEASURED_HEIGHT`, `CARRYOVER_MEASURED_UTXOS`,
`CARRYOVER_TOTAL_BLOCH`, `CARRYOVER_MEASURED_ROOT`) so an independent operator
can reproduce it and compare. This edition does not reconstruct why the chain
stopped early; it records that the end of the chain arrived, in the event,
sooner than any number the project had published, and that this is the third
unilateral change to that number in three days.

A related trap, recorded because it already produced a wrong published figure:
some earlier documents describe the carryover as "measured at height 43,172".
The chain was never at height 43,172 — that was a **block count**, and in a DAG
the two differ by design. Quote heights as heights.

The number 50,000 was originally argued from a carryover-cap race
(`docs/specs/BLOCH-TOKENOMICS-V4.md` §3.1) that has since been retired along
with the cap itself (§3: every holder carries over in full, no scale-down, no
founder-exclusion list). What survives of the rationale is the notice logic:
about two weeks of public notice at decision time, on a round number — and the
spec's counterintuitive but correct observation that *longer* notice is worse
here, because holders need do nothing (balances are captured on-chain
automatically) while the one action notice enables is accumulating more coins
before the cut (§3.1).

**Status: fired.** Designed (V4 §3.1–3.2), built and tested
(`mod.rs:437-466` and the four wiring sites above), deployed, and executed:
Genesis-3 produced its last block at height 39,918 on 2026-08-13 and has
produced none since.

## 2.3 Why the chain ended: the honest argument, in full

Edition 1 said, in its Chapter 5 and again in Chapter 8, that Genesis-2 was "a
young chain with low accumulated hashrate, and is realistically
51%-attackable," that how long that window would persist was "an open
question," and that the dossier would not pretend to answer it with a number
it did not have. Edition 2 can now answer it: the window did not close. It was
not closing. Genesis-3 inherited the same condition — low external hashrate,
concentrated block production, and (per §1.3 above) stretches with effectively
one producer and no independent validator. Merged mining, activated in August,
borrowed real Bitcoin work but by its own module's admission is "a bootstrap
lever, not a security guarantee" (`auxpow.rs:26`) — and can worsen the 51%
profile against a large Bitcoin miner, not improve it.

A protocol in that condition has three honest options: continue and keep
labelling confirmations as reversible indefinitely; wait for organic hashrate
that two chain generations failed to attract; or end the chain deliberately
and move its ledger to a security model whose budget does not depend on
external hashrate arriving. The project chose the third. The specific
reasoning for *halting* rather than running the old chain in parallel is in
`BLOCH-TOKENOMICS-V4.md` §3.2 and is worth restating because it is not
obvious:

1. **A halt must be a consensus rule, not an announcement.** "A chain does not
   stop because it was announced." If blocks above the terminal height were
   merely unwanted, miners would keep producing them and the halt would be "a
   fork nobody agreed to. Making them **invalid** is what actually ends the
   chain" (`mod.rs:419-423`, V4 §3.2.1). This is a flag day in reverse, with
   every flag-day hazard this project has already lived through intact.
2. **A running dead chain is worse than a stopped one.** Had Genesis-3 kept
   producing during the planned gap between snapshot and Genesis-4 launch,
   coins would have been mined by people receiving nothing in the successor,
   and the rational miner switches off the day after the snapshot anyway —
   leaving the network without hashrate during exactly the period it still has
   users, wallets and an explorer pointed at it (V4 §3.2). Note that the gap
   this argument was sized for (~six months) did not occur; Genesis-4 opened
   the same day. The argument for halting rather than running two chains is
   unaffected. The argument's *premise about the schedule* was wrong, and the
   review the schedule existed to allow did not take place.

## 2.4 After the halt, the chain's history stops being evidence

This is the non-obvious consequence, and the code comment above the constant
states it with no varnish: "Once mining stops, this chain's history stops
being evidence. PoW security is bought with ongoing hashrate; with none,
rewriting history below the terminal height costs almost nothing"
(`mod.rs:431-433`). This is now a live property of the historical record, not a
forecast: anyone with modest SHA-256d hashrate can produce an alternative chain
ending at height 39,918 with different balances, and it may even carry more
accumulated work than the real one (V4 §3.2.2).

Therefore **the signed snapshot artifact is canonical, not the chain**. At the
terminal height the balance set is produced, hashed, signed, and its digest
published widely enough that it cannot be quietly replaced — the same pattern
already used for `carryover.tsv.gz` and its `.sha256` companion. The snapshot
digest is to be embedded in the Genesis-4 genesis block itself, "precisely so
the record does not depend on a chain nobody is defending" (`mod.rs:433-435`,
V4 §3.2.2). Un-upgraded miners who continued past the terminal height continue
on a fork; that is tolerable "only because the canonical artifact is the signed
snapshot at this height, not whatever chain has the most work afterwards"
(`mod.rs:427-430`). **Treat any Genesis-3 balance or transaction dated after
height 39,918 as unbacked.**

> **Risk, as it actually resolved.** This section was written expecting a
> months-long interval between the halt and the Genesis-4 launch, during which
> no live chain would defend the ledger and the security of every carried-over
> balance would be exactly the security of the snapshot digest's distribution
> and of the signing key. **The interval was hours, not months** — Genesis-4
> opened the same day — so the exposure window was short. The trust point
> itself did not go away and is not removed by any mechanism in this chapter:
> **the opening balances of Genesis-4 are whatever artifact the founder signed
> and published**, and the only check on it is breadth of publication and
> independent reproduction from the pinned root
> (`CARRYOVER_MEASURED_ROOT`, plus the SHA3-256 and SHA-256 file digests, in
> `tokenomics_v4.rs`). Anyone integrating with this chain should reproduce
> that root rather than accept it. That is the price of ending a chain whose
> work-based security was not, in honest terms, doing the securing.

---

# 3. Proof of stake — the Genesis-4 chain

Genesis-4 (design codename **Bell**) replaced proof-of-work with proof of
stake, SHA-3 hashing, and finality by epoch, while keeping two things fixed by
founder constraint: the hybrid ML-DSA-65 ‖ Falcon-1024 post-quantum signature
suite, unchanged, in every consensus role; and the Coherence ZK ledger with its
frozen SHAKE-256 formats
(`docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md`, header block). **It has been
the live chain since 21:31:19 UTC on 2026-08-13.** The design document still
carries the status line "DRAFT — design only, not approved, not scheduled";
that line is stale — the design shipped, and the document has not caught up.
This edition records the discrepancy rather than quoting the stale line as
though it were current.

The design is not only a document. A pure consensus crate
(`crates/bloch-pos-committee`) implements it rule by rule, and a node binary
(`crates/bloch-pos-node`) composes those rules into the validator processes
running the mainnet. Chapter 5 draws the built/booted line precisely and states
what is *not* true of the live network; this chapter describes the rules and
cites the code that enforces them.

**Read every "booted" in this chapter with Chapter 5 attached.** Genesis-4's
consensus rules run on a mainnet operated end to end by one entity — 64 of 64
validators — over a transport with a fixed peer list, no discovery and no
authentication, with `Deposit`/`Delegate` refused at every node's mempool and
with no third-party audit of any of it.

## 3.1 Shape: a linear chain of slots and epochs — GhostDAG retired

Time is divided into **30-second slots**, 32 slots to an epoch (≈16 minutes)
(`SLOT_DURATION_SECS = 30`, `SLOTS_PER_EPOCH = 32`,
`crates/bloch-pos-committee/src/params.rs:29-34`). The slot duration is
deliberately identical to Genesis-3's PoW block target "so the transition adds
no new propagation pressure" (`params.rs:32-33`). One validator is designated
proposer per slot by stake-weighted public sortition over a hash-based beacon
(§3.5); with one proposer per slot, concurrent block production is an anomaly
rather than the norm, and **GhostDAG is retired**: Genesis-4 is a linear
chain. The header's `parents` vector narrows to a single parent under a
consensus rule `parents.len() == 1`, and fork choice becomes LMD-GHOST over
attestation weight rather than blue score (migration spec §5.2).

The V4 block header removes `bits`, `nonce`, and `timestamp` (derived from the
slot) — and the spec is explicit about what removing `bits` buys: it "deletes
the order-dependent difficulty bug class" that split Genesis-3's mainnet
(spec §5.3, §2; the incident of §1.3 above). The ≈4.6 KB hybrid proposer
signature sits in the block envelope, not the header, so the signed header
stays 248 bytes and header-sync paths never carry the signature (spec §5.3).

**Status: designed (spec §5); header/envelope built
(`crates/bloch-pos-committee/src/header.rs`); **booted on the Genesis-4
mainnet since 2026-08-13**.**

## 3.2 Committees: the active set partitioned, not sampled

Every epoch, the full active validator set is shuffled deterministically and
**partitioned** into 32 committees, one per slot — every active validator
lands in exactly one committee and votes exactly once per epoch
(`crates/bloch-pos-committee/src/committees.rs:1-35`). The union of an epoch's
committees *is* the active set, so the finality quorum denominator is total
active stake, with no sampling variance and no ambiguity.

This is a correction the project's own adversarial review forced, and the
module documentation preserves the defect rather than deleting it. The first
design sampled a 128-validator committee, and review finding F1 showed the
quorum denominator had no coherent reading — against network stake, a
128-member sample cannot hold two-thirds once the network exceeds ~192
validators, so finality would be structurally unreachable; against committee
stake, sampling variance lets a ~30% adversary exceed one-third of the
committee roughly one epoch in five and stall finality below the nominal
threshold (`committees.rs:5-18`). Finding F2 was worse in a quieter way:
independent per-slot draws routinely selected the same validator into several
slots of one epoch, whose duplicate same-target attestations the slashing
logic then correctly flagged — "honest validators slashed themselves"
(`committees.rs:29-35`). Partitioning removes both by construction.

The cost is carried honestly: one ≈4,589-byte hybrid signature per active
validator per epoch, which is cheaper than the sampled design below 384
validators (where the launch gates put the set) and imposes a scaling ceiling
around ~4,096 validators, at which point sub-sampling — and finding F1 with
it — would have to return unless signature aggregation becomes practical;
measurement says that is "research, not engineering" (`committees.rs:37-46`,
`spikes/prover-cost/RESULTS.md`).

The partition for epoch N is seeded with a one-epoch look-ahead (the beacon
mix fixed at the close of epoch N−2), closing a grinding attack in which the
proposers of an epoch's trailing slots could withhold reveals to re-sort the
next epoch's partition (finding F6, `committees.rs:60-80`).

The epoch transition derives the partition rather than storing it — "a stored
partition is a cache" — and asserts it covers the eligible set exactly once
(`crates/bloch-pos-committee/src/transition.rs:1264-1273`).

> **Note — residual constants.** `params.rs` still carries `COMMITTEE_SIZE =
> 128` and `SLOT_SUBCOMMITTEE_SIZE = 8` (`params.rs:17,27`), and the
> `finality.rs` module docstring still narrates the earlier "full epoch
> committee of 128" design (`finality.rs:5-8`). The spec's §5.1 table marks
> both constants **removed**, and the composition layer binds the partition
> path (`transition.rs:1143`, `transition.rs:1268-1269`,
> `committees::epoch_committees` at `committees.rs:171`). The stale constants
> and docstring are documentation debt, recorded here so no reader mistakes
> them for the operative design.

**Status: designed (spec §5.1, §6.5.3); built with the F1/F2/F6 corrections
(`committees.rs`, `sample.rs`, `transition.rs`); **booted on mainnet** — with
the caveat that the "active set" being partitioned is 64 validators run by one
entity, so the partition disperses duties, not control.**

## 3.3 Fork choice: LMD-GHOST

Between finalized checkpoints, the canonical head is selected by LMD-GHOST —
Latest Message Driven: only each validator's most recent attestation counts,
the weight of a block is the total effective stake of validators whose latest
message is that block or a descendant, and the head is found by walking from
the latest **justified** checkpoint, taking the heaviest child at each step
(`crates/bloch-pos-committee/src/forkchoice.rs:1-10`). Equivocating validators
are dropped from fork-choice weight permanently (`forkchoice.rs:54-58`).
Starting the walk at the justified checkpoint gives two properties for free:
finalized history can never be reorganized out, and the walk is bounded by the
unfinalized suffix (`bloch-pos-node/src/engine.rs:50-53`).

The engine binds this rule and the documentation states why the naive
alternative is not merely weaker but wrong: longest-valid-chain "lets a
proposer with no attested support drag the chain by building fast … Length is
not the security statement in proof of stake; attested stake is"
(`engine.rs:33-48`). The engine rebuilds the fork-choice store from scratch on
every head computation rather than caching it — the `expected_bits` lesson
applied where a cache would be cheapest to get wrong (`engine.rs:54-60`).

**Status: designed; built; booted on mainnet — the engine selects its head via
`forkchoice_head` (`engine.rs:370-374`).**

## 3.4 Finality: Casper-style justification and finalization

One checkpoint per epoch. A checkpoint is **justified** when attestations
carrying it as target — from that epoch's committee members, with the
currently highest justified checkpoint as source — account for at least
two-thirds of active stake; the comparison is integer arithmetic,
`3·attesting ≥ 2·total` in `u128`, so "exactly 2/3 justifies and 2/3 − 1
satoshi does not, identically on every node"
(`crates/bloch-pos-committee/src/finality.rs:15-20`,
`committees.rs:273`). A checkpoint is **finalized** by consecutive
justification: when the supermajority link `source → target` has
`target.epoch == source.epoch + 1`, the source becomes final
(`finality.rs:21-24`).

The safety argument fits in a paragraph and the module carries it: each
validator counts at most once per epoch (duplicates deduped; *conflicting*
votes mark the validator an equivocator and count for no target,
order-independently), so two conflicting checkpoints at one epoch would need
two disjoint ≥2/3 quorums out of one whole — impossible; at most one root can
be justified per epoch, hence at most one finalized (`finality.rs:56-62`).
Requiring one uniform source per justification is what makes each
justification a property of exactly one link rather than a mosaic
(`finality.rs:31-40`).

The state is a pure fold over the vote history — no clock, no cache, "no
channel to anything but its inputs" — and the incremental epoch processor is
tested to equal the from-history fold (`finality.rs:42-54`). The module names
its ancestor incident: consensus state living outside committed inputs is what
froze every Genesis-3 follower on 2026-08-08.

**Status: designed (spec §5.1, §6.5); built (`finality.rs`); booted — the
Genesis-4 mainnet has justified and finalized checkpoints by epoch since
2026-08-13, and the node exposes the justified/finalized pair over RPC
(`crates/bloch-pos-node/src/rpc.rs`, `Finality`).** Edition 1 and earlier
drafts of this chapter both said, correctly at the time, that no finality
gadget had ever finalized a block on a public Bloch network; **that sentence is
now false and the record should show it changed on 2026-08-13.** What the
change does not mean: the ≥2/3 quorum is measured over 64 validators operated
by a single entity, so a supermajority is presently one party's decision, and
"finalized" here carries exactly as much independence as that set does.

## 3.5 Randomness: hash-based commit-reveal, no VRF

Proposer sortition and committee shuffling are seeded by a RANDAO-style
accumulator over SHAKE-256 preimages: each validator commits a hash chain at
registration (`RANDAO_CHAIN_LENGTH = 8_192`, `params.rs:53`), reveals one
preimage per slot it proposes, and the beacon mixes reveals per slot under a
dedicated domain tag (`DS_RANDAO`, `params.rs:83`;
`crates/bloch-pos-committee/src/beacon.rs`). The design uses commit-reveal
rather than a VRF because no standardized post-quantum VRF exists and the
founder constraint forbids new primitives (spec §6.3–6.4); uniqueness comes
from preimage binding, not signature uniqueness. Every signed or hashed object
in the protocol lives under a fixed 16-byte domain-separation tag so no
digest can be replayed across domains (`params.rs:69-119`).

**Status: designed; built (`beacon.rs`, `sample.rs`); booted on mainnet.**

## 3.6 Slots, stakes, and the lifecycle

The staking lifecycle is specified in spec §7 and implemented in
`crates/bloch-pos-committee/src/staking.rs`:

| Parameter | Value | Source |
|---|---|---|
| Minimum deposit | 25,000 BLCH | `staking.rs:97` |
| Activation delay | 8 epochs (≈2.1 h), rate-limited at 4 activations/epoch | `staking.rs:103,108` |
| Exit delay | 32 epochs (≈8.5 h) | `staking.rs:113` |
| Withdrawal delay | 2,048 epochs (≈22.8 days) | `staking.rs:120` |
| Per-validator stake cap | 1% of active stake, fixed-point | `delegation.rs` (spec §5.1) |
| Slashing | proposer equivocation and Casper surround/double votes | `slashing.rs`, `attestation.rs` |
| Inactivity leak | quadratic after 4 epochs of non-finality, quotient 64 | `params.rs:59,67` |

**Status of this lifecycle on the live chain: built, and not usable by anyone
outside the operator.** `Deposit` and `Delegate` transactions are refused at
every node's mempool (`crates/bloch-pos-node/src/engine.rs:1900-1907`) because
bonding is not yet funded from the eUTXO set — a `Deposit` names an amount,
spends no output, and would therefore register bonded stake without destroying
spendable coins. The refusal is node-side policy, not a consensus rule: a block
that already carries a deposit still applies it. Both halves belong in an
honest account: the refusal closes a path by which stake could be minted from
nothing against an unauthenticated endpoint, **and** it means the table above
describes a lifecycle no third party can currently enter. Closing it properly
requires giving deposits and withdrawals eUTXO inputs and outputs — a
wire-format change needing a flag day.

The **inactivity leak** deserves its own sentence because it is the liveness
backstop deterministic finality requires: after four epochs without finality
the stall is presumed a partition or abandonment rather than jitter, and
absent validators bleed stake quadratically until the remaining live stake is
again a supermajority of the shrunken total — sized for recovery in hours, not
days (`params.rs:54-67`, `finality.rs:25-29`).

**Weak subjectivity** is confronted rather than waved at. Under PoW a fresh
node needs only the genesis; under PoS, once stake has cleared withdrawal its
keys can sign an alternative history at zero cost, and a fresh node cannot
distinguish the two from inside the protocol. The answer is a weak-subjectivity
checkpoint obtained out of band, adopted as a floor the node never reverts
below (`crates/bloch-pos-committee/src/ws.rs:1-19`,
`docs/specs/BLOCH-WEAK-SUBJECTIVITY.md`) — the module's own documentation
records that the spec's first window arithmetic was wrong and re-derives it
(`ws.rs:21-25`). **Status: designed and built as format/verification rules;
the fresh-sync path that would use them is not built (§5.2) — so on the live
chain the long-range-attack answer is specified and unavailable.**

## 3.7 The genesis cohort and the one-third rule

A fresh PoS genesis has a bootstrap circularity: deposits need blocks, blocks
need validators, and there is no PoW to seed the set. Genesis-4 therefore
launched with a **genesis validator cohort** the founder funds and operates —
**64 validators, all of them, and still all of them** —
"a centralised start, by construction"
(`crates/bloch-pos-committee/src/genesis_cohort.rs:7-10`) — under a consensus
rule, not a promise: the cohort is a fixed set published in the genesis block,
it can only shrink, and its combined effective stake is capped by a schedule
declining linearly from the whole set at genesis to **one-third at one year**,
then holding (`genesis_cohort.rs:30-40`). One-third is not chosen for
modesty: it is exactly the share that can stall a two-thirds quorum, so the
rule says in one number that after year one the founder cannot halt the chain
alone. The module states with equal clarity what the rule does *not* give:
one-third is the liveness threshold, not the safety one — nothing about the
cap stops finalization of a bad state, which needs 2/3 and "is out of reach
either way" (`genesis_cohort.rs:16-27`). Stake above the cap earns nothing
and carries no weight; it is not confiscated (`genesis_cohort.rs:37-40`).

**Status: designed (V4 §3.3); built (`genesis_cohort.rs`); booted on mainnet
— and currently binding on nothing, because the taper reduces a cohort's share
of a set that contains no one else.** The rule's promise is that after one year
the founder cannot halt the chain alone. That promise is only meaningful if
independent validators exist by then, and today none can be created:
`Deposit`/`Delegate` are refused at every node's mempool and the transport has
a fixed peer list with no discovery. The cap is real code; it is not yet a real
constraint.

## 3.8 The state-transition discipline

Every rule above composes in one place: `Transition::apply_block` /
`process_epoch` (`crates/bloch-pos-committee/src/transition.rs:1-11`), written
against three rules that are Genesis-3's failures generalized into axioms:
every consensus value comes from the parent's committed state, never from
node-local mutable state; no function may depend on input arrival order; and
caps are measured against totals they do not themselves reduce
(`transition.rs:14-30`). The committed state is a plain value — no clock, no
cache, no interior mutability — and even the state root is recomputed from
leaves on every call, "because a memoized root that survives one forgotten
invalidation is exactly how `expected_bits` split the mainnet on 2026-08-08"
(`transition.rs:15-21`).

**Status: built (with the largest test surface in the crate); booted on
mainnet.**

---

# 4. The retraction — finality, dropped and readopted

Edition 1's Chapter 8 stated, as plainly as its FACTS record allowed: "Casper
FFG was never integrated, never activated, and never shipped on Genesis-2.
There is no bonded validator committee running on the live chain… Any scaffold
or reference code that touches on FFG concepts that may exist in the
repository is unshipped research." And its Chapter 5 gave the design
philosophy behind the drop: "a bonded validator set is, definitionally, a
privileged operator class whose stake or membership confers a role no other
node can perform."

Genesis-4's core is a Casper-style finality gadget. This section explains the
inversion — what changed in the reasoning, not merely in the outcome — because
a dossier that reversed a position this central without accounting for it
would forfeit the credibility the designed/built/booted discipline exists to
earn.

## 4.1 What has not changed: the facts Edition 1 stated remain true of the chain it described

Start with what is *not* being retracted. Every factual sentence in Edition
1's Chapter 8 remains true **of Genesis-2 and Genesis-3**: no finality gadget
ever finalized a block on either. Genesis-3's finality was PoW depth,
probabilistic, Bitcoin-style, exactly as Chapter 8 described for Genesis-2, and
it remained so through the chain's last block at height **39,918** on
2026-08-13. The FFG-era research scaffolds still exist in this repository and
still carry their honest labels: `crates/bloch-ffg` — a static 14-of-21
committee design — says in its module header "**Status: FOUNDATION. NOT wired
into consensus.** Standalone + tests only… Unaudited"
(`crates/bloch-ffg/src/lib.rs:18-20`), and a later miner-weighted FFG-BFT
overlay concept was likewise explicitly dropped (recorded in the migration
spec's baseline table: "Finality: PoW depth only. FFG-BFT explicitly dropped",
spec §2).

**One sentence from earlier drafts of this chapter must now be withdrawn, and
withdrawn explicitly rather than edited away.** It read: *"Three finality
designs have now existed in this project's history; zero have booted on a
public network,"* and undertook not to describe the Genesis-4 gadget in
stronger terms "until a public network finalizes a checkpoint under it." That
condition was met on 2026-08-13. The **fourth** design — the Casper-style
gadget of Chapter 3 — is **booted on a public mainnet and finalizing
checkpoints by epoch**. The undertaking is discharged by saying so, and the
honest qualification travels with it: the ≥2/3 quorum being met is a quorum of
64 validators operated by one entity.

What is being retracted is a *thesis*, not a record: the thesis that pure
proof-of-work depth was the right — and sufficient — finality model for this
chain.

## 4.2 The reasoning Edition 1 gave, and where the record broke it

Edition 1's argument for pure PoW had two legs.

**Leg one: probabilistic finality backed by accumulated work suffices, and
matures.** Chapter 5 was honest that Genesis-2 was young and 51%-attackable,
and framed that as the transient condition of "every young proof-of-work
chain… before enough independent hashrate accumulates on it," with the
duration "an open question that depends on external adoption." That framing
contained an unexamined assumption: that the accumulation would happen. The
record since is the answer. Two chain generations, an ASIC-native relaunch,
standard Stratum infrastructure, and merged mining with Bitcoin did not
produce an independent hashrate base. The difficulty post-mortem in the code
concedes that for stretches "the chain effectively had one producer and no
independent validator" (`mod.rs:43-44`); the AuxPoW module concedes that
borrowed Bitcoin work "can worsen the 51% risk, not fix it" (`auxpow.rs:25-26`);
and the terminal-height comment concedes the endpoint of the logic: "PoW
security is bought with ongoing hashrate; with none, rewriting history…
costs almost nothing" (`mod.rs:431-433`). A finality model whose guarantee is
"the cost of reversion rises with accumulated work" provides, on a chain where
work never meaningfully accumulated, approximately nothing — and Edition 1's
own risk boxes said as much in the conditional. Edition 2's difference is
only that the conditional has resolved. Waiting longer was not a strategy; it
was the absence of one.

**Leg two: a bonded validator set is a privileged operator class, incompatible
with ownerlessness.** This argument was correct as stated and remains
correct. What changed is the honesty of its application. The ownerless-PoW
framing implicitly compared PoS-with-a-committee against PoW-as-Bitcoin — an
open set of miners disciplined by real external cost. The PoW that Bloch
actually had was, for measured stretches, one producer and no independent
validator (`mod.rs:43-44`), on a chain whose
supply was ~94% held by one address (spec §0.1). That is a privileged operator
class in everything but name — worse than a bonded committee in one respect,
because nothing on-chain named it, capped it, or scheduled its decline. The
proof-of-stake design does not solve the concentration; the migration spec
opens by stating it as the plan's "single largest risk" and refuses to launch
without distribution gates (spec §0, §11). But it converts an unnamed de facto
privilege into named, consensus-bounded ones: the genesis cohort is published
in the genesis block, can only shrink, and its weight is forced below the
finality-stalling threshold within a year by rule (`genesis_cohort.rs:30-40`).
Between an undeclared monopoly of work and a declared, capped, decaying
monopoly of stake, the second is the more honest object — and honesty about
who holds power is the property this project's governance story actually rests
on.

There is a third, smaller strand: Edition 1 treated "no committee" as
protecting the validity/finality distinction. The PoS design keeps that
distinction fully intact — validity remains deterministic and proof-gated
(now against committed state under `transition.rs`'s rules), while finality
becomes a *stronger* claim than depth: accountable, slashable, two-thirds of
bonded stake. Nothing in the Chapter 8 taxonomy is abandoned; the finality
column upgrades from "probabilistic, cost-based" to "deterministic,
accountable" — on a chain whose cost-based column had, in practice, no cost
in it.

## 4.3 What the reversal pays, stated without discount

The migration spec's §0 lists the three prices before the architecture, and
this dossier repeats them in the same order, unhedged:

1. **Stake concentration.** Measured at the terminal Genesis-3 snapshot
   (height 39,918, 452,726 outputs, 16 addresses): **17,046,829,380 of
   18,146,400,000 BLOCH — 93.94% of the carryover — sits at one address, the
   founder's**, liquid and stakeable
   (`tokenomics_v4.rs::LARGEST_CARRYOVER_ADDRESS_BLOCH`,
   `::CARRYOVER_TOTAL_BLOCH`, `::CARRYOVER_MEASURED_HEIGHT`). Including the
   10% grant the founder holds **27.04% of the 100 B cap**; the Foundation
   holds a further **29.00%**; together **56,046,829,380 of the
   57,146,400,000 BLOCH issued at slot 0**, leaving **1,099,570,620 — 1.92% —
   with third parties. The spec's line stands: "On day one of a naive PoS
   migration, the founder *is* the consensus."** Mitigations — the
   genesis-cohort cap, the 1% per-validator cap, Nakamoto-coefficient launch
   gates — bound it; none solves it.

   **And the record now has the defect this paragraph promised not to
   footnote.** Distribution was a hard Go/No-Go launch gate (spec §11).
   Genesis-4 launched on 2026-08-13 with **G1–G4 unmet**: independent stake
   0%, one entity operating **64 of 64 validators**, Nakamoto coefficient 1,
   zero unaffiliated operators — and with **no external audit**, which G7
   required before launch. This edition said it would treat a launch that
   skipped those gates as a defect in the record rather than a footnote. It
   is recorded here as a defect in the record.
2. **Securities framing.** Staking rewards to bonded holders materially
   strengthen an investment-contract reading of BLCH; the civic-node,
   value-beside-the-point posture "survives PoW far more comfortably than it
   survives PoS." Legal review is a Phase-0 blocking deliverable (spec §0.2).
3. **A discarded security budget.** Merged mining is the cheapest real
   security Bloch will ever have, and PoS discards it, together with the
   miner-facing go-to-market (spec §0.3). Chapter 2's terminal-height
   argument is why the budget was judged insufficient anyway; this line
   records that it was a real thing given up, not a nothing.

> **Note.** The shortest honest summary of this chapter: Edition 1 said "no
> finality gadget exists, and pure PoW is the design." Both halves were true
> of the chain it described. Edition 2 says: a Casper-style gadget **is** the
> design and has been finalizing checkpoints on a public mainnet since
> 2026-08-13, and pure PoW is no longer the design — because the empirical
> premise under the old design, that work would accumulate, failed. The
> decision was taken with its costs written down; what was not done is
> waiting for the conditions the same document set for taking it.

---

# 5. What runs, and what is still not ready

This chapter is the edition's spine, because Chapter 3 could be read — in the
wrong direction, now — either as describing something that has not launched or
as describing a decentralised network. Neither is right. **Genesis-4 is a live
mainnet, and it is a live mainnet operated by one party.** This chapter draws
that line precisely.

Earlier drafts of this chapter opened: *"The Genesis-4 node exists at devnet
stage, and its own binary says so before this dossier does."* **That sentence
is false and is withdrawn.** It was true when written. The word "devnet"
remains accurate about exactly one thing — the *transport* — and about nothing
else.

## 5.1 What actually runs

The Genesis-4 mainnet has been producing and finalizing since 21:31:19 UTC on
2026-08-13. Validator processes produce blocks, attest, justify and finalize,
with real ML-DSA-65 ‖ Falcon-1024 hybrid signatures on every consensus path and
append-only block-log persistence where restart equals deterministic replay
(`crates/bloch-pos-node/src/store.rs:3-21`). The engine is a single consensus
thread driven by the slot timer and network events, binding the
`Transition`/`CommittedState` seam and LMD-GHOST head selection
(`engine.rs:1-6`, `engine.rs:370-374`); a node that rejects its own produced
block panics loudly, a rule named after the Genesis-3 h28,080 incident
(`engine.rs:24-30`). Around the engine the node carries a bounded mempool
(`MEMPOOL_MAX = 4_096`), a JSON-RPC server (`rpc.rs` — `sendrawtransaction`,
`getmempoolinfo`, chain and finality reads), and transfers that execute.
Public read RPC: `https://posternlabs.com/g4rpc`.

**Who runs it: one entity, 64 of 64 validators.** There is no independent
validator on this network. One operator can stall finality and one operator can
stop the chain, and neither requires a mechanism in the protocol — it requires
only ceasing to operate. Every capability described in Chapter 3 should be read
through that sentence.

## 5.2 What does not exist — corrected against the node that ships today

Earlier drafts of this section quoted the binary's module header as the
authoritative inventory of absences: *"no RocksDB store, no libp2p gossip, no
transactions (deposits/exits/transfers), no slashing-evidence pipeline, no
weak-subjectivity sync, no RPC, no fork choice beyond a linear chain, no
mainnet genesis manifest."* **Most of that list is out of date.** It is quoted
here so a reader who finds it elsewhere in the repository knows it has been
superseded, and each entry is given its current answer. What replaces it is a
shorter list, and the two items on it are the two that matter most to anyone
who wants to *use* this chain.

Overtaken — these exist and run:

- **Transactions.** Transfers execute on the live chain, submitted through
  `sendrawtransaction` and admitted to a bounded mempool (`rpc.rs`;
  `engine.rs`, `MEMPOOL_MAX = 4_096`).
- **RPC.** A JSON-RPC surface exists (`rpc.rs`, ~1,500 lines) and is publicly
  readable at `https://posternlabs.com/g4rpc`. Note the node's own warning: the
  RPC authenticates nothing, so binding it to a routable address is an explicit
  act plus a firewall (`engine.rs`, `rpc_bind`).
- **Fork choice.** LMD-GHOST with reorganization (`engine.rs:33-48`).
- **A mainnet genesis manifest.** It exists — Genesis-4 launched from it, built
  on the signed terminal snapshot of Chapter 2. The manifest itself is not
  committed to this repository.
- **A libp2p stack.** `p2p.rs` implements gossipsub with the 2026-08-07 mesh
  fixes, a Genesis-4-only protocol prefix, and directed paginated sync. **It is
  not what the fleet runs** — see below. Do not read this row as "a production
  network layer exists".

Still absent, and these are load-bearing:

- **The live transport is the devnet mesh.** `Transport::Devnet` is the default
  and is what the fleet runs (`engine.rs:104-107`, `main.rs:765`): a
  point-to-point TCP full mesh with a **fixed peer list, no discovery, and no
  authentication** (`net.rs`). This is the mechanical reason **a third party
  cannot join the Genesis-4 network**. The node's own words about this path
  are unchanged and still correct: "This is not the production network layer."
- **Deposits and delegations are refused.** `Deposit` and `Delegate` are
  rejected at every node's mempool (`engine.rs:1900-1907`) because bonding is
  not funded from the eUTXO set: a deposit names an amount, spends no output,
  and would register bonded stake without destroying spendable coins —
  measured at 25,000 BLOCH of stake per unauthenticated request. The refusal is
  node-side policy, not consensus. Consequence, stated both ways: it closes a
  path by which anyone reachable could mint stake from nothing, **and** it
  means **no one can become a validator**, so the validator set cannot become
  plural. Fixing it properly is a wire-format change and needs a flag day.
- **No slashing-evidence pipeline in the node.** The slashing rules and the
  evidence transaction exist in the committee crate; the machinery that would
  detect, package and carry evidence is not in the node.
- **No weak-subjectivity fresh-sync path.** The checkpoint format and
  verification exist (`ws.rs`); the sync path that would consume them does not.
  On a live PoS chain that is the long-range-attack answer being specified and
  unavailable.
- **Persistence is an append-only block log, not RocksDB** (`store.rs:3-21`).
  Restart is O(chain length) deterministic replay through the same
  `Transition`. Deliberate, documented, and a scaling item rather than a
  correctness one.

Two pieces of recorded documentation debt carry over unchanged: the pure crate
ships two parallel producer/validator seams (`transition.rs` vs
`derive.rs`/`produce.rs`) whose committed state roots are not byte-compatible —
the engine binds exactly one, and the unreconciled situation is flagged in
place rather than papered over (`engine.rs:8-22`); and the residual
sampled-committee constants noted in §3.2 (`params.rs:17,27`).

## 5.3 The launch, against the plan that preceded it

Earlier drafts of this section read: *"There is no Genesis-4 launch date, and
this dossier does not imply one … the honest ordering is: terminal snapshot,
then the integration work of §5.2, then third-party review, then gates, then —
only if the gates pass — a launch."* **The launch happened, and that ordering
was not followed.** The record:

| The plan | What happened |
|---|---|
| Snapshot at height 50,000 | Genesis-3 stopped at **39,918**, 2026-08-13 |
| ~6 months of code review before Genesis-4 | **No interval** — Genesis-4 opened 21:31:19 UTC the same day |
| Third-party review (G7 covers the Falcon online-signing path) | **Not done.** No external audit exists |
| Go/No-Go distribution gates G1–G4 | **Not met.** Independent stake 0%; 64 of 64 validators one entity; Nakamoto coefficient 1; zero unaffiliated operators |

This edition does not editorialise about why. It records that the conditions
the project set for itself were not the conditions under which it launched, and
that a reader weighing the network's maturity should weigh that fact rather
than the plan.

## 5.4 The consensus stack, labelled — the table this edition exists for

| Capability | Designed | Built | Booted |
|---|---|---|---|
| Genesis-3: SHA-256d PoW, GhostDAG K=10, 30 s target | ✓ | ✓ | ✓ mainnet, **ended h39,918 / 2026-08-13** |
| Genesis-3: AuxPoW merged mining under Bitcoin | ✓ | ✓ | ✓ mainnet (h≥8,500), ended with the chain |
| Genesis-3: ancestry-derived difficulty | ✓ | ✓ | ✓ mainnet (h≥30,030), ended with the chain |
| Genesis-3: terminal height | ✓ (V4 §3.1–3.2) | ✓ (`mod.rs:437-466` + 4 wiring sites) | **fired — chain stopped at h39,918** (below the announced 50,000) |
| Signed terminal snapshot artifact | ✓ (V4 §3.2.2) | ✓ | ✓ taken at h39,918: 452,726 outputs, 18,146,400,000 BLOCH; root + file digests pinned in `tokenomics_v4.rs` |
| G4: slots/epochs, linear chain, V4 header | ✓ | ✓ | ✓ **mainnet** |
| G4: partitioned committees, sortition, RANDAO beacon | ✓ | ✓ | ✓ **mainnet** |
| G4: LMD-GHOST fork choice | ✓ | ✓ | ✓ **mainnet** |
| G4: Casper-style justification/finalization | ✓ | ✓ | ✓ **mainnet** — quorum is 64 validators, one operator |
| G4: inactivity leak | ✓ | ✓ | ✓ mainnet (rules active) |
| G4: slashing rules | ✓ | ✓ | ✓ mainnet (rules) / ✗ no evidence pipeline in the node |
| G4: transfers | ✓ | ✓ | ✓ **mainnet** |
| G4: supply cap as consensus invariant (`SupplyCapExceeded`) | ✓ | ✓ | ✓ **mainnet** |
| G4: staking lifecycle (deposits/delegations) | ✓ | ✓ (rules) | ✗ **refused at every node's mempool** |
| G4: genesis cohort, one-third-in-one-year cap | ✓ | ✓ | ✓ mainnet — binding on nothing while the set is one operator's |
| G4: weak-subjectivity checkpoints | ✓ | ✓ (format/verify) | ✗ (no fresh-sync path) |
| G4: production network transport | ✓ (libp2p in-tree) | ✓ | ✗ — **the fleet runs the devnet mesh: fixed peers, no discovery, no authentication** |
| G4: persistent store (RocksDB) | ✓ | ✗ (append-only block log instead) | n/a |
| A finality gadget on a public Bloch network | ✓ | ✓ | ✓ **since 2026-08-13** |
| Third-party audit of any of the above | — | — | ✗ **none, ever** |

> **Risk, closing.** The proof-of-work consensus this edition documents has
> ended. The proof-of-stake consensus that replaced it is live, carries value,
> and is unaudited — running on 64 validators owned by one party, over a
> transport that admits no strangers, with the transaction class that would let
> anyone else participate refused at every node. Nothing in the table above is
> a decentralisation claim. Every stronger sentence a reader may encounter
> elsewhere should be checked against it.

---

*Copyright © 2026. Licensed AGPL-3.0-or-later. This chapter cites code at
specific lines of the `bloch-pos` repository (integration branch, and where
noted the `deploy/g3-terminal-50000` branch) and of the Genesis-3 node tree
(`src/`); line numbers drift as code moves, but every claim above was
verified against the cited line at the time of writing.*
