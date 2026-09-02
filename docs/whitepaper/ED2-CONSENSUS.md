<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Institutional Dossier — Edition 2

## The Consensus Chapters: Genesis-3, Its Planned End, and the Proof-of-Stake Design

```
Document:   ED2-CONSENSUS
Edition:    2 · 2026
Supersedes: Edition 1, Chapters 5–8 (Consensus I — Proof of Work;
            Consensus II — The BlockDAG & GhostDAG; The Genesis-2 Hard Fork;
            Finality & the Dropped FFG)
Repository: bloch-pos (gitlab.com/blochsispow-group/bloch-pos)
License:    AGPL-3.0-or-later
```

**Honest status, inherited and enforced.** Edition 1 adopted a mantra and this
edition keeps it: **designed ≠ built ≠ booted**. Having a specification, having
code that implements it, and having that code running as the consensus-enforced
rule on a live network are three different states, and every capability in
these chapters is labelled with which of the three it has reached. Conflating
them is the single most common way a technical dossier misleads a reader, and
Edition 1 was written to avoid it systematically. So is this one — which
matters more this time, because Edition 2 must document a *designed* consensus
(proof of stake) alongside a *booted* one (Genesis-3), and must also document a
reversal: a finality mechanism Edition 1 correctly described as dropped is now
the center of the design. That reversal is explained in Chapter 4, honestly,
including what changed in the reasoning and what has *not* changed in the
facts.

Three status vocabularies used throughout:

- **Designed** — specified in a reviewed document; no claim that code exists.
- **Built** — implemented and tested as code; no claim that it runs anywhere
  that matters.
- **Booted** — running as an enforced rule on a network; the only state that
  constitutes a property of a live chain. "Booted (devnet)" means running only
  on local, throwaway-key validator processes — explicitly *not* a public
  network.

---

# 1. Genesis-3 — the consensus that runs today

Edition 1 documented Genesis-2, the live chain of mid-2026. On 2026-07-29 the
network relaunched as **Genesis-3**: not a fork of Genesis-2 but a brand-new
chain starting at height 0 with its own genesis block and a distinct chain
identifier, ingesting the same carried-over ledger as opening balances. This
chapter documents what Genesis-3 actually runs — all of it booted, on mainnet,
today — and Chapter 2 documents the unusual fact that distinguishes this
edition from every ordinary protocol dossier: the chain has a consensus-encoded
final block, and it is days away.

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

**Status: booted.** Genesis-3 mainnet has been producing blocks since
2026-07-29.

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

**Status: booted.**

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

**Status: booted** (active above 30,030 on the live chain).

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

**Status: booted.**

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

**Status: booted** (active at and above height 8,500; merged blocks accepted
on mainnet since 2026-08-01).

## 1.6 What Genesis-3 is, in one table

| Component | Mechanism | Source | Status |
|---|---|---|---|
| Chain identity | `0xB10C_0004`, fresh genesis, carryover opening balances | `mod.rs:179`, `mod.rs:396-411` | Booted |
| Proof of work | SHA-256d, 80-byte Bitcoin-layout header, little-endian from height 0 | `mod.rs:199-207`, `mod.rs:2489-2496` | Booted |
| Difficulty | 30 s target, 60-block retarget; ancestry-derived bits above h30,030 | `mod.rs:262`, `mod.rs:2281`, `mod.rs:125` | Booted |
| Ordering | GhostDAG over a BlockDAG, K = 10 | `mod.rs:251` | Booted |
| Merged mining | Namecoin-style AuxPoW under Bitcoin, active at h8,500 | `auxpow.rs`, `mod.rs:22`, `mod.rs:1756` | Booted |
| Finality gadget | None — PoW depth only, exactly as Edition 1 stated for Genesis-2 | Ch. 4 below | n/a |
| Terminal height | Chain ends at a fixed height; blocks above are consensus-invalid | Ch. 2 below | Built; flag-day deploying |

---

# 2. The terminal height — why Genesis-3 ends

This is the chapter Edition 1 could not have contained. Genesis-3 has a
consensus-encoded last block. At that height a signed balance snapshot is
taken; the snapshot — not the chain — becomes the canonical record; and
Genesis-4, a proof-of-stake chain, launches from that artifact roughly six
months later. Nothing about this is framed as an upgrade of the running chain.
The chain is not being continued. It is being ended, deliberately, and the
protocol's own constants say so.

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

## 2.2 The value: 80,000, then 50,000 — a flag day with a three-day fuse

The constant was introduced at 80,000 on 2026-08-11 (commit `ced885d`; the
value on this repository's integration branch, `mod.rs:438`). On 2026-08-12
the founder lowered it to **50,000**, shipped as a single-constant diff on the
dedicated branch `deploy/g3-terminal-50000` (commit `38258aa`) against the
exact tree already running fleet-wide — the commit message states the
discipline plainly: a three-day flag day is not the place to ship a month of
work with no mainnet soak. At the measured 21.57 s/block cadence, height 50,000 arrives
roughly three days from that commit, and every node must be running the
50,000 binary before it does. The commit is equally plain about the failure
mode: "A node still on the 80,000 binary keeps accepting blocks above 50,000,
and the moment one does, the halt itself becomes the fork."

The number 50,000 was originally argued from a carryover-cap race
(`docs/specs/BLOCH-TOKENOMICS-V4.md` §3.1) that has since been retired along
with the cap itself (§3: every holder carries over in full, no scale-down, no
founder-exclusion list). What survives of the rationale is the notice logic:
about two weeks of public notice at decision time, on a round number — and the
spec's counterintuitive but correct observation that *longer* notice is worse
here, because holders need do nothing (balances are captured on-chain
automatically) while the one action notice enables is accumulating more coins
before the cut (§3.1).

**Status: designed (V4 §3.1–3.2); built and tested (`mod.rs:437-466` and the
four wiring sites above); booted-in-progress — the 50,000 flag-day binary was
cut 2026-08-12 for fleet deployment inside the ~3-day window. The deploy
window is itself the named risk.**

## 2.3 Why the chain ends: the honest argument, in full

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
   producing during the ~six months between snapshot and Genesis-4 launch,
   coins would be mined by people receiving nothing in the successor, and the
   rational miner switches off the day after the snapshot anyway — leaving the
   network without hashrate during exactly the months it still has users,
   wallets and an explorer pointed at it (V4 §3.2).

## 2.4 After the halt, the chain's history stops being evidence

This is the non-obvious consequence, and the code comment above the constant
states it with no varnish: "Once mining stops, this chain's history stops
being evidence. PoW security is bought with ongoing hashrate; with none,
rewriting history below the terminal height costs almost nothing"
(`mod.rs:431-433`). Anyone with modest SHA-256d hashrate can, months after the
halt, produce an alternative chain ending at 50,000 with different balances —
and it may even carry more accumulated work than the real one (V4 §3.2.2).

Therefore **the signed snapshot artifact is canonical, not the chain**. At the
terminal height the balance set is produced, hashed, signed, and its digest
published widely enough that it cannot be quietly replaced — the same pattern
already used for `carryover.tsv.gz` and its `.sha256` companion. The snapshot
digest is to be embedded in the Genesis-4 genesis block itself, "precisely so
the record does not depend on a chain nobody is defending" (`mod.rs:433-435`,
V4 §3.2.2). Un-upgraded miners who continue past 50,000 continue on a fork;
that is tolerable "only because the canonical artifact is the signed snapshot
at this height, not whatever chain has the most work afterwards"
(`mod.rs:427-430`).

> **Risk.** Between the halt and the Genesis-4 launch there is no live chain
> defending this ledger — only a signed artifact and the breadth of its
> publication. The security of every carried-over balance during that window
> is exactly the security of that digest's distribution and of the signing
> key. This is a real, named trust interval, not a technicality, and no
> mechanism in this chapter removes it. It is the price of ending a chain
> whose work-based security was not, in honest terms, doing the securing.

---

# 3. Proof of stake — the Genesis-4 design

Genesis-4 (design codename **Bell**) replaces proof-of-work with proof of
stake, SHA-3 hashing, and deterministic finality, while keeping two things
fixed by founder constraint: the hybrid ML-DSA-65 ‖ Falcon-1024 post-quantum
signature suite, unchanged, in every consensus role; and the Coherence ZK
ledger with its frozen SHAKE-256 formats
(`docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md`, header block). The design
document's own status line is reproduced here rather than improved upon:
"DRAFT — design only, not approved, not scheduled."

The design is not only a document. A pure consensus crate
(`crates/bloch-pos-committee`) implements it rule by rule, and a devnet node
binary (`crates/bloch-pos-node`) composes those rules into running validator
processes. Chapter 5 draws the built/booted line precisely; this chapter
describes the design and cites the code that exists for each part.

## 3.1 Shape: a linear chain of slots and epochs — GhostDAG retired

Time is divided into **30-second slots**, 32 slots to an epoch (≈16 minutes)
(`SLOT_DURATION_SECS = 30`, `SLOTS_PER_EPOCH = 32`,
`crates/bloch-pos-committee/src/params.rs:29-34`). The slot duration is
deliberately identical to today's PoW block target "so the transition adds no
new propagation pressure" (`params.rs:32-33`). One validator is designated
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
(`crates/bloch-pos-committee/src/header.rs`); booted (devnet only).**

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
(`committees.rs`, `sample.rs`, `transition.rs`); booted (devnet only).**

## 3.3 Fork choice: LMD-GHOST

Between finalized checkpoints, the canonical head is selected by LMD-GHOST —
Latest Message Driven: only each validator's most recent attestation counts,
the weight of a block is the total effective stake of validators whose latest
message is that block or a descendant, and the head is found by walking from
the latest **justified** checkpoint, taking the heaviest child at each step
(`crates/bloch-pos-committee/src/forkchoice.rs:1-10`). Equivocating validators
are dropped from fork-choice weight permanently (`forkchoice.rs:54-58`).
Starting the walk at the justified checkpoint bounds it by the unfinalized
suffix (`bloch-pos-node/src/engine.rs:50-53`). That source used to claim a
second property for free — "finalized history can never be reorganized out" —
and both it and this sentence were CORRECTED 2026-09-01. The walk starts at the
*justified* root, and the state committed there finalizes two epochs below the
head, so the deepest cut the algorithm may legitimately propose is itself a
finality rewind. Measured: finalized epoch 6 -> 4 -> 2 -> 0 in three in-rules
cuts.

The devnet engine binds this rule and the documentation states why the naive
alternative is not merely weaker but wrong: longest-valid-chain "lets a
proposer with no attested support drag the chain by building fast … Length is
not the security statement in proof of stake; attested stake is"
(`engine.rs:33-48`). The engine rebuilds the fork-choice store from scratch on
every head computation rather than caching it — the `expected_bits` lesson
applied where a cache would be cheapest to get wrong (`engine.rs:54-60`).

**Status: designed; built; booted (devnet only) — the devnet engine selects
its head via `forkchoice_head` (`engine.rs:370-374`).**

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

**Status: designed (spec §5.1, §6.5); built (`finality.rs`); booted (devnet
only) — devnet validator processes justify and finalize over a local mesh
(`bloch-pos-node/src/main.rs:5-8`). No checkpoint has ever been finalized on
any public Bloch network.**

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

**Status: designed; built (`beacon.rs`, `sample.rs`); booted (devnet only).**

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
the fresh-sync path that would use them is not built (§5.2).**

## 3.7 The genesis cohort and the one-third rule

A fresh PoS genesis has a bootstrap circularity: deposits need blocks, blocks
need validators, and there is no PoW to seed the set. Genesis-4 therefore
launches with a **genesis validator cohort** the founder funds and operates —
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

**Status: designed (V4 §3.3); built (`genesis_cohort.rs`); booted (devnet
only).**

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

**Status: built (with the largest test surface in the crate); booted (devnet
only).**

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

## 4.1 What has not changed: the facts Edition 1 stated remain true

Start with what is *not* being retracted. Every factual sentence in Edition
1's Chapter 8 remains true today, and remains true of Genesis-3: no finality
gadget has ever finalized a block on any public Bloch network. Genesis-3's
finality is PoW depth, probabilistic, Bitcoin-style, exactly as Chapter 8
described for Genesis-2, and it will remain so until the chain's last block at
height 50,000. The FFG-era research scaffolds still exist in this repository
and still carry their honest labels: `crates/bloch-ffg` — a static 14-of-21
committee design — says in its module header "**Status: FOUNDATION. NOT wired
into consensus.** Standalone + tests only… Unaudited"
(`crates/bloch-ffg/src/lib.rs:18-20`), and a later miner-weighted FFG-BFT
overlay concept was likewise explicitly dropped (recorded in the migration
spec's baseline table: "Finality: PoW depth only. FFG-BFT explicitly dropped",
spec §2). Three finality designs have now existed in this project's history;
zero have booted on a public network. The Genesis-4 gadget of Chapter 3 is
**designed and built, booted only on a local devnet** — and this edition will
not describe it in any stronger terms until a public network finalizes a
checkpoint under it.

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
becomes a claim of a different *kind* than depth: a discrete, two-thirds-of-
bonded-stake commitment rather than a probabilistic one. This passage used to
call it "accountable, slashable" and to describe the finality column as
upgrading to "deterministic, accountable". CORRECTED 2026-09-01: accountability
is the half that has not shipped. Equivocation is detected and permanently
dropped from fork-choice weight, but it is not *punished* — slashing evidence
cannot travel on the wire (§ the gaps table below), so the column moves from
"probabilistic, cost-based" to "discrete, and still with no cost in it". The
honest statement is that Genesis-4 replaced one absent cost with another,
and gained determinism of form rather than of guarantee.

## 4.3 What the reversal pays, stated without discount

The migration spec's §0 lists the three prices before the architecture, and
this dossier repeats them in the same order, unhedged:

1. **Stake concentration.** ≈94% of existing supply at one address, measured
   at height 18,809 (spec §0.1). "On day one of a naive PoS migration, the
   founder *is* the consensus." Mitigations — the genesis-cohort cap, the
   1% per-validator cap, Nakamoto-coefficient launch gates — bound it; none
   solves it. Distribution is a hard Go/No-Go launch gate (spec §11), and
   this edition will treat any Genesis-4 launch that skipped those gates as
   a defect in the record, not a footnote.
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
> finality gadget exists, and pure PoW is the design." Both halves were true.
> Edition 2 says "no finality gadget has ever booted on a public network, and
> pure PoW is no longer the design — because the empirical premise under the
> old design, that work would accumulate, failed." The first half is still a
> fact; the second is a decision, taken with its costs written down.

---

# 5. What is not ready

This chapter is the edition's spine, because everything in Chapter 3 could be
read — wrongly — as a description of a running network. The Genesis-4 node
exists at **devnet stage**, and its own binary says so before this dossier
does.

## 5.1 What actually runs

The devnet is real and non-trivial: N validator processes produce blocks,
attest, justify and finalize over a local TCP mesh, with real
ML-DSA-65 ‖ Falcon-1024 hybrid signatures and append-only block-log
persistence where restart equals deterministic replay
(`crates/bloch-pos-node/src/main.rs:5-8`). The engine is a single consensus
thread driven by the slot timer and network events, binding the
`Transition`/`CommittedState` seam and LMD-GHOST head selection
(`engine.rs:1-6`, `engine.rs:370-374`); a node that rejects its own produced
block panics loudly, a rule named after the Genesis-3 h28,080 incident
(`engine.rs:24-30`). Devnet keys are throwaway by construction, never
printed, 0600 on disk; production keys are out of scope for this tool
entirely (`main.rs:17-22`).

## 5.2 What does not exist — the node's own list

The binary's module header is the authoritative inventory, quoted rather than
paraphrased (`main.rs:10-15`):

> "What it is NOT yet — honestly, per the integration plan
> (`docs/specs/BLOCH-POS-NODE-INTEGRATION.md`): no RocksDB store, no libp2p
> gossip, no transactions (deposits/exits/transfers), no slashing-evidence
> pipeline, no weak-subjectivity sync, no RPC, no fork choice beyond a linear
> chain, no mainnet genesis manifest."

Spelled out, because each item is a load-bearing absence:

- **No transactions.** The devnet chain carries consensus objects only. The
  staking lifecycle of §3.6 is built as validation rules
  (`staking.rs`), but no deposit, exit, transfer, or Coherence operation can
  be submitted to, carried by, or executed on the devnet chain. A chain that
  cannot move value is a consensus test rig, and this one is labelled as
  such.
- **No libp2p.** Networking is a localhost TCP full mesh with length-prefixed
  frames — "This is not the production network layer" (`net.rs:1-7`). The
  plan is to adapt the Genesis-3 libp2p/gossipsub stack with the 2026-08-07
  mesh fixes; "that work is not done" (`net.rs:5-7`). The pure crate's gossip
  admission-control layer (`gossip.rs`) exists but is not wired to this mesh
  (`net.rs:12-14`).
- **No RPC.** There is no interface for a wallet, explorer, or exchange to
  query or submit anything. The RPC surface is specified
  (`docs/specs/BLOCH-RPC-V4.md`) — designed, not built.
- **No slashing-evidence pipeline.** Slashing conditions are built as rules
  (`slashing.rs`); the machinery that would detect, package, and carry
  evidence on-chain is not.
- **No weak-subjectivity sync.** The checkpoint format and verification exist
  (`ws.rs`); the fresh-node sync path that would consume them does not.
- **No mainnet genesis manifest.** There is no Genesis-4 genesis. The input
  it requires — the signed terminal snapshot of Chapter 2 — does not exist
  yet either.

One entry on the list has been overtaken by the code and is recorded as such:
the engine now implements LMD-GHOST fork choice with reorganization
(`engine.rs:33-48`), so "no fork choice beyond a linear chain" overstates the
gap; the header list simply lags the engine. Two further pieces of recorded
documentation debt: the pure crate ships two parallel producer/validator
seams (`transition.rs` vs `derive.rs`/`produce.rs`) whose committed state
roots are not byte-compatible — the engine binds exactly one and the
unreconciled situation is flagged in place rather than papered over
(`engine.rs:8-22`); and the residual sampled-committee constants noted in
§3.2 (`params.rs:17,27`).

## 5.3 No launch date

There is no Genesis-4 launch date, and this dossier does not imply one. The
schedule that exists is relative and conditional: the snapshot at height
50,000 (days away), then Genesis-4 "roughly six months later, after code
review" (V4 §3.2) — with the migration spec's Go/No-Go gates (§11) standing
between the code and any mainnet, distribution gates included, and the spec
itself still marked "not approved, not scheduled." Six months is a planning
figure, not a commitment; the honest ordering is: terminal snapshot, then the
integration work of §5.2, then third-party review, then gates, then — only if
the gates pass — a launch.

## 5.4 The consensus stack, labelled — the table this edition exists for

| Capability | Designed | Built | Booted |
|---|---|---|---|
| Genesis-3: SHA-256d PoW, GhostDAG K=10, 30 s target | ✓ | ✓ | ✓ mainnet |
| Genesis-3: AuxPoW merged mining under Bitcoin | ✓ | ✓ | ✓ mainnet (h≥8,500) |
| Genesis-3: ancestry-derived difficulty | ✓ | ✓ | ✓ mainnet (h≥30,030) |
| Genesis-3: terminal height 50,000 | ✓ (V4 §3.1–3.2) | ✓ (`mod.rs:437-466` + 4 wiring sites) | flag-day deploying (commit `38258aa`) |
| Signed terminal snapshot artifact | ✓ (V4 §3.2.2) | tooling staged (`deploy/artifacts/bloch-snapshot-utxo`) | — (taken at h50,000) |
| G4: slots/epochs, linear chain, V4 header | ✓ | ✓ | devnet only |
| G4: partitioned committees, sortition, RANDAO beacon | ✓ | ✓ | devnet only |
| G4: LMD-GHOST fork choice | ✓ | ✓ | devnet only |
| G4: Casper-style justification/finalization | ✓ | ✓ | devnet only |
| G4: inactivity leak | ✓ | ✓ | devnet only |
| G4: slashing rules | ✓ | ✓ | devnet only (no evidence pipeline) |
| G4: staking lifecycle (deposits/exits/withdrawals) | ✓ | ✓ (rules) | ✗ (no transactions exist) |
| G4: genesis cohort, one-third-in-one-year cap | ✓ | ✓ | devnet only |
| G4: weak-subjectivity checkpoints | ✓ | ✓ (format/verify) | ✗ (no sync path) |
| G4: transactions, libp2p, RPC, RocksDB, mainnet genesis | partly (specs) | ✗ | ✗ |
| Any finality gadget on a public Bloch network | — | — | **never, to date** |

> **Risk, closing.** The consensus that is booted is ending by rule; the
> consensus that would replace it is a devnet that cannot yet carry a
> transaction. Between them stand a signed artifact, roughly six months of
> integration and review, and launch gates that are allowed to say no. That
> is the honest state of Bloch consensus as of this edition, and every
> stronger sentence a reader may encounter elsewhere should be checked
> against the table above.

---

*Copyright © 2026. Licensed AGPL-3.0-or-later. This chapter cites code at
specific lines of the `bloch-pos` repository (integration branch, and where
noted the `deploy/g3-terminal-50000` branch) and of the Genesis-3 node tree
(`src/`); line numbers drift as code moves, but every claim above was
verified against the cited line at the time of writing.*
