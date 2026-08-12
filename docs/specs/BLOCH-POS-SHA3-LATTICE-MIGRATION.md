<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Bloch — Migration to Proof-of-Stake (SHA-3 + Lattice)

**Project design document — "Genesis-4 / Bell"**

```
Document:   BLOCH-POS-SHA3-LATTICE-MIGRATION
Status:     DRAFT — design only, not approved, not scheduled
Type:       Standards Track (consensus) + Process (migration)
Created:    2026-08-10
Owner:      PMO, Postern Labs Ltda
Track:      GIP-0003 (to be filed) / ADR-036 (to be filed)
Supersedes: nothing yet — reverses ADR-033 §"ownerless PoW base" if adopted
```

> **Fixed inputs (founder constraints).** Two parts of the system are **not**
> up for redesign and are treated throughout as given:
>
> 1. **The PQ signature arrangement stays as it is** — the hybrid
>    ML-DSA-65 ‖ Falcon-1024 suite, unchanged, in every consensus role.
> 2. **The ZK ledger (Coherence) stays** — C1-frozen formats, SHAKE-256
>    primitives, raw FRI-STARK proofs, no elliptic-curve ZK.
>
> These are constraints, not conveniences: the ≈ 4.6 KB hybrid signature is
> what sets slot time, committee size and block size (§5.1, §6.5), and keeping
> the shielded pool forces one new consensus rule on the staking design
> (§6.6.3). Both consequences are worked through rather than assumed away.

---

## 0. Read this first — the founder-level objection

This document designs, in full, a migration of the Bloch base chain from
Proof-of-Work to Proof-of-Stake with SHA-3 hashing and lattice signatures. It
is a complete, executable plan. It is also a plan whose **single largest risk is
not technical**, and the PMO's duty is to state that before the architecture:

1. **Stake concentration.** As measured at height 18,809, one address (the
   founder) holds ≈ 3.427 B of 3.634 B existing BLCH — about **94% of
   circulating supply**. Proof-of-Stake makes coins the consensus weight. On
   day one of a naive PoS migration, the founder *is* the consensus. This is
   the exact inverse of the ownerless thesis restored in ADR-033 and of the
   "coins don't vote" governance model. Section 4.1 specifies consensus-level
   mitigations (ineligibility covenants, stake caps, Nakamoto-coefficient
   gates); none of them fully solve it, and §11 makes distribution a hard
   Go/No-Go gate rather than a best-effort.

2. **Securities framing.** Staking rewards paid to bonded holders materially
   strengthen an investment-contract reading of BLCH. The current public
   posture — a civic node movement, value beside the point, not a security —
   survives PoW far more comfortably than it survives PoS. Legal review is a
   **Phase 0 blocking deliverable**, not a Phase 5 checkbox.

3. **Discarded security budget.** The chain is today merged-mined with Bitcoin
   via AuxPoW (live since height 8,500). That borrowed SHA-256d hashrate is the
   cheapest real security Bloch will ever have. PoS discards it, and discards
   the "we court Bitcoin miners, not traders" go-to-market with it.

None of the three is a reason to refuse the work. They are reasons to run the
plan with the gates in §11 armed, and to be honest in every public artifact
about what is being traded away. The rest of this document assumes the founder
has read §0 and still wants the migration designed and staffed.

---

## 1. Scope

### 1.1 In scope

- Replacement of SHA-256d with SHA-3 (SHA3-256 / SHAKE-256) as the chain's
  hash function across block identity, Merkle commitments, state commitments
  and randomness.
- Replacement of Proof-of-Work leader election with stake-weighted leader
  election plus a BFT finality rule.
- Lattice (post-quantum) signatures in a **consensus** role for the first time,
  using **the existing signature arrangement unchanged**: the hybrid
  ML-DSA-65 ‖ Falcon-1024 suite already in `crates/bloch-crypto/src/crypto/mod.rs`.
- The staking lifecycle: deposit, activation queue, attestation duty, rewards,
  slashing, exit, withdrawal.
- The migration mechanics themselves: hybrid period, flag-day, rollback.
- Ecosystem migration: pool, stratum, explorer, wallet, L2, SDKs, RPC.

### 1.2 Out of scope

- Changes to the emission curve. Emission V3 (ADR-035, tail floor 60 BLCH at
  epoch 6) is treated as fixed input; PoS changes *who* receives issuance, not
  *how much* is issued.
- Changes to the transaction format, address format, or the eUTXO VM, beyond
  the two new transaction types in §7.
- **Changes to the PQ signature arrangement.** The hybrid suite
  `SUITE_MLDSA65_FALCON1024` (0x0001) is a fixed input. No new signature
  algorithm, no role split, no per-message scheme selection. PoS consumes the
  signature layer exactly as it exists. §6.2 and §6.5 are written around that
  constraint rather than around a convenient one.
- **Changes to Coherence (the ZK ledger).** The C1-frozen shielded-pool formats
  — SHAKE-256 note commitments, hash-derived nullifiers, the SHAKE-256
  incremental accumulator, `check_spend`, and raw FRI-STARK verification with
  no Groth16/EC wrapper — are preserved byte-for-byte. §6.6 specifies what the
  migration must not break, and the one new consensus rule the shielded pool
  forces on the staking design.
- The premine vesting schedule (10,368,000-block cliff + 480 monthly tranches).
  Premine ineligibility is retired with the taint machinery — see §4.
- Any L2/EVM change beyond re-pointing its anchor to the new finality signal.

### 1.3 What this document does not claim

- It does not claim lattice hardness secures consensus. The lattice primitives
  here are **signatures** (ML-DSA, Falcon) — their security is FIPS 204/206
  signature security, not a hardness assumption about block production. This is
  the same discipline the Module-SIS PoW crate already applies to itself.
- It does not claim the leader election is private. §6.3 chooses a *public*
  sortition on purpose and pays a DoS cost for it, because no standardised
  post-quantum VRF exists (§6.4).
- It does not claim PoS is more decentralised than PoW for Bloch specifically.
  Given §0.1, the honest default assumption is that it is less so, until the
  distribution gate in §11 is met.

---

## 2. Baseline — what Bloch is today

Grounded in the reference node (`~/dev/BlochSISPoW-project`, branch
`g3-integration`):

| Property | Today |
|---|---|
| Consensus | Proof-of-Work, GhostDAG BlockDAG, k = 8 |
| PoW hash | SHA-256d over an 80-byte Bitcoin-compatible `MiningHeader` projection (`crates/bloch-crypto/src/core/mod.rs:~700`) |
| Merged mining | AuxPoW active since h8,500; Bitcoin work secures Bloch |
| Block target | 30 s (`TARGET_BLOCK_TIME_SECS`, `tokenomics_v2.rs:78`) |
| Block header | `version, parents: Vec<[u8;32]>, merkle_root, timestamp: u64, bits: u32, nonce: u64` (`core/mod.rs:652`) |
| Difficulty | ASERT-style, `bits` per block |
| Signatures | Hybrid **ML-DSA-65 ‖ Falcon-1024**, suite-tagged envelope (`SUITE_MLDSA65_FALCON1024 = 0x0001`); pk 1,952 ‖ 1,793 B, sig 3,309 ‖ ~1,280 B, **both must verify** (`crypto/mod.rs:16-42`) |
| Signature escape hatch | `SUITE_MLDSA65_ONLY = 0x0002` already defined — Falcon is removable without a format break |
| ZK ledger | **Coherence** shielded pool, C1-frozen: SHAKE-256 commitments/nullifiers, SHAKE-256 incremental accumulator (depth 32), SP1 **raw FRI-STARK** proofs, **no elliptic-curve ZK** (`crates/coherence-core`, `src/coherence`, wired in `main.rs:844`) |
| Hashing | SHA-2 for consensus, SHA-3/SHAKE-256 already a dependency (`sha3 0.10`) and already the native hash of Coherence, audit chains and L2 commitments |
| Finality | PoW depth only. FFG-BFT explicitly **dropped** (`docs/specs/POSTERN-FFG-BFT-FINALITY.md`) |
| Nominal supply | 21 B BLCH, not hard-capped (perpetual tail) |
| Distribution | ≈ 94% of existing supply at one address (§0.1) |

Two known consensus fragilities inform the design and are called out where
they bite:

- **Block-identity keying.** A prior defect keyed the DAG by `pow_hash` while
  storage keyed bodies by `block_hash`. Any change to the hash function walks
  straight through this area (§5.4).
- **Order-dependent difficulty validation.** `expected_bits` is derived from
  mutable local state rather than from ancestry, so nodes running identical
  binaries can diverge at retarget heights. PoS **deletes this bug class
  outright** (there is no difficulty), which is a genuine, non-marketing
  argument in the migration's favour — but §5.5 requires that stake state not
  reintroduce the same pattern.

---

## 3. Target architecture — summary

**Name:** Genesis-4, codename **Bell**. Merge event = **"the Bell transition"**.

| Layer | Choice | Rationale |
|---|---|---|
| Hash | SHA3-256 (fixed) + SHAKE-256 (XOF), domain-separated | Keccak sponge, no length-extension, PQ-adequate (Grover: quadratic only), already in-tree |
| Block identity | `SHA3-256(DS_BLOCK ‖ canonical_header)` | Replaces SHA-256d; §5.4 |
| Leader election | Stake-weighted public sortition over a hash-based beacon | No standardised PQ VRF exists; §6 |
| Randomness | Hash-based commit-reveal (RANDAO-style) over SHAKE-256 preimages, mixed per slot | Uniqueness comes from preimage binding, not signature uniqueness |
| All signatures | **Unchanged**: hybrid ML-DSA-65 ‖ Falcon-1024 suite, for identity, proposal and attestation alike | Founder constraint; no new primitive enters the tree |
| Finality | Bloch-BFT: two-round, ≥ 2/3 stake, checkpoints every epoch | Deterministic finality; replaces PoW depth |
| Chain shape | Linear chain, **30 s slots**, 32-slot epochs, committee **128** voting at the epoch boundary + 8 per slot | Cadence, not committee size, is what the 4.6 KB signature actually constrains; §6.5 |
| Vote compression | **Optional optimisation** — epoch-boundary FRI-STARK proof over the quorum | Measurement removed the dependency; §6.5.1 |
| ZK ledger | Coherence C1 preserved; its roots enter `state_root`; shielding is closed to tainted coins | §6.6 |

---

## 4. Distribution and the anti-capture design — retired and replaced

> **This section described taint propagation, and taint no longer exists.**
> It was written for a migration *in place*, where the founder's ~94% holding
> sat on the chain being converted and had to be marked ineligible coin by coin.
> Two later decisions removed its subject: Genesis-3 halts and Genesis-4 launches
> from a snapshot (`BLOCH-TOKENOMICS-V4.md` §3.2), and the carryover crosses as
> **one undifferentiated set with no exclusion list** (§1 of the same document).
> There is no class of coin left to mark.
>
> Three mechanisms went with it: the taint set, the 300 M holder cap, and — the
> one worth naming — the **exclusion list as an unaudited power**. Whoever wrote
> that list would have decided who counts as founder, with nothing in the
> protocol checking it. That risk did not get mitigated; it stopped existing.

### 4.1 What answers concentration instead

Not coin marking. Three things, in descending order of how much they actually
do:

1. **The allocation itself.** The founder's new grant is 17% under a 10-year
   cliff and 40-year linear vest — the strictest schedule on the chain, far
   beyond any market benchmark.
2. **Vesting on the Foundation buckets.** VC and team hold nothing liquid at
   genesis; marketing releases a quarter; liquidity is liquid by function
   (`BLOCH-TOKENOMICS-V4.md` §7B).
3. **Gates measured on stake that is not insider stake.** G1–G4 exclude stake
   whose beneficial owner is the Foundation, the founder, or Postern Labs —
   including Foundation-delegated stake and the genesis validator set
   (`BLOCH-ENTITY-STRUCTURE.md` §5.1, tokenomics §3.3).

### 4.2 What that does not fix, stated plainly

The carried-over balance is **liquid at genesis**, and the largest single
address holds 3,546,175,400 BLCH — 70.4% of the circulating supply at slot 0.
Gate G2 requires the largest holder under 25%, which this schedule does not
reach until roughly **year five**.

An earlier draft cliffed the founder's entire position and bought a genesis
where the founder held no spendable stake at all. Carrying the balance across
liquid gave that up. The tokenomics document states the year-by-year figures
(§4A); this document's job is only to record that the gates in §11 are what
enforce it, and that they are not met at launch.

One distinction stays available and is still undecided: **liquid is not the
same as stakeable**. A carried-over balance can be spendable while remaining
ineligible to stake. Nothing about carrying it across liquid decides that it
votes, and that decision is what determines whether the gates are reachable
before year five.

---

## 5. Chain structure

### 5.1 Slots and epochs

| Constant | Value | Note |
|---|---|---|
| `SLOT_DURATION_SECS` | **30** | Deliberately identical to today's PoW block target — see below |
| `SLOTS_PER_EPOCH` | 32 | 16 min/epoch |
| `EPOCHS_PER_CHECKPOINT` | 1 | Justification per epoch; finality ≈ 32 min |
| `MIN_DEPOSIT_BLCH` | 100,000 | Sized so a validator set of ~1,000 is reachable from realistic float |
| `MAX_VALIDATOR_STAKE` | 1% of active stake | 1% cap, resolved by fixed point — `delegation.rs` |
| ~~`COMMITTEE_SIZE`~~ | **removed** | Replaced by partitioning — see §6.5.3 |
| ~~`SLOT_SUBCOMMITTEE_SIZE`~~ | **removed** | Same |
| Committee size | **derived: `ceil(N / 32)`** | The active set is partitioned, not sampled |
| `ATTESTATION_CADENCE` | **once per validator per epoch** | Each validator serves in exactly one slot committee |
| `ACTIVATION_DELAY_EPOCHS` | 8 | ~2.1 h |
| `EXIT_DELAY_EPOCHS` | 32 | ~8.5 h |
| `WITHDRAWAL_DELAY_EPOCHS` | 2,048 | ~22.8 days; weak-subjectivity margin |
| `SLASH_PROPOSER_EQUIV` | 5% of stake + ejection | Two blocks, same slot |
| `SLASH_SURROUND_VOTE` | 5% of stake + ejection | Casper-style surround/double vote |
| `INACTIVITY_LEAK_RATE` | quadratic after 4 epochs of non-finality | Recovers liveness from a stalled set |

All values are proposals for Phase 1 review; every one of them is a consensus
constant requiring a KAT and a devnet sweep before it is frozen.

**Why 30 s slots, a committee of 128, and epoch-boundary voting.** Two earlier
drafts got this wrong in opposite directions. The first used 12 s slots and a
committee of 128, sized around a compact attestation signature the fixed
arrangement does not provide. The second corrected the signature size but kept
per-slot voting, and paid for it by halving the committee to 64.

Measurement settled it (`spikes/prover-cost/RESULTS.md`). The dominant variable
is not slot time or committee size — it is **how often the committee votes**.
Moving the full committee's vote to the epoch boundary cuts both proving cost
and signature storage by 32×, which buys back the committee size *and* removes
the need for aggregation. A small per-slot subcommittee (§6.5.2) preserves the
fork-choice weight that epoch-only voting would otherwise destroy.

The remaining price is **finality latency** — ≈ 32 min, against ≈ 13 min for a
12 s-slot design. That is the honest cost of a 4.6 KB signature, and it is not
recoverable without changing the signature arrangement.

### 5.2 Retiring GhostDAG

GhostDAG's blue-score ordering exists to make concurrent PoW blocks useful.
With one designated proposer per slot, concurrency is an anomaly, not the
norm. Genesis-4 is a **linear chain**:

- `BlockHeader.parents` narrows from `Vec<[u8;32]>` to a single
  `parent: [u8;32]`. The field is kept as a vector in the wire format with a
  consensus rule `parents.len() == 1` so that serialisation code, explorers and
  SDKs need a smaller diff.
- Fork choice becomes **LMD-GHOST over attestation weight**, with the latest
  justified checkpoint as the root — not blue score.
- `reachability.rs` and the DAG anticone machinery are retained but demoted to
  historical-chain queries only (pre-transition blocks remain a DAG forever).

**Migration hazard:** the historical DAG and the post-transition chain coexist
in one database. The transition block is the unique block whose parent is a
DAG selected-tip and whose children are linear. Every index, every RPC, and
the explorer must handle that seam. Assistant A5 owns a seam test matrix.

### 5.3 Block header (Genesis-4)

```text
BlockHeaderV4 {
    version:            u32          // 4  — 0xB10C_0005
    parent:             [u8; 32]     // 32 — SHA3-256 block id
    state_root:         [u8; 32]     // 32 — SHA3-256 of the eUTXO + stake state
    body_root:          [u8; 32]     // 32 — SHA3-256 Merkle root of transactions
    slot:               u64          // 8
    proposer_index:     u32          // 4  — index into the active validator set
    randao_reveal:      [u8; 32]     // 32 — SHAKE-256 preimage for this slot
    randao_mix:         [u8; 32]     // 32 — accumulated beacon after mixing
    justified_root:     [u8; 32]     // 32 — latest justified checkpoint
    finalized_root:     [u8; 32]     // 32 — latest finalized checkpoint
    attestation_root:   [u8; 32]     // 32 — root over the quorum in the body
    coherence_root:     [u8; 32]     // 32 — Coherence accumulator root, §6.6
}

BlockEnvelope {
    header:       BlockHeaderV4
    proposer_sig: HybridSig          // ≈4,589 — ML-DSA-65 ‖ Falcon-1024, suite-tagged
    body:         Body               // transactions + attestation quorum
}
```

Removed relative to V3: `bits`, `nonce`, `timestamp` (derived from `slot`),
`parents: Vec<_>`. Removing `bits` is what deletes the order-dependent
difficulty bug class described in §2.

The proposer signature sits in the **envelope, not the header**. With a 4.6 KB
hybrid signature, an in-header signature would make the header itself larger
than a typical Bitcoin block's worth of headers, and every light-client and
header-sync path would carry it. Keeping the signed object small (`header` is
248 B) means header chains stay cheap and only full validation pays for the
signature.

### 5.4 Block identity — the one change that touches everything

```text
block_id = SHA3-256( DS_BLOCK ‖ canonical_serialize(header_without_proposer_sig) )
```

`block_id` is the **only** identifier. There is no second hash, no `pow_hash`,
and no mining projection. This is deliberate: the historical
`pow_hash` / `block_hash` split caused the DAG-keying defect that stalled tip
selection. Genesis-4 forbids the pattern at the type level — `BlockId` is a
newtype with no second constructor and no `From<PowHash>`.

Assistant A2 owns a property test asserting that no code path in the tree
derives a block identifier from anything other than `BlockId::of(&header)`.

### 5.5 State commitment and determinism

`state_root` commits to a SHA3-256 sparse Merkle tree over:

- the eUTXO set,
- the validator registry (pubkeys, stake, activation/exit epochs, slashed flag),
- the current and previous epoch attestation participation records,
- the randao mix history for the last 2 epochs,
- **the Coherence shielded-pool state**: the SHAKE-256 accumulator root and the
  nullifier-set root (§6.6). Today these live in an in-memory `ShieldedPool`
  (`main.rs:844`); under PoS they must be committed, because finality means
  nothing if the shielded state is not part of what gets finalized.

**Hard rule, learned from the difficulty defect:** every consensus-relevant
value used to validate block *B* must be derivable from `B.parent`'s committed
state, never from node-local mutable state. Validator set, proposer schedule,
committee assignment and beacon mix are all read from `state_root` of the
parent. A reviewer checklist item ("does this read local mutable state?") is a
merge blocker for DEV-1, and A4 audits for it explicitly.

---

## 6. Cryptography

### 6.1 SHA-3 domain separation

One hash function, many uses; every use gets a tag. Tags are ASCII, fixed
length 16, right-padded with `0x00`:

| Tag | Use |
|---|---|
| `BLCH4:BLOCK\0…` | Block identity |
| `BLCH4:BODY\0…` | Transaction Merkle tree |
| `BLCH4:STATE\0…` | State SMT nodes |
| `BLCH4:ATTEST\0…` | Attestation signing root |
| `BLCH4:RANDAO\0…` | Beacon mixing |
| `BLCH4:SORTIT\0…` | Sortition draw |
| `BLCH4:DEPOSIT\0…` | Deposit message |
| `BLCH4:SLASH\0…` | Slashing evidence |

Fixed-length digests use SHA3-256. Variable-length or multi-output derivation
uses SHAKE-256. SHA-256d survives **only** in the historical verification path
for pre-transition blocks, and is never used to produce anything new.

### 6.2 Lattice signatures — the arrangement is fixed

**One suite, every role.** Validator identity, deposits, exits, slashing
evidence, block proposals and attestations all use the existing hybrid
`SUITE_MLDSA65_FALCON1024`. There is no role split, no second scheme, and no
per-message algorithm negotiation.

| | ML-DSA-65 | Falcon-1024 | Hybrid total |
|---|---|---|---|
| Public key | 1,952 B | 1,793 B | 3,745 B |
| Signature | 3,309 B | ~1,280 B | **≈ 4,589 B** |
| Verification | both must pass | both must pass | AND, not OR |

What that buys and what it costs, stated plainly:

- **Buys:** no new primitive enters consensus. The code, the KATs, the wallet,
  the SDKs and the audit surface are the ones that already exist. A break in
  either lattice family alone does not break the chain — that is the whole
  point of the hybrid, and it is a genuinely strong position to hold into a
  consensus role.
- **Costs:** ≈ 4.6 KB per consensus message. Every sizing decision in §5.1
  descends from that number, and §6.5 stops being an optimisation and becomes
  structural.

**Falcon-1024 caveat, non-negotiable for DEV-2.** Falcon signing uses
floating-point Gaussian sampling with a documented history of side-channel and
implementation pitfalls. PoS does not add Falcon to the tree — it is already
there — but it **changes the threat model materially**: today Falcon signs
occasionally, in a wallet, usually offline; under PoS it signs every slot on an
internet-facing machine holding bonded stake. That is a different exposure for
the same code. Requirements: constant-time / integer-emulated signing path
only, no FP fallback in release builds, deterministic KATs, and remote-timing
review by A4 against a validator that is signing on a schedule an attacker can
predict (§6.4 makes the schedule public).

**The escape hatch already exists and stays closed by default.**
`SUITE_MLDSA65_ONLY = 0x0002` is defined in-tree precisely to prove Falcon is
removable without a format break. Under the founder constraint it is **not**
adopted; it is documented here so that if A4's timing review returns a P0 on
online Falcon signing, the response is a suite change already contemplated by
the format — dropping to 3,309 B, 28% smaller — rather than an emergency
redesign. Adopting it would be a founder decision reversing this constraint,
recorded in the ADR.

### 6.3 Randomness beacon

RANDAO-style, hash-based, no VRF and no BLS:

1. At registration a validator commits `c_0 = SHAKE-256^k(seed)` for
   `k = 8,192` iterations (a hash chain).
2. In its assigned slot the proposer reveals `r_i`, the preimage one step down
   the chain. Nodes verify `SHAKE-256(r_i) == c_i` and set `c_{i+1} = r_i`.
3. `randao_mix_{n+1} = SHA3-256(DS_RANDAO ‖ randao_mix_n ‖ r_i)`.

Preimage binding gives the property ML-DSA cannot: **uniqueness**. There is
exactly one valid reveal per slot, so a proposer cannot grind its contribution.
It can *withhold* (skip its slot) — the standard RANDAO last-revealer bias,
bounded at one bit of influence per withheld slot, and expensive because a
skipped slot forfeits the proposer reward.

Chain exhaustion (after `k` slots) requires a re-commit transaction; A1 owns
the exhaustion test.

### 6.4 Why not a VRF

The obvious design would be VRF-based private sortition (Algorand-style). It is
not available post-quantum:

- **ML-DSA is not unique.** FIPS 204 signatures are randomised; even in hedged
  or deterministic mode, many valid signatures exist for one (key, message)
  pair. A hash of an ML-DSA signature is therefore **grindable** — a proposer
  can re-sign until the sortition output favours it. Any design that treats
  "hash of a PQ signature" as a VRF output is broken. This must be stated in
  the GIP so no future implementer reinvents it.
- **Falcon is not unique either**, and the hybrid is not unique twice over — so
  keeping the current arrangement does not open a VRF path that the role-split
  design lacked. The beacon in §6.3 is signature-independent by construction,
  which is exactly why the founder constraint costs nothing here.
- **Lattice VRFs exist but are research-grade.** LB-VRF-style constructions
  (Esgin et al., 2021) achieve uniqueness only for a small bounded number of
  evaluations per key, requiring frequent key rotation. Interesting; not a
  foundation for mainnet in 2026.

Consequence, accepted deliberately: **sortition is public.** Anyone can compute
the proposer schedule for the current epoch. Mitigations: proposer identity is
an index, not a network address; validators are expected to run behind sentry
nodes; the schedule is only revealed one epoch ahead. This is a real DoS
surface and is documented as such rather than hidden.

A PQ-VRF track is kept open as research (§14) and can upgrade sortition later
without touching the rest of the design.

### 6.5 Attestation footprint — the binding constraint

The hybrid signature is ≈ 4,589 B, and the cadence decides everything. Measured
figures, from `spikes/prover-cost/`:

| Cadence | Signature bytes/year | Avg per block | In-circuit cycles/s |
|---|---|---|---|
| Committee 64, **every slot** | 308.7 GB | 286.8 KB | 15.52 M |
| Committee 128, **epoch only** | 19.3 GB | 17.9 KB | 0.97 M |
| **Committee 128 epoch + 8 per slot** (**adopted**, founder decision 2026-08-10) | **57.9 GB** | **53.8 KB** | **2.91 M** |

Per-slot voting made the quorum the dominant term in block size and forced the
committee down to 64. Epoch-boundary voting removes that pressure entirely: the
chosen design carries a **larger** committee at **one fifth** the proving cost
and **one fifth** the storage of the per-slot design.

#### 6.5.1 Epoch aggregation — optional optimisation, not a dependency

An earlier draft of this section called STARK vote-aggregation **structural**,
on the reasoning that without it the committee is pinned at 64 and the chain
accretes ~310 GB/year of undiscardable signatures.

**Measurement retired that claim.** The 310 GB/year was a consequence of
per-slot voting, not of the signature size. At epoch cadence the same committee
— doubled to 128 — produces 19.3 GB/year, and the chosen design (§6.5.2) 57.9
GB/year. That is ordinary, prunable-at-leisure data. Aggregation would still be
*nice* (it would let the committee grow without bound), but nothing in the
design now **depends** on a research-frontier result. The spike did not find a
way to pay the cost; it found a way not to incur it.

The design is a natural fit for infrastructure that already exists for the ZK
ledger:

1. Per-slot attestations are carried raw in the block, as above. Nothing is
   proven in real time — no proving system is asked to keep up with a 30 s slot.
2. At each epoch boundary, a prover produces **one FRI-STARK proof** that the
   epoch's quorum signatures verified and that the checkpoint was justified by
   ≥ 2/3 stake. This reuses `crates/coherence-prover` (SP1, Plonky3, raw FRI)
   and inherits its non-negotiable rule: **raw FRI verification, never SP1's
   Groth16 wrapper** — a curve SNARK would silently destroy the post-quantum
   property of the whole consensus (`COHERENCE-C1.md §3`).
3. Once an epoch is finalized and its proof is verified, **the raw signatures
   become prunable**. Archival nodes may keep them; a fully validating node
   syncing from a finalized checkpoint verifies the proof instead.

Measured cost of the in-circuit statement (`spikes/prover-cost/RESULTS.md`,
2026-08-10), on real PQClean signatures verified by pure-Rust verifiers
compiled to `riscv32im`:

| | Instructions | Keccak permutations | Keccak share |
|---|---|---|---|
| ML-DSA-65 verify | 5,909,451 | 208 | 57.7% |
| Falcon-1024 verify | 1,312,901 | 31 | 38.4% |
| **Hybrid, marginal** | **7,274,849** | 239 | 54.2% |

Two findings worth carrying forward. **Falcon-1024 verifies 4.5× cheaper than
ML-DSA-65** — the bottleneck is the NIST-standardised half, not the exotic one,
which inverts the intuition about which half to drop if cost ever forces the
question. And **the cost is exactly linear in N** (0.41% spread across four
distinct signature pairs, zero fixed overhead), so batching buys nothing in the
guest: any saving must come from the proof system itself.

#### 6.5.3 Partition, do not sample — the F1 correction

The adversarial review found that the sampled design has **no coherent quorum
denominator**, and that both readings fail:

| Denominator | Failure |
|---|---|
| Network stake | A 128-validator sample cannot hold ⅔ of network stake past ~192 validators — and gate G4 *requires* ≥ 200. **Finality structurally unreachable**; the inactivity leak fires forever |
| Committee stake | A 128-sample has enough variance that a ~30%-stake adversary exceeds ⅓ of the committee in roughly one epoch in five, stalling finality below the nominal threshold |

**The fix is to partition the active set rather than sample it.** Shuffle
deterministically, cut into 32 committees, one per slot. Every validator lands
in exactly one committee and votes exactly once per epoch, so the union of an
epoch's committees *is* the active set. The denominator is then total active
stake, unambiguous and reachable by construction — the property Ethereum has,
which the sampled design gave up without noticing what it was buying.

It also removes finding **F2**. Under independent per-slot draws a validator was
routinely drawn in several slots of one epoch and emitted several attestations
sharing a `target_epoch`, which `is_double_vote` correctly flags as slashable.
Honest validators slashed themselves, and the reward was harvestable. Under a
partition, two attestations sharing a target epoch really are equivocation.

**Cost, stated honestly.** One hybrid signature per active validator per epoch,
against 384 under the sampled design:

| Validators | Sampled | Partitioned | Per slot | KB/slot |
|---:|---:|---:|---:|---:|
| 200 | 384 | 200 | 7 | 31 |
| 384 | 384 | 384 | 12 | 54 |
| 1,000 | 384 | 1,000 | 32 | 143 |
| 4,096 | 384 | 4,096 | 128 | 574 |

Partitioning is **cheaper below 384 validators** — where gate G4 puts the launch
— and more expensive above. The scaling ceiling is around 4,096 validators, past
which sub-sampling would have to return and F1 with it. Aggregation would lift
the ceiling; the measured in-circuit cost (§6.5.1) says that is research, not
engineering. Recording the ceiling now is better than discovering it at 5,000
validators.

#### 6.5.2 Per-slot subcommittee — superseded by §6.5.3

Epoch-only voting removes the per-slot attestation weight that LMD-GHOST uses
for fork choice. Without it, intra-epoch reorgs become cheap: ordering inside an
epoch would rest on slot number and the proposer signature alone.

Ethereum does not actually do this. There, every validator votes once per epoch,
but the set is sliced into 32 committees — one per slot — so every slot still
carries attestation weight. Literal epoch-only voting is a different and weaker
thing.

The design therefore keeps a **`SLOT_SUBCOMMITTEE_SIZE = 8`** sample attesting
each slot purely for fork-choice weight, with the full 128 voting at the epoch
boundary for justification and finality. Cost: 2.91 M cycles/s and 57.9 GB/year
— against 15.52 M and 308.7 GB for the per-slot design it replaces.

### 6.6 Coherence (the ZK ledger) — preserved, and what PoS must not break

Coherence is kept exactly as frozen in `COHERENCE-C1.md`. Notably, it is the
part of the system that needs **no cryptographic migration at all**: its
commitments, nullifiers and accumulator are already SHAKE-256, and its proof
system is already hash-based FRI with elliptic-curve ZK explicitly excluded. The
SHA-3 migration in §6.1 brings the rest of the chain *to where Coherence already
is*, rather than moving Coherence anywhere.

Four requirements follow.

#### 6.6.1 Continuity across the transition

The commitment accumulator is **incremental** and the nullifier set is
**monotone**. Neither may be reset, re-rooted, or rebuilt at
`TRANSITION_HEIGHT`. A note shielded at height *h* < transition must be
spendable at *h* + 1 with a witness computed under the old tree, and every
nullifier ever published must remain permanently unspendable. This is a
correctness requirement with a privacy failure mode: a reset accumulator would
force every holder to re-shield, linking old notes to new ones and
retroactively de-anonymising the pool.

A3 owns a shadow-fork test that shields before the transition and spends after
it, asserting witness validity and nullifier persistence across the seam.

#### 6.6.2 Shielded state must be finalized state

The shielded pool is currently in-memory (`ShieldedPool::new()`, `main.rs:844`).
Under PoS its accumulator root and nullifier-set root are committed in
`state_root` and mirrored in `BlockHeaderV4.coherence_root` (§5.3, §5.5).
Finality that does not cover the shielded pool would leave the private ledger
reorganisable after the transparent one is settled — the worst possible
asymmetry, and precisely the class of divergence this chain has already been
bitten by when consensus state lived outside the committed state.

#### 6.6.3 Deposits must spend transparent outputs

Stated as consensus rules, enforced by every node:

```
INVALID  deposit_tx if any input is a shielded output
```

The companion rule — that shielding a tainted coin is invalid — went with the
taint set (§4). What remains is the direction that was always load-bearing on
its own: **stake must be attributable**, so a validator's bond always traces to
transparent coins.

The first rule is enforceable because a shield transaction spends **transparent**
inputs, whose ancestry is public — the privacy boundary is not violated by
checking it. The second rule closes the reverse direction: stake must be
attributable, so a validator's bond always traces to transparent coins.

The two-class-coin cost this rule used to carry is gone with the taint set:
no coin is marked, so none is second-class. The remaining constraint is narrow
and uncontroversial — a shielded note has no `OutPoint` to bond, so it could not
back a deposit in any case.

A9's audit found this is not a retrofit at all: the shield bridge **does not
exist yet**. `ShieldedTx` has no transparent fields and `check_spend`'s balance
equation means value can neither enter nor leave the pool. So the rule is a
day-one design constraint on a bridge that has still to be built, at no
privacy cost and no migration cost.

#### 6.6.4 Shared prover infrastructure

`crates/coherence-prover` (SP1 guest + host + HTTP service, GPU-deployed) is the
same infrastructure §6.5.1 needs for epoch aggregation. One prover service, two
statements. This is a real economy of scope — and a real coupling: an outage or
a regression in that service now affects consensus pruning as well as shielded
spends. A6 owns availability requirements; the consensus path must degrade to
"keep raw signatures" rather than stall when the prover is unavailable.

---

## 7. Staking lifecycle

Two new transaction types in the eUTXO model.

### 7.1 `DEPOSIT`

```text
DepositTx {
    amount:            u64            // ≥ MIN_DEPOSIT_BLCH, ≤ MAX_VALIDATOR_STAKE
    validator_pubkey:  [u8; 3745]     // suite-tagged hybrid: ML-DSA-65 ‖ Falcon-1024
    randao_commitment: [u8; 32]       // c_0, §6.3
    withdrawal_addr:   Address        // where the stake returns
    proof_of_possession: HybridSig    // ≈4,589 B over SHA3-256(DS_DEPOSIT ‖ fields)
}
```

Validity: inputs must be **transparent** (§6.6.3);
amount within bounds; PoP valid under **both** halves of the suite; suite tag
== `SUITE_MLDSA65_FALCON1024`. One key pair serves identity, proposal and
attestation — there is no separate attestation key, because there is no
separate attestation algorithm. The deposit output is locked to a
consensus-owned script; it is not spendable until withdrawal.

Deposits are accepted **on the PoW chain during the hybrid phase** — this is
how the validator set exists before the transition.

### 7.2 `EXIT` and withdrawal

Voluntary exit is a hybrid-signed message; the validator stops being assigned
after `EXIT_DELAY_EPOCHS`, and the stake becomes spendable to
`withdrawal_addr` after `WITHDRAWAL_DELAY_EPOCHS`. The long withdrawal delay is
the weak-subjectivity margin: it must exceed the window in which an exited
validator could sign a conflicting history for free.

### 7.3 Slashing

Evidence transactions carry two conflicting signed messages. Penalty:
`SLASH_*` percentage plus immediate ejection; a whistleblower reward of 1/32 of
the penalty goes to the including proposer. Correlated-slashing amplification
(penalty scaled by how much stake was slashed in the same window) is
**included** — without it, a single entity controlling many validators is
punished no more than an unlucky solo operator.

### 7.4 Rewards

Issuance per Emission V3 is unchanged in *quantity*. The recipient split
becomes: 7/8 to attesters pro-rata to participation, 1/8 to the proposer, with
the inclusion-delay weighting standard to Casper-style designs. Transaction
fees follow the existing endowment split (`ENDOW_FEE_SHARE_BPS = 1000`).

`MINER_SHARE_BPS` / `VALIDATOR_SHARE_BPS` in `tokenomics_v2.rs:119-121`, today
100/0, invert at the transition. Note that this file currently asserts
`VALIDATOR_SHARE_BPS == 0` with the comment "removed (no BFT)" — the constants
and their comments are consensus-adjacent documentation and must be corrected
in the same commit, not later.

---

## 8. The transition mechanism

> **SUPERSEDED 2026-08-10.** This section designed Genesis-4 as a flag-day fork
> on the running chain, with a hybrid period, and explicitly rejected a fresh
> genesis. The founder decided otherwise: the chain **halts** at height 80,000,
> a signed balance snapshot is taken, and Genesis-4 launches from it about six
> months later after code review (`BLOCH-TOKENOMICS-V4.md` §3.2).
>
> What that changes: there is no hybrid period, no `TRANSITION_START`, no
> DAG→linear seam to cross, and no upgrade partition — the old chain is not
> continued, it is ended. §4.1's taint machinery goes with it: it was built
> because the live distribution could not be fixed in place, and a fresh genesis
> replaces coin-marking with the allocation and its vesting schedules.
>
> The text below is retained because the gates (§11), the rollback thinking
> (§13) and the testing strategy (§12) still apply to launching a new chain.

Genesis-4 was designed as a **flag-day fork on the existing chain**, not a new
genesis. The carryover approach used for Genesis-3 was rejected here: a new
genesis at that stage would reset the very distribution history that §4.1
depends on.

```
        PoW only            hybrid (shadow finality)         PoS only
  ──────────────────┬────────────────────────────────┬──────────────────►
                    │                                │
              TRANSITION_START                  TRANSITION_HEIGHT
              (deposits open,                   (PoS binding,
               attestations                      PoW checks dropped,
               non-binding)                      AuxPoW deactivated)
```

- **`TRANSITION_START`** (height, published ≥ 8 weeks ahead): deposit
  transactions become valid; validators begin attesting; attestations are
  **gossiped, stored, and scored but do not affect fork choice**. The chain is
  still pure PoW. This is a live-fire rehearsal on mainnet with zero consensus
  authority — the single most valuable de-risking step in the plan.
- **`TRANSITION_HEIGHT`**: activation, gated by §11. From this block, PoW
  validity checks are dropped, `AUXPOW_ACTIVATION_HEIGHT` is superseded, and
  fork choice switches to LMD-GHOST over attestations. The transition block
  itself is the last PoW block and the first finalized checkpoint.
- **Nodes that do not upgrade** stop following the chain at
  `TRANSITION_HEIGHT` — they will see the first V4 block as invalid. This is a
  clean partition, not a silent divergence, and is the correct behaviour.

Given the yamux/release-gap history in this project, **release engineering is a
first-class risk**: the published binary must be the binary the fleet runs, and
the fleet must be verified on it before the flag day, not during. Assistant A6
owns this and holds a veto (§9.4).

---

## 9. Organisation

**PMO + 3 developers (Claude Fable 5) + 6 assistants.**

### 9.1 PMO

Owns the plan, the risk register, the gates (§11), the flag-day calendar, GIP
and ADR filing, and the external comms sequence (English, per standing policy).
The PMO does not write consensus code. The PMO's core deliverable is that no
phase exits without its exit criteria met and evidenced.

### 9.2 Developers

| Role | Owns | Primary deliverables |
|---|---|---|
| **DEV-1 — Consensus core** | Slots/epochs, fork choice, finality, state transition, transition mechanism | LMD-GHOST + justification/finalization, `BlockHeaderV4`, DAG→linear seam, flag-day activation logic |
| **DEV-2 — Cryptography, beacon & prover** | SHA-3 domain separation, hybrid-suite integration, RANDAO, sortition, epoch aggregation | Hash migration across the tree, constant-time Falcon-1024 signing path, beacon + sortition + full KAT suite, **the §6.5.1 proving-cost spike** |
| **DEV-3 — Staking, economics, node, P2P & ZK-ledger continuity** | Deposit/exit/withdrawal, slashing, rewards, gossip, sync, RPC, wallet, Coherence state commitment | Two new tx types, the §6.6.3 transparent-input rule, reward accounting, attestation gossip topics, RPC surface, sync from a finalized checkpoint, shielded roots in `state_root` |

Interfaces between the three are frozen at the end of Phase 1 as Rust traits
with no implementations; every later phase codes against them.

### 9.3 Assistants

| # | Assignment | Standing deliverable |
|---|---|---|
| **A1** | Conformance & test vectors | Cross-implementation KATs for every hash tag, signature, beacon step, sortition draw; the vector file is the spec's ground truth |
| **A2** | Fuzz & property testing | Fuzz targets for header/tx/attestation decode; property tests for the §5.4 identity invariant and §5.5 determinism rule |
| **A3** | Devnet & fleet operations | Multi-node devnets, shadow-fork replays of mainnet, chaos scenarios (§12), fleet health during hybrid |
| **A4** | Adversarial review & security | Threat model, per-phase adversarial pass, long-range/weak-subjectivity analysis, slashing-evidence review, §6.4 grinding review |
| **A5** | Documentation & ecosystem | GIP-0003, ADR-036, spec upkeep, explorer/wallet/SDK/L2 migration, the DAG-seam test matrix, public-facing English copy |
| **A6** | Release engineering | Reproducible builds, prebuilt fleet binaries, upgrade runbooks, rollback packaging, "published == running" verification |

### 9.4 Rules of engagement

- **A4 and A6 hold vetoes.** A4 can block a phase exit on an unresolved
  security finding; A6 can block a flag day on a build/fleet mismatch. Only the
  founder overrides, and the override is recorded in the ADR.
- **Two-reviewer rule on consensus code.** Every consensus-affecting merge needs
  one other DEV plus A4.
- **No consensus constant lands without a KAT** (A1) and a devnet sweep (A3).
- Weekly: PMO risk-register review. Per phase: written exit-criteria evidence.

---

## 10. Phases

### Phase 0 — Decision and framing (weeks 1–3) — BLOCKING

Deliverables: this document reviewed and accepted or rejected by the founder;
legal review of the securities framing (§0.2); GIP-0003 filed; ADR-036 filed
recording the reversal of the ownerless-PoW position; a public English
statement of what is being traded away (merged mining, Bitcoin-miner GTM).

*Exit:* founder go/no-go recorded. **If legal review is negative, the project
stops here.** Nothing downstream is worth doing under an unresolved framing
risk.

### Phase 1 — Specification freeze (weeks 4–9)

Full consensus spec: constants, header, state layout, fork choice, finality,
sortition, staking lifecycle, slashing. Interface traits frozen. Threat model
v1 (A4). KAT format defined (A1).

*Exit:* spec reviewed by all three DEVs plus A4 with no open P0 questions;
every constant in §5.1 either confirmed or revised with rationale.

### Phase 2 — Cryptographic foundation (weeks 6–13, overlaps Phase 1)

SHA-3 domain-separated hashing across the tree; constant-time Falcon-1024
signing path with KATs; RANDAO chain; sortition; hybrid deposit/PoP path;
**the §6.5.1 epoch-aggregation proving-cost spike**. DEV-2 leads, A1 and A2 in
lockstep.

*Exit:* full KAT suite green; Falcon signing path reviewed by A4 with no
unresolved side-channel finding under a predictable signing schedule; fuzzers
clean for 72 h; **a measured proving cost for one epoch's quorum, with the
aggregation go/no-go decision recorded** (§6.5.1).

### Phase 3 — Consensus implementation (weeks 10–19)

DEV-1: slots, epochs, LMD-GHOST, justification/finalization, `BlockHeaderV4`,
state transition, DAG→linear seam. DEV-3: deposits, exits, slashing, rewards,
gossip, RPC, sync-from-checkpoint. A3 runs devnets continuously
from week 12.

*Exit:* a 30-node devnet finalizes for 7 consecutive days including induced
partitions, 1/3 offline, and equivocation injection; all slashing paths
exercised.

### Phase 4 — Shadow fork and public testnet (weeks 18–25)

Shadow-fork mainnet state at a recent height and run the transition on it,
repeatedly. Then a public testnet ("Bell testnet") with external operators —
external participation is the point; a testnet run only by Postern proves
nothing about the validator-set assumption.

*Exit:* three consecutive successful shadow-fork transitions, **each including a
shield-before / spend-after Coherence continuity test** (§6.6.1); testnet
finalizing for 14 days with ≥ 20 independent external validators; sustained
block propagation measured at the 296 KB/block working point (§6.5) with no
mesh or stream-limit regressions.

### Phase 5 — Mainnet hybrid (weeks 24–?, duration set by §11)

`TRANSITION_START` on mainnet. Deposits open. Attestations non-binding.
Distribution program runs (§4.3). Fleet on the release binary, verified (A6).

*Exit:* §11 gates all green. **This phase has no fixed end date by design** —
it ends when distribution allows, or the project halts.

### Phase 6 — Transition and post-merge (flag day + 8 weeks)

`TRANSITION_HEIGHT`. Then: withdrawals enabled after
`WITHDRAWAL_DELAY_EPOCHS`; explorer/wallet/L2 anchor migration completed;
AuxPoW and stratum decommissioned. Epoch aggregation (§6.5.1) is **not** on this
critical path — the cadence change already delivered what it was for; it returns
only if the committee needs to grow well beyond 128.

---

## 11. Go/No-Go gates for `TRANSITION_HEIGHT`

Every one must be green. Any red halts the flag day; there is no partial
activation and no "we'll fix it after the merge".

| # | Gate | Threshold |
|---|---|---|
| G1 | **Independent eligible stake** | ≥ 15% of circulating supply is deposited by parties that are not the Foundation, the founder, or Postern Labs |
| G2 | **Concentration** | No single entity controls > 25% of active stake; top-3 < 50% |
| G3 | **Nakamoto coefficient** | ≥ 7 for block production and for finality |
| G4 | **Validator count** | ≥ 200 active validators, ≥ 50 operated by parties unaffiliated with Postern Labs |
| G5 | **Client diversity or explicit acceptance** | Single-client risk formally accepted in writing by the founder if no second implementation exists |
| G6 | **Hybrid stability** | ≥ 30 days of non-binding attestations with ≥ 95% participation and zero unexplained divergence |
| G7 | **Security** | A4 sign-off; no open P0/P1; external review of the online Falcon-1024 signing path |
| G8 | **Release integrity** | A6 sign-off: published binary == fleet binary, reproducible, rollback package staged and tested |
| G9 | **Legal** | Phase 0 legal position still valid under the final reward design |
| G10 | **Network capacity** | 54 KB/block average and the epoch-boundary burst (≈ 588 KB) sustained on the real fleet for ≥ 14 days: no gossip-mesh degradation, no yamux stream-limit failures, p99 propagation < 5 s |
| G11 | **ZK-ledger continuity** | Shield-before / spend-after passes on three shadow forks; nullifier set and accumulator provably unbroken; shielded roots finalized (§6.6) |

G1–G4 are the honest statement of §0.1: **if the coins do not distribute, the
migration does not happen.** That is the correct outcome, not a failure of the
engineering.

---

## 12. Testing, verification, chaos

- **KATs (A1):** every hash tag, every signature op, beacon steps, sortition
  draws, deposit/exit/slash message encodings, state-root computations. The
  vector file is normative for any future implementation.
- **Property tests (A2):** block identity has exactly one derivation (§5.4);
  no consensus value reads node-local mutable state (§5.5); state root is
  deterministic under transaction reordering within a block; serialisation
  round-trips.
- **Fuzzing (A2):** header, transaction, attestation, deposit, slashing
  evidence decoders; differential fuzzing of SHA-3 tag handling.
- **Chaos scenarios (A3):** 1/3 offline; 1/3 + 1 offline (inactivity leak
  recovery); network partition and heal; equivocating proposer; mass
  simultaneous exit; beacon-chain exhaustion; clock skew ±30 s; a validator set
  that is 60% one operator.
- **Shadow forks (A3):** repeated transitions from real mainnet state — the
  only test that exercises the DAG→linear seam against real data, and the only
  place the Coherence continuity test (§6.6.1) is meaningful.
- **ZK-ledger tests (A1/A3):** shield before the transition, spend after;
  nullifier double-spend attempts across the seam; a shield transaction with a
  a deposit spending a shielded output must be rejected (§6.6.3); shielded roots present and finalized in `state_root`.
- **Adversarial passes (A4):** one per phase, plus a dedicated long-range /
  weak-subjectivity analysis and a sortition-grinding analysis (§6.4).

---

## 13. Rollback and abort

- **Before `TRANSITION_HEIGHT`:** abort is free. The hybrid phase changes
  nothing binding; deposits are refundable by a consensus rule that unlocks
  deposit outputs if the transition does not occur by
  `TRANSITION_DEADLINE_HEIGHT`. **This refund rule ships in the same release as
  the deposit rule** — it is not added later.
- **After `TRANSITION_HEIGHT`:** rollback is a coordinated hard fork back to
  PoW at a chosen height, discarding post-transition history. It is
  catastrophic, it requires the ASIC fleet and pool to be recoverable on
  short notice, and A6 stages the PoW binary + runbook for the entire
  post-merge window. Treat it as a fire extinguisher, not a plan.
- **Abort triggers:** any G-gate turning red pre-flag-day; a P0 cryptographic
  finding at any time; finality stalling > 4 epochs on the hybrid rehearsal;
  negative legal position.

---

## 14. Open questions

1. **PQ-VRF.** Can a bounded-evaluation lattice VRF (LB-VRF family) with
   epoch-scoped key rotation give private sortition at acceptable cost? Would
   upgrade §6.3–6.4 without touching the rest.
2. **STARK epoch aggregation (§6.5.1).** ~~Highest-value unknown~~ — **answered
   and demoted**. The in-circuit cost was measured (7.27 M instructions per
   hybrid verification, linear in N) and the cadence change removed the
   dependency. What remains open is only the upside case: if the committee ever
   needs to exceed ~128, what does one FRI proof over the epoch quorum cost on
   affordable hardware? Requires the SP1 toolchain to convert cycles into
   seconds.
3. **Falcon-1024 online.** Is a constant-time integer-only Falcon signer
   available and reviewable for a machine that signs on a publicly predictable
   schedule? The arrangement is fixed, so the answer here is a *security*
   question, not a design choice — and if it is P0, §6.2's suite escape hatch
   is the only lever, and pulling it requires reversing the constraint.
4. ~~**Taint set permanence and the two-class coin.**~~ **Dissolved.** The
   carryover crosses as one undifferentiated set, so no coin is marked and none
   is second-class. What replaced the question is narrower and still open:
   whether a carried-over balance that is *liquid* is also *stakeable* (§4.2).
   That one decides whether the gates are reachable before year five.
5. ~~**Weak subjectivity** — who signs the checkpoint in an ownerless system?~~
   **Answered by [ADR-036](../adr/ADR-036-retract-ownerless-adopt-foundation.md):**
   the ownerless premise is retracted and the Foundation publishes checkpoints.
   The question that replaces it is narrower and practical — publish under an
   *m-of-n* key held beyond the Foundation, with an explicit review date, so the
   arrangement does not become permanent by inertia
   (`BLOCH-ENTITY-STRUCTURE.md` §5.3). The mechanism — checkpoint format,
   cadence, boot consumption, and the m-of-n/review-date parameters — is
   specified in [`BLOCH-WEAK-SUBJECTIVITY.md`](BLOCH-WEAK-SUBJECTIVITY.md).
6. ~~**Do nothing** — fix the difficulty defect and stay on PoW.~~ **Overtaken
   by events.** The founder decided on a Genesis-4 relaunch with new tokenomics
   on 2026-08-10, so the live chain is not the thing being changed; it is being
   replaced. This option is retained only as history — it was the right question
   to ask while the alternative was amending the running chain.
7. **Attestation cadence** — ~~per-slot vs epoch-boundary voting~~ **decided**:
   the hybrid, 8 per slot for fork-choice weight plus 128 at the epoch boundary
   for finality (§6.5.2). Confirmed 2026-08-10.

---

## 15. Immediate next actions

| # | Action | Owner | Gate |
|---|---|---|---|
| 1 | Founder decision on §0 | Founder | Phase 0 |
| 2 | Legal review of PoS reward framing | PMO | Phase 0, blocking |
| 3 | File GIP-0003 and ADR-036 | A5 | Phase 0 |
| 4 | Measure the untainted float precisely at current tip | DEV-3 | Feeds G1 |
| 5 | Falcon-1024 constant-time signer availability spike | DEV-2 | Phase 1 |
| 6 | Freeze consensus interface traits | DEV-1 | Phase 1 exit |
| 7 | Draft the distribution program (§4.3) | PMO | Phase 5 prerequisite |
| 8 | **Epoch-aggregation proving-cost spike** (§6.5.1) | DEV-2 | Phase 2 exit |
| 9 | Founder decision on the two-class coin (§6.6.3, §14.4) | Founder | Phase 1 |

---

## 16. Copyright

Released under MIT OR Apache-2.0, consistent with the reference node.

---

### Appendix A — Constant summary

| Constant | Proposed | Section |
|---|---|---|
| `SIGNATURE_SUITE` | `0x0001` ML-DSA-65 ‖ Falcon-1024 (unchanged) | 6.2 |
| `SLOT_DURATION_SECS` | 30 | 5.1 |
| `SLOTS_PER_EPOCH` | 32 | 5.1 |
| `MIN_DEPOSIT_BLCH` | 100,000 | 5.1 |
| `MAX_VALIDATOR_STAKE` | 1% of active stake | 4.1 |
| `MAX_ACTIVATIONS_PER_EPOCH` | 4 | 4.1 |
| `COMMITTEE_SIZE` | 128 (voto na fronteira de época) | 5.1, 6.5 |
| `SLOT_SUBCOMMITTEE_SIZE` | 8 (só peso de fork-choice) | 6.5.2 |
| `ACTIVATION_DELAY_EPOCHS` | 8 | 5.1 |
| `EXIT_DELAY_EPOCHS` | 32 | 5.1 |
| `WITHDRAWAL_DELAY_EPOCHS` | 2,048 | 5.1, 7.2 |
| `SLASH_PROPOSER_EQUIV` | 5% + ejection | 5.1, 7.3 |
| `SLASH_SURROUND_VOTE` | 5% + ejection | 5.1, 7.3 |
| `RANDAO_CHAIN_LENGTH` | 8,192 | 6.3 |
| `BLOCK_VERSION` | 0xB10C_0005 | 5.3 |

### Appendix B — Ecosystem impact checklist (A5)

| Component | Impact |
|---|---|
| Coherence shielded pool | **Formats unchanged**; roots move into committed state; shield closed to tainted inputs (§6.6) |
| `coherence-prover` (SP1/FRI service) | Second consumer: epoch aggregation (§6.5.1); availability now consensus-adjacent |
| Wallet shielded flows | Must surface "this coin cannot be shielded / staked" for tainted outputs |
| `bloch-pool`, stratum V1/V2, proxies | Decommissioned at flag day |
| AuxPoW / merged mining | Deactivated; BTC submit path retired |
| ASIC fleet (S19j Pro, 100 TH/s) | No longer usable for Bloch; disposition decision needed |
| Explorer (`blochl1.com`) | New header fields, finality display, DAG→linear seam |
| Wallet / PWA | Deposit/exit UX, staking views |
| L2 (`bloch-l2-evm`, chainId 8400) | Anchor to finalized checkpoints instead of PoW depth |
| SDKs (Python, Go), OpenAPI | Header schema, new RPCs |
| Node operators | Mandatory upgrade; clean partition if they do not |
| Snapshot / onboarding runbook | Sync-from-finalized-checkpoint replaces k=8 DAG snapshot |
