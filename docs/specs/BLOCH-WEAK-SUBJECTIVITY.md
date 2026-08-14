<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch — Weak subjectivity: checkpoint format, publication, and sync

> **Genesis-4 is live.** Bloch has been running under **proof of stake** since
> 21:31:19 UTC on 2026-08-13, when Genesis-3 (proof of work) stopped
> permanently at height **39,918**. 30 s slots, 32-slot epochs, Casper-style
> justification/finalisation by epoch, hybrid ML-DSA-65 ‖ Falcon-1024
> signatures on every consensus path. Nothing in this document that describes
> mining, hashrate, difficulty, retargeting or proof-of-work depth describes
> the current network.
>
> **The live security question is concentration, not hashrate.** All 64
> validators are operated by a single entity; 93.94% of the carryover
> (17,046,829,380 of 18,146,400,000 BLOCH) sits at one address and carried
> balances are stakeable, so if that balance stakes the Nakamoto coefficient
> is 1; and 56,046,829,380 of the 57,146,400,000 BLOCH issued at slot 0 is
> held by the founder and the Foundation, leaving 1.92% of genesis supply in
> third-party hands. One operator can halt the chain and one holder can outvote
> every other. The live transport is a point-to-point TCP full mesh with a
> fixed peer list, **no discovery and no authentication**, and
> `Deposit`/`Delegate` are refused at every node's mempool — which is why a
> third party cannot yet join the network or become a validator.

> **PARCIALMENTE SUPERADO — 2026-08-11.** Esta analise foi escrita contra o
> estado do projeto naquele dia e depende de premissas que mudaram DEPOIS:
>
> - **a maquinaria de taint** — dissolvida: o carryover atravessa como um conjunto so, sem lista de exclusao, entao nao ha classe de moeda a marcar.
> - **o comite amostrado (128 por epoca + 8 por slot)** — substituido por particao do conjunto ativo: o quorum amostrado nao tinha denominador coerente (achado F1).
>
> O texto NAO foi reescrito, de proposito: o raciocinio que produziu cada
> achado tem valor mesmo quando a premissa mudou, e reescrever apagaria a
> trilha. Leia os achados; confira as premissas contra
> `BLOCH-TOKENOMICS-V4.md` e `BLOCH-POS-SHA3-LATTICE-MIGRATION.md`, que sao
> os normativos.


```
Document:  BLOCH-WEAK-SUBJECTIVITY
Status:    PARTIALLY IMPLEMENTED. The **boot gate** is wired end to end and
           running on the live chain: `bloch_pos_committee::ws` decides and
           `crates/bloch-pos-node/src/ws_boot.rs` supplies its inputs —
           154-byte canonical envelope, m-of-n verification under the real
           hybrid suite, persisted `ws_latest.bin`, anti-rollback, conflict
           refusal, genesis anchor as first checkpoint. **Checkpoint-sync
           state download does not exist** (`bloch-pos-node/src/main.rs:27`),
           and this build bakes **no Phase A signer keys** — the signer
           arrangement comes from `--ws-signer-set <file>`, so the m-of-n
           quorum is operator-supplied, not pinned in the binary. Constants
           still require KATs before freeze; no KATs exist anywhere in the
           PoS crates (`BLOCH-POS-GAPS.md` GAP-6).
Created:   2026-08-11
Owner:     A12 (sync & weak subjectivity), reviewed by A4, implemented by DEV-3
Follows:   ADR-036 (the Foundation publishes checkpoints)
Relates:   BLOCH-POS-SHA3-LATTICE-MIGRATION.md §5.1, §6.5, §7.2, §14.5
           BLOCH-ENTITY-STRUCTURE.md §4, §5.3
           BLOCH-TOKENOMICS-V4.md §3.2.2
           src/bin/bloch-snapshot-utxo.rs (the honesty template)
```

---

## 0. The problem, stated before the mechanism

Under PoW, the canonical chain is the one that cost the most energy. A node
syncing from genesis with no trusted input can, by verification alone, reject
every forged history: forging one costs as much as making the real one.

Under PoS that property does not exist. A validator whose stake has been fully
withdrawn can sign anything, forever, at zero cost. Take any committee from more
than `WITHDRAWAL_DELAY_EPOCHS` ago: if ≥ 2/3 of that committee's stake has since
exited and withdrawn, its former members can sign a **complete alternative
history** from that point — different blocks, different justifications,
different "finality" — and every signature in it verifies. Slashing cannot touch
them; there is no stake left to slash. This is the classic long-range attack,
and no amount of protocol cleverness makes a fresh node able to distinguish the
two histories *from within the protocol*. Both are internally valid. The
difference between them is not cryptographic; it is **which one the network
actually lived through** — and that is information a fresh node simply does not
have.

The industry answer, and ours, is **weak subjectivity** (Buterin, 2014): a node
must obtain, from outside the protocol, a recent finalized checkpoint — a trust
anchor — and refuse any history that conflicts with it. The open question was
never *whether* Bloch needs this; it was *who signs the anchor*. In the
ownerless design that question had no clean answer, and §14.5 of the migration
spec called it the design's sharpest philosophical conflict.
**[ADR-036](../adr/ADR-036-retract-ownerless-adopt-foundation.md) answered it:
the ownerless premise is retracted, and the Foundation publishes
weak-subjectivity checkpoints.** This document specifies the mechanism — and,
in §7, prices the trust honestly, because ADR-036 also obliges us to: it calls
this "a real centralisation cost, honestly stated".

One framing worth fixing early, because it disciplines the whole document.
`bloch-snapshot-utxo.rs` already says the true thing about artifacts of this
kind:

> A snapshot is a TRUST ANCHOR, not a proof. Whoever starts from it trusts that
> the set is the real one at that height.

Everything below is engineering *around* that sentence, never *past* it. The
checkpoint makes the trust explicit, minimal, auditable, and revocable on a
schedule. It does not make it disappear.

---

## 1. The weak subjectivity period — why 2,016 epochs is the number (was 2,048; corrected below)

The window in which a node's own knowledge remains self-sufficient is bounded
by how fast stake can leave.

From the migration spec §5.1 and §7.2: exits take effect after
`EXIT_DELAY_EPOCHS = 32`, but the stake only becomes **spendable** — and the
validator only becomes **unslashable** — after `WITHDRAWAL_DELAY_EPOCHS =
2,048` epochs ≈ 22.8 days. §7.2 says explicitly that this delay *is* the
weak-subjectivity margin. Before withdrawal completes, signing a conflicting
history is suicidal: the surround/double-vote evidence (§7.3) burns 5% and
ejects, and correlated-slashing amplification makes a coordinated attack burn
far more. After withdrawal completes, signing a conflicting history is free.

> **CORRECTED 2026-08-11 (A7, implementation).** The equality below was wrong,
> and the error had a sign: the period was too *long*, not conservative. A
> validator still carries duties for `EXIT_DELAY_EPOCHS` after its exit is
> included (`staking.rs::ValidatorRecord::assigned_duties_at` — an exit must
> not dodge already-assigned duties), so a member of the committee that
> finalized epoch `F` may have exited as early as `F − (EXIT_DELAY_EPOCHS − 1)`
> and clears withdrawal at `F + WITHDRAWAL_DELAY_EPOCHS − EXIT_DELAY_EPOCHS
> + 1`. With the period at the full withdrawal delay, a node still trusted its
> own finality for 31 epochs (~8 h) during which every signer of it could
> already be unslashable. The period is therefore **derived** in code
> (`ws.rs::WS_PERIOD_EPOCHS`) as:

```
WS_PERIOD_EPOCHS = WITHDRAWAL_DELAY_EPOCHS − EXIT_DELAY_EPOCHS = 2,016  (≈ 22.4 days)
```

with one epoch of margin below the earliest possible full withdrawal;
`ws.rs::tests::old_window_had_an_unslashable_hole` demonstrates the defect of
the original constant against the real staking functions, and
`corrected_window_leaves_no_gap` pins the fix.

A node whose latest *own-witnessed* finalized checkpoint is younger than
`WS_PERIOD_EPOCHS` can rely on it: any validator who could contradict it still
has stake at risk. A node whose knowledge is older than that **cannot trust its
own database's finality markers as a defense against forged continuations** —
the signers of everything it knows may already be gone.

Three honest footnotes on this bound:

- ~~**It is conservative, deliberately.** Exit churn is rate-limited, so in
  practice ≥ 2/3 of a committee's stake cannot all clear withdrawal in one
  period; the *real* safe window is usually longer.~~ **Falsified 2026-08-11,
  both halves, on re-derivation against the crate.** (a) *Validator* exits are
  not rate-limited anywhere: the churn budget (`WARMUP_RATE_BPS`, 25 bps since
  2026-08-11) meters *delegation* warm-up and cool-down in `delegation.rs`,
  and `MAX_ACTIVATIONS_PER_EPOCH` meters *entry* — nothing in `staking.rs`
  meters exits, so the entire self-bonded set can exit in a single epoch and
  clear withdrawal simultaneously. There is no churn credit to decline; on
  the path that decides this bound there is nothing to take. (b) The constant
  was not conservative — see the correction above: the duty/exit overlap made
  it 31 epochs too long. Ethereum's dynamic churn-derived period remains a
  possible refinement, but it would have to start from an exit queue that
  does not currently exist.
- **Delegated collateral leaves faster than validator keys become free** —
  the footnote the 900 → 25 bps change (2026-08-11) re-prices. A long-range
  forgery needs validator *keys*, and the period above guarantees their
  owners are still slashable inside the window. But what those owners have at
  risk decays on the delegation clock, which is much faster: delegation
  cool-down is `COOLDOWN_EPOCHS = 32` (not the 2,048-epoch withdrawal delay),
  and at 25 bps two thirds of an all-delegated set drains in ≈ 439 epochs
  (`ln 3 / −ln(1 − 0.0025)`), so the collateral behind a validator's
  weight-at-`F` can shrink to its self-bond in ≈ 471 epochs ≈ 5.2 days —
  under a quarter of the window
  (`ws.rs::tests::delegated_collateral_erodes_inside_the_window` measures
  it). Signing a forged continuation then costs each conspirator ~5% of a
  self-bond plus ejection: real, not free, but far below 5% of the weight
  they carried. At the old 900 bps this erosion took ~12 h; the churn change
  slowed it ~10×, strictly favorable — and still no credit is taken. Whether
  delegation cool-down should scale toward the withdrawal delay is a
  consensus-parameter question flagged for the founder, not decided here.
- **The clock is an input.** "How old is my knowledge" is computed by comparing
  the last finalized slot against wall-clock time. A node whose clock can be
  set backward by an attacker can be convinced it is fresh when it is stale.
  This is a standard NTP-trust caveat, shared with every slots-based chain; the
  node SHOULD refuse to start if its clock disagrees grossly with peer time,
  and the runbook must say to use authenticated time sources on validator
  boxes.

---

## 2. Checkpoint format

### 2.1 The signed object

The checkpoint commits to a finalized epoch boundary. Canonical serialization:
fields in declared order, integers fixed-width little-endian (matching storage
conventions), no framing, no optional fields.

```text
WeakSubjectivityCheckpoint {
    version:            u16        // format version, starts at 1
    network_id:         u32        // Genesis-4 network id; binds the artifact to one chain
    genesis_root:       [u8; 32]   // block_id of the Genesis-4 genesis block
    epoch:              u64        // the finalized epoch this checkpoint attests
    block_root:         [u8; 32]   // block_id (§5.4) of the finalized epoch-boundary block
    state_root:         [u8; 32]   // BlockHeaderV4.state_root of that block
    validator_set_root: [u8; 32]   // SMT root of the validator registry at that state
    issued_at:          u64        // unix seconds at signing
    signer_set_id:      u32        // which arrangement (§6) signed this — see §6.4
}
```

```
ws_digest = SHA3-256( DS_WSCKPT ‖ canonical_serialize(checkpoint) )
DS_WSCKPT = "BLCH4:WSCKPT" right-padded with 0x00 to 16 bytes   (§6.1 tag family)
```

Notes on the fields:

- `genesis_root` and `network_id` prevent cross-chain and testnet-vs-mainnet
  replay. A testnet checkpoint must be unusable on mainnet by construction, not
  by operator care.
- `validator_set_root` is included so a syncing node can verify the registry it
  downloads (§4.3) against the checkpoint directly, without first
  reconstructing the full state SMT.
- There is **no `expires_at` field**. Expiry is a *consumer-side* rule computed
  from `epoch` against `WS_PERIOD_EPOCHS` (§4.2); baking a second notion of
  freshness into the artifact would create two clocks that can disagree.

### 2.2 The signature envelope

There is no production-ready threshold lattice signature — threshold ML-DSA is
research-grade — and none is needed for an artifact verified once at boot. The
m-of-n is a plain list of independent hybrid signatures:

```text
CheckpointEnvelope {
    checkpoint:  WeakSubjectivityCheckpoint
    signatures:  Vec<(signer_index: u8, sig: HybridSig)>   // ≈4,589 B each, suite-tagged
}
```

Verification (all MUST hold):

1. Every listed `signer_index` exists in the signer set identified by
   `signer_set_id`, and no index appears twice.
2. Every signature verifies over `ws_digest` under **both** halves of the
   hybrid suite (`SUITE_MLDSA65_FALCON1024`, AND-composition, §6.2 of the
   migration spec).
3. At least `WS_SIGNER_M` signatures are valid.
4. **At least one valid signature comes from the external subset** (§6.2). This
   rule is enforced in verification, not left to signing-ceremony discipline —
   a quorum consisting only of founder-adjacent keys must not verify.

Size: a fully signed envelope is under 25 KB. It travels as a file.

### 2.3 Distribution form

Two renderings of one artifact, same digest discipline as `carryover.tsv` and
its `.sha256`:

- **`wscheckpoint-<epoch>.bin`** — the canonical bytes. What verifiers consume.
- **`wscheckpoint-<epoch>.json`** — human-readable rendering plus the hex
  `ws_digest`. What announcements quote. The JSON is a *view*; the binary is
  the artifact. Anyone can recompute the digest from either and get the same
  answer — the property the snapshot tool already establishes as the house
  rule: the file and the root are two views of one artifact.

Publication channels (per Tokenomics V4 §3.2.2: "widely enough that it cannot
be quietly replaced"): the Foundation site, the GitHub and GitLab release
pages, the explorer (`blochl1.com`, which should render the latest checkpoint
digest on its front page), and the announcement channel. The point of multiple
channels is not redundancy of hosting — it is that quietly *replacing* a
published checkpoint requires rewriting all of them at once, in public.

---

## 3. Publication cadence

```
WS_PUBLICATION_INTERVAL_EPOCHS = 256      (≈ 2.85 days)
WS_FRESH_EPOCHS                = 1,008    (= WS_PERIOD/2, ≈ 11.2 days — soft threshold, warn)
WS_PERIOD_EPOCHS               = 2,016    (≈ 22.4 days — hard threshold, refuse; §1 correction)
```

The Foundation publishes a checkpoint for the latest finalized epoch that is a
multiple of 256. Rationale for the numbers:

- **256 vs the 2,016 window** gives a ~7.8× margin: the signing ceremony can
  fail or be skipped **six consecutive times** before any previously published
  checkpoint ages past the hard threshold (the seventh miss is the liveness
  event — this said "seven" when the window was the uncorrected 2,048;
  `ws.rs::tests::publication_cadence_margin` pins the count). m-of-n
  ceremonies involving external parties (§6) *will* occasionally slip; the
  cadence is chosen so that slippage is an operations annoyance, never a
  liveness event for fresh sync.
- **The soft threshold at half the period** (1,008) exists so that staleness is
  surfaced while there is still ~11 days of margin to fix whatever is wrong,
  rather than discovered at the cliff edge.
- Publication is also **event-driven** in two cases: (a) immediately after any
  mass-slashing event or any epoch in which more than 5% of active stake
  exits — the situations in which the *effective* safe window shrinks fastest;
  (b) immediately before any announced signing-ceremony downtime.

Additionally, **every node release bakes in the latest checkpoint at build
time** (the Bitcoin-`assumevalid` / Ethereum-client-default pattern). A freshly
downloaded binary is therefore at most release-age stale even before it fetches
anything. This adds no *new* trust — whoever runs a binary already trusts its
builder completely, since the binary could simply lie about all verification —
but it must be counted honestly in §7: it makes Postern Labs' release channel a
second checkpoint authority in practice, because release signing keys are
Postern's (`BLOCH-ENTITY-STRUCTURE.md` §4).

---

## 4. How a node consumes the checkpoint

### 4.1 Sources, in precedence order

1. `--ws-checkpoint <file | url | hex-digest>` — operator-supplied. A bare
   digest is enough: the node fetches the envelope from any peer or channel and
   verifies that its `ws_digest` matches. The digest is 64 hex characters; it
   fits in a tweet, a chat message, or a phone call, which is exactly the
   out-of-band property weak subjectivity needs.
2. The release-baked checkpoint, if no flag is given.
3. A previously stored checkpoint in the node's own database, if fresh (§4.2).

The node persists the **highest-epoch checkpoint it has ever verified**
(`ws_latest` in the meta CF). Anti-rollback rule: a validly signed envelope for
an epoch *older* than `ws_latest` is logged and ignored. Without this, a stolen
old quorum signature could "refresh" a node backward into an attacker's window.

### 4.2 Boot decision — the four states

Let `age` = (current epoch estimated from wall clock) − (node's own latest
finalized epoch, from its database).

| State | Condition | Behaviour |
|---|---|---|
| **Fresh node** | empty database | Checkpoint **required** (flag or release-baked). No checkpoint → refuse to sync, with an error message that says why, in these terms. |
| **Recently offline** | `age < WS_FRESH_EPOCHS` | Resume from own finalized head. Own finality **is** the subjectivity anchor. If a published checkpoint is available, compare (§5); do not require one. |
| **Stale, inside the window** | `WS_FRESH_EPOCHS ≤ age < WS_PERIOD_EPOCHS` | Resume, but log a prominent warning and attempt to fetch a fresh checkpoint before following any peer that offers a competing finalized branch. |
| **Beyond the window** | `age ≥ WS_PERIOD_EPOCHS` | **Refuse to follow any peer** (`ERR_WS_STALE`). The node's own finality markers are no longer a defense — every validator that signed them may have fully withdrawn and can now sign a conflicting continuation for free. This is exactly the offline-longer-than-`WITHDRAWAL_DELAY_EPOCHS` case: the checkpoint stops being optional and becomes the only sound way back in. |

The recovery path from `ERR_WS_STALE`: obtain a fresh checkpoint (§4.1),
verify the envelope (§2.2), then reconcile it against local history:

- If `checkpoint.block_root` is a **descendant** of the node's own finalized
  head (established by syncing headers from the local head to the checkpoint
  and verifying each epoch's justification along the way — quorum signatures
  or the §6.5.1 FRI proof), the node keeps its database and continues forward.
  This is the common case: the node was simply away.
- If it is **not a descendant**, then either the node's local history was
  forged while it was away, or something is deeply wrong with the published
  checkpoint. The node MUST NOT auto-wipe and re-sync. It halts with both
  roots printed and requires an explicit operator decision
  (`--ws-accept-reorg <root>`), because whichever side is wrong, silently
  discarding a database is how evidence disappears.

### 4.3 What syncing from a checkpoint actually does

Sync-from-finalized-checkpoint replaces the Genesis-3 k=8 DAG snapshot
onboarding (migration spec, Appendix B). Concretely:

1. **Anchor.** Verify the envelope. Set the fork-choice root and finality floor
   to `checkpoint.block_root`. The node will never, under any input, revert
   below it. LMD-GHOST runs with this as its root (§5.2 of the migration
   spec).
2. **State.** Download the state at the checkpoint — eUTXO set, validator
   registry, participation records, randao mixes, taint-set root, Coherence
   accumulator and nullifier roots (§5.5) — from any peer or snapshot mirror,
   and verify every piece against `checkpoint.state_root` /
   `checkpoint.validator_set_root`. **This step is trust-free given the
   anchor**: the SMT commitments make the data self-authenticating against the
   root. The trust lives entirely in the 32 bytes of the root, never in who
   served the data. (This is the same split the snapshot tool draws between
   the file and its commitment.)
3. **Forward sync.** From the checkpoint, sync blocks forward, fully
   validating: proposer signatures, subcommittee attestations, epoch
   justifications (raw quorum or FRI proof, §6.5.1), Coherence roots. From
   here on the node is a fully validating participant like any other.
4. **Backfill (optional).** Historical blocks below the checkpoint may be
   fetched and verified backward against the parent-hash chain for archival or
   explorer purposes. Availability caveat, learned the hard way on this fleet:
   pruned peers may be unable to serve old bodies at all — the 2026-07 fleet
   had pruned ~95% of all bodies below the tip. History below the anchor is a
   service, not a guarantee.

**The scope of what was trusted must be kept narrow and stated:** the node
trusted one thing — that `block_root` is the real network's finalized epoch
boundary. Everything else it verified.

---

## 5. Detecting a false checkpoint — what is detectable and what is not

This section exists because the question "how would a node know?" deserves a
written answer rather than an implied one.

**Detectable, and the client MUST check:**

| Attack | Detection |
|---|---|
| Checkpoint signed by wrong/insufficient keys | Envelope verification fails (§2.2 rules 1–3) |
| Quorum made entirely of founder-adjacent keys | External-subset rule fails (§2.2 rule 4) |
| Testnet or other-chain checkpoint replayed | `network_id` / `genesis_root` mismatch |
| Rollback to an older validly-signed checkpoint | Anti-rollback against stored `ws_latest` (§4.1) |
| Tampered state served during sync | SMT verification against `state_root` fails (§4.3.2) |
| Checkpoint quietly different across channels | Digest comparison across ≥ 2 channels (below) |

The client SHOULD, when networked, fetch the current checkpoint digest from at
least two independent publication channels and compare. A mismatch is a loud
alarm and a refusal to proceed. But this check must be priced honestly: if the
same party controls all the channels, agreement between them proves nothing —
the snapshot tool's phrasing applies verbatim: *agreement across independent
operators is the evidence, not the artifact's say-so.*

**Detectable as a conflict, but not adjudicable:** a fresh node syncing from a
forged checkpoint will, on the real network, encounter peers whose finalized
chain conflicts with its anchor. Both branches carry internally valid
signatures — that is the nature of the attack. The node cannot decide which
history is real; what it can and MUST do is *notice the disagreement*: if
peers advertise a finalized root that conflicts with the node's anchor and
back it with well-formed justifications, the node raises `WS_CONFLICT`,
logs both roots, and alerts the operator rather than silently living in a
partition. Detection of disagreement is achievable; resolution from inside the
protocol is not.

**Not detectable, full stop:** a checkpoint that is validly signed by `m`
genuine keyholders but attests a forged history — because the keyholders
colluded, were coerced, or had their keys stolen together — **cannot be
detected by a fresh-syncing node from within the protocol.** The node will
verify everything perfectly and be perfectly wrong. There is no cryptographic
remedy; the remedies are social and structural: the independence of the
signers (§6), the multiplicity of channels (§2.3), the fact that every node
already running — whose own finality is younger than `WS_PERIOD_EPOCHS` —
will reject the forged branch outright and say so in public, and the review
date (§6.3) that keeps the arrangement itself under scrutiny. That is the cost
of trusting, and it is written here so nobody has to discover it.

One structural limit on the blast radius, and it is a real one: **the
checkpoint can never override a running node's own finality.** By §4.2, nodes
with fresh local finality treat the published checkpoint as a cross-check, not
a command; a conflicting checkpoint triggers `WS_CONFLICT`, never a reorg.
The signers' power is therefore confined to nodes with nothing of their own to
stand on — fresh installs and the long-offline. They can deceive the newcomer;
they cannot move the network.

---

## 6. Who signs — the arrangement, its parameters, and its expiry

ADR-036 names the Foundation as publisher. `BLOCH-ENTITY-STRUCTURE.md` §5.3
immediately flags that as a real centralisation point and proposes two
mitigations: an m-of-n key held by parties beyond the Foundation, and an
explicit review date. Both are adopted here, evaluated first.

### 6.1 Mitigation 1 — m-of-n beyond the Foundation: real, but only as real as the signers' independence

What m-of-n buys: no single key compromise or single coerced party can sign a
forged checkpoint; the attack requires `m`-way collusion or `m`-way key theft.
What it does not buy: if the `n` holders are the Foundation's board, Postern's
staff, and the founder's associates, the m-of-n is the same social cluster
with extra ceremony — the exact "same people, new letterhead" failure the
entity structure document warns about (§1, the Anza criticism). The mitigation
is worth exactly as much as the *independence* of the external signers, which
is why rule 4 of §2.2 makes at least one external signature a **verification
requirement**, not a policy hope.

There is also an honest bootstrapping problem: at genesis, Bloch has no
independent ecosystem to draw signers from. Pretending otherwise would produce
theatre. So the arrangement is phased, and the launch phase is labelled as
what it is.

**Phase A — launch (signer_set_id = 1).** `2-of-3`:

| # | Holder | Subset |
|---|---|---|
| 0 | Bloch Foundation (operational key, HSM-held where the suite allows) | internal |
| 1 | Postern Labs (release-engineering custody, separate premises and personnel from key 0) | internal |
| 2 | The external security-audit firm engaged for the migration review | **external** |

With the external-subset rule, every valid Phase A quorum includes the
auditor. Stated plainly: **Phase A is founder-adjacent trust with one outside
witness.** It is not decentralised and must not be described as decentralised.
It is, however, strictly better than a single Foundation key, and it is what
is actually available on launch day.

**Phase B — by the first review date (signer_set_id = 2).** `3-of-5`, with at
least **two** valid signatures required from the external subset:

| # | Holder | Subset |
|---|---|---|
| 0 | Bloch Foundation | internal |
| 1 | Postern Labs | internal |
| 2 | The security-audit firm | external |
| 3 | The lead fund of the VC round | external |
| 4 | The largest validator operator by stake **not** delegated from the Foundation (per the §5.1 entity-structure reporting rule — beneficial-owner view, not `Registry` view) | external |

Rationale for these externals rather than others: each has a *financial*
stake in the true history being the canonical one — the auditor's reputation,
the fund's vested position, the operator's bonded stake — which aligns them
against forgery without requiring them to be altruists. The fund is an
imperfect choice (it is inside the return-expectation tent that ADR-036
erected) but it is adversarial to precisely the attack that matters here:
nobody holding vested tokens co-signs a history that rewrites balances.
Signer 4's seat is defined by a measurement, not a name, and rotates with the
measurement at each review.

Under 3-of-5 with two-external-minimum, the Foundation and Postern together
(2 keys) cannot produce a quorum, and no two externals plus one internal can
be outvoted into existence by internal keys alone. A forged checkpoint
requires at least two independent outside parties to join a conspiracy
against their own economic interest.

Key handling: each signer holds an ordinary hybrid keypair
(`SUITE_MLDSA65_FALCON1024`, the same suite as everything else — no new
primitive enters the system for this). No threshold ceremony, no DKG, no
shared secret: five keys, five machines, five organisations. Signing is
offline-capable — the canonical bytes are 154 B and can be carried to an
air-gapped machine.

### 6.2 The external-subset rule, restated as the invariant

```
Phase A:  valid ⇔ ≥ 2 valid sigs  AND  ≥ 1 from {2}
Phase B:  valid ⇔ ≥ 3 valid sigs  AND  ≥ 2 from {2,3,4}
```

Client-enforced (§2.2 rule 4). This is the line that keeps the m-of-n from
degenerating into the Foundation with extra steps.

### 6.3 Mitigation 2 — the explicit review date: cheap, necessary, and given teeth

A review date that is only a calendar entry becomes permanent by inertia —
which is the precise failure §5.3 tells us to design against. Adopted
parameters:

- **Review cadence: every 12 months**, first review 12 months after Genesis-4
  launch. Each review produces a public ADR that either re-confirms the
  arrangement, rotates signers, or moves to a successor mechanism. Silence is
  not an outcome; the ADR is the deliverable.
- **Enforcement (the dead-man's switch):** each signer set carries an
  `arrangement_valid_until` epoch, hard-coded in the client alongside the
  signer pubkeys. Clients **warn** when accepting checkpoints signed under an
  arrangement past 12 months of age, and **refuse new checkpoints** from an
  arrangement past 15 months (12 + 3 grace). The failure mode of a skipped
  review is therefore "fresh sync degrades until governance acts" — running
  nodes are entirely unaffected — rather than "the arrangement quietly
  becomes permanent". The 3-month grace exists so an administratively late
  review is recoverable without an emergency release.
- **The question each review must answer in writing:** can checkpoint signing
  move closer to the validator set? The intended end state, once G1–G4 are met
  on measured, beneficial-owner numbers, is that weak-subjectivity anchors are
  produced by the validator set itself (e.g., the epoch quorum's own finality
  signatures republished as the anchor, with the Foundation demoted to one
  distribution channel among several). The Foundation signing checkpoints
  should be understood as scaffolding with a planned removal date it has to
  re-justify annually — not as architecture.

### 6.4 Signer-set rotation

A rotation (new `signer_set_id`) is announced at least `WS_PERIOD_EPOCHS`
(≈ 22.4 days) in advance, as a handover statement signed by a quorum of the
*outgoing* set, published on all channels, and shipped in a client release.
During the overlap, clients accept either set; after `arrangement_valid_until`
of the old set, only the new. Compromise of an individual key triggers an
immediate out-of-cycle rotation under the same procedure, quorum drawn from
the uncompromised keys.

---

## 7. The cost, priced without discount

**Whoever syncs from scratch trusts the arrangement in §6. This is real
centralisation, and no mechanism in this document removes it.** What the
document does is bound it, and the bounds are worth stating exactly:

1. **The trust is narrow.** One 32-byte root, obtained once, at boot.
   Everything else — state, history forward, every signature, every epoch
   proof — is verified. The checkpoint signers cannot mint coins, cannot alter
   balances under an honest anchor, cannot reorg any running node (§5), and
   cannot even deceive a fresh node without producing an entire internally
   consistent forged chain to back the forged root.
2. **The trust is periodic, not continuous, for anyone who stays online.** A
   node that comes back inside `WS_PERIOD_EPOCHS` never consults the
   Foundation at all. The population exposed to the signers is exactly: fresh
   installs, and nodes offline longer than ~22.4 days.
3. **The trust is not new in kind — but it recurs, and that is the difference
   from PoW.** Genesis-4 itself launches from a founder-signed balance
   snapshot whose digest is embedded in the genesis block
   (`BLOCH-TOKENOMICS-V4.md` §3.2.2): every Genesis-4 node, PoS or not,
   already begins from a signed artifact, and the tokenomics spec is explicit
   that after the PoW halt *the signed artifact is canonical, not the chain*.
   The weak-subjectivity checkpoint is that same act, recurring. The honest
   contrast with PoW is precisely the recurrence: a PoW chain asks for trust
   once, at genesis, and never again; this design re-asks every fresh-syncing
   node to trust a recent checkpoint, forever — or until §6.3's end state
   retires the arrangement.
4. **Today, both fresh-sync roads lead near the founder.** The Foundation
   quorum is founder-adjacent in Phase A, and the release-baked fallback is
   signed by Postern. Until Phase B seats genuinely independent signers —
   and until the review process demonstrably functions — a fresh node's trust
   decision is, in substance, "I trust the project's founding cluster to tell
   me which chain is real." Written here because it is true, and because the
   entity-structure document's own standard (§5.2: controls, not disclosure
   alone) demands that the arrangement be judged by its Phase B delivery, not
   its Phase A labels.
5. **And if the signers lie, the newcomer cannot tell.** §5 already said it;
   it bears repeating in the cost ledger: a validly-signed false checkpoint is
   undetectable from inside the protocol. The defenses are the independence of
   the quorum, the publicity of the channels, the running network's refusal to
   follow, and the annual review — social structures, every one. That is what
   "weak subjectivity" means, and the name is accurate.

---

## 8. Constants and ownership

| Constant | Value | Anchor |
|---|---|---|
| `WS_PERIOD_EPOCHS` | 2,016 (= `WITHDRAWAL_DELAY_EPOCHS − EXIT_DELAY_EPOCHS`, ≈ 22.4 d; derived in `ws.rs`, §1 correction) | §1 |
| `WS_FRESH_EPOCHS` | 1,008 (= `WS_PERIOD_EPOCHS / 2`, ≈ 11.2 d, warn threshold) | §3 |
| `WS_PUBLICATION_INTERVAL_EPOCHS` | 256 (≈ 2.85 d; ~7.8× margin) | §3 |
| `DS_WSCKPT` | `"BLCH4:WSCKPT"` + `0x00` padding to 16 B | §2.1 |
| Signer set, Phase A | 2-of-3, ≥ 1 external | §6.1 |
| Signer set, Phase B | 3-of-5, ≥ 2 external | §6.1 |
| Arrangement review | 12 months; hard stop at 15 | §6.3 |
| Rotation notice | ≥ `WS_PERIOD_EPOCHS` ahead | §6.4 |

Every constant is a Phase 1 review item and lands with a KAT (A1) and a devnet
sweep (A3), per the rules of engagement. The KAT set must include: envelope
verification vectors (valid; m−1 sigs; quorum without external; duplicate
signer index; wrong `network_id`; rollback attempt), and the boot state
machine (§4.2) exercised at the three age boundaries.

| Deliverable | Owner |
|---|---|
| Envelope encode/verify + KATs | DEV-2, vectors A1 |
| Boot state machine, `ERR_WS_STALE`, `WS_CONFLICT`, anchor floor in fork choice | DEV-3 |
| Checkpoint-sync state download & SMT verification | DEV-3 |
| Long-range attack replay on devnet (forge a post-withdrawal history, confirm a fresh node with a checkpoint rejects it and one without follows it) | A3 + A4 |
| Adversarial review of §5's detectability claims | A4 (veto-holding) |
| Signing-ceremony runbook, channel publication automation, release-baking | A6 |
| Phase B signer recruitment and the review-ADR calendar | PMO / Foundation |

---

## 9. Copyright

Released under **AGPL-3.0-or-later**, consistent with the reference node.
