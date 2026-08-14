<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Kirpich under PoS — the fail-closed charter-audit gate as a consensus rule

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

```
Document:  BLOCH-KIRPICH-UNDER-POS
Status:    DRAFT — design analysis for the Ustav-at-L1 promotion (fleet brief
           2026-08-11); no code changed by this document
Created:   2026-08-11
Relates:   BLOCH-USTAV-L1.md (DEV-4, parallel — the promotion of the charter
           itself to a consensus object; this document covers only the GATE),
           BLOCH-POS-SHA3-LATTICE-MIGRATION.md, BLOCH-ENTITY-STRUCTURE.md,
           crates/bloch-euvm/src/kirpich.rs
```

**Scope split with DEV-4.** BLOCH-USTAV-L1.md owns the charter as a consensus
object: its state representation, the registration transaction, `charter_id`
in `state_root`, upgrade mechanics of the charter format. This document owns
the *gate*: what fail-closed means when the closer is a validator set instead
of a miner, what enforcing the gate costs per block, what its liveness surface
is, and who — if anyone — holds approval power over charters. Where the two
documents must agree (audit-at-registration-only, rule-set versioning), the
requirement is stated here and flagged as an interface for DEV-4.

---

## 1. The code exists — inventory

The task brief allowed for Kirpich being marketing copy with no code behind
it. **That is not the case.** Kirpich is implemented, tested, and shaped like
a consensus rule already — it is just not wired as one:

| What | Where |
|---|---|
| Dispatcher, `Severity`/`Finding`/`AuditReport`, canonical ordering | `crates/bloch-euvm/src/kirpich.rs` (301 lines) |
| Lane A — module conflicts, KRP-001..005 | `crates/bloch-euvm/src/kirpich/conflicts.rs` |
| Lane B — completeness, KRP-020..026 | `crates/bloch-euvm/src/kirpich/completeness.rs` |
| Lane C — unsafe params, KRP-040..045 | `crates/bloch-euvm/src/kirpich/params.rs` |
| Lane D — emitted programs, KRP-060..064 | `crates/bloch-euvm/src/kirpich/emitted.rs` |
| Gated compile entry point `compile_charter_audited` | `crates/bloch-euvm/src/modules.rs` |
| Integration test of the fail-closed contract | `crates/bloch-euvm/tests/kirpich_gate.rs` |

23 KRP rules across four lanes; `Deny` blocks the audited compile, `Warn` is
advisory, `Info` is vocabulary no lane emits. The implementation already keeps
the disciplines a consensus rule needs, stated in its own module docs: pure
function of the charter, byte-identical `AuditReport` for the same charter, no
clock, no float, no `HashMap` iteration, no IO, checked/saturating arithmetic,
and **no rule panics on any charter** — a malformed charter yields findings,
never a crash.

Where it stands today, per its own honesty note (`kirpich.rs` lines 11–17):
**FOUNDATION, tests-only, NOT consensus-wired**, behind the off-by-default
`euvm` cargo feature, and it never blocks the un-audited `compile_charter`
path. The audited path is opt-in. The public description matches: the live
site (`posternlabs-deploy`, e.g. `apps/enterprise/products.html`) calls Ustav
and Kirpich "Postern tooling built on that VM — reference/tooling, not
consensus rules, not part of the ownerless base."

One discrepancy to record: the same site copy says the Genesis-3 mainnet node
"ships built with `--features euvm`" and that the eUTXO VM is consensus-wired
from height 0. In *this* repo (`~/dev/BlochPOS`, the Genesis-4 base),
`Cargo.toml:64-68` says `euvm` is **off by default and NOT wired**, and
`src/main.rs:40` marks the adapter "NOT wired into accept_block". Whichever
statement is true of the shipped G3 binary, the PoS repo's starting point is:
Kirpich today gates nothing that consensus sees.

## 2. Who closes, under PoS

"Fail-closed" under PoW had one closer with a clear incentive: the miner
building the template refuses the transaction, and every full node re-checks.
Under PoS the closure is the same *function* enforced at three concentric
points, and it is worth being precise about which point does what:

1. **The proposer, at mempool admission.** A charter-registration transaction
   whose charter audits `denied` is rejected before it enters a block
   template. This is hygiene, not enforcement — a modified proposer can skip
   it.
2. **Every full node, in the state-transition function.** This is the actual
   gate. If Ustav is L1, "block contains a registration of a Deny-audited
   charter" is an *invalid state transition*, exactly like an overspend. The
   block is not "unpopular"; it can never be part of any honest node's chain.
3. **The attesters, and therefore finality.** Honest attesters run the same
   deterministic audit, see the same `denied: true`, treat the block as
   invalid, and do not vote for it. Under LMD-GHOST it accrues no fork-choice
   weight; the slot is effectively skipped and the proposer forfeits the slot
   reward (the same skipped-slot economics BLOCH-POS-SHA3-LATTICE-MIGRATION.md
   §6.3 relies on against RANDAO withholding). A
   denied charter can only be *finalized* if more than two thirds of stake
   runs software that removed the rule — which is a hard fork, not a bypass.

So the answer to "a validator that accepts a reproved charter is doing what?"
is: **producing an invalid block** — option one, not option two. It is not
merely a block nobody chooses; it is a block no honest node will extend or
attest under any circumstance, because validity is prior to choice.

**Is it slashable? No, and it should not be.** Slashing in this design
(§7.3 of the migration spec) is evidence-based and covers exactly
equivocation: two conflicting signed messages, compact enough to carry in a
transaction and verify cheaply. "This block contains an invalid charter" has
no compact evidence smaller than the block plus re-execution — which every
node already performs. Adding invalid-block slashing would buy nothing (the
block already cannot enter the chain, and the proposer already loses the slot
reward) and would add a whole evidence-handling surface, including the risk
that a *bug in the audit* becomes a way to slash honest proposers. The
deterrent stands as: forfeited reward, an orphaned block, and a signed,
attributable public record of having tried.

## 3. What the gate costs per block

If the gate is consensus, every validator pays the audit on every block that
carries a charter registration. Estimate, with inputs pinned:

- Slot time 30 s; block budget per gate G10 of
  BLOCH-POS-SHA3-LATTICE-MIGRATION.md is **54 KB/block average** (epoch
  burst ≈ 588 KB).
- Audit cost is a pure function of the charter bytes. Lanes A–C are linear
  scans plus bounded pairwise key comparisons (`BTreeMap`/`BTreeSet`, no
  hashing games); Lane D is the expensive one: it runs `compile_charter`
  **twice** (the KRP-060 determinism check) and SHA-256d-hashes every emitted
  program. Emitted output is itself capped by KRP-062's own ceilings
  (`MAX_TOTAL_BYTES = 256 KiB`, `MAX_TOTAL_GAS = 8_000_000` static, in
  `emitted.rs`), and emitted size is linear in charter size (keys are copied
  inline, ops are constant per signer) — there is no amplification loop.
- Charter input size is bounded by the transaction, which is bounded by the
  block. Under the unchanged hybrid suite, a registration carries the
  issuer's ML-DSA-65 ‖ Falcon-1024 signature (≈ 4,589 B per the spec's §5.3
  envelope figure), and every pubkey a charter embeds raw costs ≈ 3.7 KB
  (ML-DSA-65 1,952 B + Falcon-1024 1,793 B). A realistic six-module charter
  with ~8 role keys is therefore ≈ 30–35 KB — **about one charter fits in an
  average block**. The 54 KB budget is itself the admission cap.

Order-of-magnitude arithmetic (⚠️ *estimated, not benchmarked — see §7*):
two compiles plus hashing over at most a few hundred KiB of emitted bytes at
~1 GB/s single-core SHA-256 is well under 1 ms; the scans are noise. Ceiling
**single-digit milliseconds per block, against a 30-second slot: under 0.03%
of the slot budget.** For calibration, verifying *one* hybrid signature
already costs the same order of magnitude, and a full block carries many.

Conclusion: **CPU is not the cost of promoting Kirpich to consensus.** The
cost is the one the fleet brief names: consensus surface. Every KRP rule
becomes fork-choice-relevant; a rule bug is a chain bug; a rule change is a
flag-day. The per-block audit is cheap precisely because the rule set is
static, deterministic, and input-bounded — and those three properties are now
load-bearing, which is what §4 is about.

Two conditions keep the estimate valid, both interfaces for DEV-4's
registration design:

- **Audit at registration only.** The audit runs once per charter lifetime,
  in the block that registers it — never per spend, never per block for
  already-registered charters. Spends check the *compiled* validators, which
  is the VM's normal job.
- **The charter tx pays size-proportional fees** like any transaction, so the
  audit's input bound is economically enforced, not just structurally.

## 4. The liveness question — Kirpich against the cohort-cap precedent

The genesis-cohort cap (`crates/bloch-pos-committee/src/genesis_cohort.rs`,
`apply_cohort_cap`) is this project's precedent for a rule that chose to
**defer instead of halt**. Its long comment records why, and the reasoning is
worth restating before deciding whether Kirpich should inherit the posture:
the cap is computed as a share of *non-cohort* stake, so at a cold launch with
zero independent stake the cap is zero, the entire validator set drops to
zero weight, and integer truncation makes this bite at **epoch 5, about 1.3
hours after genesis** — a rule written to decentralise the chain would have
killed it on day one. So the cap defers, and `cap_status` reports *why*: "the
shortfall becomes visible instead of becoming an outage."

**Kirpich should NOT inherit the deferral posture, and the reason is the
scope of the object each rule binds.** The cohort cap binds the validator
set — a whole-chain object. When it misfires, the chain stops; there is no
smaller blast radius available, so the honest fallback is to report. Kirpich
binds a single transaction at the admission edge. When it fires — rightly or
wrongly — exactly one charter registration fails and the chain continues to
its next block untouched. A "deferring Kirpich" would mean admitting a
charter that audits `Deny` and flagging it for later, which is not a softer
gate; it is no gate. Fail-closed at transaction granularity is not a
chain-liveness surface, so the trade the cohort cap had to make does not
arise. The gate stays fail-closed.

But the cohort-cap lesson does transfer, in three places where a
transaction-scoped rule can still reach chain scope:

1. **A panic or divergence is the chain-scope failure mode.** The epoch-5
   truncation was found by adversarial review, not by the author. Kirpich's
   equivalents are: a lane that panics on a hostile charter (the whole
   state-transition aborts → every node crashes on the same block), or a
   lane whose verdict differs across builds (→ consensus split, the
   difficulty-validation post-mortem again). The crate already promises
   no-panic, no-clock, no-float, no-HashMap; at L1 those promises must be
   **pinned**: the audit becomes a fuzz target over arbitrary charter bytes
   (extend the A2 fuzz list in migration-spec §12), with debug/release
   differential runs, and the §5.5 reviewer rule — "does this read local
   mutable state?" — applies to every KRP lane as a merge blocker. The audit
   must remain a pure function of the charter bytes *only*: never of chain
   state, height, or registry, or same-binary nodes can diverge.
2. **Retroactivity is the deferred-halt of this rule.** The rule set will
   change (a KRP-065 will exist someday). If a new rule re-evaluates
   *already-registered* charters, a rule-set upgrade becomes a retroactive
   freeze of user funds — a rule that kills at a distance, the exact shape
   the cohort comment warns about. Requirement (interface for DEV-4): a
   registered charter records the **rule-set version** it was audited under;
   upgrades activate by flag-day and apply only to registrations at or after
   it; nothing re-audits the past. The compiled validators of an
   already-registered charter stay spendable forever under their own terms.
3. **Enforce Deny, report Warn — the cap's own split.** `apply_cohort_cap`
   enforces; `cohort_share_bps` reports and is explicitly "reporting, not
   consensus." Kirpich at L1 keeps the same line: only `Severity::Deny` is
   consensus. `Warn` and `Info` stay off-chain (RPC, explorer, tooling) —
   promoting advisory findings would make every future *warning* a hard fork.

And the cap's deepest sentence has an exact analog worth writing down: the
cap "cannot manufacture decentralisation out of nothing," and Kirpich cannot
manufacture charter *quality* out of static analysis. It catches structural
defects — ambiguous supply, unsatisfiable quorums, neutered guards, funds
locked forever. It does not and cannot catch a charter that is coherent,
well-formed, and predatory. Nobody may cite "Kirpich-audited" as an
endorsement of a token; the site copy rule for the gate is the same as for
the cap: say what is enforced, and where enforcement stops.

## 5. Who approves a charter — nobody, and keeping it that way

**Today there is no approver in the code, and that is a finding, not a gap.**
`kirpich_audit` is a pure function; "approval" is the absence of a `Deny`
finding. No key signs charters in, no registry admits them, no allowlist
exists. Promotion to L1 must preserve exactly this: the only admission
authority over charters is the deterministic rule set every node runs.

The permanent power therefore does not disappear — it relocates. It is the
power to **change the rule set**, which is protocol-upgrade power, and it can
be named under the two-entity structure (BLOCH-ENTITY-STRUCTURE.md):

- The **Bloch Foundation** holds the spec: KRP rule changes are published as
  GIPs with flag-day activation, under the Foundation's §2 role ("publishes
  specs, GIPs, checkpoints"). Postern Labs holds **no protocol authority**
  (§2), but writes the implementation and signs node releases (§4: "whoever
  builds, signs").
- It is auditable the way the genesis cohort is and the §5.4 taint list is
  not: the rules are AGPL source with stable public codes (KRP-001..064),
  the report is byte-deterministic so **anyone can recompute any verdict**,
  and changes land only through a published GIP plus a flag-day that every
  operator chooses to run. There is no list to write and no key to hold —
  "written once, in public," per the cohort's own standard.
- Honesty clause, same as §5.2's: until the Foundation has the
  independent-majority board of ENTITY-STRUCTURE §5.2, "the Foundation
  publishes the rule change" and "Postern Labs ships it" are the same people
  with two letterheads. The structure is the design for where the power goes,
  not a claim that it has already been separated.

**One anti-pattern to forbid by name.** Any override mechanism — "the
Foundation may bless a denied charter," a registrar key, an on-chain
allowlist of approved issuers — recreates the §5.4 taint-list problem
*inside consensus*: an unaudited list-writing power, held permanently, deciding
who may issue tokens. The genesis cohort was explicitly designed so that "no
list-writing power [is] retained by anybody"; the charter gate must meet the
same bar. If a deployment genuinely needs permissioned issuance, that policy
belongs inside a charter's own `Governance`/`ComplianceKycGate` modules —
per-token, chosen by the issuer, visible in the charter — never in the gate
that admits charters.

## 6. What is gained, what is bought

Per the fleet brief, stated once and not re-litigated here: gained — a
charter that cannot be bypassed by talking to the contract directly, because
the gate sits in the state-transition of every node rather than in a build
tool an issuer can decline to run. Bought — 23 rules' worth of consensus
surface, upgrade rigidity (every rule change is a flag-day), and the fact
that a token issuer's malformed charter becomes every validator's validation
cost (bounded, per §3, by the block budget). The promotion decision itself is
DEV-4's document; this one says the gate can carry it if §4's three
requirements are met.

## 7. What this document did NOT do — stated plainly

- **No benchmark was run.** The §3 numbers are order-of-magnitude estimates
  from input bounds and hash throughput, labelled as such. A criterion
  benchmark of `kirpich_audit` + double `compile_charter` over
  budget-maximal hostile charters is a required gate before consensus
  wiring; if it lands above ~50 ms per block the §3 conclusion must be
  revisited in writing.
- **No code was changed.** Kirpich remains tests-only and off-by-default;
  this is analysis, not wiring.
- **The registration transaction, charter state object, and `state_root`
  leaf are not designed here** — DEV-4's BLOCH-USTAV-L1.md owns them. The
  three interfaces this document imposes on that design: audit at
  registration only (§3), rule-set version pinned per charter (§4.2), Deny
  is the only consensus severity (§4.3).
- **The dependency on the EVM-at-L1 decision is flagged, not resolved.** The
  other direction of this wave asks whether `crates/bloch-euvm` "survives,
  is absorbed, or dies." Kirpich audits charters that compile to *eUTXO
  validators*; if the eUTXO VM dies in favour of an account-model EVM,
  Ustav-at-L1 has no compile target and both this document and DEV-4's need
  a new substrate section. The two wave directions collide exactly here and
  someone must own the collision.
- **Charter size under PQ keys is flagged for DEV-4:** `TokenCharter` stores
  raw pubkey bytes; at ≈ 3.7 KB per hybrid key, realistic charters consume
  most of a 54 KB block. Whether registered charters should reference key
  hashes instead (with keys revealed at spend, as the base already does) is
  a charter-object question, not a gate question — but it decides how many
  registrations a block can carry.
