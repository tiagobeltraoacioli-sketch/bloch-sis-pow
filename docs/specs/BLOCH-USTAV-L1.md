<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# BLOCH-USTAV-L1 — Promoting the Ustav token charter from tooling to consensus

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

**Status:** PROPOSAL — decision required. Nothing in this document is wired.
**Wave:** 2026-08-11, DEV-4.
**Depends on:** the EVM-at-L1 decision (same wave, see §10) and the euvm
integration blockers (§8).

Sources this spec is derived from (read them before disputing a claim here):

- `crates/bloch-euvm/src/modules.rs` — the Ustav charter → validator compiler.
- `crates/bloch-euvm/src/kirpich.rs` (+ `src/kirpich/*.rs`) — the fail-closed
  charter-audit gate.
- `crates/bloch-euvm/src/minting.rs` — the mint machinery and the *correct*
  cap policy (`fixed_supply_cap_policy`).
- `crates/bloch-euvm/tests/audit_modules.rs`,
  `crates/bloch-euvm/tests/audit_modules_supply.rs` — two proven charter
  defects that this spec treats as preconditions, not footnotes.
- `crates/bloch-euvm/docs/euvm-non-local-state.md` — the SMT commitment
  primitive for non-per-UTXO charter state.
- `crates/bloch-pos-committee/src/state_root.rs` — the closed leaf list this
  spec must open (once, minimally).
- The published internal audit
  (`posternlabs-deploy/audits/Bloch-euvm-Internal-Audit.md`) — findings F1–F6.

---

## 1. What Ustav and Kirpich are today

**Ustav (PSTRN-1)** is the token-charter standard: a token is a
`TokenCharter` — a name plus an *ordered* composition of six module kinds
(Supply, TransferPolicy, ComplianceKycGate, Vesting, Governance, Custody).
`compile_charter` deterministically emits one eUTXO validator program per
module; the compilation is a pure function of the charter (same charter ⇒
byte-identical programs, same `charter_id`). The token's asset id **is** the
`validator_hash` of its Supply module (`CompiledToken::policy_id`).

**Kirpich** is the fail-closed static audit over that compile path: four rule
lanes (module conflicts, compliance completeness, unsafe params, emitted-byte
defects — codes KRP-001..KRP-064), a canonical deterministic `AuditReport`,
and a gated entry point (`compile_charter_audited`) that refuses to compile
any charter carrying a `Deny` finding.

Both are today, explicitly and correctly, labeled **"FOUNDATION / reference,
unaudited, NOT consensus-wired"**. The euvm crate itself sits behind an inert
activation sentinel (`EUVM_ACTIVATION_HEIGHT = u64::MAX` in `harness.rs`).
Nothing here validates blocks.

## 2. The gain, stated precisely: what a charter cannot do as tooling

In the current model, a charter's guarantees bind **only the outputs that
carry the charter's validator hashes**. The asset id binds nothing but the
minting policy. Concretely:

1. Alice's issuer registers token REG with a TransferPolicy freeze and a KYC
   gate. Outputs the issuer creates carry those validator hashes.
2. Bob receives REG and spends it into an output guarded by a **plain
   signature validator** — or any validator of his choosing. Nothing stops
   him: value conservation only tracks the asset id, not the guard.
3. From that point on, REG circulates with **none** of its charter rules
   attached. The freeze never runs again. The KYC gate never runs again.

That is what "bypassed by talking to the contract directly" means in the
eUTXO model: the charter is a convention about which guards outputs *should*
carry, and any counterparty willing to accept an unguarded output exits the
convention unilaterally. Kirpich, likewise, gates only issuers who choose the
audited entry point; `compile_charter` (un-audited) is public API.

**Promotion to L1 means one thing above all:** a consensus rule that the
guard *follows the asset* — every output carrying a charter-bound asset must
be guarded by that charter's validator set, checked by every node, forever.
That property cannot be built as tooling. It is the entire reason to do this,
and it is a real property: a regulated-asset issuer on Bloch would get, at
the base layer, what Ethereum-style token contracts get only by keeping all
balances inside one contract's storage.

Everything else in this document is the price.

## 3. What exactly becomes consensus

Three candidate scopes. The difference decides whether a charter bug is a
chain bug.

### Option U-A — the charter itself is consensus semantics

The node stores charter bodies and *interprets* them: consensus code
understands "Supply", "Vesting", "KYC" as first-class notions. Every module
kind's meaning is fork-critical; adding a seventh module kind is a hard fork;
a semantic bug in any module's interpretation is a chain bug in the fullest
sense (nodes disagreeing on whether a spend is legal ⇒ split).

Rejected. This is the maximal consensus surface for the minimal additional
benefit over U-C, and it reproduces at L1 exactly the shape of failure the
2026-08-08 `expected_bits` split taught us to fear: meaning living in node
code rather than in committed bytes.

### Option U-B — only a commitment (hash) of the charter is consensus

The chain anchors `charter_id` (and perhaps the asset→charter binding) in
state; charter *rules* stay outside consensus, enforced by tooling that reads
the anchor. A charter bug is never a chain bug.

Rejected, honestly: this is approximately the status quo plus a registry. The
§2 bypass survives intact — nothing forces an output to carry the charter's
guards, because the thing that would force it (a per-transaction check) is
exactly what U-B declines to add. If the founder wants the anchor without the
enforcement (a lighter, reversible first step), U-B is that step — but it
must not be sold as "Ustav at L1", because a charter under U-B can still be
bypassed by talking to the contract directly.

### Option U-C — RECOMMENDED: charter bytes + mechanical enforcement, no charter interpretation

Consensus takes on exactly three mechanical rules, and no understanding of
what any module *means*:

1. **Registration validity.** A charter enters the chain in a registration
   transaction carrying the full canonical charter bytes. The transaction is
   valid iff (a) `kirpich_audit(charter)` yields no `Deny` finding, (b) the
   charter is within the consensus size/gas ceilings (§6), and (c) the
   registration fee covers the priced cost (§6). Every node runs the audit;
   the audited compile path (`compile_charter_audited`) stops being opt-in
   and becomes the *only* path to an on-chain asset id.
2. **The binding invariant.** For every transaction, for every output whose
   value carries an asset bound to a registered charter: the output's guard
   must be (or include, under the composition rule the charter declares) the
   charter's compiled validator set. Checked per transaction by every node.
   This single rule is what closes the §2 bypass.
3. **Execution.** Spends and mints of bound assets run the compiled programs
   through the existing euvm machinery (`spend`, `validate_tx_with_mint`) —
   which is already the plan for euvm generally once its activation sentinel
   is lowered. Ustav adds no new interpreter.

The node never asks what a charter means. It asks: does the audit pass, does
the guard match, does the program return true.

**Is a charter bug a chain bug under U-C?** Split the question:

- A **charter bug** (an issuer writes a bad composition, an unsatisfiable
  quorum, a wrong key) is a **token bug**: the blast radius is that token's
  outputs — stuck, or under-guarded, per §5. The chain does not care whether
  the program's verdict is *wise*, only that every node computes the same
  verdict. This holds **only if** the VM is panic-clean (the internal audit
  confirms `run()` is) and gas is metered by real work (it is not yet — F2,
  §8). Without those two, a charter bug *is* a chain bug, via crash-vs-run
  divergence or via unmetered validation work.
- A **compiler bug or Kirpich bug** is a **chain bug**, full stop. Under U-C,
  `compile_charter`, every module emitter, `kirpich_audit` and all four
  lanes, and the canonical charter serialization become fork-critical
  consensus code. Two nodes whose compilers emit different bytes for the same
  charter, or whose audits disagree on `denied`, split the chain. KRP-060
  (non-deterministic recompile ⇒ Deny) becomes a *consensus self-check*, not
  an advisory. This is the honest core of the cost: promotion moves ~7,000
  lines of currently-reference Rust into the set of code that can halt the
  network.

## 4. Anchoring in `state_root`

`crates/bloch-pos-committee/src/state_root.rs` commits a **deliberately
closed** list of components — eUTXO set, validator registry, participation,
randao, and three *foreign roots* committed as single leaves under their own
tags (taint, Coherence accumulator, Coherence nullifiers). There is no
extension point, on purpose: every leaf is a consensus decision.

Ustav must open that list. Two ways:

- **Per-entry tags** (one leaf per charter, one per binding): maximal proof
  granularity, but it puts an unbounded, issuer-driven entry set directly
  into the consensus tree and widens the `ConsensusState` struct with
  variable-shaped charter data.
- **RECOMMENDED — the foreign-root pattern**, exactly as taint and Coherence
  already do it: **one** new component tag (`TAG_USTAV_REGISTRY`, the next
  unused tag byte) committing **one** 32-byte root of an Ustav registry tree
  owned by the euvm/Ustav module, plus one new field on `ConsensusState`.
  The registry tree itself (an SMT — the `state.rs` primitive documented in
  `euvm-non-local-state.md`, or a second instance of the pos-committee `Smt`)
  maps:
  - `charter_id → H(canonical charter bytes)` (the charter set), and
  - `asset_id → charter_id` (the binding relation §3 rule 2 reads).

  This is the minimal opening: one tag, one field, one root. Inclusion and
  non-inclusion proofs against the registry root give light clients "this
  asset is/is not charter-bound" without new tree machinery.

The §5.5 discipline transfers unchanged: the registry root entering
`ConsensusState` must be derivable from the parent block's committed state —
never from a node-local registry cache. A node that answers the binding
invariant from an in-RAM map that drifted from the committed root is the
`expected_bits` failure wearing a new coat.

**Data availability.** The root commits hashes; validation needs *bytes*
(you cannot compile a hash). Charter bytes enter via registration
transactions, so they exist in block history — but Genesis-4 nodes onboard
from the weak-subjectivity snapshot, so **the snapshot format must carry the
full charter byte set** alongside the state it commits. This is a change to
the snapshot contract (`BLOCH-WEAK-SUBJECTIVITY.md`) and must be specced
there before activation, or a fresh node can verify the registry root and
still be unable to validate a single bound-asset transaction.

## 5. Can a charter be changed?

The fleet brief is blunt that governance is no longer ownerless
(`BLOCH-ENTITY-STRUCTURE.md`). Precisely because of that, this spec draws one
hard line first:

> **The chain — and therefore the foundation — holds no power over any
> charter.** There is no consensus path by which the foundation, the founder,
> or a validator majority amends, freezes, or repairs a third party's
> charter. This is a structural absence (no such transaction type exists),
> not a policy promise. Anyone can verify it by reading the transaction
> validity rules.

Within that line, amendment is **per-charter, opt-in, declared at
registration**:

- **Default: immutable.** `charter_id` is identity. No amendment authority
  exists unless the charter declares one.
- **Opt-in: a declared amendment authority.** A charter may include an
  amendment clause — structurally an n-of-m authority in the same shape the
  Governance module already compiles. An amendment is then an on-chain
  transaction, signed by that authority, that updates the registry leaf from
  the old charter hash to the new (and recompiles the binding for future
  outputs; already-created outputs keep the guards they were created under —
  guards on existing eUTXOs are immutable by the nature of the model).
- **Auditability.** Whether a token's rules can change, and who can change
  them, is readable from the charter bytes before anyone accepts the first
  unit of the token. Every exercise of the power is a transaction in a block.
  The holder of the power is whoever the issuer named — a power the issuer
  retains for as long as the charter says, visible to everyone, revocable
  only if the charter's own amendment clause permits amending the clause.
  That is the honest shape: promotion does not remove issuer power, it
  forces issuer power to be declared in advance and exercised in public.

**A token whose immutable charter has an error stays broken.** Fail-closed
defects (the unspendable sentinel `compile_governance` emits, an
unsatisfiable custody leg) mean permanently locked outputs. Fail-open defects
mean a permanently under-guarded token. The remedy is social, not
consensual: register a corrected charter (a new `charter_id`, and — because
the asset id is the Supply module's hash — a new asset), and migrate holders
voluntarily. The chain will not rescue a broken charter, for the same reason
it holds no override power: a rescue path *is* an override power. This must
be said in issuer-facing documentation in exactly these words.

## 6. Kirpich fail-closed under PoS: who runs the gate, and what it costs everyone

**Who runs it: everyone, always.** Under U-C the gate is a transaction
validity rule, so it is run by every validator on every proposed block
containing a registration, by every full node on every received block, and
again by every syncing node replaying history. A proposer who includes a
Kirpich-denied registration produces an invalid block and forfeits the slot.
There is no "the issuer's tooling ran the audit" — the issuer's audit is a
convenience; the network's audit is the rule.

**The one-off cost (registration) is small and bounded.** Kirpich is static
analysis plus a double compile; lane D already imposes static ceilings on the
emitted set (KRP-062: `MAX_VALIDATOR_BYTES` / `MAX_TOTAL_BYTES` /
`MAX_VALIDATOR_GAS` / `MAX_TOTAL_GAS` in `kirpich/emitted.rs`), and the
governance emitter refuses compositions past its signer bound
(`compile_governance`, the `m > 253` fail-closed guard). Those ceilings
graduate from audit heuristics to **consensus parameters** under U-C, and a
consensus-side cap on total charter byte length must join them (a
253-signer charter of hybrid PQ keys — ≈3,745 B per key, per the
`ValidatorRecord.pubkey` doc — is on the order of 1 MB of charter). Estimate,
unmeasured: auditing plus double-compiling a ceiling-sized charter is single-
digit milliseconds per node. Across a fleet of *N* full nodes, a spam
registration costs the network roughly *N* × that — node-seconds per attempt
for realistic *N*. That is acceptable **iff the registration fee prices it**;
the DoS lever is mispricing, not the audit itself.

**The perpetual costs dominate, and they are the real "everyone pays":**

1. **State, forever.** Every node stores every registered charter's bytes
   (§4 data availability) for the life of the chain. Bounded per charter by
   the size cap; unbounded in count except by the registration fee. This is
   state rent economics by another name and must be priced as such.
2. **Validation, per transfer.** The binding invariant makes every transfer
   of a bound asset run the full module stack on every full node. The
   measured per-module costs exist in-repo
   (`modules.rs::gas_cost_is_deterministic_and_matches_formula_for_each_module`
   pins exact gas per module under the length-proportional model); the
   dominant real cost is PQ signature verification — order of 0.1 ms per
   hybrid verify (estimate). A worst-case legal governance module (threshold
   at the signer bound) is ~250 hybrid verifies ≈ **tens of milliseconds of
   CPU per spend, per node, network-wide**. One issuer's maximal charter,
   heavily traded, becomes everyone's block-validation budget. Gas must
   price this truthfully — which it cannot until F2 (flat gas) is fixed —
   and the block gas limit, not politeness, is what bounds it.
3. **Rule rigidity.** Today Kirpich can grow a new lane in a patch release.
   Under U-C, the KRP rule set *is* charter validity: adding, removing, or
   tightening a Deny rule changes which charters are legal — **a hard
   fork**, every time. The rule set must therefore be versioned
   (`USTAV-CHARTER-v1` already domain-tags the id preimage; the Kirpich rule
   set must be pinned to that version), frozen per charter-format version,
   and changed only by flag-day. The fail-closed philosophy survives
   promotion; the agility does not. Anyone proposing U-C must accept that a
   *missing* Kirpich rule (a defect class nobody wrote a lane for) is
   permanent for every charter registered before the next fork.

## 7. The Supply module's claim does not survive promotion

`tests/audit_modules_supply.rs` documents that the Supply module "claims to
be the fixed maximum". What the test **actually proves** is the opposite: the
compiled Supply program's cap gate compares `cap` against a
**redeemer-supplied** `requested` value that is bound to nothing. The real
mint delta (`MINT_CTX_DELTA`) and the prior on-chain supply
(`MINT_CTX_PRIOR_SUPPLY`) — both provided by the mint machinery precisely for
this purpose — are never read by the program. The test mints 10⁶× the cap in
one transaction with `requested = 0`, and the mint is authorized. The
contrast test in the same file shows `minting.rs`'s own
`fixed_supply_cap_policy` — which reads prior supply + delta — rejecting the
identical over-cap mint. The defect is the `modules.rs` emitter, not the mint
machinery.

**So: no, the claim does not survive becoming consensus — promoting the
module as-is would make it worse.** Consensus enforcement means every node
faithfully executes a program that does not enforce the thing the charter
promises. The chain would be *certifying* a false cap: a wallet reading
"charter-bound, Supply cap C" from the registry would be reading a statement
the network validates syntactically and violates economically. A consensus
rule that launders a bug into a guarantee is strictly worse than a tool with
a known bug.

Preconditions this forces (see also §8):

- **Rewrite `compile_supply`** on the `fixed_supply_cap_policy` pattern:
  read `MINT_CTX_PRIOR_SUPPLY` and `MINT_CTX_DELTA`, enforce
  `prior + delta ≤ cap` — a **total-supply** cap, which is what "fixed
  maximum" means and what issuers will believe they are getting. The current
  emitter's semantics ("per-single-mint request ceiling") is not a cap even
  when correctly bound.
- **Close the redeemer-padding bypass** proven in `tests/audit_modules.rs`:
  the TransferPolicy freeze is fully defeated by prepending one attacker
  value to the redeemer, because emitted programs use fixed top-relative
  `Pick` offsets and `spend()` imposes no redeemer arity check. Fix in the
  VM (per-program declared arity, enforced in `spend`) or in the compiler
  (bottom-anchored reads); either way, a Kirpich lane-D rule must pin the
  fix. Under U-C this bug would be a *consensus-enforced* bypass of every
  regulated token's freeze — the exact charter-bug-becomes-chain-bug shape
  §3 warns about, already sitting in the tree, already documented.

## 8. Preconditions — hard blockers before any activation parameter exists

In dependency order. None are optional; several are already published as
audit findings.

1. **euvm itself becomes consensus** — Ustav-at-L1 is meaningless while
   `EUVM_ACTIVATION_HEIGHT` is the inert sentinel. The internal audit's
   blockers gate this: **F1** (the block commitment must bind the real
   eUTXO state root, not the 36-byte scalar summary) and **F2**
   (length-proportional gas + memory ceilings). §6's cost model is fiction
   until F2 is real.
2. **`overflow-checks = true` mandated in every consensus build profile**
   (audit cross-cutting finding) — otherwise identical binaries at different
   profiles diverge panic-vs-wrap on charter arithmetic.
3. **Supply emitter rewritten and re-proven** (§7), with the
   `audit_modules_supply.rs` tests inverted into pins of the fix.
4. **Redeemer-arity enforcement** (§7), pinned by a Kirpich rule and a
   regression test on every module kind.
5. **Consensus charter ceilings**: total charter bytes, module count, and
   the KRP-062 budget constants promoted to consensus parameters in one
   authoritative location (imported, never restated — the repo rule).
6. **Kirpich rule-set versioning** pinned to the charter format version
   (§6.3), with a test that the v1 rule set is frozen.
7. **Registry anchoring**: the new `state_root` component tag, the
   `ConsensusState` field, and the snapshot-format extension for charter
   bytes (§4), specced in `BLOCH-WEAK-SUBJECTIVITY.md` and the interfaces
   contract.
8. **Third-party audit** of the promoted surface (compiler + Kirpich +
   binding invariant), per the internal audit's own step 4 — it reviewed
   this code explicitly as *reference*, and its verdict does not transfer to
   consensus use.

## 9. The decision, both sides at full volume

**Gained:** a token charter that is *law for that token* — un-bypassable by
any spender, any wallet, any counterparty; the guard follows the asset. A
freeze that always runs. A KYC gate that cannot be exited by sending to a
bare key. A supply cap (post-§7) that every node enforces against real
minted supply. Amendment powers that must be declared in advance and
exercised in public. For the RWA/regulated-asset products Postern anchors to
this chain, that is the difference between "our tooling checks" and "the
network guarantees" — a category difference, and the only version of Ustav
an exchange, custodian, or regulator can rely on without trusting Postern.

**Bought with:** the charter compiler and audit gate become fork-critical
consensus code (~7k lines promoted from reference); every Deny-rule change
becomes a hard fork; every node stores every charter forever and executes
every bound token's full module stack on every transfer, priced only as well
as the gas model is honest; an issuer's declared-immutable mistake is
permanent and the chain constitutionally will not fix it; and two
already-proven charter bugs (§7) show exactly what gets consecrated if
promotion outruns remediation. The consensus surface grows by precisely the
amount of code that today is allowed to be wrong.

Recommendation: **U-C, sequenced strictly behind §8** — and if the founder
wants an anchor on-chain sooner, ship U-B *explicitly labeled as
registry-only* first, because U-B is reversible and U-C is not.

## 10. Interaction with EVM-at-L1 (same wave)

This entire spec assumes the eUTXO VM survives as the L1 token layer: Ustav
compiles to eUTXO validators, the binding invariant is stated over eUTXO
outputs, and the registry pattern leans on the euvm SMT. The parallel
EVM-at-L1 workstream is deciding whether `bloch-euvm` "survives, is
absorbed, or dies." If it dies, Ustav-at-L1 as specced here dies with it and
must be re-targeted at whatever account-model token representation replaces
it — where the binding invariant becomes a very different (and harder)
statement about contract storage. **Do not schedule §8 work until that
decision lands.** If both land, the two specs must be merged by one owner;
the binding invariant and the EVM's token surface cannot be defined twice.

## 11. What I did NOT do

- **No code.** No compiler changes, no Kirpich changes, no `state_root`
  tag, no `ConsensusState` field, no transaction types. This is a spec.
- **No fixes for the two proven defects** (§7) — they are stated as
  preconditions with owners-to-be-assigned, not fixed here.
- **No measurements.** The millisecond figures in §6 are labeled estimates;
  the per-hybrid-verify cost and the audit-of-a-ceiling-charter cost were
  not benchmarked on this machine or any fleet box. The gas figures I cite
  are the repo's own pinned test values, referenced, not re-derived.
- **No canonical charter serialization.** U-C requires one (the bytes that
  enter the registration tx and hash into the registry); `modules.rs` has a
  charter-id *preimage* but no full canonical byte encoding of a
  `TokenCharter`. Defining it is normative follow-up work.
- **No fee/pricing schedule** for registration or state rent (§6) — that
  belongs with the V4 fee model owner, against `tokenomics_v4.rs`, and I did
  not restate or invent numbers.
- **No ruling on the EVM interaction** (§10) — flagged, not resolved.
