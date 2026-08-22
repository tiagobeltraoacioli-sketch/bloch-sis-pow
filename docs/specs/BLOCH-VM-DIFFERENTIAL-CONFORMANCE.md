<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch VM Differential Conformance — front specification (harnesses + reporting)

```
Document:   BLOCH-VM-DIFFERENTIAL-CONFORMANCE
Status:     SPEC — approved scope for the conformance front; harness code
            does not exist yet, and TODAY neither execution target exists
            either (see §1 — this is stated, not hidden)
Created:    2026-08-22
Owner:      Conformance front lead
Decision:   NONE at consensus level. Every artifact this front produces is
            dev tooling in standalone workspaces (the euvm-tooling posture,
            euvm-tooling/Cargo.toml:3-16). Nothing here is reachable from
            the node's state-transition path, ever — a conformance harness
            that can be linked into bloch-pos-node has already failed.
Relates:    crates/bloch-euvm            (what it is and is NOT — §1.1),
            docs/specs/BLOCH-SBPF-CORE.md            (Front 1, no code yet),
            docs/specs/BLOCH-SVM-ACCOUNTS-SCHEDULER.md (Front 2, no code yet),
            docs/specs/BLOCH-L1-EXECUTION-PLAN.md    (E2 = the real EVM target),
            docs/specs/BLOCH-L1-EVM-REUSE-AUDIT.md:73 (revm =41.0.0, CANCUN),
            docs/adr/ADR-040-evm-and-ustav-at-l1.md
```

## 0. The one correction this spec must make before it can be useful

The front was chartered as: *(a) run `bloch-euvm` against official Ethereum
test vectors; (b) run the sBPF core against Solana reference vectors.*

**(a) contains a category error and this spec refuses to paper over it.**
`bloch-euvm` is not an EVM. It is a deterministic eUTXO *validator* stack
machine with its own opcode set, `i128` checked arithmetic and a
`BTreeMap` multi-asset value model (crates/bloch-euvm/src/lib.rs:1-24;
Cargo.toml header: "Minimal deterministic eUTXO validator VM"). The "e" is
*extended-UTXO*, not Ethereum. `ethereum/tests` (GeneralStateTests /
VMTests) exercises the Ethereum VM ISA, the account/trie state model and
the Ethereum gas schedule — none of which `bloch-euvm` implements or claims
to implement. Running those vectors against it would yield 0% — not
because `bloch-euvm` is wrong, but because the vectors do not apply.
Reporting that 0% as a conformance number, or hand-translating a few
vectors into euvm programs and calling the result "Ethereum conformance",
would be testing the implementation against itself with extra steps. We do
neither.

What follows from the correction:

- **`bloch-euvm` has no external reference implementation.** It is its own
  reference. "Differential conformance" is undefined for it; its assurance
  story is (and remains) its 331 in-repo tests, the negative/control
  discipline, golden vectors, and mutation-proofing (§4).
- **The EVM that CAN be conformance-tested is E2's `crates/bloch-l1-evm`**
  (BLOCH-L1-EXECUTION-PLAN §2): a revm `=41.0.0` / `SpecId::CANCUN` harness
  copied from `bloch-l2-evm` (BLOCH-L1-EVM-REUSE-AUDIT.md:73). That crate
  does not exist in this repo yet. When it does, `ethereum/tests` applies
  to it directly and §2 below is the harness that runs it — specified now
  so it executes on E2's first green build, not months later.
- **The sBPF side is honest already**: BLOCH-SBPF-CORE.md says "no code
  exists yet" in its own header. §3 specifies the harness against the day
  Front 1's M2 lands.

**Consequence for today's deliverable:** this front can ship harness
*specifications*, vector *provenance* (pinned upstream commits, obtainable
— verified reachable 2026-08-22), applicability *filters as data*, and the
mandatory *report format*. It cannot ship a single executed conformance
number, because neither execution target exists. A number reported before
its target exists would be fabricated. The `nao_feito` list at the end of
this document is therefore long, on purpose.

---

## 1. Targets and non-targets, measured

| Candidate target | Exists today? | External reference? | Conformance verdict |
|---|---|---|---|
| `crates/bloch-euvm` (22 files, 12,574 lines, 331 tests) | YES — standalone, not referenced by bloch-pos-node/committee | **NO** — own ISA, own state model | Differential conformance **NOT APPLICABLE**. Assurance = §4 (mutation + golden vectors + crypto-callback KATs). |
| `crates/bloch-l1-evm` (E2) | **NO** | YES — `ethereum/tests` + every mainline client | §2 harness, blocked on E2. |
| `crates/bloch-sbpf` (Front 1) | **NO** | YES — anza-xyz/sbpf (the Agave VM), firedancer-io/test-vectors | §3 harness, blocked on Front 1 M1/M2. |
| SVM accounts/scheduler (Front 2) | NO (spec only) | Partial — firedancer syscall/txn fixtures | Out of scope until Front 2 has code AND Front 1's harness is green. |

Upstream vector sources, probed 2026-08-22 (all HTTP 200, so "could not
obtain" is not available as an excuse):

- `github.com/ethereum/tests` — GeneralStateTests, MIT-licensed JSON
  fixtures, multi-GB. Consumed by fork filter (Cancun only), never
  wholesale.
- `github.com/anza-xyz/sbpf` — the canonical Solana VM (successor of
  solana_rbpf); its own test suite doubles as executable semantics.
- `github.com/firedancer-io/test-vectors` — ~4.7 GB repo, actively pushed
  (2026-08-18); the `vm_interp` protobuf fixtures are the closest thing to
  official sBPF interpreter vectors, being what Firedancer↔Agave use to
  check *each other*.

**Vendoring rule (all three):** vectors are pinned by upstream commit hash
+ per-file SHA-256 manifest committed in-repo, fetched by a script into a
gitignored `vectors/` dir, verified against the manifest before any run.
Multi-GB blobs are never committed; a run without a verified manifest must
refuse to report (an unpinned corpus can drift and silently change the
pass rate). Upstream licenses (MIT / Apache-2.0) are recorded in the
manifest and re-verified at every pin bump; vectors are test inputs, not
linked code, so the AGPL boundary question only arises for the
solana-sbpf *dev-dependency*, which §3 confines to a standalone workspace.

---

## 2. Harness A — `ethereum/tests` against `crates/bloch-l1-evm` (blocked on E2)

**Crate:** `conformance/evm-statetest/` — own `[workspace]` table, exactly
the euvm-tooling isolation idiom (euvm-tooling/Cargo.toml:15-16), path-dep
on `crates/bloch-l1-evm` only. Never a member of the node workspace.

**What it proves — and the subtlety that makes it worth building at all:**
revm itself is conformance-tested upstream (`revme statetest` runs these
same fixtures). The exposure is NOT revm; it is the ~856-line Bloch harness
*around* revm that E2 copies from `bloch-l2-evm/src/executor.rs` and then
edits — deposit-loop deletion, V4 fee routing replacing "never burn",
gas accounting, EIP-1559 effective price, state-root fill
(BLOCH-L1-EVM-REUSE-AUDIT.md:82). Every one of those edits is a chance to
break Ethereum semantics while revm underneath stays perfect. The harness
therefore drives vectors through **E2's public `execute(parent_state,
ordered_txs)` boundary** (BLOCH-L1-EXECUTION-PLAN, E2 "Pure interface"),
never through revm directly — going straight to revm would test upstream's
work and skip ours.

Mechanics:

1. Parse GeneralStateTests JSON; select the **Cancun** post-state block
   only (revm pin is `SpecId::CANCUN`, BLOCH-L1-EVM-REUSE-AUDIT.md:73).
2. Load pre-state into E2's state type; build the tx from
   `transaction` + indexed `data`/`gasLimit`/`value`; execute.
3. Compare: post-state root, logs hash, and tx success/revert against the
   fixture's expectation. Any mismatch = FAIL, named by fixture id.
4. **Applicability filter, as data** (`filters/evm.toml`, one entry per
   exclusion, each with a reason code):
   - `EXCL-BLOB`: fixtures requiring type-3 blob transactions — E2 rejects
     blobs by design (reuse audit §executor phase 2); these run as
     *expected-reject* cases, not skips: the harness asserts the rejection.
   - `EXCL-FORK`: pre-Cancun-only and post-Cancun fixtures.
   - `EXCL-AUTH`: fixtures whose semantics depend on the sender-recovery
     path if D-AUTH lands PQ-only (ADR-040 open question). Until D-AUTH,
     the harness injects the sender through E2's `TxAuthorizer` seam
     (BLOCH-L1-EXECUTION-PLAN §1) — which conveniently means conformance
     does NOT wait on the founder's authorization decision.
   - Note the intended-divergence trap: E2 replaces basefee routing with
     the V4 burn/validator split. If that edit changes *in-EVM observable*
     state (miner balance, BASEFEE opcode results), affected fixtures fail
     honestly and land in the report as `DIVERGENT-BY-DESIGN` with the ADR
     citation — a named category, never silently filtered, because each
     one is a place Bloch-EVM contracts behave unlike Ethereum contracts
     and users must be able to read that list.
5. Report per §5.

**Mutation gate for the harness itself (repo rule 3):** before the first
real run is believed, flip one storage write in a scratch copy of E2 and
one gas constant; the harness must go red on both. A differ that stays
green under a mutated engine is comparing nothing.

## 3. Harness B — Solana vectors against `crates/bloch-sbpf` (blocked on Front 1)

**Crate:** `conformance/sbpf-diff/` — own `[workspace]`; path-dep on
`crates/bloch-sbpf`; `solana-sbpf` (pinned `=x.y.z`, chosen at first
implementation against whatever Front 1's ISA subset tracked) as a
dependency **of the harness only** — the standalone workspace exists
precisely so no Solana code can ever enter the node dependency graph.

Two oracles, because they fail differently:

**B1 — differential execution against `solana-sbpf`.** Generate programs
in the BSC-0-representable subset (BLOCH-SBPF-CORE §whitelist: no `callx`,
no ELF dynamic relocations, minimal syscall table) from three sources:
Front 1's own fixtures, the anza test-suite programs that survive the
subset filter, and a structured fuzzer (M3's macro-assembler). Run each in
both VMs and compare **semantic outcome only**: r0, fault class, and the
written memory regions.

> **The CU trap, stated so nobody falls in it:** compute-unit counts are
> deliberately NOT compared. BLOCH-SBPF-CORE pins its own cost table with
> its own golden vectors (BLOCH-SBPF-CORE.md:304,394 — D2); Solana's cost
> model is calibrated to Solana. A naive differ would report ~100% CU
> "failures" that mean nothing and bury the real semantic divergences.
> `cu_used` is compared only against Bloch's OWN pinned vectors, never
> across VMs. Same for fault-*at*-PC when budgets differ: fault class
> compares, faulting position compares only under equalized budgets.

**B2 — firedancer `vm_interp` fixtures.** Sparse-checkout only the
`vm_interp` subtree (the repo is 4.7 GB; the manifest pins the commit).
Decode the protobuf fixtures; classify each against the v0 subset filter
(`filters/sbpf.toml`): fixtures using forbidden opcodes (`callx` →
BLOCH-SBPF-CORE V4 rejects it *by design*), unsupported SBPF versions,
loader/ELF features, or syscalls outside the minimal table are EXCLUDED
with named reason codes. The rest execute and compare result/fault.

**Expectation, written down in advance so the first report surprises
no one:** the applicable fraction of B2 will be SMALL in v0 — the subset
is deliberately narrow, and BLOCH-SBPF-CORE §0 forbids any "Solana
compatible" sentence until the §9 gate passes. A report of "62% of
vectors excluded as out-of-subset, 100% of applicable passed" is a
*good* v0 report; a report of "100% pass" with no exclusion list is a
lie by omission and §5 makes it unshippable.

## 4. `bloch-euvm` — what this front does for the VM with no reference

No conformance theater. Three real things:

1. **Mutation-proof the existing 331** (repo rule 3, and the reason it
   exists: two reverted consensus sites recently survived a 489-test
   suite). Script: for each opcode-semantics site and each gas-charge site
   in src/lib.rs / batcher.rs / minting.rs, apply one mutation (off-by-one
   the gas cost, swap a comparison, drop a `checked_`), run the suite,
   record survivors. **Every surviving mutant is a filed gap with a named
   missing test** — the deliverable is the survivor list, not a green run.
2. **Host-callback KATs:** the VM's crypto surface (SHA-256, SHAKE-256 —
   src/lib.rs:28-30) verified against NIST CAVP vectors in the euvm-tooling
   workspace. Small, closes the "right primitive, wrong parameters" hole;
   explicitly NOT sold as VM conformance.
3. **Golden-outcome pinning** on the harness/batcher boundary if audit
   review finds outcomes not already pinned (the audit_* suites largely do
   this; verify, don't duplicate).

## 5. The report format — mandatory, or the number is void

One schema for every harness, `docs/conformance/REPORT-<target>-<date>.md`:

```
target:        crate + exact commit of the VM under test
corpus:        upstream repo + pinned commit + manifest SHA-256
total:         N vectors in corpus slice
applicable:    A (= total − excluded)
passed:        P
failed:        F  — EVERY failure listed: fixture id + one-line divergence
divergent-by-design: D — listed, each with the ADR/spec citation
excluded:      E  — grouped by reason code, each code defined in filters/*.toml
rate:          P/A, stated as "P of A applicable", NEVER as a bare percent
harness-mutation-gate: the two mutations run + confirmation both went red
```

Rules with no exceptions: a rate without the named failing list is not a
report; an exclusion without a reason code in the filter file is a FAIL;
`DIVERGENT-BY-DESIGN` requires a citation or it is a FAIL. 70% with the
30% named beats an unnumbered "passes".

## 6. Order of work and what blocks what

- **C0 (this spec)** — no dependencies. The only deliverable that exists.
- **C1** — vector provenance: pin commits, write fetch+verify scripts and
  SHA-256 manifests, land `filters/*.toml` skeletons. No dependencies;
  can land now. No VM required.
- **C2** — Harness A skeleton compiling against a mock `execute()` shaped
  like E2's pure interface; goes live the day `crates/bloch-l1-evm` has a
  green build. **Blocked on E2 (DEV-4).**
- **C3** — Harness B; B1 blocked on Front 1 M2 (interpreter), B2
  additionally on M3 (fixtures/assembler). **Blocked on Front 1.**
- **C4** — euvm mutation campaign + CAVP KATs (§4). Depends on nothing;
  can start now; produces the survivor list, not code in bloch-euvm.
- **NOT scheduled:** anything consensus-visible; SVM scheduler
  conformance (needs Front 2 + B-green); JIT differential testing (no
  JIT exists and BLOCH-SBPF-CORE forbids one).

## 7. `nao_feito` — the current, complete list

- No conformance number exists for anything, and none is claimable: both
  execution targets (`bloch-l1-evm`, `bloch-sbpf`) have zero code.
- No vectors are vendored yet (C1 not started; only reachability was
  verified, 2026-08-22).
- The charter's item (a) — "bloch-euvm against Ethereum vectors" — is
  answered NOT APPLICABLE (§0), not delivered.
- The euvm mutation survivor list (C4) has not been run.
- `solana-sbpf` version pin and the exact `vm_interp` protobuf schema
  handling are unchosen — both are C3-time decisions against Front 1's
  actual ISA subset, not now.
