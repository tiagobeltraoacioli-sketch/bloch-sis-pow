# Mutation campaign — measured results, 2026-08-22

Runner: `../run_mutation_campaign.py` (mutates a scratch COPY; the repo tree is
never touched). Raw rows: `2026-08-22-euvm-331.tsv`, `2026-08-22-harness-gate.tsv`.

## Target `euvm` — detector = bloch-euvm's own 331 tests

Baseline: **331 passed, 0 failed, 4 ignored** (doc-tests) at 751afdae.

**15 of 16 mutants killed. One SURVIVOR, named below** — the point of the
exercise (repo discipline rule 3), not a footnote.

### SURVIVOR — M13-shake-truncated-read

```
crates/bloch-euvm/src/lib.rs:424-431   Op::Shake256
-   r.read(&mut out);          // 32 XOF bytes
+   r.read(&mut out[..31]);    // 31 bytes; out[31] stays 0x00
```
Result: **0 of 331 tests failed.** The whole suite is green with the VM's
SHAKE-256 opcode silently zeroing the last byte of every digest it produces.

Why the gap exists, measured rather than guessed: `Op::Shake256` is **never
executed by any test in the crate**. Every reference to it outside the
interpreter is textual or about gas —
- `src/state.rs:939` asserts only `SHAKE256_GAS == gas_cost(&Op::Shake256)` (a
  constant, not an execution),
- `src/state.rs:81-95` reimplements SHAKE hashing *privately* for the sparse
  Merkle tree, so `state`'s many tests exercise `sha3::Shake256` the crate but
  never the opcode's plumbing,
- `tests/audit_panics.rs:75` mentions it only in a comment.
The validator programs the tests do build (P2PKH, hash-lock, KYC gates) hash
with `Op::Sha256d`. So the opcode's *semantics* had no test at all; only its
*price* did. That is exactly the shape of a decorative-coverage hole: 331 green
tests, one opcode whose output nobody checks.

Closed by this front: `conformance/euvm-conformance` now runs 378 NIST CAVP
SHAKE256 vectors through `run()`. The same mutant as **H01** kills that suite
(see below) — 378 failures instead of 0.

Remaining, NOT closed (see the front's `nao_feito`): a truncated read is caught
now, but the opcode still has no test pinning its behaviour under
`MAX_OPERAND_BYTES`-scale operands, and `state.rs`'s private SHAKE helper is
still a second implementation of the same primitive that could drift from the
opcode without any test noticing (their gas constants are pinned to each other;
their *outputs* are not).

### Killed (15)

| id | site | mutation | killed by |
|---|---|---|---|
| M01-sha256d-single | lib.rs:421 | `Sha256d` hashes once, not twice | 3 (`p2pkh_validator`, `hashlock_validator`, `kyc_membership_against_root`) |
| M02-gas-free | lib.rs:361 | every op charged 0 gas | 12 |
| M03-expectdepth-relax | lib.rs:380 | `ExpectDepth` accepts deeper stacks | 1 (`transfer_policy_freeze_is_bypassed_by_padding_the_redeemer` — the exact regression the op was added for) |
| M04-verify-noop | lib.rs:455-460 | `Op::Verify` never aborts | 9 |
| M05-verifysig-accept | lib.rs:465 | every signature accepted | 12 |
| M06-spend-hash-unchecked | lib.rs:567 | revealed program need not match `validator_hash` | 2 |
| M07-conservation-allows-loss | lib.rs:724 | conservation rejects inflation only, allows destruction | 4 |
| M08-fee-burn-swap | lib.rs:769 | `fee_burn` returns the split swapped | 2 |
| M09-lt-off-by-one | lib.rs:412 | `Op::Lt` becomes `<=` | 16 |
| M10-minting-negative-supply | minting.rs:235 | burn may drive supply below zero | 2 |
| M11-stateproof-sibling-swap | state.rs:299 | Merkle siblings folded mirrored | 17 |
| M12-amm-fee-removed | batcher.rs:165 | `amm_out` ignores the LP fee | 2 |
| M14-eq-always-true | lib.rs:407 | `Op::Eq` always answers 1 | 6 |
| M15-gas-hash-flat | lib.rs:251 | hash ops lose the byte-proportional gas term | 3 (incl. `gas_is_decoupled_from_hashed_bytes_cpu_dos`) |
| M16-kirpich-never-denies | kirpich.rs:158 | the fail-closed audit gate never denies | 4 |

Two kills worth calling out because they show the suite pinning a *rule*, not a
value: M03 dies in exactly one test, the padded-redeemer bypass documented at
`lib.rs:119-134` — the regression that motivated `ExpectDepth` is genuinely
pinned. M15 dies in `gas_is_decoupled_from_hashed_bytes_cpu_dos`, the F2 CPU-DoS
bound described at `lib.rs:200-207`.

## Target `harness` — detector = this front's CAVP KAT suite

The §4 gate of `docs/specs/BLOCH-VM-DIFFERENTIAL-CONFORMANCE.md`: a differ that
stays green under a mutated engine compares nothing. H01-H03 mutate the ENGINE
(the KATs must go red); H04-H06 mutate the HARNESS's own parser/controls (its
self-assertions must go red). H07 is a PREDICTED survivor, included on purpose so
the report shows a survivor being analysed instead of hidden.

**Final: 7 of 7 killed** (`2026-08-22-harness-gate.tsv`). The first run was
**6 of 7**, and both the survivor and how it was closed are recorded below,
because a gate that only ever shows 7/7 proves nothing about the gate.

| id | mutates | effect | KAT tests that died |
|---|---|---|---|
| H01-engine-shake-truncated | lib.rs:424 | `Op::Shake256` reads 31 XOF bytes | **3** — `shake256_opcode_matches_nist_for_all_applicable_vectors`, `len_zero_vector_is_the_empty_message`, `kats_run_metered_and_within_budget` |
| H02-engine-sha256d-single | lib.rs:421 | `Sha256d` hashes once | 1 |
| H03-engine-eq-always-true | lib.rs:407 | `Op::Eq` is a tautology | 2 — both suites' CONTROL halves |
| H04-parser-no-len0-truncate | harness | the `Len = 0` / `Msg = 00` trap | 3 |
| H05-parser-drops-rows | harness | corpus silently halved | 5 |
| H06-control-not-corrupted | harness | `corrupt()` becomes identity | 2 — the control of the controls |
| H07-harness-swallow-vmerror | harness | `VmError` folded into `false` | 1 (after the fix; **SURVIVED the first run**) |

**H01 is the whole point of this front.** The identical mutation is `M13`, the
one survivor of bloch-euvm's own 331 tests. The same broken opcode that 331
tests call green, 378 NIST vectors call red. That is the difference between a
suite that covers code and a suite that checks answers.

**H03 is the gate on the gate.** If `Op::Eq` always answered 1, every positive
KAT would be a tautology and a green run would mean nothing. It dies in both
suites — via the CONTROL halves, not the positive ones, which is the correct
signature.

### H07 — the survivor, and why it was closed rather than just reported

First run: mutating the harness so a `VmError` returns `false` instead of
panicking killed **0 tests**. The mutant was predicted to survive and it did: on
the green path the VM never errors, so nothing observed the difference. The
consequence it would allow is not cosmetic — a harness misconfiguration (wrong
gas budget, wrong operand type) would have been reported as *failing vectors*,
i.e. a fabricated conformance number pointing at the engine instead of at the
harness.

Closed two ways, both required:
1. `tests/cavp_shake256.rs::harness_surfaces_vm_errors_instead_of_reporting_them_as_mismatches`
   drives a real `VmError::TypeError` through the public helper and asserts the
   panic (`#[should_panic]`), with a direct `run()` call as its control half
   proving the seed genuinely errors.
2. The error-handling arm was **de-duplicated into `unwrap_kat()`**. It had been
   copy-pasted into two helpers; a rule with two copies is a rule where mutating
   one copy leaves the other intact, and the campaign's exactly-once check would
   have refused to run at all. One rule, one site, one mutant.

Second run: 7/7.

### A blind spot found in this runner itself

H07's first *killed* row still read `n_failed=0`. The kill verdict was right (it
comes from the exit code) but the evidence column was empty, because libtest
prints `test <name> - should panic ... FAILED` and the runner's regex only
matched `test <name> ... FAILED`. A mutation report whose evidence column can go
silently blank is the same class of defect it is meant to catch, so the regex was
fixed (`run_mutation_campaign.py::failing_tests`) and the table regenerated.
bloch-euvm has no `#[should_panic]` tests, so the `euvm` TSV was unaffected.

## What this campaign does NOT establish

- **16 mutants is not a mutation score.** These are hand-picked at sites where a
  regression would be consequential; they are not an exhaustive or uniformly
  sampled mutant set, so "15/16" is emphatically not "94% mutation coverage".
  A real score needs a tool (`cargo-mutants`) generating every mutant it can.
- Untouched by this campaign: `harness.rs`, `modules.rs`, and the four `kirpich/`
  lanes have exactly ONE mutant between them (M16), despite being ~4,000 lines.
  Their tests may be as decorative as `Op::Shake256`'s were, and nothing here
  says otherwise.
- A killed mutant proves *a* test noticed, not that the test suite pins the rule
  *correctly*. M09 (`Lt` -> `Le`) dying in 16 tests is evidence of coupling, not
  of a boundary being deliberately specified.
