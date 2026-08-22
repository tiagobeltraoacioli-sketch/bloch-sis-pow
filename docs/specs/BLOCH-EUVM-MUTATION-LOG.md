# BLOCH-EUVM-MUTATION-LOG — proving the tests catch what they claim to

Companion to `BLOCH-EUVM-GAP-MAP.md`. Scope: `crates/bloch-euvm/` only.

A green suite is not evidence. This repository learned that the hard way: a review
found that reverting **two consensus sites** survived a 489-test suite. So every rule
this crate's tests claim to enforce was **disabled at its source**, and the whole
suite re-run against the broken code. A mutant that survives marks a rule nothing
actually tests.

**Method.** One mutation at a time, applied to the real source, whole suite run,
source restored. Harness: `mut/run.py` (not committed — it is scaffolding, and the
mutations themselves are reproduced verbatim below so anyone can redo this by hand).

Three rounds were run. Round 1: 19 mutants against the pre-existing rules and the code
added in this pass. Round 2: 6 mutants re-testing the one survivor and its blast
radius, after new tests were written to kill it. Round 3: a **null control** plus
re-verification of the thinnest results, after a second harness defect was found.

---

## The method's own failure, reported first

The **first** round-1 run used a plain `cargo test`, which **fail-fasts after the
first failing test target**. Unit tests in `src/` run before integration tests in
`tests/`, so as soon as a `src/state.rs` unit test failed, cargo never ran
`tests/euvm_pinned_roots.rs` at all — and the killer lists were silently truncated.
Every mutant still showed as KILLED, so nothing looked wrong; the *attribution* was
wrong, and attribution is the entire point of the exercise. Without it there was no
way to tell whether the new pinned tests were load-bearing or decorative.

Re-run with `--no-fail-fast`. Every number below comes from that run.

The general form of the mistake is worth keeping: **a mutation harness that does not
run the complete suite measures the tests it happens to reach, not the suite.**

### Defect 2 — mtime-preserving restore left a stale mutant binary

The harness restored each file with `shutil.move(path + ".bak", path)`. Within one
filesystem that is a rename, and a rename **preserves the backup's original mtime**.
So after a run the source on disk was correct but *older* than the artifact cargo had
just built from the mutant — cargo therefore considered the mutant build current and
**did not rebuild**. This was caught in the act: two byte-pinned `validator_hash`
tests failed against a `lib.rs` that `git diff` showed as clean, because the test
binary had been linked against a mutated `encode_program`.

Within the harness this did **not** corrupt the results: each mutation is applied by
writing the file, which stamps a fresh mtime, so every mutant genuinely compiled. The
damage was to whatever ran *after* the harness — including, briefly, this pass's own
test runs. Fixed by rewriting the original bytes and calling `os.utime(path, None)`
rather than moving the backup back.

Both defects share a shape worth naming: **the harness was trusted to be correct
while it was the instrument measuring correctness.** Round 3 therefore begins with a
null control (below) instead of assuming.

---

## FIRST-ORDER FINDING — a surviving mutant: opcode-encoding drift

**M15. `Op::Dup`'s encoding tag `0x10` → `0x1a` in `encode_program` (lib.rs).
SURVIVED all 352 tests. Zero failures.**

Why that matters: `validator_hash(p) = SHA-256d(encode_program(p))` is the identity
an `ExtOutput.validator_hash` commits to, and `CompiledToken::policy_id` turns one
into a **native asset id**. Changing an encoding tag silently:

- re-addresses every eUTXO guarded by a program containing that op — funds become
  unspendable by the program that was supposed to guard them, or spendable by another;
- renames every token whose `policy_id` derives from an affected Supply module.

This is exactly the class of change a byte-pinned test exists to stop, and it walked
through the entire suite untouched.

**Root cause, measured.** `modules::compile_charter` only ever emits **14 of the 26**
encoding tags. It never emits `Dup`, `Drop`, `Sub`, `Mul`, `Shake256`, `Size`,
`TxOutDatum`, `TxOutValidator`, `TxOutValue`, `SelfValidator`, `SelfAsset`, or
`TxOutAsset`. Pinning six compiled charter hashes — which looked like solid identity
coverage, and was the coverage this pass itself added in
`compiled_charter_hashes_are_pinned` — therefore pinned only the tags the charter
happens to use. **Twelve tags had no protection at all**, in the original 331-test
suite and in the improved one.

**Fixed in the same pass.** `tests/euvm_pinned_roots.rs` gained four tests: the
byte-for-byte encoding of a program containing *every* `Op` variant, that program's
`validator_hash`, each tag pinned individually (so a failure names the culprit op),
and an exhaustive `match` that **fails to compile** when a new `Op` is added — so the
coverage cannot silently stop being exhaustive the way it did here.

Round 2 confirms the fix on M15 and five neighbouring identity mutations (below).

---

## Secondary finding — identity drift was entirely unprotected before this pass

Three round-1 mutants change a committed identity while keeping the code perfectly
self-consistent, so no internal-consistency test can see them:

| mutant | killed by |
|---|---|
| **M13** SMT `LEAF_TAG` `0x00` → `0x03` | 5 tests — **all new** (`*_root_is_pinned`) |
| **M14** SMT `KEY_TAG` `0x02` → `0x05` | 6 tests — **all new** |
| **M16** charter domain `USTAV-CHARTER-v1` → `v2` | 1 test — **new** (`compiled_charter_hashes_are_pinned`) |

Every killer is a test added in this pass. **The pre-existing 331-test suite would
not have caught any of them**: it verified that the SMT was consistent with itself,
never that it produced the *agreed* bytes. Since these roots ride in the harness's
`"EUV1"` committed block section, that was a real hole, and it is the reason the KATs
were written before the refactor rather than after.

---

## Round 1 — full results (19 mutants, `--no-fail-fast`)

### Pre-existing rules

| # | mutation | rule disabled | result | killers |
|---|---|---|---|---|
| M1 | `run`: `op_gas(op,&st)` → `gas_cost(op)` | F2 byte-proportional gas | KILLED | 4 |
| M2 | `Op::ExpectDepth` → no-op | stack-arity assertion | KILLED | 1 |
| M3 | `spend`: drop `ValidatorHashMismatch` | program↔output binding | KILLED | 2 |
| M4 | `minting`: `if false && in_plus_mint != out_plus_fee` | per-asset conservation | KILLED | 7 |
| M5 | `batcher`: remove canonical `sort_by` | submission-order independence | KILLED | 5 |
| M13 | `LEAF_TAG` `0x00`→`0x03` | SMT leaf domain separation | KILLED | 5 |
| M14 | `KEY_TAG` `0x02`→`0x05` | SMT key domain separation | KILLED | 6 |
| M15 | `Op::Dup` tag `0x10`→`0x1a` | program encoding identity | **SURVIVED** | **0** |
| M16 | charter tag `v1`→`v2` | charter-id domain separation | KILLED | 1 |

M2 is killed by exactly one test — `transfer_policy_freeze_is_bypassed_by_padding_the_redeemer`,
the regression test written for the original attack. Thin, but pointed at precisely
the right thing. M16 likewise has a single killer, and it is a byte pin.

### Code added in this pass

| # | mutation | rule disabled | result | killers |
|---|---|---|---|---|
| M6 | `gate_allows_bound`: drop the `proof.key` check | identity binding (reverts to the bypass) | KILLED | 3 |
| M7 | `invalidate_path`: `0..TREE_DEPTH` → `0..1` | full path invalidation (255 stale memos) | KILLED | 11 |
| M8 | `recompute_root` only when `root_hash.is_none()` | eager root maintenance | KILLED | 23 |
| M9 | `prefix_at`: drop the partial-byte mask | node-cache key uniqueness | KILLED | 8 |
| M10 | `spine_hash`: swap left/right children | child ordering in the spine fold | KILLED | 30 |
| M11 | `prove`: emit the on-path child as sibling | off-path sibling selection | KILLED | 28 |
| M12 | `remove`: skip `invalidate_path` | invalidation on deletion | KILLED | 1 |
| M17 | `compress`: also require `d % 2 == 0` | lossless compression | KILLED | 3 |
| M18 | `expand`: drop the popcount check | witness/bitmap consistency | KILLED | 1 |
| M19 | `compress`: compare against `empty[d]` | correct ladder level | KILLED | 2 |

**M12 is the thinnest survivor-adjacent result in the set**: a `remove` that forgets
to invalidate the cache — leaving a deleted key still committed in the root — is
caught by exactly **one** test (`state::tests::registry_add_update_new_root`, which
happens to remove a key and compare roots). That single test is load-bearing for a
whole class of stale-cache bug. It is recorded here rather than papered over; adding
a dedicated removal/root test is worth doing and is **not** done (see the gap map's
open list).

M18's single killer is the test written for it in the same pass, which is the
expected shape for a fresh guard, not a gap.

---

## Round 2 — the fix, verified (6 mutants)

Re-run after adding the exhaustive opcode pins. All six kill.

| # | mutation | result | killers |
|---|---|---|---|
| M15 | `Op::Dup` tag `0x10`→`0x1a` (the round-1 survivor) | **KILLED** | 3 |
| M20 | `Op::SelfAsset` tag `0x74`→`0x7a` | KILLED | 3 |
| M21 | `Op::TxOutValue` tag `0x72`→`0x7b` | KILLED | 3 |
| M22 | `PushBytes` length prefix LE→BE (operand, not tag) | KILLED | 3 |
| M23 | `Op::Drop` tag → `0x10`, colliding with `Dup` | KILLED | 3 |
| M24 | `validator_hash`: SHA-256d → single SHA-256 | KILLED | 2 |

M20/M21 confirm the fix generalizes to other previously-unreachable tags, not just
the one that was caught. M23 confirms tag **injectivity** is checked, not merely each
tag's value. M22 confirms operand encoding is pinned, not only op tags.

---

## Round 3 — controlling the instrument (4 mutants)

Run after the mtime fix. The first entry is the control the earlier rounds lacked.

| # | mutation | expected | result | killers |
|---|---|---|---|---|
| **C0** | **null control**: rename a local (`popcount` → `bits_set` + alias). No behaviour change whatsoever. | **must SURVIVE** | **SURVIVED** | **0** |
| M2 | `Op::ExpectDepth` → no-op (re-verify) | killed | KILLED | 1 |
| M12 | `remove` skips `invalidate_path` (re-verify) | killed | KILLED | **3** (was 1) |
| M6 | `gate_allows_bound` drops the identity check (re-verify) | killed | KILLED | 3 |

**C0 surviving is the result that makes the other 25 mean something.** A harness that
reported KILLED for a pure rename would be measuring build noise, and every kill in
this document would be void. It does not.

M12 rose from 1 killer to 3 because the thin coverage it exposed was closed in the
same pass: `tests/euvm_pinned_roots.rs` gained
`incremental_root_equals_a_fresh_rebuild_after_every_mutation` (the incremental root
must equal a cache-free rebuild after *every* mutation, including deletions and a
drain to empty) and `cache_history_does_not_leak_into_the_root`. Both are aimed
directly at stale-cache bugs rather than tripping over them incidentally.

M2 remains a single-killer result. Its one killer,
`transfer_policy_freeze_is_bypassed_by_padding_the_redeemer`, is the regression test
written for the original redeemer-padding attack and points at exactly the right
behaviour — but a single test guarding a stack-arity rule that is baked into
`validator_hash` is thin, and it is **left thin**: broadening it means new
`ExpectDepth` fixtures across the module compiler, which is a larger change than this
pass should make. Recorded as known-thin, not fixed.

---

## Standing summary

- **29 mutants across three rounds: 1 null control (survived, as required) and 28
  real mutations. 27 killed on first exposure; 1 survived; that 1 is now killed by
  tests written in response.**
- The survivor (M15, opcode-encoding drift) was a real coverage hole in a
  consensus-grade identity, invisible to both the original 331-test suite and to this
  pass's own first attempt at pinning identity.
- **Two defects in the harness itself** are documented above — fail-fast truncation
  and an mtime-preserving restore. Both showed all-green while measuring the wrong
  thing. The null control in round 3 exists because of them.
- **Known-thin coverage, left thin and named:** M2 (`ExpectDepth`) rests on a single
  test. M12's thinness was closed.
- **Reproducing this:** the mutations are quoted verbatim in the tables above against
  named source constructs. The scaffolding is not committed; it is four lines of file
  I/O around `cargo test -p bloch-euvm --offline --no-fail-fast`, and it must restore
  sources with a fresh mtime.
