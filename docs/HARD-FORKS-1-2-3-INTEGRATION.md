# Hard forks 1, 2 and 3: integration record

Branch: `codex/hardforks-123-final-20261020` (local only, never pushed).
Base: mainnet release `b4a21fb657d0beb17f64c62889b605c9a7a2d031`.
Integration tip: the commit that adds this document, on top of `deef5dca`
(the last code commit; every count below refers to it or to the commit named).

**Every activation constant is `u64::MAX` (inert) on this branch.** Nothing
here is armed. The owner arms gates himself, in one release commit (§7).

Release integrity: `git merge-base --is-ancestor b4a21fb6 <tip>` holds, and
`scripts/hf-release/qualify.sh` now refuses any candidate that does not
descend from the fleet release (HF1 review H-3). No source branch that
forks before `b4a21fb6` was merged. In particular the original
`codex/hf2-sigdet-20261020` is **not** in this history: its sanitized copy
`codex/hf2-sigdet-neutral-20261020` was merged instead, and
`codex/hf-wallet-20261020` (which does not descend from `b4a21fb6`) was left
out.

## 1. Owner decisions applied

| Decision (2026-10-20) | Where it is enforced |
| --- | --- |
| Do everything without touching deposits and withdrawals. Transfer, deposit, withdrawal and L2 bridge transaction signing, verification, fees and mempool acceptance stay as in `b4a21fb6` at every epoch. | `SIG_CANONICAL_ACTIVATION_EPOCH` judges consensus messages only (votes, proposals, evidence, KES leaves); transactions use `SignaturePolicy::transaction`, never a canonical policy. Tests: `transition::tests::hf_gates_leave_transfers_byte_identical` (committee: the same V1 `Transfer` and V2 `TransferV2` with every HF gate that has a test override forced open at genesis, versus all shut: same verdict, fee, unspent set and state root), `v1_transfer_forms_stay_valid_across_the_canonical_flag_day` and `offline_cli_v1_signatures_verify_under_the_transaction_policy_at_every_epoch` (node, real hybrid crypto and mempool admission, every v1 byte form, all four pin/canonical gate states), `honest_reference_signatures_from_every_backend_are_admitted` (strict relay keeps honest wallet transfers). Suite `0x0002` transfers stay refused at admission exactly as today (`non_hybrid_transfer_keys_are_refused_before_signature_verification`). |
| Suite `0x0003` is opt-in only. | HF3 opens the suite for spend witnesses only; `0x0001`/`0x0002` validity, fees and post-state are pinned identical across the gate (`21cd34bc`). |
| The lattice-break emergency is never part of a scheduled release. | `hard_forks::NEVER_IN_A_SCHEDULED_RELEASE`, test `emergency_gates_are_never_release_armable`. |
| The new binary ships only when HF1, HF2 and HF3 are all ready; mainnet stays on `b4a21fb6` until then. | Nothing is armed. The earlier "claim finality only, this week" release candidate is superseded. |
| Include the node-only ML-DSA strict relay. | `codex/node-mldsa-strict-relay-20261020` merged; ungated, node-only (mempool, relay, proposer selection); blocks and votes unchanged. |

**HF1 claim finality and depositors/withdrawers** (item (c) of the owner
scope): claim finality changes nothing a depositor sees. For withdrawers it
changes which finalized checkpoint an L2 withdrawal claim may rely on (it
must be this chain's own). Claim format, fees and amounts are unchanged; on
a healthy chain claims behave as today, except for a one-time pause of
about 2 epochs (~32 min) right after activation, until the first checkpoint
recorded under the rule finalizes. `getl2settlement` gains additive fields
(`finalized_checkpoint`, `claimable`, `claimable_large`). It is a separate
gate (`HF1_CLAIM_FINALITY_EPOCH`) and can be armed alone.

**Growth cap / funded delegation** (item (d)): the cap only delays the
activation epoch of a queued funded validator; no user transfer, delegation
deposit or withdrawal changes. Inert.

## 2. Merge order and commits

First-parent history of the integration branch (oldest first):

| Commit | Subject |
| --- | --- |
| `3fb2ebbc` | integrate: merge codex/hf-node-only-20261020 (node-only hardening, no consensus change) |
| `c21c38c6` | integrate: merge codex/hf3-tags-20261020 at e0bfbfff (wire tag allocation table only) |
| `ba6c8330` | integrate: merge codex/hf1-core-20261020 (HF1 claim finality + frozen finality set, both inert) |
| `0132cb95` | tests: HF1 security review tests (frozen finality set findings F1-F3 ignored-with-reason) |
| `626ae8bc` | integrate: merge codex/hf-cryptoaudit-20261020 (FIPS KATs, fuzz harnesses, signer hardening; node-only) |
| `696f40d1` | integrate: merge codex/hf2-slashing-20261020 (P5a evidence pre-admission, inert) |
| `b141865a` | integrate: merge codex/hf2-growthcap-20261020 (funded-activation growth cap, inert) |
| `286de2b9` | integrate: merge codex/indexer-hf-ready-20261020 (indexer halts with reason at flag days, gate table) |
| `58f68945` | hard forks: one list of HF1/HF2/HF3 activation gates with ordering rules |
| `f266c26d` | integrate: merge codex/hf1-owntarget-20261020 (HF1 own-target votes, inert) |
| `553e0a78` | integrate: merge codex/hf2-sigdet-neutral-20261020 (canonical consensus signatures + ML-DSA pin, inert) |
| `f8cedf64` | integrate: merge codex/hf3-tags-20261020 (HF3 PQ suite migration + lattice emergency, inert) |
| `f6e4ae8a` | indexer: index the post-quantum migration transactions (0x18-0x1A) |
| `321f2418` | integrate: merge codex/hf3-slhdsa-20261020 (HF3 suite 0x0003 spends, inert) |
| `69884e8f` | indexer: verify HF3 suite-0x0003 spend witnesses like the node does |
| `6a224a76` | integrate: merge codex/hf3-kes-20261020 (HF3 forward-secure validator keys, inert) |
| `83c8a7d3` | tests: HF2/HF3 security review test hf23_p5a_* ported to the integrated API |
| `b05afe46` | integrate: merge codex/hf2-sigdet-neutral-20261020 at ab6694dd (offline-CLI v1 invariance test, devnet-equivocate epoch rule) |
| `b418a512` | integrate: merge codex/node-mldsa-strict-relay-20261020 (node-only strict ML-DSA relay policy) |
| `6a7d0e08` | integrate: merge codex/hf3-kes-20261020 at 148c4c90 (KES rehearsal fixes: rescue rule, signature bound, bind delay, leaf cache; inert) |
| `307120fc` | integrate: merge codex/hf1-core-20261020 at c7192133 (test: the frozen finality set does not change who the leak charges) |
| `735a2499` | integrate: merge codex/node-duty-retry-20261020 (node-only late retry of a skipped attestation duty) |
| `faaf6416` | integrate: merge codex/hf-verify-harness-20261020 (tooling/docs, no consensus change) |
| `4ecff3da` | integrate: merge codex/hf-schedule-20261020 (tooling/docs, no consensus change) |
| `2699e196` | integrate: merge codex/hf-release-kit-20261020 (tooling/docs, no consensus change) |
| `f7feaad5` | integrate: merge codex/hf-rehearsal-20261020 (tooling/docs, no consensus change) |
| `5345fe5b` | integrate: merge codex/hf-replay-guard-20261020 (tooling/docs, no consensus change) |
| `e86acf5c` | integrate: merge codex/hf-ecosystem-20261020 (tooling/docs, no consensus change) |
| `03d1b13d` | hf-release: qualify.sh refuses a candidate that does not descend from the fleet release |
| `f9729be3` | integrate: merge codex/sig-fit-resign-20261020 (signers re-sign until the signature fits ADMISSION_PQ_SIGNATURE_MAX; no consensus change) |
| `b249ced7` | hardened clippy: no new panic or always-true comparison in bloch-pos-committee from the HF lines |
| `87feb406` | integrate: merge codex/hf-rehearsal-20261020 at e9a6b07c (tooling: robust leak check, --l2-epoch) |
| `9b55c6a6` | hf-release: qualify.sh refuses a release build that enables mldsa-pin-replay-qualification |
| `6ce03c17` | tests: HF23 re-review tests for KES key history (R-1) and indexer KES leaves (R-2) |
| `e0755236` | committee: keep KES key history so rotations cannot erase slashability (R-1) |
| `05ba0bdb` | indexer: verify KES leaves in the bound v2 form during replay (R-2) |
| `6859288d` | node: never broadcast an empty duty signature; document evolution spread (F-7) |
| `deef5dca` | integrate: merge codex/hf3-rescue-dos-20261020 (F-9: cap free RescueCommit per block behind the lattice emergency gate; inert) |

The KES re-review fixes (`codex/hf3-kes-fixes-20261020`) were cherry-picked
(`-x`) rather than merged, so that the branch's review-only commit message
stays out of this history; its two tests are re-committed with a neutral
message (`6ce03c17`).

## 3. Conflicts resolved

**hf1-owntarget into hf1-core.** Both gate blocks kept in `params.rs`.
`close_epoch` records the claim-finality checkpoint root first, then the
own checkpoint. `FinalityRecord` carries `finality_set` and
`own_checkpoints`; the finality leaf appends FSET first, then
OWN-CHECKPOINTS (each absent while empty, so historical leaves keep their
bytes; new test `finality_leaf_extensions_have_one_order_and_compose`, HF1
review L-3). The owntarget form of `split_claims` (`split_mixed`) is used;
both lines' tests kept. `ffg_branch_tests.rs` is hf1-core's copy with the
post-fix tests arming own-target together with the frozen set; the p2a-only
post-fix test now runs un-ignored and passes (HF1 review M-2 property). The
temporary test feature `hf1-claim-finality-tests` is removed.

**Local state cache.** One decoder; sections are written and parsed in
`wire_alloc::local_cache::ORDER`: L2 [L2CP], KES, PQ, FSET, FFGO. Section
markers come from `wire_alloc`.

**hf2-sigdet-neutral.** `Keystore::sign` keeps the p9e `sign_released`
path with `crypto::sign`/`verify` (byte-identical v1); `sign_under(policy)`
goes through `sign_released` with signer and verifier of the same policy.
`slashing::verify_offender_signature` stays the one rule shared by
consensus and the P5a pre-admission and judges each message under
`SignaturePolicy::consensus(message epoch)`; the message epoch of a vote is
its slot's epoch everywhere (signer, gossip, block, evidence). The
bloch-crypto ACVP test, fuzz target and standalone lock files took the
sigdet versions (same p9e base).

**hf3-tags (PQ migration).** `SignatureVerifier` keeps
`verify_with_key_under` and `verify_spend_at_epoch`. `PolicyVerifier`
overrides `verify_spend_at_epoch`: suite-0x0003 witnesses go to the inner
spend rule, every other key is judged as `verify_with_key` under the
wrapper's policy. State tree carries the PQ rescue commitments.

**hf3-slhdsa.** One `verify_spend_at_epoch`. `pq_migration.rs` takes the
suite id, signature bound and verify gas from
`params::SUITE_SLHDSA128S_FALCON1024`,
`params::SLHDSA_FALCON_MAX_ENVELOPED_SIG_LEN` and
`fee_market::SLHDSA_FALCON_VERIFY_GAS`. Const assertion
`HF3_PQ_MIGRATION_EPOCH >= HF3_SLH_SUITE_EPOCH`.

**hf3-kes.** The KES branch carried older copies of the sigdet crypto patch
and of the tag table; the newer versions were kept. `PolicyVerifier`
forwards `verify_kes` and `verify_kes_leaf` unchanged (KES leaves are v2
bound from the first signature). Gossip, block proposer, included votes and
the node's header checks call `kes::verify_validator` through
`PolicyVerifier::consensus` of the message's own epoch.
`verify_offender_signature` resolves keys through `kes::verify_validator`,
and `verify_precheck_signatures` passes the whole state (KES keys and bind
epoch) instead of the bare validator map: the ported review test
`hf23_p5a_precheck_must_accept_genuine_kes_evidence_that_consensus_slashes`
caught the bare-map version. A KES-registered validator's key binding is
never treated as final (relay verdict "ignore", not a peer fault).
`sign_duty`'s static branch signs with `sign_for_epoch`. Node verification
caches merged (KES leaf cache root, HF2 policy keys, HF3 per-suite units).
State root has 35 components (`TAG_KES_ROOT` 0x22, `TAG_PQ_RESCUE_COMMIT`
0x24). Every HF3 transaction tag (0x17–0x1B) is now landed; the indexer
knows `kes_register`/`kes_rotate`.

**node-mldsa-strict-relay.** Its two crypto commits re-apply the sanitized
commits already merged (one `verify_pinned`). `StrictRelayVerifier` and
`strict_relay_hybrid` also wrap the integrated entry points:
`verify_with_key_under` adds the reference check only under `Compatible`
(every other policy already uses it), `verify_spend_at_epoch` adds it for
lattice keys, KES leaves are forwarded unchanged.

**node-duty-retry.** The retry call sits inside the slot loop's
`attestation_due` gate, after the on-time duty and its latch. The
duty-retry structural test was adapted to the hf-node-only gate test
(the retry must precede the proposer step that ends the gated branch).

**hf-release-kit.** `qualify.sh` gains the ancestry check and refuses a
release build that enables `mldsa-pin-replay-qualification`.

**hf3-kes-fixes (re-review R-1, R-2, F-7).** KES key history
(`KES_KEY_HISTORY_PERIODS = 365`, local-cache KES section v3) so a rotation
cannot erase slashability; the indexer verifies bound KES leaves; no empty
duty signature is ever sent. **hf3-rescue-dos (F-9).** At most
`RESCUE_COMMITS_MAX_PER_BLOCK = 4` free rescue commits per block behind the
lattice-emergency gate; node mempool selection after tipped transactions.

**sig-fit-resign.** `Keystore::sign_fitting` sits beside the p9e release
path and is not routed through it (that path aborts on repeated failure; a
signature that does not fit a length bound is an error for the CLI).

Review findings handled at integration time: HF1 M-5 (claim finality may
ship alone; frozen set requires it no later), HF1 L-3 (one leaf/cache
order, both-armed test), HF23 F-1 (KES leaves bound; test
`kes_leaves_verify_under_every_consensus_signature_policy` fails if signer
and leaf verifier drift to mismatched forms under any policy), F-3 (P5a
pre-admission judges exactly as consensus, incl. KES), F-4 (own-epoch
judging), F-11 (one set of SLH-DSA constants).

## 4. The central gate list

`crates/bloch-pos-committee/src/hard_forks.rs`:

- `HARD_FORK_GATES`: every HF1/HF2/HF3 activation constant, with its fork.
  A test fails if an `HF1_*`/`HF2_*`/`HF3_*` epoch constant in `params.rs`
  is missing from the list. The indexer's gate table lists them too
  (`tools/bloch-indexer/tests/consensus_gates.rs`).
- `hard_fork_schedule_coherent(...)`, a `const` assertion over the shipped
  values:
  - frozen finality set ⇒ claim finality armed, no later;
  - own-target votes ⇒ frozen set armed, no later;
  - every HF2 and HF3 gate ⇒ claim finality armed at least 90 epochs
    (24 h) earlier;
  - KES enforcement ⇒ KES registration no later (and `params.rs` keeps its
    14-day registration window assertion);
  - PQ migration ⇒ SLH-DSA suite no later; lattice emergency ⇒ PQ
    migration no later;
  - the P5a and KES aliases equal their release switches.
- `RELEASE_ARMABLE` (today: `HF1_CLAIM_FINALITY_EPOCH`): a test fails if
  any other HF gate leaves `u64::MAX`. Extend it in the same commit that
  arms anything else.
- `NEVER_IN_A_SCHEDULED_RELEASE`: the lattice emergency.

| Gate | Fork | Kind | Planned (schedule, Plan A) | Status |
| --- | --- | --- | --- | --- |
| `HF1_CLAIM_FINALITY_EPOCH` | HF1 | consensus | 6460 | inert; GO with conditions |
| `HF1_FROZEN_FINALITY_SET_EPOCH` | HF1 | consensus | later release | inert; NO-GO |
| `HF1_OWN_TARGET_VOTES_EPOCH` | HF1 | consensus | later release | inert; NO-GO |
| `HF2_SLASHING_V2_EPOCH` (= `NATIVE_SLASHING_ACTIVATION_EPOCH`) | HF2 | node policy | 6550 | inert; GO when scheduled (FD-2 preconditions) |
| `HF2_GROWTH_CAP_EPOCH` | HF2 | consensus | 6550 or never | inert; NO-GO as a security control |
| `SIG_CANONICAL_ACTIVATION_EPOCH` | HF2 | consensus (validator messages) | 6550 | inert; GO when scheduled (dual-arch replay) |
| `MLDSA_PIN_ACTIVATION_EPOCH` | HF2 | consensus (ML-DSA backend) | 6550 | inert; GO when scheduled (dual-arch replay) |
| `HF3_KES_EPOCH` (= `KES_REGISTRATION_EPOCH`) | HF3 | consensus | not scheduled | inert; NO-GO for now (R-1/R-2 fixed, re-review pending) |
| `HF3_KES_ENFORCE_EPOCH` (= `KES_ACTIVATION_EPOCH`) | HF3 | consensus | not scheduled | inert; NO-GO for now (R-1/R-2 fixed, re-review pending) |
| `HF3_SLH_SUITE_EPOCH` | HF3 | consensus (spends) | 6562 | inert; GO when scheduled |
| `HF3_PQ_MIGRATION_EPOCH` | HF3 | consensus | not scheduled | inert; GO for 0x18 (owner decision needed: withdrawal credentials) |
| `LATTICE_EMERGENCY_ACTIVATION_EPOCH` | HF3 | emergency | never scheduled | inert |

## 5. Test counts

`cargo test --workspace` with `CARGO_BUILD_JOBS=4`, excluding the closed
Genesis-3 crate `bloch` (legacy) and `bloch-l2-proof`. No HF branch touches
either (checked with `git diff`); in debug builds under the shared host
load their tests take hours (`backfill_flood_lab`, the real Groth16
`real_proof`). Both were run once separately (bottom row).

| Integration commit | Content added | Passed | Failed | Ignored |
| --- | --- | --- | --- | --- |
| `58f68945` | node-only, tag table, hf1-core, HF1 review tests, cryptoaudit, hf2-slashing, growth cap, indexer, `hard_forks.rs`, transfer invariance test | 2548 | 0 | 55 |
| `f266c26d` | hf1-owntarget | 2564 | 0 | 53 |
| `553e0a78` | hf2-sigdet-neutral | 2599 | 0 | 54 |
| `f6e4ae8a` | hf3-tags PQ migration + indexer PQ kinds | 2626 | 0 | 54 |
| `69884e8f` | hf3-slhdsa + indexer 0x0003 verifier | 2666 | 0 | 55 |
| `83c8a7d3` | hf3-kes + ported hf23 test (tree identical to the tested scratch tip) | 2733 | 0 | 55 |
| `03d1b13d` | sigdet-neutral `ab6694dd`, strict relay, KES `148c4c90`, hf1-core `c7192133`, duty retry, tooling, qualify ancestry check | 2748 | 0 | 59 |
| `f9729be3` | sig-fit-resign | 2759 | 0 | 60 |
| `87feb406` | hardened-clippy fix, rehearsal `e9a6b07c` | 2759 | 0 | 60 |
| `6859288d` | re-review tests + KES fixes (R-1, R-2, F-7) | 2762 | 0 | 60 |
| `deef5dca` | rescue-commit cap (F-9) | **2768** | **0** | **60** |
| `deef5dca`, separately, `--release` | legacy `bloch` + `bloch-l2-proof` | 1215 | 4 | 11 |

Counts include tests that failed once in the full run and passed when rerun
alone (added to "passed"):

- `native_passphrase_tty` (PTY/signal timing) fails intermittently under the
  shared host load in most full runs; it passed every time it was rerun alone.
- `hd_wallet::tests::create_save_load_roundtrip` failed once (`69884e8f`)
  while a second test run on another worktree was writing the same temporary
  path; passes alone.
- `engine::duty_view_anchor::giving_three_blocks_back_moves_the_duty_view_seed_and_the_partition`
  depends on random keys (the node must be drawn to propose in epoch 2); it
  fails in roughly 1 run in 10 both on `87feb406` and on the tip (15-run
  samples), passed 5/5 on `b4a21fb6`. Not a regression the samples can
  distinguish; flagged for a deterministic fixture.

Legacy (`bloch`, closed Genesis-3; no HF branch touches `legacy/`,
`bloch-sis-pow` or `coherence-core`): `pow::tests::k4_mined_block_rejected_at_canonical_height`
(twice, lib and bin) and `security_tests::vuln01_difficulty_bypass` also
fail on `b4a21fb6`; `tx_validity_is_invariant_to_dual_and_pow` is
probabilistic (passed 1 of 3 release reruns). `bloch-l2-proof`: all pass
(`real_proof` included).

Not run by `cargo test --workspace`: `tools/bloch-indexer` declares
`[lib] test = false` (since before `b4a21fb6`), so its library unit tests
(including the re-review test `hf23_archive_verifier_must_accept_bound_kes_leaf_signatures`)
run only with `cargo test -p bloch-indexer --lib`. That test passes on the
tip. The node's `genesis::tests::vesting_is_not_enforced`, included into the
indexer library by `#[path]`, panics when forced that way because it walks
`CARGO_MANIFEST_DIR/../bloch-pos-committee/src`; same on `b4a21fb6`.

### Hardened clippy (`bloch-pos-committee`, pinned toolchain)

| Tree | Panics | Arith | Other |
| --- | --- | --- | --- |
| script baseline | 0 | 186 | 0 |
| `b4a21fb6` (the fleet release) | 2 | 213 | 0 |
| merged HF lines before `b249ced7` | 4 | 230 | 2 |
| `87feb406` and the tip `deef5dca` | 2 | 230 | 0 |

The release itself is above the script's baseline (both panic sites are in
`l2_settlement.rs`). The HF merges added two `unwrap`s in the KES signature
decoder and two always-true comparisons in the KES schedule assertions;
`b249ced7` removes them without changing behaviour. The KES and rescue
fixes add nothing. The 17 arithmetic findings the HF lines add are left to
their owners:

| File (tip) | Count | Origin |
| --- | --- | --- |
| `state_root.rs` (finality-certificate proof paths, ~1100-1193) | 8 | `codex/hf-node-only-20261020` (`a9fd29ae`) |
| `transition/pq_migration.rs` (rotation charge, rescue reveal) | 4 | `codex/hf3-tags-20261020` (`5b3c5e16`) |
| `fee_market.rs:242` (per-suite verify gas) | 1 | `codex/hf3-slhdsa-20261020` (`41c2f765`) |
| `kes.rs:268`, `params.rs` `kes_period` | 2 | `codex/hf3-kes-20261020` (`2287cf8a`) |
| `transition.rs` (KES registered-stake share) | 1 | `codex/hf3-kes-20261020` (`f32193f2`) |
| `staking.rs:140` | 1 | `codex/hf2-growthcap-20261020` (`3e362ca0`) |


`native_passphrase_tty` (a PTY/signal timing test) fails intermittently
under heavy host load and passed every time it was rerun alone; it is
listed where it was rerun.

## 6. Open review findings and GO / NO-GO

The HF1 review (`codex/hf1-review-20261020`) and the HF2/HF3 review
(`codex/hf23-review-20261020`) are not merged as documents; their tests
are (HF1 `finality_hf1_review_tests.rs`, three ignored-with-reason; HF23
`hf23_*`). Findings below are summarized.

| Fork / rule | Verdict | Open items |
| --- | --- | --- |
| HF1 claim finality | **GO with conditions** (HF1 review) | Full-history replay to the tip with the armed release build, compared per block against `b4a21fb6` on two archivals (schedule R4); mixed-fleet qualification; release descends from `b4a21fb6` (now enforced by `qualify.sh`); notice limited to this rule. |
| HF1 frozen finality set | **NO-GO** (HF1 review) | H-1 (one host holds more than a third of duty weight, so a single-host outage halts finality), H-2 (stake that leaves the roster stays in the set; an exit of a third makes the halt permanent; needs an exit churn limit), M-1 (recovery epochs must be bound to an expected checkpoint root), M-4 (soak and 7-day notice), L-1, L-2 (non-canonical retention during halts), L-4 (off-chain verifiers). Review tests F1–F3 stay ignored-with-reason. |
| HF1 own-target votes | **NO-GO this release** | Merged inert and tested (the p2a post-fix test passes); needs the frozen set first (schedule O2) and a devnet measurement of the justification rate with real latency (L-3). |
| HF2 slashing (P5a) | **GO when scheduled** (HF23 re-review) | Relay policy only. F-3 and F-6 fixed, F-10 mitigated. The FD-2 preconditions of the security flag-day plan must be met first. |
| HF2 growth cap | **NO-GO as a security control** | F-8: does not bound the funded-delegation path; changes a committed field (needs replay and its own epoch). |
| HF2 `SIG_CANONICAL` + ML-DSA pin | **GO when scheduled** (HF23 re-review) | F-1, F-4, F-12 fixed. Arming needs a full-history replay with byte-identical roots on x86_64 and aarch64 under `mldsa-pin-replay-qualification`, and a release build proven without that feature (now checked by `qualify.sh`). `SIG_CANONICAL` is a validator-facing flag day (all validator signers sign v2 from that epoch). |
| HF3 KES | **NO-GO for now** | Re-review R-1 (High: a rotation sequence could erase provable KES-era equivocation evidence) and R-2 (Medium: the indexer's `ArchiveVerifier` lacked `verify_kes_leaf` and would halt at KES bind) are fixed on this branch (`e0755236`, `05ba0bdb`; the re-review tests pass), as is the F-7 empty-signature residual (`6859288d`). Still needed before arming: a re-review of the fixes, the registration window, a devnet rehearsal of rotation/rescue/expiry/bind, and the owner decision on `ADMISSION_PQ_SIGNATURE_MAX` (unchanged here). `HF3_KES_EPOCH` is itself a flag day (the first 0x17/0x1B block forks old nodes). |
| HF3 SLH-DSA suite 0x0003 | **GO when scheduled** (HF23 re-review) | No open finding; opt-in for spend witnesses only; recalibrate p9f gas against the pinned verifier. |
| HF3 PQ migration (0x18 rotation) | **GO for 0x18; NO-GO for the lattice-emergency gate** | F-9 (fee-free rescue commits could fill blocks) fixed on this branch (`deef5dca`, at most 4 free commits per block behind the emergency gate); re-review pending. Owner scope: credential rotation touches withdrawal credentials, so it needs an explicit owner decision before arming. The emergency gate is never part of a scheduled release. |

Ecosystem (`docs/HF-1-2-3-ECOSYSTEM-COMPATIBILITY.md`): the indexer must be
rebuilt from the armed release before E1 (it halts with a reason
otherwise); the wallet/exchange signer blocker for HF2 disappears with the
transaction re-scope; explorer labels for 0x17–0x1A live outside this
repository. L2 hosts must be rebuilt against the release
(`codex/hf-l2-compat-*` in this and the `bloch-l2-evm` repository; the L2
attestor kit's defensive checks are on `bloch-l2-evm`
`codex/sig-fit-resign-20261020` `028fffd`).

Harness (`scripts/hf-verify/run-all.sh`): run on the integration tree (`bd9d63bd`, same HF1 code as the tip) with
`--arm HF1_CLAIM_FINALITY_EPOCH --arm HF1_FROZEN_FINALITY_SET_EPOCH --arm HF1_OWN_TARGET_VOTES_EPOCH --model none`
(start epoch 5860). At the time of writing the 60/40 and three-way splits
had run 3,500+ split epochs: **no side finalized anything after the split,
so no conflicting finalization and no double pay**; the flip side is
exactly HF1 review H-1: a 60% side cannot reach two thirds of the frozen
set, so finality halts for the whole split. The remaining scenarios
(50/50, heal-both, votes-cross) and the CF+FS-only run were still running
on the shared host; their reports land in the run's `report.txt`.

## 7. Arming (owner only)

Not executed by the integrator. Run from the repository root on the release
commit, then run `cargo test --workspace` and `scripts/hf-release/qualify.sh`
on the result before signing. Every pattern below was checked to match
exactly where listed on the integration tip (the two-line assert in
`l2_settlement_tests.rs` matches twice, both intended).

### 7.1 HF1 claim finality at the planned epoch 6460 (Plan A)

One command (BSD/macOS `sed`; on GNU sed drop the `''` after `-i`). For
Plan B replace every `6460` with `6550`.

```
sed -i '' -e 's/^pub const HF1_CLAIM_FINALITY_EPOCH: u64 = u64::MAX;$/pub const HF1_CLAIM_FINALITY_EPOCH: u64 = 6460;/' -e 's/^        assert_eq!(HF1_CLAIM_FINALITY_EPOCH, u64::MAX);$/        assert_eq!(HF1_CLAIM_FINALITY_EPOCH, 6460);/' -e 's/^            assert!(!native_claim_finality_active(epoch));$/            assert_eq!(native_claim_finality_active(epoch), epoch >= 6460);/' -e 's/^        assert_eq!(crate::params::HF1_CLAIM_FINALITY_EPOCH, u64::MAX);$/        assert_eq!(crate::params::HF1_CLAIM_FINALITY_EPOCH, 6460);/' -e 's/^            assert!(!crate::params::native_claim_finality_active(epoch));$/            assert_eq!(crate::params::native_claim_finality_active(epoch), epoch >= 6460);/' crates/bloch-pos-committee/src/params.rs crates/bloch-pos-committee/src/transition/l2_settlement_tests.rs
```

It sets the constant and turns the two inert pins
(`hf1_tests::hf1_ships_inert_as_a_whole`,
`native_claim_finality_gate_is_inert`, and the precondition of
`below_the_claim_finality_gate_nothing_is_recorded`, whose split runs in
the first epochs) into pins of the armed value. `RELEASE_ARMABLE` already
allows this gate; `hard_fork_schedule_coherent` accepts claim finality
alone. Check before signing: E1 ≥ publication epoch + 270 (72 h, schedule
O8), recomputed for the actual publication date.

### 7.2 Any other gate (none is armable in the next release; see §6)

Same pattern, one `-e` for the constant and one per inert pin, plus adding
the gate's name to `RELEASE_ARMABLE` in `hard_forks.rs`:

| Constant (defined in) | Planned | Inert pins to rewrite in the same commit |
| --- | --- | --- |
| `HF1_FROZEN_FINALITY_SET_EPOCH` (`params.rs`) | later | `params.rs` `hf1_ships_inert_as_a_whole`, `finality.rs` `the_gate_ships_inert` |
| `HF1_OWN_TARGET_VOTES_EPOCH` (`params.rs`) | later | `l2_settlement_tests.rs` `hf1_own_target_votes_gate_is_inert`, `below_the_own_target_gate_nothing_is_recorded` |
| `HF2_SLASHING_V2_EPOCH` (`params.rs`) | 6550 | `transition.rs` `hf2_slashing_v2_gate_ships_inert` |
| `HF2_GROWTH_CAP_EPOCH` (`params.rs`) | 6550 or never | `transition/funded/tests.rs` `hf2_growth_cap_gate_is_inert` |
| `SIG_CANONICAL_ACTIVATION_EPOCH` (`params.rs`) | 6550 | `transition.rs` `sig_canonical_gate_is_inert` |
| `MLDSA_PIN_ACTIVATION_EPOCH` (`params.rs`, the non-qualification definition) | 6550 | `transition.rs` `mldsa_pin_gate_is_inert` |
| `HF3_SLH_SUITE_EPOCH` (`params.rs`) | 6562 | `fee_market.rs` `hf3_fee_gate_ships_inert_and_is_bit_identical_below_it`, `transition.rs` `hf3_slh_suite_gate_is_inert`, node `verification.rs` `spend_path_below_hf3_is_the_context_free_path` and the `engine.rs` HF3 admission test |
| `HF3_KES_EPOCH`, `HF3_KES_ENFORCE_EPOCH` (`params.rs`) | not scheduled | `params.rs` `the_mainnet_schedule_is_unarmed`, node `kes_tests.rs` `rotation_is_refused_at_the_door_while_hf3_is_unarmed` |
| `HF3_PQ_MIGRATION_EPOCH` (`params.rs`) | not scheduled | `transition/pq_migration/tests.rs` `pq_migration_gates_ship_inert` |
| `LATTICE_EMERGENCY_ACTIVATION_EPOCH` | never in a scheduled release | — |

The schedule's epochs (`docs/HARD-FORKS-1-2-3-ACTIVATION.md`, Plan A: HF1
6460, HF2 6550, HF3 6562; Plan B: 6550 / 6640 / 6652) assumed publication by
2026-10-21. With the decision to ship only when all three forks are ready,
every epoch must be recomputed from the actual publication epoch
(E1 ≥ publication + 270; HF2/HF3 ≥ E1 + 90, enforced by the const
assertion).
