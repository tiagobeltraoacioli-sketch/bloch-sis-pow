# L2 program rollback: emergency release kit

Status: PREPARED, NOT SCHEDULED. Everything here ships `L2_PROGRAM_ROLLBACK_EPOCH = u64::MAX`.
Base: `codex/fork-candidate-native-r7-20261102` 27f195d7 (agent 116), branch
`codex/rollback-release-r7-20261102`.

What the rollback does (agent 89): from epoch R, L1 replaces `PROGRAM_NEXT` (the sparse-witness
guest) with `PROGRAM_FALLBACK` (the complete-witness guest, same next rules, same configuration).
No block is rewound for rules. Optional `ROLLBACK_HEAD_RESET` also moves the settled head back,
for the case where the sparse guest settled a block the rules do not give. It acts once, only on
the policy the swap installed. It is a hard fork: a new release, most stake upgraded by R.

## Files

| File | Role |
|---|---|
| `arm.py` | Deterministic arming. Edits `params.rs` (R, and S checked), `l2_settlement.rs` (optional reset), `hard_forks.rs` (both L2 gates join `RELEASE_ARMABLE`). Refuses: R <= S, lead < 270 epochs, swap not armed in the base, candidate pins, a non-inert rollback, a malformed reset. Writes `manifest.json`. |
| `build.sh` | Clone base, `arm.py`, commit with fixed author and the base commit's dates (same armed hash on every builder), canonical container build, `RELEASE.txt`. |
| tests | `the_l2_program_gates_ship_inert_or_armed_by_the_release_kit`, `an_armed_l2_program_gate_needs_final_programs`, `next_program_gate_is_inert_and_chooses_no_epoch`, `the_rollback_gate_is_inert_and_the_fallback_proves_the_same_rules`, `the_schedule_is_empty_while_inert_and_names_only_what_is_ahead`: pass inert and armed, so the armed commit needs no test edits. |

The base MUST be the shipped swap release (its `L2_NEXT_PROGRAM_EPOCH` = S, `PROGRAM_NEXT_FINAL`
true). `--candidate-pins` exists only for qualification on the candidate tree.

## Go / no-go signals

GO means: start the owner steps below now. Each signal names the monitor check
(`deployment/mainnet/l2_monitor.py` of the L2 release) that detects it, and the confirmation that
must hold before GO.

| # | Signal | Detected by | Confirm before GO | Rollback form |
|---|---|---|---|---|
| G1 | Sparse guest refuses a valid block, or its proof fails, at the same L2 block repeatedly | `settlement_age` CRIT, `events[settler]` (retry/halt), `l2_proof_cost` CRIT, settler log `proof failed` | Same artifact fails on a second prover host; the complete guest executes the same block (execute-only) | No reset |
| G2 | L1 accepted a settlement whose state root the attestors cannot rebuild | `attestors` CRIT (attestors halt on rebuild mismatch), `follower_status[*]` CRIT, `foreign_settlements[*]` CRIT, `l1_accepted_agreement` | Two independent followers rebuild from L1 data and disagree with the accepted root; name the last honest block | With `ROLLBACK_HEAD_RESET` = last honest block, unless a leaf outside its tree was already paid (then the reset refuses; still roll back) |
| G3 | A soundness bug in the sparse guest is reported (audit, disclosure) and not yet exploited | Out of band; then watch `claims_vs_withdrawn`, `escrow_conserved`, `release_window` | Reproduced against the pinned ELF | No reset |
| G4 | Wrong pin: the program L1 holds after the swap is not the release's sparse ELF | `l1_l2_identity` CRIT, `l1_gates_vs_l2_build` | `getl2settlement.program` vs the release manifest | No reset |
| N1 | L1 finality stalled or nodes split | `l1_finality_lag`, `l1_stuck[*]`, `l1_height_spread`, `l1_accepted_agreement` | | NO-GO: an L1 problem; a fork needs a healthy L1 |
| N2 | Settler, prover host or DA down | `heartbeat`, `unit[*]`, `da_balance[*]`, `memory`, `disk[*]` | | NO-GO: operational fix |
| N3 | Fallback cannot prove at the current height | `l2_export_runway`, L2 height; agent 81: empty block 157.8M gas at 4096, 307.5M at 8191, largest proven 235M | Past ~6,200 the fallback needs a larger prover | NO-GO unless a larger prover is ready, and the export limit is lifted on the L2 build |
| N4 | Proofs slow but succeeding | `l2_proof_cost` WARN | | NO-GO: tune the prover (agent 93) |

While deciding: claims of 100 BLCH or more need 3 of 5 attestors, and attestors halt by themselves on
G2. Small claims stay inside `max(10% of escrow, 10 BLCH)` per 2,880 blocks (agent 89).

## Operator checklist (validators, RPC, L2 operators)

Before R:
1. Verify the release: `RELEASE.txt` armed commit, two builder digests equal (`compare-pos-release-builds.sh`), signature.
2. Stop the node cleanly, replace `bloch-pos`, start. Do not wipe data (recovery after a wipe needs a refill from a healthy node: `ERR_WS_REQUIRE_CHECKPOINT`).
3. `getchaininfo.hard_forks`: `l2_program_rollback` = R; `l2_next_program` = S unchanged.
4. `getl2settlement.program_schedule` lists exactly `{epoch: R, fallback pins}`.
5. L2 operators: install the release's follower A/B, settled RPC, produce-dev and attestor package (each links the native crate and must replay R). Settler config gets `fallback_program` (complete witness, guest `44d4c9d7…` or the final fallback ELF, `prover_args ["--mainnet"]`).
6. Report the upgrade in the operator channel. Owner tracks upgraded stake: target 90% one day before R.

At R:
7. `getl2settlement.program` = fallback pins from the first block of R. A node that did not upgrade stops at R's first slot with `StateRootMismatch`.
8. Settler logs `l2-block-reproved-for-program`, no `l2-block-rewound-at-swap`, no halt.
9. Followers report `active_program.elf_keccak` = fallback; `safe`/`finalized` keep moving.
10. Monitor: `l1_l2_identity` OK with the new pins, `settlement_age` back to normal after one proof.

## Owner steps (English)

1. Confirm a GO signal above and its confirmation. Record the evidence.
2. Choose the form: no reset (G1, G3, G4) or reset (G2), and the last honest block for a reset (`reset.json`: number, commitment, 766-byte statement).
3. Read the current mainnet epoch P. Choose R >= P + 270 (3 days). Shorter only as your explicit decision; it risks a split.
4. On two build hosts: `scripts/hf-release/l2-rollback/build.sh <swap-release-commit> <new-dir> --swap-epoch S --rollback-epoch R --publish-epoch P [--head-reset reset.json]`.
5. `scripts/compare-pos-release-builds.sh A/builder-a B/builder-a` must PASS; armed commits must be equal.
6. `scripts/hf-release/qualify.sh <armed-commit> --source <archival copy> --baseline-bin <swap release bloch-pos>`; VERDICT PASS.
7. Build the L2 side (follower, RPC, produce-dev, attestor package) against the armed native commit; set the settler's `fallback_program`.
8. Sign and publish the release and the notice (agents/120 rollback section) with R, the reason and the form.
9. Track upgraded stake; at 90% one day before R, go. Below that, publish a later R instead of letting R pass with a minority upgraded.
10. At R, watch the checklist items 7 to 10; afterwards, decide whether value limits (`D`, `B`) change.

A Brazilian Portuguese copy of the owner steps is in the release report (agents/126-rollback-release.md), at the owner's request.
