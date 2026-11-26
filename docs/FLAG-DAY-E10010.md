<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Flag day at epoch 10010 (2026-12-03): seed look-ahead, transaction-count bound, network-bound static signatures

Status: **constants armed on a branch, nothing released, nothing deployed.**
Owner decision of 2026-11-25 ("seven days"), written at mainnet epoch 9373.
The epoch is armed in the commit that carries this file, on
`codex/pq-review-fixes-20261125-armed-e10010`. The same work with every gate
still inert is `codex/pq-review-fixes-20261125`; merge that one if the flag day
is postponed.

> **The constant, the tripwire and this file land in the SAME commit**
> (`docs/RELANCA-G4-DIAS-DE-BANDEIRA.md` §0). They do. What that commit does
> NOT contain is the tag-time table in §7: it is filled when the release is
> tagged, and a tag without it is not an armed release.

This file is a sibling of `docs/RELANCA-G4-DIAS-DE-BANDEIRA.md`, which is the
operational runbook for arming `ANCESTRY_SEED_ACTIVATION_EPOCH`. Its §2
(choosing E\*), §3 (the predicate on every node), §4 (verification after the
boundary), §5 (disarming) and §6 (the silently parked node) are the method
followed here and are not repeated. They do not apply word for word: that
runbook was written for 64 nodes, the binary `bloch-pos-e1400`, ports
16400 + index and line numbers of `relanca/e1400`; it pairs the seed gate with
`LEAK_RECOVERY_ACTIVATION_EPOCH`, which was armed separately at 2880; and its
formula rounds E\* up to the next hundred where this one rounds to the next
ten. Read its commands as templates and take hosts, ports and the binary name
from the current fleet.

---

## 1. The epoch

```
genesis_time          = unix 1786656679   (2026-08-13 21:31:19 UTC)
epoch length          = 32 slots x 30 s = 960 s; 90 epochs a day
written at            = unix 1795655371   (2026-11-26 01:09:31 UTC), epoch 9373
seven days later      = epoch 10003.6
E*                    = 10010              (rounded up to the next ten)
epoch_start_utc(E*)   = 1786656679 + 960 x 10010 = 1796266279
                      = 2026-12-03 02:51:19 UTC (2026-12-02 23:51:19 BRT)
first slot of E*      = 320320
lead at writing       = 636.4 epochs (7 d 1 h 42 min)
```

The epoch number is binding. Clock times are estimates.

`params::FLAG_DAY_E10010` names the epoch. Each of the three gates below
carries the literal `10_010` in its own declaration (the tools that read
`params.rs` need a value there), with a compile-time assertion that keeps it
equal to `FLAG_DAY_E10010`.

### 1.1 The schedule is at the limit of the sibling runbook's own formula

Sibling runbook §2.2 asks for `E* - epoch_at_tag >= 2 x (R + S + D)`, with
S = 90 (the soak) and D = 180 (the 48 hours before E\*), and R the rollout in
epochs. That is at least 540 + 2R epochs between the tag and E\*:

```
R = 5   (parallel rollout)      tag no later than epoch 9460 = 2026-11-27 00:11 UTC
R = 48  (serialized 64 nodes)   tag no later than epoch 9374 = already past at writing
```

R is not known here. The sibling's replay time (7 min) was measured near epoch
1006; the chain is about nine times longer now and the local state cache is
bound to the build digest, so every node replays in full on upgrade. **Measure
R first. If the tag cannot be cut by the deadline that R gives, postpone
(§6) rather than compress the soak or the 48 hours.** "Tag" in that formula is
the moment the armed build is cut for rollout; the public tag of §5 comes
later, after the predicate.

## 2. What is armed

| Gate | Review item | Rule from E\* |
| --- | --- | --- |
| `ANCESTRY_SEED_ACTIVATION_EPOCH` | B4 | The committee and proposer seed of epoch `E` is the RANDAO mix at the close of `E - 2` instead of `E - 1` (`committees::MIN_SEED_LOOKAHEAD_EPOCHS = 1`). |
| `STAKING_TX_METERING_ACTIVATION_EPOCH` | B5 | A block may carry at most `MAX_TRANSACTIONS_PER_BLOCK` (4,096) transactions. The capacity metering of staking transactions has been in force since `WITHDRAWAL_ACTIVATION_EPOCH` (2,884), so this adds only the count bound. |
| `STATIC_KEY_NETWORK_BINDING_ACTIVATION_EPOCH` | B2 | A validator signing with its static key (no KES key registered) signs `kes::static_message`: the consensus root bound to the network domain and the validator index. KES signatures are unchanged. |

Nothing else changes. In particular: transfers, deposits, withdrawals, fees,
wallet signing, the wire format of every transaction, and every KES signature.

### 2.1 What each one does NOT do

- **Seed look-ahead** does not remove the last-revealer bias. The trailing
  proposers of epoch `E` stop influencing `E + 1` and still influence `E + 2`
  by one bit per withheld slot. It also makes the duty schedule public two
  epochs ahead instead of one (`committees.rs`, on the constant).
- **The count bound** charges no fee and makes no staking message pay.
- **Network binding** does not make KES mandatory. The static-key fallback
  after KES binds stays (a validator that never registered still signs), so
  the liveness property of review F-2 is kept.

## 3. Who must do what, and by when

Every item is a precondition of the tag, not of E\*. Before E\* the armed
binary behaves exactly as the inert one, so rolling early is free and rolling
late splits the chain (`RELANCA-G4-DIAS-DE-BANDEIRA.md` §3, item 0).

| Who | What | Why |
| --- | --- | --- |
| Every validator and every observer | Run the armed binary before E\*. | All three rules change which blocks or signatures are valid. A node on the old binary at E\* follows a different chain, and with the seed rule it parks silently (§6 of the sibling runbook). |
| Operators of validators WITHOUT a registered KES key | Run the armed binary before E\*, or their proposals and votes stop verifying at E\*. | Their static key must sign the bound message from E\*. Registering a KES key before E\* removes the dependency. |
| Operators of `tools/bloch-indexer` | Rebuild from this tree before E\*. | It replays through the linked transition: a build from this tree is correct across the gate, an older one stops at the first block of epoch 10010. |
| Users of `tools/participation/participation.py` | Use the version in this tree. | Older copies partition every epoch with the mix of E - 1; from 10010 they would report mass missed duties that did not happen. |
| Maintainers of every verifier outside this repository that checks validator duty signatures (L2 light-client guests, bridges, indexers that verify) | Carry `kes::static_message` before E\*, or accept that static-key votes stop counting for them at E\*. | `kes::verify_validator` is the one definition inside this repository; anything that re-implements it is not updated by this commit. With at least 90% of stake on KES at the bind, a verifier that drops static-key votes still sees a two-thirds majority, but that is an estimate, not a check: **measure the registered share before the tag.** |
| Wallets, exchanges, pools | Nothing. | No transaction rule they sign under changes. |

## 4. What was verified, and what was not

Verified, on `aarch64`, debug builds, 2026-11-25:

- The full `bloch-pos-committee`, `bloch-pos-node` and `bloch-finality-cert`
  suites pass with the three gates at 10010.
- `flag-day-e10010-rehearsal` (a qualification feature, never shipped) puts the
  three gates at epoch 2.
  `the_attester_and_the_judge_agree_on_both_sides_of_the_flag_day` grows one
  chain through epoch 6 in that build. The head advances in every epoch, so
  the producer and the real transition agree on the proposer draw under the
  look-ahead seed and on the network-bound static signature; and at every
  epoch, once that epoch is fully produced, the seed a validator attests under
  equals the seed its peers judge it against, in that one engine and on its
  own branch. That is the agreement the pre-flag-day test says must be
  re-derived once the gate is armed. It says nothing about the count bound
  (the test's mempool is empty, so 4,096 is never approached), about a second
  node, or about the moment a head is still in the previous epoch.
- The whole `bloch-pos-node` suite was also run in that build. It passes
  except `ws_boot::tests::the_compiled_anchor_is_the_hashed_file_and_names_mainnet`,
  which fails by design there: gates at epoch 2 sit below the release anchor
  (8742) and `check_gates_above_anchored_history` refuses them.
- The committee tests of `kes::static_message` cover the cross-network replay
  on both sides of the gate.

A limit of that qualification build, stated so it is not read as a pass: the
`bloch-pos-committee` suite does NOT pass in it (90 unit tests, 2 and 5 in two
integration files). Its fixtures sign proposals and votes by hand over the bare
root and most build states that name no network domain, so from epoch 2 the
rule refuses them (`BadSignature`). Five were read and all five were that; the
rest were not triaged one by one. The committee suite is therefore evidence
for the shipped epochs only, and the node suite is the evidence for the
crossing.

NOT verified, and required by the sibling runbook before the tag:

1. **The two-node devnet rehearsal with a control** (§3 item 7 there): a log
   produced under the OLD rule, replayed in full by the armed binary, crossing
   E\* without a fork, beside the same devnet with the constants inert. The
   in-process test above crosses the boundary in one engine; it is not two
   nodes and it does not replay an old log.
2. **The predicate on every node** (§3 items 1 to 6 there): identical input,
   identical binary in the process, replay finished everywhere, identical
   `state_root` at one sampled height, no boundary vote drops, a 90-epoch soak.
3. **The registered KES share of stake**, read from mainnet.
4. **No external verifier was examined.** Which of them re-implement the
   static-key rule is not known from this repository.
5. **x86_64.** Nothing here was run on it.

## 5. Order of operations

1. Review and merge the inert branch. It is safe on its own.
2. Run the devnet rehearsal with control (§4 item 1) on the armed branch.
3. Build the armed release. Distribute it. Bring it up on the fleet.
4. Check the predicate (§4 item 2) no later than E\* - 180 (2026-12-01
   02:51 UTC). Its 90-epoch soak has to end by then, so the fleet must be on
   the armed binary by E\* - 270 (2026-11-30 02:51 UTC).
5. Only then publish the public tag, with §7 filled in. The lead the formula
   of §1.1 constrains is the earlier moment the armed build was cut, not this
   one.
6. After E\*: the checks of the sibling runbook §4, from the first boundary at
   or past E\*.

If the predicate fails at E\* - 180, the two honest options are the ones the
sibling runbook gives: proceed only when the missing node's cause is known,
local and unrelated to the fold and the ready nodes hold more than two thirds
of stake; otherwise postpone.

## 6. Postponing, and why there is no rollback

Postponing is one commit, not one line. The epoch is written in:

- `params.rs`: `FLAG_DAY_E10010` and the literal in each of the three gate
  declarations (the compile-time assertions fail if they disagree);
- the tripwires `the_replay_compatibility_gates_are_inert_until_armed`,
  `staking_tx_metering_gate_is_inert`,
  `static_key_network_binding_gate_is_inert` (`kes.rs`), and the neighbouring
  boundary tests in `transition.rs` that use 10_007 to 10_011;
- `hard_forks::tests::a_gate_armed_into_anchored_history_is_refused`;
- the node tests `a_replay_failure_names_a_gate_armed_at_or_below_the_failing_epoch`
  and `the_block_admission_authority_is_the_static_key_hash_while_unarmed`;
- `scripts/lifecycle_devnet_soak_lib.py` (the pinned value) and
  `tools/participation/participation.py` (`ANCESTRY_SEED_ACTIVATION_EPOCH`);
- prose in `schedule.rs`, `params.rs`, `docs/VALIDATOR-OPENING.md` and this
  file.

`grep -rn "10_010\|10010\|10_009\|10_008"` finds them. Roll that binary
before E\*. A postponed epoch must again be
strictly in the future and after the rollout.

Once one block exists at or past E\*, the fold that produced it is consensus
history. Raising the constant afterwards is itself a consensus change with its
own rollout, and it orphans every block past E\*. Problems after E\* are fixed
forward.

The release anchor must not be re-baked at or past epoch 10010 while these
gates are still listed in `GATES_UNARMED_IN_CANONICAL_HISTORY`
(`check_gates_above_anchored_history` refuses it). Remove them from that list
in the commit that re-bakes the anchor above them.

## 7. Fill in at the tag, BEFORE tagging

| field | value |
| --- | --- |
| `FLAG_DAY_E10010` | 10010 |
| `utc(E*)` | 2026-12-03 02:51:19 UTC |
| epoch at which the armed build was cut for rollout | |
| `E* - that epoch` (at least `2 x (R + S + D)`, §1.1) | |
| wall epoch at the instant of the public `git tag` | |
| `t_replay` re-measured, host and date | |
| registered KES share of effective stake, epoch and source | |
| external verifiers confirmed to carry `kes::static_message` | |
| devnet rehearsal with control: commit, result | |
| release tag | |
| sha256 of the binary | |
| sha256 of the block log installed on the fleet | |
| height / `state_root` after replay (equal on every node) | |
| number of distinct views in the sweep of sibling runbook §4.3 (must be 1) | |
| commit carrying constant + tripwires + this file | |
