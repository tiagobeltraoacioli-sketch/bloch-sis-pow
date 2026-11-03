# L2 program rollback: emergency release runbook (v2, after the round-10 tabletop)

Status: PREPARED, NOT SCHEDULED. Everything here ships `L2_PROGRAM_ROLLBACK_EPOCH = u64::MAX`.
v1: agent 126, `codex/rollback-release-r7-20261102` f1f14196. v2: agent 169,
`codex/rollback-tabletop-r10-20261102`, after the walk in `TABLETOP-R10.md`. Every change from v1 is
marked **[v2]**.

What the rollback does (agent 89): from epoch R, L1 replaces `PROGRAM_NEXT` (the sparse-witness
guest) with `PROGRAM_FALLBACK` (the complete-witness guest, same next rules, same configuration).
Optionally, `ROLLBACK_HEAD_RESET` moves the settled head back to a named block N in the same
transition. It is a hard fork: a new release, with most stake upgraded by R.

**[v2] Know its limit before you need it.** The reset refuses if *any* withdrawal leaf beyond N's
tree was claimed before R (`l2_settlement.rs:1710`). Forged leaves can be claimed about 40 min after
their settlement (64 blocks plus finality). Without a reset, the newest withdrawal record is kept
forever (`l2_settlement.rs:1962-1967`). If that record is forged, it keeps paying up to 10% of the
escrow per 2,880-block window after R as well. Unless a fence or forfeit-reset ships in the December
release (TABLETOP-R10.md, recommendation 1), an attacker who claims once before R makes the L2
unrecoverable and the drain open-ended.

**[v3, agent 222] The December release carries the FORFEIT form** (`HeadReset.forfeit`, inert while
`ROLLBACK_HEAD_RESET` is `None`). With `"forfeit": true` in `reset.json` the reset applies even after
claims beyond N: the claims of leaves at or above C = N's withdrawal count are forgotten (so the new
chain's leaves at those indices pay), the forged roots stop paying at R, the target's root is recorded
again if retention had pruned it, and what the forged claims released stays released: that amount is
the **forfeit**, the escrow shortfall the owner must cover (agents/222-g2-fence.md). Use it for G2a
only. In G2b keep the plain form and the brake: a forfeit there forgets honest paid claims whose
withdrawals the rebuild re-includes, and pays them twice. No fence (longer claim delay) ships: to keep
the plain reset reachable it would have to exceed the whole response time, about 4 to 5 days, for
every honest withdrawal.

## Files

| File | Role |
|---|---|
| `arm.py` | Deterministic arming of R (and S checked), optional `ROLLBACK_HEAD_RESET`, both L2 gates into `RELEASE_ARMABLE`. Refuses: R <= S, S <= 8710, lead < 270, base without the swap, candidate pins, rollback already armed, malformed reset. Writes `manifest.json` |
| `build.sh` | Clone base, `arm.py`, commit with fixed author and the base's dates, canonical container build, `RELEASE.txt`. **[v2]** The armed commit exists only in `<out>/src` |
| `TABLETOP-R10.md` | **[v2]** The exercise, the findings, the decision points |
| `LOCAL-BRAKE-DESIGN.md` | **[v2]** The node-local brake; **[v3]** built by agent 222: `bloch-pos run … --l2-brake-key <pk>`, signed file `l2-brake.json` + `.sig`, `bloch-pos l2-brake sign/check` |

## Before the December release ships (prerequisites) [v2]

Each item is a blocker for this runbook being usable in hours rather than days.

| # | Prerequisite | Why |
|---|---|---|
| P1 | The December release contains this kit (126's commits, this file) | `build.sh` takes `arm.py` from the base; a mismatch should stop the build (`build.sh:32` only WARNs) |
| P2 | Final `PROGRAM_FALLBACK` pins from a pinned-container build (126 finding; 142's `3ad3a4f0…`) and the fallback ELF and keys staged on the prover host | No guest build during an emergency |
| P3 | Settler config already carries `fallback_program` at the December install | It is used only when L1 reports the fallback (`settler_v3.py:1036-1041`, `program_of`) |
| P4 | Decision on fence or forfeit-reset (TABLETOP-R10.md, recommendation 1) | Without it, G2 with an active attacker is unrecoverable |
| P5 | Decision on the node-local brake; if yes, in the December node release | Only thing that can hold claims inside the 40-minute window |
| P6 | Owner-run per-settlement rebuild alerting the owner directly | Detection today depends on an attestor operator relaying |
| P7 | A `reset-target` tool: L2 number N → `reset.json` (statement from the L1 block, commitment recomputed and matched against two followers' settlement logs) | `reset_head` does not check the commitment; a wrong one freezes the L2 |
| P8 | Reset crossing with real proofs, including the restart of settler, followers, settled RPC and attestors | Never run (126 limits; L1-11) |
| P9 | Archival copy for `qualify.sh --source` refreshed weekly on the build host, with `--expect-slot/--expect-root` from two archivals | Saves hours (agent 40) |
| P10 | Operator contact list with each operator's stake, a pre-agreed upgrade time, and a named deputy for the owner | No on-chain version signal exists |
| P11 | Three notice templates: incident, release, recovery (below) | |

## Go / no-go signals

| # | Signal | Detected by | Confirm before GO | Form |
|---|---|---|---|---|
| G1 | Sparse guest refuses a valid block, or its proof fails, at the same L2 block repeatedly | `settlement_age` CRIT, `events[settler]`, `l2_proof_cost` CRIT, settler log `proof failed` | Same artifact fails on a second prover host; the complete guest executes the same block | No reset |
| G2a | L1 accepted a settlement that rebuilds differently, **not** settled by the own settler (the state is known only to its author) | `foreign_settlements[*]` CRIT, settler halt (refused rebuild), attestor `refused-rebuild-differs`, owner rebuild (P6) | **[v2]** `bloch-l2-produce-dev reconstruct` on two hosts with independent followers both refuse at N+1; N named | Reset to N if still possible (check below); otherwise fence or forfeit-reset if shipped (P4); otherwise see "Reset impossible" |
| G2b | **[v2]** Same, but the own settler settled N+1 (the own database holds the state) | Same, minus `foreign_settlements`; own settler log `accepted` at N+1 | Same | Reset to N, or no reset and continue on the off-rule state (attestors then need an exception for N+1) |
| G3 | Soundness bug reported, not exploited | Out of band; watch `claims_vs_withdrawn`, `escrow_conserved`, `release_window` | Reproduced against the pinned ELF | No reset |
| G4 | Program on L1 after the swap is not the release's sparse ELF | `l1_l2_identity` CRIT, `l1_gates_vs_l2_build` | `getl2settlement.program` vs the release manifest | No reset |
| N1 | L1 finality stalled or nodes split | `l1_finality_lag`, `l1_stuck[*]`, `l1_height_spread`, `l1_accepted_agreement` | | NO-GO: fix L1 first |
| N2 | Settler, prover host or DA down | `heartbeat`, `unit[*]`, `da_balance[*]`, `memory`, `disk[*]` | | NO-GO: operational fix |
| N3 | Fallback cannot prove at the current height | `l2_export_runway`, L2 height (81: past about 6,200 needs a larger prover) | | NO-GO unless a larger prover is ready |
| N4 | Proofs slow but succeeding | `l2_proof_cost` WARN | | NO-GO: tune the prover (93) |

## Phase A: contain (T0 to T0+30 min). Do not wait for confirmation [v2]

Every step here is reversible. Do it on the first credible report.

A1. Stop the own settler (stops own settlements on top of a wrong block, and own proofs):

```
sudo systemctl stop bloch-l2-mainnet-settler.service
```

A2. Ask each of the five attestor operators to pause signing:

```
sudo touch /etc/bloch-l2-attestor/PAUSE
```

A3. If the brake exists (P5), engage it on every own RPC node first, then on own validators, with
`claims_from_leaf_index` = the withdrawal count of the last block you believe honest (best guess now,
refined in B3), `settlements` = true for G2a, `until_epoch` = now + 450. See `LOCAL-BRAKE-DESIGN.md`.
**[v3]** Write `l2-brake.json` (exact keys: `version` 1, `chain_id` 700770, `claims_from_leaf_index`,
`settlements`, `until_epoch`, `reason`), sign it once with the brake key, copy both files into each
node's data dir. Each node must have been started with `--l2-brake-key <brake public key file>` (the
file outside the data dir, root-owned); without the flag the brake is disabled. Confirm with
`getmempoolinfo` → `l2_brake.state` = `on` on every own node. A file that does not verify is ignored
(`state` = `refused`, a CRIT line every slot).

```
bloch-pos l2-brake sign --genesis <genesis.json> --brake l2-brake.json --key <brake.sk> --pubkey <brake.pk> --out l2-brake.json.sig
```

```
bloch-pos l2-brake check --genesis <genesis.json> --brake l2-brake.json --sig l2-brake.json.sig --pubkey <brake.pk> --epoch <current epoch>
```

A4. Ask the bridge guardians to pause the Ethereum vault (no new USDC deposits into a frozen L2).

A5. Post the incident notice (template I below). Ask users not to deposit to the L2 escrow.

A6. Record the L1 view now, from two RPCs:

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}' http://80.240.16.185:8080
```

```
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getl2settlement","params":[]}' http://199.247.22.8:8080
```

Keep `accepted`, `withdrawals.claimed`, `release_window` and `program`.

## Phase B: diagnose (T0+30 min to about T0+2 h)

B1. Rebuild from L1 on two hosts with independent followers. **[v2]** The follower checks L1
finality only; the rebuild is `produce reconstruct`. Values for the mainnet arguments are in
`deployment/mainnet/attestor/attestor_lib.py:20-21`:

```
bloch-l2-produce-dev reconstruct --target <new-empty-dir> --l1-follower <follower-native-state> --timestamp-rule 1:<L2_GENESIS_TIME>:30000 --rules mainnet --domain <L2_DOMAIN> --genesis-time <L2_GENESIS_TIME>
```

It refuses at the first off-rule block: that is N+1. N is the last block that rebuilds identically.

B2. G2a or G2b: was N+1 settled by the own settler? Look for its `accepted` event with N+1's hash:

```
sudo journalctl -u bloch-l2-mainnet-settler.service --since "<T0 - 6 h>" -o cat
```

B3. **Can the reset still apply?** Let C = N's withdrawal count. If any bit at or above C is set in
`withdrawals.claimed` (A6), `reset_head` will refuse at R. Re-check this every hour until R.

B4. Decision D1, the form:

| Case | Reset still possible | Form |
|---|---|---|
| G1, G3, G4 | — | Rollback, no reset |
| G2a | yes | Rollback with reset to N; keep claims ≥ C held (brake) until R |
| G2a | no, forfeit shipped (December release) | **[v3]** Rollback with the FORFEIT reset to N (`"forfeit": true`); the drain stops at R; the shortfall is what the forged claims released |
| G2a | no, neither shipped | See "Reset impossible" |
| G2b | yes | Rollback with reset to N (recommended), or no reset and continue on the off-rule state |
| G2b | no | No reset; continue on the off-rule state; attestor package with an exception for N+1; decide the shortfall. Not the forfeit form: it would forget honest paid claims that the rebuild pays again |

**Reset impossible (G2a, nothing shipped).** The forged root stays the newest record after R and
keeps paying up to 10% of the escrow per window. Nobody but the author can settle a successor. Roll
back anyway (it removes the sparse guest, so no new forged settlements), and publish plainly that
the L2 is frozen and the escrow exposed. Start the design of a second emergency fork with a fence
at N. That needs its own 270-epoch lead.

B5. For a reset: produce `reset.json` for N (P7). **[v3]** Add `"forfeit": true` only in the G2a
forfeit row of D1; `arm.py` refuses any other value than a JSON boolean and defaults to `false`. Without the tool, by hand: the commitment of block
N is in the follower's settlement log (`<status stem>.settlements.jsonl`, field `commitment`, entry
`l2_number` = N) on **both** hosts, and must be equal. The 766-byte statement is the bytes after the
33-byte header of the `0x13` transaction in the L1 block named by that entry's `native_block`.

## Phase C: release (about T0+2 h to T0+10 h)

C1. Choose P_pub, the epoch at which you expect to **publish** (now + build + qualification, about
40 epochs), and R. **[v2]** R = the first epoch at 16:11 UTC (epoch ≡ 70 mod 90) at or after
P_pub + 270. Every extra 90 epochs adds one release window of exposure. Write S, R, P_pub down once:
**both builders must use the same three numbers** (P_pub enters the armed commit through the
manifest).

C2. On build host A (repeat on host B with B's directory names):

```
scripts/hf-release/l2-rollback/build.sh <swap-release-commit> <new-dir-A> --swap-epoch <S> --rollback-epoch <R> --publish-epoch <P_pub> --head-reset <reset.json>
```

Without a reset, leave out `--head-reset <reset.json>`.

C3. **[v2]** Copy B's builder output next to A's, then compare:

```
rsync -a <host-B>:<new-dir-B>/builder-a/ <new-dir-A>/builder-b/
```

```
<new-dir-A>/src/scripts/compare-pos-release-builds.sh <new-dir-A>/builder-a <new-dir-A>/builder-b
```

Both `RELEASE.txt` files must show the same `armed_commit`.

C4. **[v2]** Qualify from the armed clone, against the shipped swap release as the base:

```
<new-dir-A>/src/scripts/hf-release/qualify.sh <armed-commit> --base-commit <swap-release-commit> --source <archival-copy-dir> --baseline-bin <swap-release-bloch-pos> --expect-slot <slot> --expect-root <root>
```

Without `--base-commit`, the default base b4a21fb6 makes every gate armed since then count as
changed, and the gate-schedule check fails (`qualify.sh:362-393`). With it, the only changed gate is
`L2_PROGRAM_ROLLBACK_EPOCH`. If the emergency is less than one day after S, add
`--force-epoch <S + 1>` and use a source copied after epoch S + 17. The expected verdict is
`VERDICT: PASS`. A forced post-activation replay that stops with "did not re-apply" is the expected
shape (agent 40).

C5. L2 side, in parallel with C4: build follower, settled RPC, produce-dev and the attestor package
against `<armed-commit>` (NATIVE_LOCK set to the armed native lock). Hash on two hosts. Ship the
attestor package to the five operators. **[v2]** Not scripted yet: follow the release recipe of the
December L2 release with the native commit replaced.

C6. Sign the node and L2 releases. Before publishing, read the current epoch again. If it is past
P_pub, the real lead is shorter than the manifest says: if R minus now is under 270, rebuild with a
later R (back to C1).

C7. Publish the release and notice R (template R below).

## Phase D: the lead (publication to R)

D1. Track upgrades: own fleet by host, external operators by their confirmation, weighted by each
operator's stake from the validator set (P10). **[v2]** No on-chain signal exists.

D2. Every hour: B3 (is the reset still possible?), `release_window.released_sat`, escrow.

D3. Decision D4 at R − 90 (one day before):

| Upgraded stake | Action |
|---|---|
| ≥ 90% | Go |
| ≥ 2/3 with margin, < 90% | Go. Non-upgraded nodes stop at R and must upgrade; tell them now |
| < 2/3 | Finality will stall at R. **[v2]** A "later R" is a *second* release that every upgraded node must install before the first R, because a node on the first release activates at the first R whatever happens. Choose: push the own fleet and the operators to ≥ 2/3, or publish the re-release and get it installed in under a day |

## Phase E: at R

E1. `getchaininfo.hard_forks.l2_program_rollback` = R; `getl2settlement.program` = fallback pins
from the first block of R.

E2. **[v2]** Decision D5: did the reset apply? `getl2settlement.accepted.statement` decodes to
L2 number N and `accepted.commitment` equals `reset.json`. If not, the reset refused: go to "Reset
impossible" or G2b without reset.

E3. A non-upgraded node stops at R's first slot with a state-root refusal. Point its operator at the
release.

## Phase F: restart and resume [v2]

Order matters: the settled RPC refuses a follower log that is not contiguous from block 1
(`settlement_log.rs:208-209`), and after a reset the running follower appends N+1' after the
dropped entries.

F1. Without a reset: start the settler. It re-proves the block in flight (`l2-block-reproved-for-program`, no rewind).

```
sudo systemctl start bloch-l2-mainnet-settler.service
```

F2. With a reset (rehearse first, P8):
1. Settler stays stopped. Rebuild its database from L1 up to N (B1's command into a new directory),
   check the rebuilt head hash equals N's, move the old database aside and put the rebuilt one in
   its place. Own user transactions of the dropped blocks go back to the spool (the settler's
   `foreign_recovery` code does these steps, `settler_v3.py:105-112`; whether it triggers on an
   accepted head that moved back is untested).
2. Start the settler. Wait for the first settlement N+1' to be accepted and finalized.
3. Restart follower A and B, then the settled RPC:

```
sudo systemctl restart bloch-l2-mainnet-follower.service
```

```
sudo systemctl restart bloch-l2-mainnet-rpc.service
```

4. Attestors: install the package (C5), restart their follower, rebuild, remove `PAUSE`.

F3. Lift the brake (delete `l2-brake.json` on every own node), ask the guardians to unpause the
vault once the bridge signers see `finalized` past N+1'.

F4. Monitor: `l1_l2_identity` OK with the fallback pins, `settlement_age` normal after one proof,
`escrow_conserved` true, followers' `active_program.elf_keccak` = fallback.

F5. Post the recovery notice (template F). Decide `D` and `B`, and who covers the shortfall
(escrow minus L2 supply).

## Operator checklist (validators, RPC, L2 operators)

Before R:
1. Verify the release: `RELEASE.txt` armed commit, two builder digests equal, signature.
2. Stop the node cleanly, replace `bloch-pos`, start. Do not wipe data (a wiped node needs a refill
   from a healthy node: `ERR_WS_REQUIRE_CHECKPOINT`).
3. `getchaininfo.hard_forks`: `l2_program_rollback` = R; `l2_next_program` = S unchanged.
4. `getl2settlement.program_schedule` lists exactly `{epoch: R, fallback pins}`.
5. L2 operators: install the release's follower, settled RPC, produce-dev and attestor package.
6. Confirm the upgrade to the owner with your stake's validator indices.

At R: see Phase E. After R: see Phase F.

## Notice templates [v2]

**I, incident (A5).** "L2 settlement is paused. A settlement on L1 does not match an independent
rebuild of the L2. Do not deposit to the L2 until further notice. L1 is not affected. Withdrawals of
L2 blocks up to <N> are <unaffected / held>. Next update by <time> UTC."

**R, release (C7).** "Emergency release <version> (armed commit <hash>) replaces the L2 settlement
prover at epoch <R> (<date> 16:11 UTC). Form: <no reset / reset to L2 block N>. All validators and
L2 operators must upgrade before <R − 90 date>. A node that does not upgrade stops at epoch <R>.
Reason: <G-code and one line>. What users lose until then: <list>."

**F, recovery (F5).** "Settlement resumed under the fallback prover at <time>. <With a reset:
transactions after L2 block N are undone; exchanges must reverse credits after N; the RPC may still
serve removed blocks by hash.> Escrow position: <escrow> BLCH against <L2 supply> BLCH."
