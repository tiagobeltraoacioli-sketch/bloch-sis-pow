# L2 program rollback: tabletop exercise (round 10, agent 169)

Status: paper exercise, 2026-11-02. Nothing was built, proved, signed or deployed, and no host was
touched. The kit under test is branch `codex/rollback-release-r7-20261102` f1f14196 (agent 126). The
native code is the fork candidate under it (27f195d7). The L2 code is
`codex/fork-candidate-l2-r7-20261102` e8feb2b. Every finding below cites file:line in those trees.
The corrected runbook is `RUNBOOK.md` on this branch. The brake design is `LOCAL-BRAKE-DESIGN.md`.

## Scenario

- The December fork activated the sparse guest at S = e10060 (Thu 2026-12-03 16:11 UTC).
- Sun 2026-12-06 15:40 UTC: L1 accepts a V3 settlement of L2 block N+1. The sparse guest accepted it,
  but the rules do not give it.
- 16:05: attestor 2's agent logs `refused-rebuild-differs` for the new withdrawal root.
- 16:25 (T0): attestor 2's operator messages the owner: "the rebuild from L1 does not match block N+1".
- Assumptions: the L2 is at about height 2,700 (agent 46's cadence of about 17 min per block from
  11-04), user transactions are on, and the bUSDC bridge V3 is live. Escrow is E BLCH. The examples
  use E = 10,000.

Times are UTC. One epoch is 960 s. Epoch E starts at 1786656679 + 960·E.

## The clock that matters

The first forged leaf can be claimed about 35 to 50 min after the settlement:
`LIMITS.delay_blocks: 64` (`l2_settlement.rs:998`) plus FFG finality of the record
(`record_finalized`, `l2_settlement.rs:489`). Here that is about 16:15 to 16:30, which is before or
right at T0. Every response that relies on "no forged leaf has been claimed yet" has already lost
the race when the owner hears about it. Today nothing on L1 can stop a claim. That is the brake
that does not exist (L1-10).

## Walk, minute by minute

| Clock | Who | What happens | Kit today | Gap |
|---|---|---|---|---|
| 15:40 | anyone | L1 accepts N+1. Settlement needs no authorization (`Transaction` has no signer, `l2_settlement.rs:856-860`) | — | — |
| 16:05 | attestor agent | Rebuild differs, so it refuses the root and alerts its own operator (`attestor_agent.py:340-346`) | G2 "attestors CRIT" | Only an alert to the attestor operator; the owner's monitor sees "no signature", which is normal for roots without a 100 BLCH leaf (`l2_monitor.py:1024-1026`). **G-8** |
| ~16:20 | anyone | Forged leaves mature. Small claims start within `max(10% E, 10 BLCH)` per aligned 2,880-block window | — | No brake. **G-1** |
| 16:25 T0 | owner | Receives the report. The owner is the only decision maker: no deputy, no quorum. It is a Sunday | Owner steps 1-2 | No named deputy, no on-call rota, no weekend plan. **G-11** |
| T0+2 | owner | Opens the monitor and `getl2settlement`: accepted number, `withdrawals.claimed`, `release_window.released_sat` | — | The runbook has no "first five minutes" step |
| T0+5 | owner | **Containment.** Today the kit pauses nothing. What the owner can actually do: stop the own settler (if it settled N+1, it keeps building on it), ask the 5 attestors for `/etc/bloch-l2-attestor/PAUSE`, ask bridge guardians to pause the vault, tell users to stop depositing | none | **G-5** |
| T0+10 → T0+90 | owner, build host | Confirm on two hosts with `bloch-l2-produce-dev reconstruct`. Find N, the last block that rebuilds identically, and who settled N+1 | G2 says "two independent followers rebuild" | The follower does not re-execute; the rebuild is `produce reconstruct` (`attestor_agent.py:26,257`). **G-4** |
| T0+90 | owner | **Decision: form.** The runbook offers "reset to N; if a leaf beyond N's tree was paid the reset refuses; still roll back" | Owner step 2 | Claims have run for over an hour, so the reset **will** refuse (`l2_settlement.rs:1710`). Without the reset the forged root stays the newest record forever (`l2_settlement.rs:1962-1967`) and keeps paying 10% per window after R. **G-2** |
| T0+90 | owner | Writes `reset.json` (number, commitment, 766-byte statement) | Owner step 2 | No tool. The commitment hashes the proof bytes (`l2_settlement.rs:905-913`). The follower log has the commitment but not the statement. `reset_head` never checks the commitment, so a wrong one freezes the L2. **G-6** |
| T0+95 | owner | Reads P, picks R ≥ P+270 | Owner step 3 | P must be the planned *publication* epoch, and both builders must pass the same P (it enters the armed commit via the manifest, `build.sh:38`). **G-7** |
| T0+100 → T0+3 h | 2 build hosts | `build.sh` ×2, copy B's `builder-a` to A, `compare-pos-release-builds.sh` | Owner steps 4-5 | Copy step missing (Low) |
| T0+3 h → T0+9 h | build host | `qualify.sh <armed>` | Owner step 6 | **Wrong command.** Without `--base-commit <swap release>` it diffs against b4a21fb6 (`qualify.sh:70`), finds HF1-3, KES and S as changed gates already at or before the replayed head, and records `gate-schedule FAIL` (`qualify.sh:362-393`). It must also run from the armed clone, because the armed commit exists only there (`qualify.sh:105`). **G-3** |
| T0+3 h → T0+10 h | L2 build host | Follower, settled RPC, produce-dev, attestor package against the armed native | Owner step 7, one line | No command, no NATIVE_LOCK step (89, item 6), no attestor package round (5 parties). Fallback pins are not final (126 finding). **G-9** |
| T0+10 h | owner | Sign, publish the release and the notice | Owner step 8 | agents/120 has a plan paragraph, not an emergency notice. **G-12** |
| Mon 12-07 ~02:30 | owner | Publication at about e10370. R ≥ e10640 → first 16:11 boundary is **e10690 (Thu 12-10 16:11)** | — | — |
| lead | owner | "Track upgraded stake" | Owner step 9 | No version signal exists on chain or in peer data. Only the own fleet plus operators' word. **G-10** |
| R−90 (Wed 12-09 16:11) | owner | Stake under 90%: "publish a later R instead" | Owner step 9 | Wrong logic: nodes already on the first release still activate at R. A later R means everyone upgrades **again** within a day. **G-13** |
| R (Thu 12-10 16:11) | all | Swap to the fallback. If the reset applies, the head moves to N | Checklist 7-10 | Nothing says how to check whether the reset applied, or what to do if it refused |
| R + minutes | owner | Restart the L2 side after a reset | — | Settler is halted on N+1 and needs rewind/reconstruct to N. The running follower appends a non-contiguous entry, and the settled RPC refuses it: "not contiguous from block 1" (`settlement_log.rs:208-209`) or "regressed" (`:182`). Both need a restart. Never rehearsed with real proofs (126 limits; L1-11). **G-14** |
| R + 1 proof | owner | Settlement resumes under the fallback. Lift brake, unpause attestors and bridge, notice | Owner step 10 | No resume order |

**What users lose meanwhile (T0 to R + one proof, about 4 days):**

- The L2 settled view freezes at N: `finalized` holds and `safe` closes (follower fail-closed). Transfers, swaps and bridge mints or burns on L2 do not settle. The DEX finality gate holds every quote at N.
- With a reset, every L2 transaction after N is undone. Own blocks go back to the spool and are re-included under the fallback (`produce rewind`). Blocks only the attacker held are gone. Exchanges that credited at `finalized` after N must reverse.
- Withdrawals: small claims of honest leaves at or below `count(N)` keep working unless a brake blocks them. Large claims need new attestor signatures, which stop while the attestors pause.
- Deposits on L1 cannot be refused by consensus. They wait in the inbox and mint after recovery, but they raise the escrow that the window drains, so the notice must ask users not to deposit.
- **Escrow at risk:** the window cap is per **aligned** window (`l2_settlement.rs:574`). From 16:20 Sunday to R on Thursday 16:11 is 3.99 days of native blocks, which touches 4 or 5 aligned windows depending on where the first claim falls: up to 1 − 0.9⁵ = **41%** of E (4,095 BLCH at E = 10,000), against 89's 34% for four. If R slips one day, up to 6 windows: 47%. (One window is 2,880 native blocks, so it lasts at least a day; missed slots stretch it.) **Without a working reset or fence the drain continues after R** at 10% per window: 65% after 10 windows, 96% after 30.

## Findings

| # | Sev | Finding | Evidence |
|---|---|---|---|
| G-1 | High | No way to stop forged small claims inside their roughly 40-minute maturity. The owner hears about it at about the time the first claim is possible | `l2_settlement.rs:998`, `:489`; attestor alerts go to the attestor operator |
| G-2 | High | Against an active attacker, the reset form (G2) is unreachable: one forged claim before R makes `reset_head` refuse, and the runbook's "still roll back" then leaves a frozen L2 whose forged root stays the newest record, so the escrow keeps draining at 10% per window after R. 89's "34% at four windows" assumes the rollback stops the drain | `l2_settlement.rs:1700-1716` (refusal), `:1962-1967` (newest record kept), `:1084-1094` (unknown state) |
| G-3 | High | Owner step 6 cannot pass: `qualify.sh` without `--base-commit` uses b4a21fb6, so every gate armed since then counts as changed and sits before the replayed head (gate-schedule FAIL). The `armed` forced set would also shift all of them. The armed commit exists only in `<out>/src`, so `qualify.sh` must run from that clone | `qualify.sh:41,70,105-112,178,266-290,362-393`; `build.sh:27-39` |
| G-13 | High | Step 9's "below 90%, publish a later R" does not undo the first release: upgraded nodes activate at the first R. Needs a decision table (go at ≥ 2/3 with margin; abort only if the same operators re-upgrade in < 1 day) | `params.rs:2743` is compiled; no runtime input (`params.rs:2738-2742`) |
| G-4 | Medium | G2 confirmation names the wrong tool. The follower checks L1 finality; the rebuild is `bloch-l2-produce-dev reconstruct --l1-follower … --rules mainnet` | `bloch-l2-native-follower.rs:490-513`; `attestor_agent.py:26,253-266` |
| G-5 | Medium | Nothing is paused. The own settler keeps settling on top of N+1 if it produced it, the settled RPC keeps serving withdrawal proofs for leaves after N, bridge guardians and attestors are not asked | `settler_v3.py` foreign path only (`:105-112`); attestor `pause_file` (`attestor_agent.py:66,303`) |
| G-6 | Medium | `reset.json` has no producer. The commitment is a hash over the proof bytes; the statement must come from the L1 block; `reset_head` checks number and identities 0-2 but not the commitment | `l2_settlement.rs:905-913`, `:1690-1716`; follower log has `commitment` but no statement (`bloch-l2-native-follower.rs:503-513`) |
| G-7 | Medium | `--publish-epoch` is part of the armed commit (manifest sha in the message), so two builders reading "the current epoch" separately get different armed commits. The 270-epoch check is against the declared P, not the actual publication | `build.sh:34-38`; `arm.py:59-61` |
| G-8 | Medium | Detection depends on an attestor operator relaying an alert. The attestor also rebuilds only for new withdrawal roots plus once a day. The owner has no own per-settlement rebuild | `attestor_agent.py:279-281,302-330`; `l2_monitor.py:1022-1060` |
| G-9 | Medium | Step 7 (L2 side) has no command: NATIVE_LOCK bump, L2 build, attestor package round, prover staging of the fallback ELF and keys. `fallback_program` pins must be final first (126: 44d4c9d7 is a Mac build; 142 rebuilt 3ad3a4f0) | 89 "L2 work" item 6; 126 "Finding" |
| G-10 | Medium | "Track upgraded stake" has no instrument: no client version in blocks or peer data | `rpc.rs:2152-2156` is the header format version only |
| G-14 | Medium | Post-R restart after a reset is unwritten and unrehearsed. The settler is halted on N+1. The running follower appends N+1' after the dropped entries, and the settled RPC refuses the log until both restart (by reading, not run) | `settlement_log.rs:176,182,208-209`; `bloch-l2-native-follower.rs:503-515` |
| G-11 | Low | Single decision maker, no deputy or rota; the scenario lands on a Sunday | — |
| G-12 | Low | No emergency notice template (120 has the December fork plan only); the compare step lacks the copy of builder B's output | agents/120 §7 |
| G-15 | Low | `build.sh` only WARNs when the base's `arm.py` differs or is absent; the December release must carry the kit, and a mismatch should stop the build | `build.sh:32` |
| G-16 | Info | If the emergency comes within about 24 epochs of S (G1/G4 at the swap), the forced qualification epoch (head − 24) is at or before S and the forced build breaks the compile-time order rule (rollback > next). Pass `--force-epoch` > S and copy the source after S + 17 | `qualify.sh:275`; `hard_forks.rs:154-157` |
| G-17 | Info | After a reset the settled RPC still serves removed blocks by hash (75's fail-open) — integrators must be told | DECISOES L1-11 |

## Decision points the runbook was missing

1. **D0, T0+5: contain without confirmation.** Every containment step is reversible, so it should not wait for proof.
2. **D1, T0+90: G2a or G2b.** G2a means N+1 was not settled by the own settler, so nobody but its author knows the state. G2b means the own settler settled it, so the own database holds the state. In G2b the L2 *can* continue on the off-rule state without a reset under the fallback. The cost is that the attestors refuse forever unless their package gets an exception list for N+1.
3. **D2, T0+90: can the reset still apply?** Check the `withdrawals.claimed` bitmap at or above `count(N)`. If any leaf is claimed and only today's code ships, the reset form is gone (G-2): plan for a frozen L2 and a continuing drain, and say so publicly.
4. **D3, R choice: loss vs. split risk.** Each 90 epochs of extra lead is one more window (about +6% of the remaining E). The first 16:11 boundary ≥ P_pub + 270 is the default.
5. **D4, R−90: go, or abort with a re-upgrade.** There is no "later R" without a second release.
6. **D5, R + 1 slot: did the reset apply?** Read `getl2settlement.accepted` (statement number = N?).
7. **D6, after R: lift the brake, unpause, review `D` and `B`.**
8. **Who absorbs the shortfall** (escrow − L2 supply after recovery). The runbook does not mention it.

## Recommendations (ordered)

1. **Before the December release, decide G-2.** Two consensus options, both inert, both in the December release:
   - **(a) Fence.** When the rollback's reset refuses, still drop withdrawal records above N (`withdrawals.retain(|r| r.l2_number <= N)`), so forged roots stop paying at R. The cost: honest leaves can then be claimed only through a later settlement, and with a frozen head there is none.
   - **(b) Forfeit-reset.** The reset applies even with claimed leaves beyond N. Their sats are recorded as a shortfall, and their claimed bits are cleared so the new chain's leaves can be paid. Watch for a double credit if an honest withdrawal in a dropped *own* block was paid and is re-included on rebuild; the rebuild must drop those withdrawals.
   Without one of them, G2a with an active attacker means losing E over weeks.
2. **Build the node-local brake** (`LOCAL-BRAKE-DESIGN.md`) into the December node release, off by default, filtered by leaf index. It does not stop a determined attacker unless the stake that runs it covers essentially every proposer slot. It does stop honest relayers in G2b, and it keeps the reset reachable there.
3. **Owner-run per-settlement rebuild** (a shadow attestor without keys) wired to `l2_monitor.py`, so detection does not wait for a person.
4. **Consider a longer small-claim delay** after the swap (e.g. 720 blocks, 6 h). It is a constant in the December rules and gives detection and the brake a head start. It slows honest withdrawals.
5. **Rehearse the reset crossing** with real proofs and the full restart order (settler rewind, follower, settled RPC, attestors) before December.
6. **Use the corrected `RUNBOOK.md`.**

## What I did not check

- No build, test, proof or private net (round 10 rules). Every finding is by reading code at the cited lines.
- The bridge V3 Ethereum side under a frozen L2: I did not trace whether the signers' `finalized` source halts on the forged settlement. I assumed yes, from the follower's fail-closed design.
- Own-stake share and per-operator stake: not used. G-13's thresholds are stated as fractions.
- `compare-pos-release-builds.sh` and `build-pos-release-container.sh` are read only for their argument shapes; 126 ran them.
