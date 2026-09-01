# What a devnet run in this repository is worth

**Measured 2026-09-01.** Three idle 2-core/8 GB Edgevana boxes (45.76.82.134,
45.76.138.60, 45.32.154.137 — the classic hosts, empty since the migration),
release and debug builds of `a381159f`, three validators per run, 1 000 ms
slots, throwaway `keygen` material, `127.0.0.1` only. Nothing here touched the
live fleet or any key material.

This document exists because the same three-node cold-start measurement was
reported by three different agents as passing, failing, and coin-flipping, and
because two runs were reported fracturing on an idle host with no external
cause. Both reports are true. They are about **different transports**.

Harnesses, all runnable by a third party from this repo:

| script | what it measures |
|---|---|
| `scripts/devnet-fratura.sh` | one no-fault run; `TRANSPORT=devnet\|libp2p`, `DECLARED=` more validators than launched, `POLL_SECS=` an RPC arm |
| `scripts/devnet-fratura-repete.sh` | R concurrent runs, so the answer is a **rate** and not an anecdote |
| `scripts/devnet-fratura-veredito.py` | the verdict, read from each node's `blocks.log` — never from RPC |
| `scripts/devnet-particao.sh` (existing) | partition-and-heal, control and split arms |

---

## The boundary, in one table

| transport | trustworthy to | evidence |
|---|---|---|
| `--transport devnet` (the default, and what the 63-node fleet runs) | **at least 1 869 slots / 58 epochs**, no observed self-fracture | 8 no-fault arms, every one 100 % identical across all three nodes, zero reorgs, zero conflicting slots |
| `--transport libp2p` (what `tests/cold_start.rs` runs, and what `~/bloch-rollout/rollout-release/travessia-libp2p.sh` proposes moving the fleet to) | **nothing at all, at any length** | **8 self-fractures in 9 runs** on idle boxes, with no external cause — first conflicting slot anywhere from 128 to 483 |

**Any fracture, on either transport, is permanent.** This is the part that
matters more than either row, and it is why a fractured run tells you nothing
about what caused it: see §3.

---

## 1. The devnet TCP mesh does not fracture on its own

Eight no-fault arms, three validators each, full mesh on one host. Every one
finished with all three `blocks.log` files byte-identical, `REORG=0`,
`reject=0`, and zero slots where two nodes held different blocks.

| arm | condition | slots | result |
|---|---|---|---|
| A | release, idle box, no observation at all | 599 | 599/599/599 identical, 17 epochs justified |
| B | release + `getchaininfo` every 2 s (894 requests) | 599 | identical |
| C | release, idle, repeat of A on another box | 899 | identical, 27 epochs justified |
| D | **debug** build (unoptimised, the `cargo test` binary) | 599 | identical |
| E | `DECLARED=6`, only 3 launched — the inactivity leak armed, `justified e0` for 13 epochs | 599 | identical (346 blocks; half the proposer slots are absent validators) |
| F | release + a poller sweeping `getblockbyslot` for **every** slot on every pass — **89 742 requests** across the consensus threads | 599 | identical |
| G | release + four busy loops saturating both cores (load 4.00 on 2 cores) | 599 | identical |
| I | release, idle, long run | **1 869** | identical, 57 epochs justified, load 0.00 |

Three of the standing hypotheses die here.

**Observation is not the cause.** Arm F put 89 742 RPC round trips through the
single consensus thread — thirty times the ~3 000 that an earlier agent's test
was found to be issuing — and the chain stayed identical. One `getchaininfo`
costs tens of microseconds on a three-node devnet: `active_roster()` is
memoised on the state generation (`engine.rs:423-432`), `head_state_root()` is
an O(1) map lookup (`engine.rs:716-721`), and the only linear term is
`height_of` scanning `self.chain` (`engine.rs:1952-1957`). That earlier agent's
finding was real for its own conditions; it does not generalise, and it is not
what these two runs saw.

**Load is not the cause.** Arm G ran the three nodes against four spinning
loops on two cores. The nodes use about 1 % of a core each; two-times
oversubscription does not move them.

**The debug build is not the cause.** Arm D is the exact binary
`CARGO_BIN_EXE_bloch-pos` gives a test.

## 2. The libp2p transport does fracture on its own

Same harness, `TRANSPORT=libp2p`, same idle box, no partition, no joining node,
no polling.

Arm H, slot 599:

```
node      height  head_slot  head_id   proposers(applied)
node0        507        599  15cbef86  {0: 117, 1: 53,  2: 337}
node1        345        599  6e6a97f0  {0: 26,  1: 241, 2: 78}
node2        507        599  15cbef86  {0: 117, 1: 53,  2: 337}

node0 vs node1: DIVERGE at block index 157 — common ancestor slot 159
slots where two nodes hold DIFFERENT blocks: 150 — first at slot 195
node1: justified e5, finalized e3     node0/node2: justified e16, finalized e14
```

That is the reported symptom exactly: identical for a while, then three heights
where there was one, and justification frozen on the node that fell off. Note
the shape of the proposer counts — after the split, node1's chain is 241/345 =
70 % its own blocks, and node0/node2's is dominated by v2's. **Each side is
extending its own branch almost alone**, which is why post-fracture heights
grow at roughly each node's stake share (1 : 2 : 3 here). Any report whose
three heights grow in the stake ratio is describing a total partition, not a
slow node.

It is **intermittent**, which is precisely how the same test came to be measured
as passing, failing, and coin-flipping. Nineteen runs, no fault injected, load
printed at the start and end of every batch:

| runs | peer scoring | fractured | first conflicting slot |
|---|---|---|---|
| H, H2, L (sequential, two boxes) | on | 2 of 3 | 195, —, 483 |
| `repBASE` ×3 (concurrent, box 45.76.82.134, load 0.00) | on | **3 of 3** | 256, 480, 418 |
| `repBASE` ×3 (concurrent, box 45.76.138.60, load 0.00) | on | **3 of 3** | 128, 359, 198 |
| **total** | **on** | **8 of 9** | |
| J, `repNOSC` ×3, `repNOSC` ×3 | **off** (`BLOCH_P2P_NO_SCORE=1`) | **0 of 7** | — |
| `repNIC` ×3 | **on**, but `NotInCommittee` reported as `Ignore` (`BLOCH_ATT_NOTINCOMMITTEE_IGNORE=1`) | **0 of 3** | — |

The `repBASE` and `repNOSC` arms ran **concurrently, on the same box, from the
same binary**, so the contrast between them is not a difference of machine,
minute, or build.

### The cause: the mesh scores its honest peers

Three arms, one variable at a time:

- turn gossipsub's peer scoring **off** entirely → the fracture is gone (0 of 7),
  and turning it back on restores it (3 of 3 on the same box minutes later);
- leave **every score term armed** and change one thing — report the
  `NotInCommittee` refusal as `Ignore` instead of `Reject`, so it stops counting
  against the sender — → the fracture is gone as well (**0 of 3**, all three at
  the full height 599).

So it is not scoring in general. It is one refusal reason, reported as a peer
penalty, against peers that did nothing wrong.

The mechanism, in the code: on a healthy three-node chain each node refuses a
large share of its peers' **honest** attestations as `NotInCommittee` (§5 has
why), and `apply_decision` maps that refusal to gossipsub
`MessageAcceptance::Reject`, which is P4 `invalid_message_deliveries` — weight
−100 on topics weighted 0.4/0.5, against `graylist_threshold = −400` and
`publish_threshold = −200` (`p2p.rs:521-597`). Three or four such refusals
inside one 60 s `decay_interval` are enough. The symptom in the logs is node0's
`p2p: publish blocks: NoPeersSubscribedToTopic` — a node that has peers,
connected, and no longer has anyone to publish to. Then §3 makes the resulting
split permanent.

The `NotInCommittee` arm ran on a box carrying another agent's work (load ~1.0
to 1.5) while the baseline batches ran at load 0.00. That difference is in the
conservative direction — arm G in §1 shows load does not by itself fracture
anything, and if it did it would push this arm toward fracturing, not away.

IP colocation is **not** the term at fault here: `ip_colocation_factor_threshold`
is 3.0 and at N=3 each node has two peers on `127.0.0.1`, so that penalty is
zero. (`ensaio-colocacao.sh` in the rollout-release directory studies a
different, real hazard at 9 nodes per IP; this is not it.)

The devnet mesh has no scoring at all, which is exactly why §1's eight arms
never lost a frame.

## 3. Whatever splits it, it never comes back

Run `scripts/devnet-particao.sh` at n=3 (halves `{0}` and `{1,2}`), split at
slot 60, heal at 180, stop at 360, on the **devnet** transport:

```
CONTROL (no split):  phase3-heal CONVERGED, 3/3, height 352 each
SPLIT:               phase3-heal DIVERGED
  node0  height=126  blocks_known=286  just=e1   fin=e0
  node1  height=321  blocks_known=388  just=e10  fin=e9
  node2  height=321  blocks_known=388  just=e10  fin=e9
```

Read `node0` again: it **holds 286 blocks** — it has the majority branch — and
it is still stuck at height 126 three minutes after the network healed. Two
independent mechanisms, either of which alone is enough:

1. **Fork choice cannot leave its own justified subtree.** `forkchoice_head`
   descends from `self.state.finality().justified.root`
   (`engine.rs:1298-1307`). Once two nodes justify different roots, neither can
   ever select a head on the other's branch, however many of the other's blocks
   it is holding. That is node0's `just=e1` against their `just=e10`.
2. **Sync is a slot watermark answered from the server's canonical log.** The
   only request either transport has is `get_blocks{after_slot}`
   (`net.rs:237-241`, `p2p.rs` `SyncRequest::GetBlocks`), and it is served by
   `Store::blocks_after` reading `blocks.log` and filtering `header.slot >
   after_slot` (`store.rs:166-207`). There is **no fetch-by-root** and **no
   re-gossip**: a block is published once, and if it is missed it can only ever
   come back if it sits at a slot *above* the asker's own head on a peer's
   *canonical* chain. Two branches over the same slot range are unreachable to
   each other by construction.

So the cost of one lost frame is not one round trip. It is the run.

This is also the in-repo explanation for an operational fact the runbooks
already record: a diverged validator does not rejoin on its own, and the
recovery is to copy the canonical `blocks.log` onto it.

## 4. Does it reach 63 nodes?

**The libp2p self-fracture does not reach it today**, because the fleet does not
run libp2p: the fleet's own `g4/start.sh` launches every validator with
`--transport devnet`. The fleet has been finalising ~99 % of epochs since epoch
1400, which is consistent with §1.

**It would reach it the day the fleet crosses.** There is a live plan to move
the 63 validators onto libp2p
(`~/bloch-rollout/rollout-release/travessia-libp2p.sh`,
`bootnodes-20260831/flagday-libp2p.sh`, `RUNBOOK-TRANSPORTE.md`). That crossing
would take the fleet from a transport that did not fracture once in eight
no-fault arms to one that fractured eight times in nine — and §3 says the
result would not heal. Nothing here says the crossing is wrong; it says the
scoring path in §5 has to be settled first, and that the crossing rehearsal
(`ensaio-transporte.sh`) should include a **no-fault** arm long enough to see
this, because the defect needs no injected fault at all.

**§3 does reach 63**, and is not a small-N artifact: neither the
justified-subtree rule nor the slot-watermark sync has any dependence on the
validator count.

Two things genuinely are small-N artifacts and should not be reported as
network defects:

- **Committees.** `epoch_committees` cuts the shuffled eligible set into
  `SLOTS_PER_EPOCH = 32` contiguous chunks (`committees.rs:275-352`). At N=3
  that is one validator each in slots 0, 1, 2 and an **empty committee in the
  other 29 slots** — three attestations per epoch for the whole network. There
  is no minimum committee size.
- **Stake.** Devnet stakes are `(i % 3 + 1) × 200 000 BLCH` (`main.rs:705-706`),
  so at N=3 one validator holds half the stake and proposes half the slots.

## 5. Why honest peers are being scored at all

On a healthy three-node chain, every node rejects a large share of its peers'
honest attestations as `NotInCommittee` — 48 of them on node0 in arm A, 90 in
arm C. The two seeds disagree by one epoch:

- consensus: `CommittedState::seed_for_epoch` uses `back = 1 + lookahead` with
  `lookahead = 0` below `ANCESTRY_SEED_ACTIVATION_EPOCH` (`u64::MAX`), i.e.
  seed(E) = `boundary_mixes[E-1]` (`transition.rs:1554-1568`);
- the node's gossip judge: `Engine::seed_for_attestation` subtracts
  `MIN_SEED_LOOKAHEAD_EPOCHS = 1` and then reads the mix at the close of
  `X - 1`, i.e. seed(E) = `boundary_mixes[E-2]` (`engine.rs:849-854`,
  `engine.rs:793-825`).

The transition re-derives its own committee from the parent state, so **this is
not a consensus divergence and it is not a flag day**: a wrongly-judged
attestation is one that never enters the loose pool, not one that changes a
state root. On the devnet mesh it costs a little fork-choice weight and nothing
else, which is why §1 never fractured. But `apply_decision` maps that
`Reject` to a peer penalty (`engine.rs:1874-1877` → gossipsub
`MessageAcceptance::Reject`), and on libp2p that is P4
`invalid_message_deliveries` with weight −100 on a topic weighted 0.4 against a
`graylist_threshold` of −400 (`p2p.rs:521-597`). Honest peers are being scored
for it. The module header three files away names exactly this hazard: *"the
2026-08-07 mesh collapsed twice from scoring honest peers"*.

**Not changed here.** Which seed is right is a consensus-adjacent decision, and
the founder's rule is that such a thing is reported before it is touched. What
this branch adds is two diagnostic switches, both off by default, both devnet
only:

- `BLOCH_P2P_NO_SCORE=1` — start the swarm with no peer scoring
  (`p2p.rs`, `build_swarm`);
- `BLOCH_ATT_NOTINCOMMITTEE_IGNORE=1` — report that one reason as `Ignore`
  instead of `Reject`, changing nothing else (`engine.rs`, `apply_decision`).

## 6. Rules for the next agent

1. **Say which transport.** A devnet result without `--transport` named is not
   a result. They behave differently, and this is the whole reason three agents
   disagreed.
2. **A libp2p run proves nothing on its own, at any length.** It fractures
   intermittently with no external cause — the earliest first-conflict measured
   here was slot 128, the latest 483, and one run in nine did not fracture at
   all. Report the rate over repeats (`devnet-fratura-repete.sh`), never a
   single run.
3. **Read the verdict from `blocks.log`, not from RPC.** `getchaininfo`'s
   `height` is `chain.len() - 1` and its `blocks_known` is `self.blocks.len()`;
   a node with `blocks_known` far above `height` is not behind, it is forked
   and stuck (§3). `devnet-fratura-veredito.py` compares the persisted chains.
4. **One workdir and one port base per run.** Two overlapping launches on the
   same ports and the same `--data-dir` destroy each other silently and look
   exactly like a fracture. This was hit once during this very investigation.
5. **`timeout` is not installed on the founder's Mac**, and that Mac is
   routinely running several agents' `cargo build` at once — it is not an idle
   box. Measure on a box you have just checked `uptime` on, and print that load
   in the result.
6. **Do not report a fracture as a cause.** Once split, the nodes cannot
   reconverge (§3), so the end state looks the same whether the trigger was a
   partition, a dropped frame, or a duplicated devnet. Only the run's own
   first-divergence slot and the common ancestor say anything.
