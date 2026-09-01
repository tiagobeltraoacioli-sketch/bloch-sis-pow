# Plan revision 2 — Genesis-4 exchange integration

Written 2026-09-01 10:00 UTC, PMO. **Supersedes `PLANO-5-SETEMBRO.md`**, which
was written 2026-08-31 and predates the transport measurement. Read
`WS0-TRANSPORT-AND-THE-EXCHANGE-NODE.md` first; it is why this revision exists.

## The clock

- **Deadline: 2026-09-05 07:07:19 UTC** — the weak-subjectivity window closes.
- **Now: 2026-09-01 10:00 UTC. 93 hours remain.**
- Cold sync, measured today, with the (unmerged) catch-up fix: **~26 hours**.
  Latest safe start **2026-09-04 05:07 UTC** — **67 hours of slack**.
- Without the catch-up fix, the same measurement suggests ~52 hours. Latest safe
  start **2026-09-03 03:07 UTC** — still 41 hours of slack.

**Sync time is not the binding constraint.** There is room. The constraint is
that we have not published a peer list, a binary, or a correction — and every
one of those is a merge or an email, not engineering.

## What changed since revision 1

Revision 1's Phase 1 was: bring ≥2 fleet nodes up on `--transport libp2p`, hand
the exchange the peer list. **That is now known to be unsafe.** The two
transports cannot interoperate; two fleet nodes switched to libp2p *leave* the
63-validator devnet chain, and the exchange would sync to a 3-node island. The
deliverable would have been a fork.

Revision 1 was not wrong about the deadline or the ordering. It predates the
measurement. **The devnet bootnode list that already exists is the correct
answer, and it is a merge away.**

---

## Phase 0 — today, 1 September. No merges, no code, no dependencies.

**0.1 — Send the settlement correction.** The text is written
(`validator-ops`, 1,070 lines). The wrong sentence is
`main:docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md:190-192`. Lead with
the timing regression (16–32 → 32–48 min), then the unfloored quorum denominator,
then that `finalized` is not a latch, then the §1.5 caveat that our two public
archival nodes run the same stale binary and so are not independent.
**No dependency. Highest value per hour in this document.** See WS5 §1.

**0.2 — Delete `deploy/fly/README.md` and banner the four PoW-era docs.** It is
on public `main`, it documents the Genesis-1 PoW node, and the infrastructure it
targets was destroyed on 23 August. WS5 §2.3 lists the minimal commit. Do not
banner the Fly file; delete it.

**0.3 — Fix `main.rs:148-150`.** Our own CLI tells the exchange that "anything
reachable from outside a firewall wants" `--transport libp2p` — which today means
zero peers and a private fork. It ships *in the binary*, so no doc edit reaches
it. One paragraph. WS0 §2.1.

**0.4 — Founder decisions, listed so they can be answered in one sitting:**
ratify `Withdraw = 0x08` (registry C-4); fund ~0.001 BLCH for the mainnet spend
rehearsal; decide disclosure on the staking-deposit defect; **name the owner of
Phase 1.1.**

---

## Phase 1 — the deadline path (1–3 September)

**1.1 — Answer one question: does a cold sync complete?** *Blocks 1.3, 1.4, and
every published word about running a node.*

`main:genesis/README.md:29-42` says devnet cold sync **does not complete** and
that a node stood up anyway *"would answer confidently and wrongly, which is
worse for an exchange than not running one."* `THIRD-PARTY-QUICKSTART.md`,
measured **today**, says it completes in ~26 hours. Both are in the repo; the
pessimistic one is the public one.

They are not the same claim — A says *no backfill*, B measures *slow backfill* —
and A is dated 14 August, so it is probably stale. **"Probably" is not adequate
for the single fact the integration rests on.** Re-run A's reproduction against a
current build; retract `genesis/README.md` or withdraw the 26-hour figure.
**Half a day of one person's time.** WS5 §4.

**1.2 — Merge `agent-ad3f0cc77273711fd`** (branch `integ/validator-opening`, 26
commits). It is the integration superset: the libp2p DNS-failure downgrade, the
C-1/C-2 wire-collision resolution, the pairwise guard tests
(`net.rs:825`, `p2p.rs:1899`, `p2p.rs:1926`), and the
`bloch_pos_peers_connected` gauge.
**It carries 5 `wip:` commits — review by `git diff --stat` from the last
validated point, not by `git log`.**
**Do not land `agent-a58dfe6cc066ef5b3` before it**, or the wire collision
returns: that tree carries the colliding numbering and has no tag assertion of
any kind. *Depends: nothing. Start now.*

**1.3 — Merge `agent-bootnode-onboarding`** — `deploy/bootnodes/bootnodes.txt`
(two devnet archival observers, both verified at epoch 1638 on the identical
finalized root today), `verify-bootnodes.sh`, and the 406-line
`THIRD-PARTY-QUICKSTART.md`. *Depends: 1.1 (for what the quick start is allowed
to promise about sync).*

**1.4 — Give the exchange a binary.** This is the gap nobody has owned.
`genesis4-node-20260814` is **consensus-dead since epoch 800** — it silently
forks onto a dead branch — and the R2 paths older docs point at return **404**.
Slashing protection, the clock gate and the catch-up fix are all on unmerged
branches, so **no release contains them**. Cut a release from the 1.2/1.3 merge
and publish it with a checksum. *Depends: 1.2, 1.3.*

**1.5 — Hand over, and lead with the seed path.** Peer list, binary, checksum,
and the instruction to **start before 07:07 UTC on 5 September**, with the reason.
**Recommend the archival-seed path over the genesis replay** — copy `blocks.log`,
`meta.bin`, `ws_latest.bin` from a current node. It sidesteps 1.1's dispute
entirely and fits the window with room. The replay is the better engineering
story; the seed copy is the deliverable. *Depends: 1.4.*

---

## Phase 2 — parallel, off the critical path (1–4 September)

**2.1 — Apply the registry rulings** (`docs/WIRE-NAMESPACE-REGISTRY.md` §6).
C-3 is already resolved in code on `recon/coherence-core-20260901`; the two stale
`0x17` claimants must be cherry-picked, never merged as trees. C-1/C-2 resolve by
merge order (1.2). C-4 needs founder ratification.

**2.2 — Lift the evidence sub-tags to named constants** (registry §1a) before the
slashing-evidence decoder merges. Bare literals in a nested `match` are invisible
to every sweep; that is exactly how they were missed for a day.

**2.3 — Move `ROLE_PARTITION` beside `ROLE_SLOT`/`ROLE_EPOCH`** (registry §9.1).
One namespace split across two files, mixed into the sortition seed, with nothing
linking the halves. Not urgent; very cheap; consensus-critical if it ever bites.

**2.4 — Fix the `inflight` underflow** (`net.rs:217` vs `engine.rs:2573`).
WS0 §7.2. Latent today, **fatal the moment a dual-stack variant exists**, and it
already makes `engine.rs:2568`'s comment false on the libp2p path.

**2.5 — Widen the consensus-gate tripwires and merge the schedule feed**
(revision 1 items 2.1–2.5, unchanged and still correct). The union is 13 gates;
the best existing digest covers 5. A digest with gaps is read as exhaustive.

---

## Phase 3 — after the deadline

Unchanged from revision 1 items 3.1–3.6, plus:

**3.7 — The zero-peer proposal guard** (WS0 §6). Refuse to propose while peer
count is zero, with an explicit opt-out for genuine single-node devnets. The
gauge exists on `integ/validator-opening`; wiring it into the duty gate
(`engine.rs:2531-2541`) is unwritten in every tree. **This is the item that
protects the *next* third-party operator**, on any transport, and it outlives
this migration.

**3.8 — A finality ratchet test.** §1.4 of WS5: `do_reorg` adopts state without
comparing finalized checkpoints, `forkchoice.rs` never mentions `finalized`, and
a downward move is not even logged. No ratchet-shaped test exists in either
crate.

---

## What cannot be done before 5 September

Stated plainly, because a schedule that hides a slip is worse than a slip.

**A signed weak-subjectivity checkpoint.** No checkpoint has ever been published
and **no signer set exists** — the epoch-1536 checkpoint reads
`signer_set_id 1 (Phase A — keys DO NOT EXIST YET)`. The publication pipeline is
built and blocked on the same thing. This needs a founder key ceremony that is
not delegable and not compressible. **This is the entire reason the 5 September
date is real:** a node synced before it never needs the checkpoint. After it,
this ceremony becomes the critical path and its duration is not ours to estimate.

**The hosted testnet.** Not deployed; hostname and ports unclaimed; the faucet
has never run against a live node and ships with payout disabled. Revision 1's
9–11 September estimate stands. *Offer instead:* the exchange runs
`local-testnet-up.sh` themselves — it has actually run and finalized, and it
gives them the spend path without mainnet funds.

**Coherence activation.** No date, and not because of scheduling: the measured
proof is 1.21 MiB against a 524,288-byte block cap — **2.43× an entire block for
one transaction** — and compressed proofs are constant-size, so tuning will not
close it. A founder architecture decision precedes any date. *Tell the exchange:*
coherence is not part of this integration and nothing about it will move under
them.

**Staking-bond withdrawal.** Built, correctly inert at
`WITHDRAWAL_ACTIVATION_EPOCH = u64::MAX`, needs a founder flag day ordered after
`FUNDED_STAKING` and `SIGNED_EXIT`. **Do not let this be conflated with exchange
payouts** in the partner conversation — those are a different thing and are built
(`crates/bloch-withdraw`).

**A fix for the staking-deposit defect.** See the correctness-debt page. It is a
consensus change; it does not belong in a four-day window alongside an
integration.

---

## Standing constraints observed

- **No activation constant is armed by this plan.** Every gate discussed here
  ships `u64::MAX`; the one new constant on this branch
  (`SLASHING_EVIDENCE_ACTIVATION_EPOCH`) was verified inert.
- **No live fleet, production node, or key material is touched by the PMO.**
  Items 1.4, 1.5 and the Phase A ceremony are founder-authorised operations and
  are named as such.
- **Nothing here goes to the website.**
