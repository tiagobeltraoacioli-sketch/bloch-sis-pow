# Bloch Genesis-4 — answer to your four asks

```
Status:     DRAFT — NOT SENT. Cleared for sending once founder decisions
            D1–D5 (§7) are answered. Every commitment below that depends on
            one carries [D#] inline.
Prepared:   2026-09-02 01:35 UTC, Postern Labs
Against:    public main @ fa4ad9be (= origin/main = github/main, verified),
            the fleet lineage tip 46133196, and the live chain.
Handling:   INTERNAL AND PARTNER-DELIVERED. Never published to the website,
            never a shared link. Delivered to you as a file.
Supersedes: the 2026-09-01 draft prepared against main @ 737078d1. Three of
            its statements are corrected here, two of them materially.
```

You wrote:

> *"If that window closes with bootnodes still unpublished, the deployment your
> own documentation recommends becomes unavailable, and the integration cannot
> reach production regardless of anything else. So: either bootnodes and a
> routable transport before the window closes, or your plan for third-party
> onboarding after it — a signed checkpoint and signer set, or whatever you
> intend. Either answer works for us. Silence does not."*

That is a fair statement of the position and we are answering both halves. The
short version:

1. **Bootnodes are published**, on public `main`, with a verifier you run
   yourself. The transport is `devnet`, not libp2p, and that is the correct and
   final answer for your node — §1.
2. **The binary you should build is not the one our own quickstart tells you to
   clone.** `main` is not on the lineage the 63 validators run, and the
   difference is live today, not gated. This is new since our last letter and it
   is the most important thing in this document — §2.
3. **A signed checkpoint will not exist by 5 September**, and the reason is a
   third party's calendar, not ours — §5. But the deadline binds less than we
   previously told you, and §5.2 explains exactly what it does and does not gate.
4. **Three corrections to things we told you or published**, including one
   settlement guarantee still live in the node's own RPC documentation — §4.

---

## 0. The clock, and what actually turns on it

**2026-09-05 07:07:19 UTC.** From this letter, **77 hours**.

Derive it rather than trusting us: Genesis-4 slot 0 was 2026-08-13 21:31 UTC;
slots are 30 s; epochs are 32 slots; the window is
`WS_PERIOD_EPOCHS = WITHDRAWAL_DELAY_EPOCHS (2048) − EXIT_DELAY_EPOCHS (32)`
= 2016 epochs ≈ 22.4 days
(`crates/bloch-pos-committee/src/ws.rs:140`,
`crates/bloch-pos-committee/src/staking.rs:113,120`).
Treat the result as "07:07 UTC give or take a slot".

### 0.1 What the binary actually does at that instant

This matters more than the date, and our previous letter stated it loosely. The
gate is `ws::boot_decision` (`crates/bloch-pos-committee/src/ws.rs:575`), and it
is evaluated **at every boot, after replay, before the RPC port opens**
(`crates/bloch-pos-node/src/engine.rs:2407`; the node returns
`PermissionDenied` and does not start, `engine.rs:2524`).

```rust
pub fn boot_decision(has_local_finality: bool, age_epochs: u64) -> BootDecision {
    if !has_local_finality      { BootDecision::RequireCheckpoint }
    else if age_epochs < WS_FRESH_EPOCHS   { BootDecision::Resume }
    else if age_epochs < WS_PERIOD_EPOCHS  { BootDecision::ResumeStaleWarn }
    else                                   { BootDecision::RefuseStale }
}
```

`has_local_finality` is `fin.epoch > 0` (`engine.rs:2390`) — genesis does not
count, deliberately, and the comment says why: *"treating the genesis checkpoint
as own finality would let every fresh node skip the gate, which is the whole
point of the gate."*

A node with no finality of its own gets `RequireCheckpoint`. That is **not**
immediately fatal: `ws_boot.rs:448` lets it through while the *anchor* is inside
the window, and for a node with no `--ws-checkpoint` the anchor is the genesis
manifest itself. So the real condition is:

> **The genesis anchor stops being an acceptable anchor when the chain's
> wall-clock epoch reaches 2016.** That is the 5 September instant. From then
> on, a node with an empty database and no signed checkpoint gets
> `Err(require_checkpoint_message(...))` and refuses to start.

After that, a node that already has its own finality is governed by
`age = wall_epoch − own_finalized_epoch`: under 1008 epochs it resumes silently,
under 2016 it resumes with a prominent warning, at or beyond 2016 it refuses to
follow any peer (`ERR_WS_STALE`). **So "sync before the 5th" is not a one-time
hurdle — it is a standing obligation not to be offline for 22.4 days.** Put that
in your runbook, not just your project plan.

### 0.2 The three ways in, and what each costs

| path | wall time | fits in 77 h | what you are trusting |
|---|---|---|---|
| **A — archival seed copy, then local replay** | ~10 min replay + ~40 min build | **yes, with days to spare** | us, for the block data — see §5.2 |
| **B — from-genesis sync over the network, release binary** | ~26 h floor | yes, if you start by **2026-09-04 04:30 UTC** | the genesis manifest only |
| **C — from-genesis sync, `main` build** | up to ~52 h | marginally | **withdrawn — see §2** |

**We recommend A, and we are not being modest about B.** B is the better
security story and it is the one we would want you to be able to take. It is
also 26 hours inside a 77-hour window with no margin for a single restart, on a
binary whose sync profile we have measured once. A is an hour, and §5.2 explains
precisely what it costs you in trust and why that cost is smaller than it looks.

**A caution about B that has cost people time.** For the first two minutes on an
idle 8-core machine — eleven minutes on the same machine under load — the node
prints two lines and then produces **no log output, no open RPC port, no answer
to `getchaininfo`, and no peer connection**, while it builds the sparse Merkle
tree over 452,726 carryover outputs. `blocks.log` stays at 0 bytes throughout.
Every signal you would use to tell "working" from "crashed at startup" is
absent. Watch `ps -o %cpu,rss`. Do not kill it.

**Budget the build separately.** The release profile is `lto = true`,
`codegen-units = 1`, `overflow-checks` on — deliberate for a consensus build —
and the final link is single-threaded: measured about **40 minutes**. Do not
drop LTO or build in debug to save it; both change the binary you are validating
with, and a debug build turns the two-minute state construction above into
hours.

---

## 1. Ask 2 — bootnodes and a routable transport

**Answered and published.** On public `main` (`fa4ad9be`), which is
`origin/main` and `github/main`:

- `deploy/bootnodes/bootnodes.txt` — the entry list
- `deploy/bootnodes/verify-bootnodes.sh` — a read-only verifier you run yourself
- `docs/THIRD-PARTY-QUICKSTART.md` — the full procedure (but read §2 first)
- `deploy/fly/README.md` — **deleted**, in commit `6ac27c70`. That is the file
  you cited. It was proof-of-work-era, described infrastructure we destroyed on
  2026-08-23, and carried the placeholder multiaddrs you found. You were right
  that it was unusable. It should not have survived the migration.

The two entry points:

```
139.180.166.5:19100
139.180.173.231:19100
```

Bare `host:port` — this is the **devnet** transport, not a libp2p multiaddr.

Both are **keyless archival observers** run by Postern Labs. They hold no
`validator.key`, so they never propose and never attest; they follow the chain
and answer block-sync requests. That is the correct thing for a third party to
peer with.

Recorded by our own verifier at 2026-09-01 06:58 UTC and committed alongside the
list: both reachable, both keyless, both `--transport devnet`, both RPC bound to
loopback, both `behind_by_slots=0`, both at epoch 1666 reporting the **identical
finalized root at equal finalized height 32356**. That last check — identical
root at *equal* height — is the one that proves they are on one chain and not
two. The root is a moving value; do not compare a live node against a value
printed in a document. Run the verifier.

**We are not publishing validator addresses, and the reason is not
convenience.** The devnet transport has no authentication and no admission
control, so a published validator address is an unauthenticated frame-push
surface directly into consensus. On 2026-08-09 one stale node dumped 1,270 old
blocks and stopped block production across the entire network.

### 1.1 Three limits on that answer

1. **Two hosts, one provider family** (`139.180.x`). One provider suspension
   takes out both. A three-host tier on three providers is the durable answer
   and is staged, not deployed. These two are what exists and is publishable
   today.
2. **They are leaves, not hubs.** Each dials the 63 validators outbound; no
   validator dials them and they do not dial each other. Your blocks arrive by
   your own periodic get-blocks request, so expect to sit 0–2 slots behind the
   head rather than exactly at it. Your *transactions* do relay: a transaction
   arriving by gossip takes the same admission path as one from the RPC and is
   re-broadcast over the observer's outbound connections.
3. **They do not run the same binary as the validators.** Our own host table
   records the archivals on `bloch-pos-quatro` (`0a3a436a`) while the fleet
   moved to `bloch-pos-cinco` (`46133196`)
   (`deploy/archival/RUNBOOK-ARQUIVAIS.md:23-25`), and it says in as many words
   that they are *"the population most likely to fork on a flag day and the
   least likely to be noticed doing it, because a wrong answer from an archival
   looks like an answer."* On 2026-09-01 they agreed with each other and with
   the fleet's finalized root. **This bears directly on the two-node
   corroboration rule we gave you in §4.1 — two nodes on the same stale build
   are not two independent nodes.** Rolling them onto the fleet lineage is
   item [D3].

### 1.2 Do not use `--transport libp2p`

The node has a second transport and it is the better stack — authenticated Noise
sessions, gossipsub, peer scoring, admission control. **Do not use it, and do
not wait for it.**

The two transports are mutually exclusive per process: `net.rs` defines
`enum Net { Devnet | Libp2p }`, one of two, chosen at startup. There is no
dual-stack mode in any released binary and no bridge. The live fleet is `devnet`
end to end.

It does not fail cleanly, which is the part that matters to you. Measured
2026-09-01, a libp2p node pointed at devnet peers:

```
p2p: NO PEERS — dial failed: Failed to negotiate transport protocol(s)
p2p: publish blocks: NoPeersSubscribedToTopic
[slot 26] proposing block 39906305 …
[slot 26] applied 39906305 by v2 — head root f0ff00ad, justified e0, finalized e0
```

It negotiates nothing, finds no peers, and then **builds its own chain while
printing "applied" and "finalized"** — a node that looks healthy and is not on
Bloch. `getchaininfo` has no peers field and there is no `getpeerinfo` method,
so zero peers is not observable over RPC at all.

**We also measured libp2p against itself**, three nodes on one idle box, one
binary, variables isolated one at a time:

```
--transport devnet   8 arms, up to 1,869 slots / 58 epochs — 0 fractures, REORG=0
--transport libp2p   9 runs — 8 self-fractures, first conflict at slot 128–483
```

Cause pinned by violation: peer scoring off → 0 of 7 fracture; scoring back on →
3 of 3; every score term armed but the `NotInCommittee` refusal reported as
`Ignore` instead of `Reject` → 0 of 3. One refusal reason, charged as a peer
penalty (gossipsub P4 at −100 against a −400 graylist), against peers that did
nothing wrong.

**We owe you one honest qualification on that measurement, and it is the reason
we are not telling you libp2p is permanently broken.** The refusal comes from
the node judging committee membership with a seed one epoch older than the
transition's — the defect described in §2.2. **The binary used for those nine
runs carries that defect; the fix for it is on the fleet lineage and was not in
the binary under test.** The measurement is therefore sound about *that binary*
and is not evidence about the release binary. Re-running the matrix on the fixed
lineage is scheduled and is not on your critical path either way.

**For your node this changes nothing: use `devnet`.** An observer signs nothing.
The properties you need from a node — replay every block, recompute every state
root, diverge loudly on bad data — are properties of the transition function,
not of the transport. What `devnet` costs you is authentication and admission
control on the wire, which is why the RPC must stay on loopback and why the node
belongs behind your own firewall.

---

## 2. New since our last letter: do not build from `main`

This is the item we would most want your engineers to read, and we found it
after the letter you are replying to.

**`main` is not on the lineage the fleet runs.**
`git merge-base --is-ancestor 46133196 main` is **false**. Six commits are in the
fleet lineage and absent from `main`, the first of which, `47f7644b`, carries
four consensus corrections.

The cause is mundane and worth stating because it tells you how much to trust
the rest: on 2026-08-25 at 02:33 UTC a merge titled *"the code the fleet runs
becomes main"* landed. `47f7644b` was committed to the fleet branch at 05:50 the
same day — **three hours after the merge that was meant to capture it.** It has
never been re-merged.

Meanwhile `docs/THIRD-PARTY-QUICKSTART.md:137` on public `main` says:

```bash
git clone https://gitlab.com/blochsispow-group/bloch-pos.git
cd bloch-pos
cargo build --release -p bloch-pos-node
```

No branch, tag or commit is pinned, and `origin` HEAD symrefs to `main`. **So
our published quickstart instructs a stranger to build off-lineage.**

### 2.1 What we previously believed, and why it was wrong

Our first reading was that the two lineages agree today because the gates
involved are unarmed, and that a `main` build would only diverge on some future
flag day. **That is not correct, and we are correcting it before you act on
it.** Two of the corrections in `47f7644b` are ungated and live on today's
chain.

### 2.2 The one that reaches you

`Engine::seed_for_attestation`. On `main` it is unconditional:

```rust
match epoch.checked_sub(committees::MIN_SEED_LOOKAHEAD_EPOCHS) { … }
```

The committed rule, `CommittedState::seed_for_epoch`
(`crates/bloch-pos-committee/src/transition.rs:1518-1548`), is gated on
`ANCESTRY_SEED_ACTIVATION_EPOCH` (`params.rs:594`, `u64::MAX`), so below the flag
day — which is **every epoch this chain has ever had** — it uses a look-ahead of
0 and reads `mix(E−1)`. `main`'s node reads `mix(E−2)`.

**Different committees, every epoch, today, with no gate in the way.**
`47f7644b` fixes it by putting the node's look-ahead behind the same constant,
so the two agree below the flag day and move together above it.

Why it reaches a keyless observer: `Engine::judge` calls
`seed_for_attestation`. An observer judges attestations even though it casts
none, and judging against a different committee changes what it considers
finalized — **which is the field you credit on.** A `main`-built observer cannot
fork itself (the other ungated correction,
`derive::validate_included_attestation`, is a producer-side inclusion filter
whose only non-test caller is `produce::produce`), but it can and will publish a
different `finalized` view from the fleet's.

**Our gate-digest self-check does not catch this.** All three binaries emit the
same digest, because the digest is over the *set* of gate constants, not over
the behaviour behind them. That is a defect in our tooling and it is on the
list.

### 2.3 What you should build instead

`release/g4-node-20260901`, tag `g4-node-20260901`, commit `7a83ca89`. Verified:
it descends from the fleet tip `46133196`, contains `47f7644b`, and is 12
commits ahead of `main`. It also carries the catch-up fix (`Arc<BTreeMap>`
copy-on-write, so an epoch roll stops paying for the whole ledger) that the
26-hour sync figure was measured with and that `main` lacks. The binary has been
reproduced byte-identically on three machines by two independent checkout paths,
and its 202 consensus constants are identical to the fleet's.

**It is on no remote.** `git branch -r --contains 7a83ca89` is empty. Publishing
it is a push and a checksum, not engineering, and it is founder decision [D1].
Until it is published we cannot honestly tell you to build anything, which is
why [D1] is the first item in §7 and has the shortest fuse in this letter.

**Until [D1] lands, do not start a sync you intend to keep.** A datadir built by
a `main` binary is not obviously corrupt and will not announce itself; the
cheapest safe course is to wait for the tag rather than to sync twice.

---

## 3. Asks 1, 3 and 4 — the answers that are not clock-bound

### 3.1 Ask 1 — test funds and testnet access

We are going to answer this less impressively than we could, because the
impressive version does not survive contact with our own repository.

**What exists:** a four-validator Genesis-4 testnet that stands up on one
machine in about eight minutes, with the complete spend path — key generation,
funded genesis allocation, transfer construction, hybrid signing, submission,
inclusion, balance change — and a withdrawal client driving it. It has been run,
and the run is written up.

**What is wrong with offering it to you today:**

1. **It is not published.** The scripts and the withdrawal crate are on internal
   branches that exist on no remote. "Run it yourself with no dependency on us"
   is therefore not true.
2. **The node CLI on `main` cannot run those scripts.** They call `bloch-pos
   spendkey`, `genesis --alloc` and `submit-tx --raw`; none of those exist in
   the published binary's command set. Cloning `main` and following the script
   fails immediately.
3. **We have a written account of the end-to-end run, not a captured
   transcript.** The hashes in our rehearsal note are elided and transcribed by
   hand. Our repository has a good pattern for this — dated, machine-produced
   reference outputs — and this work does not follow it. We would be asking you
   to take prose as evidence.

**Concretely, what we are offering:**

- **Today:** the branch, the exact build command, and a captured dated
  transcript of a full local run rather than the prose we have. If that
  transcript is what decides it for you, say so and we will prioritise producing
  it over everything else in this letter.
- **Hosted testnet: 9–11 September.** That is our internal estimate on an
  undeployed plan — the endpoint does not exist, DNS and TLS are not stood up,
  and the plan includes a 24-hour soak that cannot be compressed. It is not the
  5th and we are not going to tell you it is.
- **A small mainnet amount** is available now if you would rather rehearse
  against the real chain [D2].

**Two defects we fixed on contact,** both of which would have broken you
silently:

- Our withdrawal client **refused testnet addresses outright** — a safety rule
  with no way to switch it off for a testnet.
- **Eight sites in our tooling computed `script_hash` in a form the chain does
  not use.** The chain's native form is `SHA3-256(pubkey)`, all 32 bytes; those
  sites used the address-truncated form (20 bytes, zero-padded). Because
  consensus opens **both** as the same owner, nothing errors — you just read the
  wrong number. In our reproduction the same key showed **74,999,997,782 sat**
  under one derivation and **0** under the other. A silent zero balance is
  precisely the failure that costs an exchange money.

**One design constraint, stated openly.** The spend signing root carries **no
chain identifier**. It commits to a domain tag, the spend outpoints, the
outputs, the byte length and the tip, and nothing else
(`transition.rs:474-532`). The tag `BLCH4:SPEND` is byte-identical on every
Bloch network; it separates *message type*, not *chain*. A `network_id` exists
in the node but never reaches transaction validation — it binds only
weak-subjectivity checkpoints. Consequence: a testnet seeded from mainnet
balances would share outpoints with mainnet and a testnet-signed spend could be
replayed here. Our testnet therefore gets a fresh balance set. **Until a network
tag is folded into the signing root — scoped, not done, because it alters a
format on a running chain — that disjointness is a fact about how we operate the
testnet, not one the protocol enforces. Treat a testnet key as a mainnet key.**

### 3.2 Ask 3 — withdrawal retry semantics

Your first two clauses are right. Your third is wrong, and our own previous
answer to it was also wrong, in a different direction.

**Confirmed:** a transfer commits to exactly one base fee and conservation is a
strict equality (`transition.rs:2180`):

```rust
let created: u128 = outputs.iter().map(|o| o.value as u128).sum();
let fee = charge.base_fee_sat + charge.priority_fee_sat;
if spent_value != created + fee { return Err(TransferReject::ValueNotConserved); }
```

Equality, not `>=`. Overpaying fails exactly as underpaying does. The base fee
comes from the fee market, never from the transaction; the only price the
transaction sets is the tip. So if the base fee moves between your build and the
block that would include you, your outputs no longer balance and the transfer
must be rebuilt.

**Correction 1 — resubmitted identical bytes are not permanently invalid.** A
refusal such as `UnknownInput` is a statement about state at one moment, not
about the transaction. A transfer spending an output of another transfer still
in the mempool is refused now and applies once its parent lands. Treating the
bytes as permanently dead would strand a legitimate chained spend.

**Correction 2 — this one corrects us, not you.** An earlier draft told you a
refused transaction is barred from re-admission for `REJECTION_TTL_SLOTS = 128`
slots. **That is not true of any released binary.** There is no rejection cache
on `main`: the constant does not exist in the tree, and `Engine::on_transaction`
(`engine.rs:1345`) checks only for a duplicate already in the mempool and for
capacity. The 128-slot bar exists only on unmerged branches. **The actual retry
rule today: there is no cooldown.**

**Build against this instead:**

- **Rebuild at the current base fee** rather than resubmitting bytes. Correct
  under either behaviour, so it survives us landing the rejection cache.
- **Read `next_base_fee_millisat_per_gas` from `getchaininfo` before each
  build** (`rpc.rs:1234`).
- In practice the base fee is pinned at its floor
  (`MIN_BASE_FEE_MILLISAT_PER_GAS = 10`; the controller moves by at most 1/8 per
  block and an under-target block clamps back to the floor). Do not hard-code
  that — it stops being true the moment blocks reach target. *[Derived from the
  fee-market source plus the observation that blocks are near-empty; not
  measured against the live base fee.]*

**Two proposer behaviours that are in no document and can make a withdrawal
vanish from a node's mempool with no error reaching you:**

1. **A proposer that cannot build a block drops transactions from the tail until
   it can, and the tail is not the offender** (`engine.rs:1050-1078`). The
   mempool is a `BTreeMap` keyed by canonical bytes (`engine.rs:516`), so blocks
   are packed in **byte-lexicographic order of your encoded transaction** and
   the tail-drop is biased against transactions whose bytes sort high —
   arbitrary with respect to anything you control.
2. **A proposer that refuses its own block drops every transaction in it**
   (`engine.rs:1125-1133`).

Both evictions are **local to that node**. The transaction was already gossiped.
So "it vanished from the node I submitted to" is neither evidence it will not
confirm nor evidence that it will. **Poll for the output, not for the mempool.**

**Will the semantics change?** The fee model: no. Admission control: yes — the
mempool has a size bound (`MEMPOOL_MAX = 4,096`) and no fee-based or per-sender
policy. Adding one changes what is accepted at the door, not what is valid in a
block. You will be told before it lands.

### 3.3 Ask 4 — notification of consensus parameter changes

Fair, and the epoch-800 flag day is a good example of us failing it. Built,
tested, **not merged and not deployed**:

- **`bloch-pos selfcheck --json`**, emitting the activation epochs a binary
  knows plus a digest over the set. We verified rather than assumed the current
  behaviour: today's published binary answers `selfcheck` with a pass/fail line
  and **silently ignores `--json`** (`main.rs:95`), so a check written against
  it today would appear to pass and tell you nothing.
- **A fleet sweep** running that one command on every host — opening no data
  directory, binding no port, writing nothing — flagging any node whose digest
  disagrees with the reference.
- **A flag-day calendar** listing every gate, its dependencies, its arming
  preconditions, and a column recording **whether the format a gate governs is
  reachable on the wire at all** — because several gates arm code nothing can
  reach, and a release note without that column overstates what a binary does.

**And one thing we must say about that digest, because you would otherwise rely
on it:** as built, it is a digest over the *set of gate constants*, not over the
behaviour behind them. It does **not** distinguish a `main` binary from a fleet
binary — see §2.2, where two binaries with identical digests judge different
committees. Fixing that is a precondition of the notification service being
worth anything, and it is now scoped as such.

Current gate state:

| Gate | file:line on `main` | Value | Live? |
|---|---|---|---|
| `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` | `params.rs` | 800 | yes |
| `BLOCK_BYTES_V2_ACTIVATION_EPOCH` | `params.rs:308` | 800 | yes |
| `LEAKED_ROSTER_ACTIVATION_EPOCH` | `params.rs:257` | 1400 | yes — passed; chain was at epoch 1666 on 2026-09-01 |
| `LEAK_RECOVERY_ACTIVATION_EPOCH` | `params.rs:610` | `u64::MAX` | **inert** |
| `ANCESTRY_SEED_ACTIVATION_EPOCH` | `params.rs:594` | `u64::MAX` | **inert** |

The two inert ones are the mitigations discussed in §4.1 and §2.2. They ship in
every binary and are unreachable. You will be on the notification list and you
will get the calendar.

---

## 4. Corrections we owe you

### 4.1 The settlement guarantee — already retracted, restated here

**We gave you a guarantee that does not hold.** An earlier revision of our
integration book told you to credit on `finalized` and called it a cryptographic
settlement guarantee, "typically 1–2 epochs after inclusion". It is not one. The
page was corrected on public `main` (`de1a1056`, `b354453c`).

What Genesis-4 offers is *economic* finality under an assumption of healthy
participation. Two defects:

1. **The quorum denominator shrinks and the floor is not in force.** The
   two-thirds test is measured against a leak-adjusted denominator: stake the
   inactivity leak has eaten is subtracted from the total. A minimum-denominator
   floor of 1/2 exists in the source, is the value our founder chose, and is
   gated behind `LEAK_RECOVERY_ACTIVATION_EPOCH = u64::MAX` — compiled into
   every shipped binary and unreachable. A test on public `main` that touches no
   test hook drives three disjoint partitions of **4 validators out of 64 (6.25%
   each)** through the production arithmetic, and each finalises the same epoch
   on a different root. **This happened to us on 2026-08-24**; the settled
   post-mortem is `docs/post-mortems/2026-08-24-finality-divergence.md` on
   `main`. It takes roughly 25–28 epochs of non-finality — **6.7 to 7.5 hours** —
   before a partition can do this; our longest observed real stall was 45
   epochs, 12 hours.
2. **`finalized` is not a latch across a reorg.** Fork choice walks from the
   *justified* root, never the finalized one, and the state committed at the
   justified root already finalises below the head. **The deepest cut fork
   choice may legitimately propose is itself a finality rewind** — no invalid
   block, no misbehaving peer. Nothing in the adopt path compares incoming
   finality against outgoing; a downward move is not even logged.

**Two nodes agreeing does not mitigate defect 2.** For defect 1 the mitigation is
measured. For defect 2 it is a *reasoned consequence*: the rewind is a property
of the single-node adopt path, which every node runs independently, so two nodes
give you no correlation guarantee. We mark that distinction because it is the
difference between a test result and an inference.

**What to do instead, until we withdraw this note:**

- Credit at **finalized + 3 epochs** (~48 minutes past finality; one epoch is
  16 minutes).
- Require **two independently operated nodes** to agree on the same finalized
  **root *and* epoch** — not the epoch alone. See §1.1 limit 3: the two nodes we
  publish are currently the same build, which is [D3].
- **Re-verify immediately before releasing funds**, not once at detection.

And plainly: **the margin of 3 bounds the single-cut case with one epoch to
spare. It does not bound a repeated ratchet, and no depth is provably safe
today.** If your risk committee reads that and concludes Genesis-4 is not ready
to hold customer funds, that is a defensible reading of what we have written,
and we would rather they reach it now than after a rewind.

### 4.2 A second guarantee we have not yet retracted, and are retracting now

The correction above fixed a document. **The same claim is still live in the
node's own RPC documentation, which is what an integrator reads from the
source.**

`crates/bloch-pos-node/src/rpc.rs:1650-1652`, in the doc comment of
`enum Finality` — the type whose own text says *"This is the field an exchange
credits a deposit on"*:

> *"The guarantee rests on Casper justification and finalisation — a finalised
> checkpoint cannot be reverted unless at least one third of the total stake is
> slashed, which is a bonded, attributable, on-chain cost rather than a
> probabilistic one."*

And `rpc.rs:1669-1670`, the `Finalized` variant:

> *"At or below the finalised checkpoint. Irreversible short of a
> one-third-of-stake slashing event. **Credit here.**"*

**No stake can be slashed on this chain. Not one satoshi, under any
circumstance.** Slashing evidence has wire tag `0x05`, and the decoder is:

```rust
0x05 => return Err(TxDecodeError::EvidenceNotDecodable),
//        crates/bloch-pos-committee/src/transition.rs:782
```

Unconditional. No guard. And it is **deliberate**, documented in the function's
own comment (`transition.rs:715-729`): the evidence arm folds its nested
messages in through the roots they were signed over, and *"a signing root is a
hash; nothing recovers the envelope from it. So evidence encoded this way is
one-way by construction… evidence cannot reach a verifier through
`body.transactions`."*

Every ingress uses that one decoder — p2p mempool (`p2p.rs:1269`), direct frame
(`net.rs:293`), RPC `sendrawtransaction` (`rpc.rs:1138`), and block bodies
(`engine.rs:193-202`). A block body containing a `0x05` blob is undecodable as a
whole; it does not become processable evidence.

The penalty machinery is real, complete and tested —
`CommittedState::apply_slashing_evidence` (`transition.rs:2550`) sets
`slashed = true` and decrements the bond at `:2624` — and it is unreachable.
Equivocation **is** detected: `gossip.rs:314-318` builds a candidate and
`engine.rs:1851-1861` handles it by printing

```
EQUIVOCATION captured … slashing pipeline NOT wired — evidence is logged, not prosecuted
```

Note also that the inactivity leak, which does reduce a validator's *effective*
weight, never touches bonded stake: it accumulates in a separate map and is
subtracted only from a derived roster view (`finality.rs:159`, `:489`;
`transition.rs:3101-3106`). The only decrement of `staked_sat` anywhere in the
crate is inside the unreachable slashing path.

There is also **no activation constant to arm.**
`SLASHING_EVIDENCE_ACTIVATION_EPOCH` does not exist in the repository — it is
not set to `u64::MAX`, it is absent. This is not a feature waiting on a flag
day.

**So the economic cost our RPC documentation sells you as the basis of
settlement cannot be imposed by any code path reachable from the wire.**
Genesis-4 finality today is economic by intent and cryptographic by nothing:
reverting a finalised checkpoint costs an attacker no bonded stake, only the
coordination of the validators who would have to do it. Take §4.1's guidance —
depth, two nodes, re-verify — as the whole of what we offer, and discount the
slashing sentence to zero.

**One further disclosure, which we are marking as pending confirmation rather
than holding back.** A correction to that RPC comment is in flight in our
working tree — it retracts both sentences, adds machine-readable
`"slashing_enforced": false` and `"finalized_is_a_latch": false` to the
capabilities object so a client can branch on a flag instead of parsing prose,
and it records a measurement against the live chain at epoch 1726, both
archivals agreeing on head and root: 64 validators, all 64 with
`"slashed": false` and `"exit_epoch": null` — **including 48 whose
double-signing is committed on chain and cryptographically provable.**

If that measurement holds, it is the sharpest available statement of §4.2: the
penalty has not merely been unreachable in principle, it has already failed to
fire against provable equivocation by three quarters of the validator set.
**We have not independently re-measured it for this letter, and the test the
correction cites (`tests/slashing_backed_finality_claims.rs`) is named but not
yet written.** We are telling you it exists in that state rather than waiting
for it to be tidy. Landing and corroborating it is [D4]; you will get the
confirmed number either way.

### 4.3 Your §7.9 — partly stale, and the accurate version is worse in one place
### and better in another

You wrote that the spend path has never been exercised in production. **That is
now stale, and we should have led with the correction rather than leaving it to
you.**

Measured 2026-09-01 at slot 54,663 / height 33,768 / epoch 1,708, corroborated
across both archival nodes: between slot 5,909 and slot 51,805 (epochs
184–1,618) the chain carried **1,051 transactions**, which consumed **383,940
outputs** and created **2,099** — roughly 900 inputs each. They moved
**18,128,356,145.07452011 BLCH, 18.13% of the cap**, with production key
material, on mainnet. This is consolidation traffic rather than payment traffic,
but it is the real spend path under real load: hybrid signature verification,
conservation as an equality, and the V2 payload cap, all exercised at a scale
well beyond anything your integration will produce per transaction.

**Where you were right, and remain right:** every one of those 1,051
transactions was a transfer. **No deposit, no exit, no delegation and no
slashing evidence has ever been included in a Genesis-4 block.** The entire
staking lifecycle is unexercised in production, and §4.4 states how much of it
is not merely unexercised but unreachable.

*Provenance note, because it applies to us as much as to you:* these figures
live in `docs/LIVE-SUPPLY.md`, which carries `measured_at 2026-09-01` and a test
that fails once the measurement ages past 30 days. **That file is not yet
committed** — it exists in a working tree, not on `main`. We are giving you the
numbers with that caveat attached rather than waiting for the merge, and landing
it is [D5].

### 4.4 Your two closing items — both correct, and the accurate statements are
### worse than what you wrote

- **`validate_deposit` has no production call site.** Correct. It is at
  `crates/bloch-pos-committee/src/staking.rs:285`, exported at `lib.rs:151`, and
  declared on a trait (`interfaces.rs:795`) that has **zero `impl` blocks
  anywhere in the workspace**. Every call site is in its own `#[cfg(test)]`
  module.

  **The worse fact you did not ask about:** the `Deposit` path that *is* live
  (tag `0x02`, `transition.rs:2060-2110`) **mints stake from nothing.** It
  consumes no eUTXO, spends no input and charges no fee; it checks that the
  pubkey is unregistered, that the amount clears a minimum and a 1%-of-active
  cap, and then writes `staked_sat: *amount_sat` (`:2092`) — a value asserted by
  the transaction and backed by no coin. Nothing has ever sent one, and that is
  the only reason it has not mattered. Fixing it is a consensus change and it
  does not belong in a four-day window alongside an integration.

- **`unlock_epoch` is absent from `bloch-pos-committee`.** Correct, and the
  accurate statement is worse than "absent": the field is declared in the
  genesis allocation format and committed into the genesis digest, and there are
  **zero occurrences of it in the crate that holds the staking and spending
  rules**. Declared, not enforced. Doubly so: the five shipped mainnet buckets
  are all constructed with `unlock_epoch = 0`, so they were spendable from
  height 0 regardless. All five were spent, in epochs 1,052–1,167.

  This is now **documented and tested on public `main`** (`fa4ad9be`), which
  deletes the false doc comment claiming *"`unlock_epoch` is what makes the
  vesting consensus"* and adds two tests, both verified by violation:
  `vesting_is_not_enforced` (asserts the identifier appears nowhere in the
  authorising crate, guarded by a source-file-count precondition so it cannot
  pass vacuously) and `the_shipped_buckets_are_all_liquid_at_slot_zero`.

- **A number we will not give you.** We have internal work that assigns a wire
  tag to a staking withdrawal. **We are not quoting it**, because it is
  unmerged, contested between branches, and its current value was inherited from
  a merge-conflict resolution rather than decided. On every released binary the
  transaction tag space is exactly six values — `0x01` Transfer, `0x02` Deposit,
  `0x03` Exit, `0x04` Delegate, `0x05` SlashingEvidence, `0x06` TransferV2 — and
  anything else is `UnknownTag`. **There is no withdrawal wire form at all.**
  `staking::validate_withdrawal` exists (`staking.rs:503`) as a pure predicate
  with no transaction that can carry it and no production caller.

  For completeness on the same lifecycle: a voluntary `Exit` **is**
  wire-reachable (tag `0x03`, handled at `transition.rs:2111-2131`), contrary to
  a stricter claim we might have made — but it only sets `exit_epoch` and
  `withdrawable_epoch`. It moves no coins, and nothing anywhere reads
  `withdrawable_epoch` to release stake into the eUTXO set. **Stake that enters
  is marked exited and then sits.**

  **Please keep finding these.** Every item in your last two notes was correct.

---

## 5. Onboarding after the window — the plan you asked for

### 5.1 What will not exist on 5 September, and why

**A signed weak-subjectivity checkpoint.** Stated plainly so the schedule does
not hide a slip.

What exists: the checkpoint format (154 canonical bytes,
`ws::WeakSubjectivityCheckpoint::canonical_serialize`, size pinned by test), the
full ceremony toolchain as six subcommands of the node binary (`ws-keygen`,
`ws-signer-set`, `ws-checkpoint`, `ws-sign`, `ws-envelope`, `ws-verify`), a
recorded 2-of-3 rehearsal on four simulated machines against the live chain with
throwaway keys, and a release-profile end-to-end integration test. **An
epoch-1536 checkpoint has been produced** — 154 bytes, block root
`d5b3a122…3d32`, boundary slot 49,151.

What does not exist: **the signature.** The artifact's own README says it
verbatim — *"This artifact is unsigned … signer_set_id 1 (Phase A — keys DO NOT
EXIST YET)"*. There is no signed envelope, no signer-set file, and no keypair —
`.pk`/`.sk` searches across every tree return nothing.

**Why 77 hours does not fix that, and the reason is not engineering capacity.**
Phase A is **2-of-3 with at least one external signer**
(`WS_PHASE_A_THRESHOLD = 2`, `WS_PHASE_A_SIGNERS = 3`,
`WS_PHASE_A_MIN_EXTERNAL = 1`, `ws.rs:298-302`). The three holders are the
Foundation, Postern Labs, and an external audit firm. With `min_external = 1`,
of the three possible signing pairs — {Foundation, Postern}, {Foundation,
Auditor}, {Postern, Auditor} — **only the two containing the auditor produce a
verifying envelope**; the internal-only pair is refused with
`ExternalQuorumNotReached` (`ws.rs:487-497`).

**So the external auditor must sign every publication, and the calendar for a
key ceremony with an external firm is not ours to compress.** We are not going
to give you a date we cannot keep. What we will do is commit to the trigger:
you will be told the ceremony date within one business day of the auditor
confirming it.

*Two caveats we are recording rather than discovering later.* First, `min_external`
is read from the operator-supplied signer-set file and the policy check
`SignerSet::matches_policy` is **not called at node boot** — no release build
bakes a signer arrangement today. Second, the quorum counts distinct signer
*indices*, not distinct *keys*, so one key seated in two slots would be a 1-of-3
that defeats `min_external` entirely; that is fixed tool-side, and the
consensus-side rule is still inert. Both must be closed before a signer set we
publish is worth more than our word, and both are on the ceremony's critical
path, not after it.

### 5.2 What the deadline actually gates — and the part that is better news than
### we previously told you

We told you a node cannot cold-start trustlessly after the window. That is true
and it is the important sentence. But we were imprecise about the mechanism, and
the precision matters to your plan.

**A node seeded with donated block data is not stopped by the gate, before or
after 5 September.** The gate tests `has_local_finality = fin.epoch > 0`
(`engine.rs:2390`), computed **after replay**. A node handed `blocks.log`,
`meta.bin` and `ws_latest.bin` from a current archival node replays them
locally — re-applying every transition and recomputing every state root — and
arrives at boot with its own finality at a recent epoch. It gets `Resume`. It
never reaches `RequireCheckpoint`.

**We are telling you this rather than letting the deadline do rhetorical work it
does not do.** The consequence is not that the deadline is fake. It is that
after 5 September the deadline stops being enforced by the binary and starts
being enforced by nothing:

- **Before the window closes**, a from-genesis sync makes the *genesis manifest*
  your trust anchor. You verify a published digest of a file and every block
  after it. We are not in that chain of trust.
- **After it**, the seeded path makes *Postern Labs* your trust anchor for the
  block data. Your node still re-executes everything and still diverges loudly
  on inconsistent data. What local replay cannot detect on its own is a
  **complete and internally consistent alternative history** — which is exactly
  what weak subjectivity exists to rule out, and exactly what a signed
  checkpoint from a quorum including an external auditor would rule out again.

**That is the real content of the 5 September date for you: not whether you can
run a node, but whose word your node's history rests on.** We would rather you
took the genesis anchor while it is still on the table.

### 5.3 The plan, then

**Path A — recommended, and it closes the question this week.**

1. We publish the release tag and checksum [D1].
2. You build (~40 min) and take an archival seed copy from us; local replay is
   measured at 52 blocks/s, roughly **10 minutes** for the current chain.
3. Your node reaches its own finality and passes the gate permanently, provided
   it is never offline for 2016 epochs (22.4 days).
4. **Do it before 5 September anyway.** Same procedure, strictly better trust
   story, and it costs you nothing to do it three days early.

**Path B — if you want the genesis anchor and have the hours.** From-genesis
network sync on the release binary, ~26 hours, starting no later than
**2026-09-04 04:30 UTC**. Treat 26 hours as a floor: it was measured once, on an
idle machine, from the two published bootnodes. We would run it in parallel with
Path A rather than instead of it.

**Path C — after the window, if you have not started.** Seed copy exactly as in
Path A. It works. It rests on our word for the block data until a signed
checkpoint exists, and we will hand you one, cross-checked against your own
node's finalized root at the same epoch, as soon as the ceremony completes. Our
commitment is the trigger, not a date.

**In all three cases:** run the verifier (`deploy/bootnodes/verify-bootnodes.sh`)
before and after, keep the RPC on loopback, keep `--listen-addr 127.0.0.1`, and
run without a `validator.key` so the node prints `observer mode: no keystore`.
If you do not see that line, stop — you have a key you did not mean to have.

---

## 6. Summary of what you can act on

| When | What |
|---|---|
| **Blocked on us, hours** | The release tag and checksum [D1]. **Do not build from `main`** and do not start a sync you intend to keep until it lands — §2. |
| **On receipt of the tag** | Build, take a seed copy, be finalized and past the gate the same day — §5.3 Path A. |
| **Today, independent of us** | Change your crediting rule: **finalized + 3 epochs, two independently operated nodes agreeing on root *and* epoch, re-verified immediately before release**. Do not credit on `finalized` alone — §4.1. |
| **Today, independent of us** | Delete the one-third-of-stake slashing guarantee from your risk model. It is in our RPC source and it is not true — §4.2. |
| **Today** | Treat any testnet key as a mainnet key — §3.1. |
| **Before you write balance-polling code** | `script_hash` is `SHA3-256(pubkey)`, all 32 bytes — not the 20-byte address-truncated form. Consensus opens both, so the wrong one reads a silent zero — §3.1. |
| **On request** | Local testnet branch, build command, and a captured dated transcript of a full spend-path run. A small mainnet amount if you prefer [D2]. |
| **9–11 September** | Hosted testnet endpoint. Our estimate on an undeployed plan. |
| **Trigger, not date** | Signed weak-subjectivity checkpoint and signer set. You will be told within one business day of the auditor confirming a ceremony date — §5.1. |
| **No date** | libp2p transport, funded staking deposits, staking withdrawal, `selfcheck --json` and the gate calendar. We will not give dates for these until they are landed. |

We would rather you decided against us on accurate information than for us on
flattering information.

— Postern Labs

---

## 7. Internal only — founder decisions gating this letter. Remove before sending.

| # | Decision | Blocks | Latest useful moment |
|---|---|---|---|
| **D1** | **Push `release/g4-node-20260901` (`7a83ca89`) + tag + checksum to both remotes.** Merging arms nothing: `ANCESTRY_SEED` and `LEAK_RECOVERY` stay `u64::MAX`. Without it we cannot honestly tell them to build anything, and our own quickstart is pointing strangers off-lineage. | §2.3, §5.3, the whole letter | **2026-09-02, first working hour.** Every hour costs them window. |
| **D2** | Fund a throwaway key with ~0.001 BLCH for the mainnet spend rehearsal, and decide whether a small mainnet amount goes to the exchange. | §3.1 | 2026-09-03 |
| **D3** | Roll the two public archival observers onto the fleet lineage, or name two nodes on different builds. The two-node corroboration rule we are giving them is currently satisfied by two copies of the same stale build. | §1.1, §4.1 | 2026-09-04 |
| **D4** | **The retraction is already written, uncommitted, in the main checkout** — `rpc.rs` (+107/−20): both sentences retracted, `slashing_enforced`/`finalized_is_a_latch` flags added to capabilities, and a live measurement at epoch 1726 asserting **48 validators with provable on-chain double-signing and `"slashed": false`**. Two things needed: **(a)** corroborate the 48 figure independently before it goes to a partner — it is the single most quotable sentence in this letter and it is currently one agent's uncommitted measurement; **(b)** write `tests/slashing_backed_finality_claims.rs`, which the comment cites and which does not exist. Then commit and push. | §4.2 | **(a) 2026-09-02** — it gates sending. (b) 2026-09-03 |
| **D5** | Land `docs/LIVE-SUPPLY.md` and its expiry test on `main`. | §4.3 | 2026-09-04 |
| **D6** | Contact the external audit firm to open the Phase A ceremony calendar. **Not compressible and not delegable.** The letter commits only to a trigger, not a date, so this does not gate sending — but it gates every post-window guarantee. | §5.1 | Immediately; the window closes regardless. |

**Not requested here, and deliberately:** no activation constant is armed by
anything in this letter, no live fleet node is touched, and the libp2p crossing
plan (`~/bloch-rollout/rollout-release/travessia-libp2p.sh`) must not run — its
rehearsal injects a fault, so it cannot observe a defect that needs none, and
§1.2 now shows the defect it would need to observe was present in the binary
that produced the evidence against libp2p in the first place.
