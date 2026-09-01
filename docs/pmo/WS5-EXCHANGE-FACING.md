# WS5 — Exchange-facing: what is public, what is wrong, what is written but unsent

Written 2026-09-01, PMO. Audited against `main` (both public remotes), the
`validator-ops` branch, and 64 worktrees.

## The shape of this workstream, in one paragraph

Almost nothing here needs to be *built*. The bootnode list exists and was
verified today. The corrected integration book exists, 1,070 lines against the
347 on `main`. The third-party quick start exists, 406 lines, with a real
command line. The withdrawal client exists with 30 tests. **All of it is
unmerged and unsent, and `validator-ops` is pushed to no remote at all**
(`git branch -r --contains validator-ops` is empty). Meanwhile what the exchange
*can* read is `main`, and `main` is wrong in ways that would cost them money.
This workstream is a publishing problem wearing an engineering problem's clothes.

---

## 1. The settlement guarantee we gave them, and why it does not hold

### 1.1 The sentence

`main:docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md:190-192`:

> Finality is explicit on Genesis-4 and published in every `getchaininfo`
> response — you do not estimate it from a confirmation count. **Credit on
> `finalized` and you have a cryptographic settlement guarantee, typically 1–2
> epochs (16–32 minutes) after inclusion.**

Reinforced at `:46` (`| Settlement | finality at epoch boundaries, typically 1–2
epochs |`) and `:331` (a checklist item: *"Credit on `finalized`, read from
`getchaininfo`"* — from a single node, with no corroboration).

**Three independent defects. Each alone would require a correction.**

### 1.2 The timing is wrong — 32–48 minutes, not 16–32

Finality here is k=1 consecutive justification. A transaction in epoch *E* is
first covered by checkpoint *E+1*; that checkpoint justifies at the first block
of *E+2* and finalizes at the first block of *E+3*. Best case is just over two
epochs; normal case three. **32–48 minutes**, and unbounded under degraded
participation.

Our *older* Genesis-3 book had this right —
`main:docs/integration/BLOCH-EXCHANGE-INTEGRATION.md:1219` says *"**Time to
finality** | **≈ 32 minutes** typical; **≈ 48 minutes** worst case."* The
Genesis-4 document regressed a number we had already got correct. Worth saying
plainly in the correction: this was a regression, not a discovery.

### 1.3 "Cryptographic settlement guarantee" is conditional, and the condition is not met

The finality quorum denominator is **leak-adjusted and unfloored**:

- `finality.rs:342-345` subtracts leaked stake from the denominator,
  unconditionally.
- `finality.rs:353-364` puts the protective floor behind a gate:
  `else if !gates_forced_open() && votes.epoch < LEAK_RECOVERY_ACTIVATION_EPOCH
  { leak_adjusted }`.
- `params.rs:597` — `LEAK_RECOVERY_ACTIVATION_EPOCH = u64::MAX`. **The gate never
  opens on the live chain.**
- `params.rs:147-149` — `MIN_QUORUM_DENOMINATOR_NUM/DEN = 1/2`, inert behind the
  same gate.

So the denominator shrinks toward whatever minority a partitioned node can still
hear, and **that minority finalizes its own branch with no bug and no rule
disagreement.** The crate says so itself (`finality.rs:960-975`), and ships the
demonstration: `a_partitioned_minority_finalizes_because_the_leak_shrinks_the_denominator`
(`finality.rs:976`) has **4 of 64 validators — 6.25% — reaching a false quorum.**

**This is not theoretical. On 2026-08-24 three nodes finalized epoch 986 under
three different roots.** `finalized: true` from one node is not evidence that the
network finalized anything.

*(The founder-set quorum floor of 1/2 is a deliberate decision — liveness over
root-uniqueness. The defect is not the value; it is that the floor is gated off
entirely, so the decision is not in force.)*

### 1.4 `finalized` is not a latch — it can move backwards

Independent of §1.3, and **not covered by the two-node corroboration mitigation.**

Inside the gadget, finality is monotone (`finality.rs:458`). But the node does
not own the gadget across a reorg:

- `Engine::do_reorg` (`engine.rs:1609`) takes `state_at_canonical(ancestor)` and
  adopts it via `self.state.set_arc(st)` **unconditionally**. The function
  contains **zero occurrences of `finaliz`** — nothing compares incoming to
  outgoing.
- `forkchoice.rs` contains the string `finalized` **zero times**; fork choice
  walks from the *justified* root (`forkchoice.rs:200`) and nothing prunes by
  finalized checkpoint.
- The only adopt-path mention is a log line that is one-directional by accident
  — `engine.rs:1511` prints only `if after.finalized.epoch > before.finalized.epoch`.
  **A downward move is never even logged.**

A reorg to the justified root can therefore install a state whose finalized epoch
predates what the node was reporting. A block returned `"finalized": true` can
later report `"justified"`; `finalized_height` can decrease. This matches the
known finality-rewind incident, and **no ratchet-shaped test exists in either
crate.** That absence is the cheapest durable fix in this section.

### 1.5 The caveat that undercuts even the corrected advice

The corrected book tells the exchange to corroborate across two independent
nodes. `scripts/fleet-gates.tsv:26-27` shows **the two archival nodes serving the
public RPC quorum are on binary `bloch-pos-quatro`, while the 7 fleet boxes moved
to `bloch-pos-cinco`.** The file's own header: *"They are the population most
likely to fork on a flag day and the least likely to be noticed doing it, because
a wrong answer from an archival looks like an answer."*

**"Two independent nodes" is not independent when both are the same stale
build.** The corrected book must either name two nodes on different builds or
stop implying independence it does not have.

### 1.6 The correction is written and unsent

`docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md` on `validator-ops` is
1,070 lines (vs 347 on `main`) and already contains §5.3 *"`finalized` is not
currently a network-unique value"* and §5.4 *"`finalized` is also not a latch"*,
plus a five-point credit policy. It is backed by
`docs/integration/INTEGRATION-BOOK-AUDIT-2026-08-31.md`, which grades every claim
in the book: **25 verified, 24 stale, 10 wrong, 4 aspirational, 6 unreachable.**

**None of it has reached the exchange, and the branch is on no remote.**

The line to lead with is already drafted, at `:617`: *"We would rather you
learned this from us than from your reconciliation."* Send it.

---

## 2. What is public right now and misleads

### 2.1 The file they cited

`deploy/fly/README.md` is on `main`, and `main` is pushed to both public
remotes. Their citation is correct:

```
:43   - **P2P seed multiaddr** (to bootstrap other nodes):
:45       /ip4/<dedicated-ipv4>/tcp/16110/p2p/<peer-id>
:41   - **RPC:** `https://<app>.fly.dev`
:22   flyctl volumes create bloch_data --size 30 --region <your-region>
```

It is worse than stale. Last touched **2026-07-09**, it documents the
**Genesis-1 SIS proof-of-work node** — `--mine`, *"SIS PoW is CPU-bound"*,
*"Block found! h=1"*. It predates Genesis-4 by a month, and the Fly
infrastructure it targets was **destroyed in the 2026-08-23 Edgevana migration**.
Every concept in it is retired. A retirement banner for this exact file exists,
unmerged, at `agent-a17bdf87e3c4e85d2`, and names the `<dedicated-ipv4>` template
as *"never a dialable value, only a shape. A partner lost real time to that
ambiguity."* **Delete the file; do not banner it. Nothing in it is worth
keeping.**

### 2.2 The wider leak is worse than empty placeholders

Empty `<placeholders>` at least announce themselves. These are **filled-in, dead
addresses on the retired PoW stack**, which read as current instructions — all on
`main`, none bannered:

| file:line | content |
| --- | --- |
| `docs/CARRYOVER.md:32-35` | `--peer /ip4/192.248.190.123/tcp/16116`, `--peer /ip4/45.76.89.225/tcp/16111` |
| `docs/SNAPSHOT-BOOTSTRAP.md:94-96` | the same three lines, under *"The supported onboarding path is a snapshot"* |
| `docs/adr/ADR-021…:104` | `Bootstrap seed: /ip4/80.78.28.142/tcp/16110/p2p/<full-peer-id>` |
| `docs/PROJECT-STATUS.md:98-104` | *"every node is a seed… **mDNS** auto-discovers + dials LAN peers zero-config"* |

These are **libp2p multiaddrs for a dead chain, offered as the onboarding path** —
which is also §2.1 of `WS0`: they steer a newcomer onto the transport that
silently forks. `PROJECT-STATUS.md` is already flagged in-tree as having
*"misled one reader."*

Also: **`deploy/` on `main` is 41 files and effectively 100% obsolete** for a
Genesis-4 integrator (32 Fly TOMLs pinning the dead OVH IP `51.83.249.212`,
Akash SDLs, `# TODO: publish to a registry you control`, PoW ports, `--mine`).

And `docs/API.md`'s Genesis-3 banner carries a **false carve-out**: it says *"The
transport, authentication, error-code and pagination conventions stand."* They do
not — `rpc.rs:50-51` reads *"No API key, no rate limit, no per-method
authorisation — unlike the Genesis-3 surface, which has all three."* An
integrator reading `API.md` builds for `X-API-Key` and `--rpc-public`, neither of
which exists in the Genesis-4 binary.

### 2.3 The minimal public commit

Smallest change that stops the bleeding, in priority order:

1. **Delete `deploy/fly/README.md`** (and, on the same commit, the rest of
   `deploy/` or a single banner over it).
2. **Banner `docs/CARRYOVER.md`, `docs/SNAPSHOT-BOOTSTRAP.md`,
   `docs/PROJECT-STATUS.md`, `docs/adr/ADR-021`** as Genesis-1/3 history.
   Banners for two already exist in worktrees.
3. **Fix the `docs/API.md` carve-out sentence** — one sentence, and it currently
   promises authentication that does not exist.
4. **Publish the bootnode list and the quick start** (§3).
5. **Fix the `main.rs:148-150` libp2p help text** (WS0 §2.1) — it ships in the
   binary, so it is public in a way no doc edit reaches.

---

## 3. Bootnodes and the quick start — done, verified today, unmerged

`agent-bootnode-onboarding` (branch `integ/bootnode-onboarding`, 13 commits)
holds `deploy/bootnodes/bootnodes.txt`:

```
139.180.166.5:19100
139.180.173.231:19100
```

Bare `host:port` — **devnet transport, correct for the live fleet**, not a libp2p
multiaddr. Both are keyless archival observers, deliberately not validators. The
header records a same-day check: both at epoch 1638 reporting the **identical**
finalized root `bb9fe982…5670` at height 31462. It ships `verify-bootnodes.sh`
(read-only; fails if a bootnode is found on libp2p) and
`docs/THIRD-PARTY-QUICKSTART.md`, 406 lines, with the command line filled in.

It also documents **why a validator's own `--peers` string must never be
published**: each carries 128 entries, 64 pointing at decommissioned boxes, plus
a ghost `139.84.201.52:19063` — a dead port on a live host, which passes any
host-level reachability check.

**Contradiction to resolve before publishing:** this worktree's own
`docs/pmo/WS1-BOOTNODES-TRANSPORT.md:82-85` plans to deliver bootnodes by
bringing nodes up **on libp2p** — the opposite of the devnet list actually
delivered, and blocked anyway because **no `p2p_identity.bin` exists anywhere on
the fleet.** WS0 §4 supersedes that plan; this page is the record.

---

## 4. Can a cold sync complete? The repo holds both answers

**This is the question that decides everything else, and it must have an owner
today.** If a fresh node cannot converge, the 5 September deadline is moot —
the exchange cannot run a node before it *or* after it.

**Answer A — `main:genesis/README.md:29-42`, public, unretracted:**

> Syncing from genesis over the transport the live fleet runs (`--transport
> devnet`) **does not complete**. A node started this way applies the blocks it
> can reach, then follows the live tip over gossip **without backfilling the
> gap** — and reports a head, a height and a state root as though it were caught
> up. We reproduced it on 2026-08-14: an observer reported height 556 … while
> the network was at height 1511 … **with no error raised at any point.**
> … a node stood up before it lands would answer confidently and wrongly,
> **which is worse for an exchange than not running one.**

**Answer B — `THIRD-PARTY-QUICKSTART.md:216-248`, measured 2026-09-01 (today):**
a release build syncing from the two published bootnodes converges at ~35
slots/min against a chain advancing 2 slots/min — **~26 hours** to a head near
slot 52,600.

### 4.1 They are not the same claim, and both may be true

Answer A describes **no backfill at all** (never converges, at any speed).
Answer B measures **slow backfill** (converges). A is dated 2026-08-14; B was
measured today. The most likely reading is that **A is stale and was never
retracted** — but "most likely" is not good enough for the one fact the
integration rests on, and A is the one that is public.

### 4.2 The load-bearing caveat in Answer B

The 26-hour table was measured **with** the catch-up fix
(`fix(catch-up): share the eUTXO map so an epoch roll stops paying the ledger`,
`Arc<BTreeMap>` copy-on-write) applied — a fix that lives on
`integ/ws-checkpoint-tooling` and **is not merged, and is not in any release.**
The quickstart's own note says a build without it *"reached the same epoch in
about twice the time"*, while honestly flagging that comparison as
CPU-contaminated and not to be quoted.

**So the published 26-hour figure describes a binary the exchange cannot
currently obtain.** That is the gap to close, and it is a merge, not research.

### 4.3 PMO position

**Do not publish a quick start that promises a completing cold sync until one
person has re-run Answer A's 2026-08-14 reproduction against a current build and
either retracted `genesis/README.md` or withdrawn the 26-hour claim.** Shipping
either answer while the other stands on `main` is how an exchange ends up with a
node that "answers confidently and wrongly" — which `genesis/README.md` itself
already identifies as worse for them than having no node.

**Recommend regardless: lead with the archival-seed path**, not the replay. The
quickstart already calls it *"the faster path… recommended"*: copy `blocks.log`,
`meta.bin` and `ws_latest.bin` from a current node. It sidesteps the entire
dispute above, and it comfortably fits the window. **The replay is the
interesting engineering story; the seed copy is the deliverable.**

---

## 5. Spend path and the mainnet rehearsal

Three unmerged pieces, all single WIP commits dated 2026-08-31 18:21:

| commit | path | worktree |
| --- | --- | --- |
| `61f82dc0` | `crates/bloch-withdraw` | `agent-a101bfb4ec149a897` |
| `6a95830c` | `tools/spend-runbook` + `docs/integration/BLOCH-SPEND-RUNBOOK.md` | `agent-ae11cce07854da4e6` |
| `d3211c0a` | `tools/partner-send` | `agent-a6dd9e3aeb299f61f` |

`crates/bloch-withdraw` is the reference exchange withdrawal client: 3,769 lines,
a state machine that *"pays one withdrawal at most once"*, **30 tests** (8 in
`tests/race.rs` against a chain fake that re-runs real consensus arithmetic —
`fee_market::charge`, real hybrid signature verification, conservation as
equality). It is **UNAUDITED** by its own `Cargo.toml:26`, has never run against
a real node, and is absent from `main`'s workspace.

### 5.1 The double-payment race — the failure mode is double payment, not loss

Four chain facts combine: a transfer commits to exactly one base fee
(conservation is an *equality*, so bytes built at fee B are permanently invalid
at B′); a missed transfer is dropped from the mempool with no notice; **there is
no txid at the RPC**; and crediting is on `finalized`, not depth. Therefore
(`DOUBLE-PAYMENT-RACE.md:40-42`): *"Because a rebuilt transaction has different
bytes and there is no txid, **the transaction cannot serve as its own idempotency
key.**"*

The race: you conclude T1 will never land and rebuild as T2 over fresh coins. But
"not in mempool and the fee moved" is not proof — your node may be behind or on
another branch, the base fee **oscillates back to B**, a peer still holding T1's
bytes can get them included later, and a reorg can flip T1 from excluded to
included between your check and your rebuild. Both are then valid, they conflict
on nothing, **and both land.**

**A fix is implemented, not merely described.** Rule 1: the **pinned input set is
the payment's identity** — coins are pinned to the caller's withdrawal id
durably before signing, append-only, so every attempt spends the same set.
*"The double-payment is not made improbable; it is turned into a double-spend,
which is the one thing this chain is built to refuse."* Rule 2 (a `gettxout`
probe before rebuild) is explicitly **not** the safety property.

Residual risk is stated honestly, and note how it lands against §1.4: a node that
rewinds below its own finalized checkpoint — *"a failure mode this network has
actually exhibited"* — **can make the credit report wrong; it cannot make the
recipient be paid twice.** That is the right shape, and it is worth showing the
exchange as evidence of how we reason about their money.

### 5.2 Mainnet rehearsal: not done, and small

`BLOCH-SPEND-RUNBOOK.md:613` — *"**No write was sent to mainnet.** That is the
boundary of this rehearsal."* The **devnet** rehearsal genuinely executed with
real transcripts (txid `c3d743e0…`, slot 154, finalized, conservation checked
exactly); mainnet was read-only.

Closing it needs one founder action: **fund a throwaway key with ~0.001 BLCH
(100,000 sat)**. That is the entire blocker. It is the cheapest credibility item
in this document.

---

## 6. Defects the exchange will hit

Authoritative list: `docs/VALIDATOR-RUNBOOK.md:734-763` (§15, G1–G13) — unmerged,
and not on `main`. Those bearing on this integration:

- **G3 — no weak-subjectivity checkpoint has ever been published, and no signer
  set exists.** From **2026-09-05 07:07:19 UTC** a stranger cannot start a fresh
  node at all. The epoch-1536 checkpoint in `agent-a58dfe6cc066ef5b3` is
  **UNSIGNED** (`signer_set_id 1 (Phase A — keys DO NOT EXIST YET)`).
- **G4** — no published bootstrap peers on `main`; *"a stranger has no one to
  dial."* Fixed by §3, pending merge.
- **G5** — slashing protection, doppelganger detection, the clock gate and the
  cold-sync fix are **all on unmerged branches; no release contains them.**
  Release `genesis4-node-20260814` is **consensus-dead since epoch 800** —
  *"it silently forks onto a dead branch — do not run it"* — and the R2 paths
  older docs point at return **404**. **There is no good binary to hand them.**
- **G9** — the RPC has no authentication, no rate limit and no CORS, on a port
  that accepts `sendrawtransaction`. **All 64 fleet nodes were exposed on
  2026-08-30.**
- **G11** — RPC port `16400` (docs/fleet) vs `16310` (binary default) vs `16400`
  (libp2p listen default): following the doc with libp2p produces a bind
  conflict. See WS0 §5.1.

**Hosted testnet** (`deploy/testnet/`): *"plan + scripts, not yet deployed"*;
ports and `t4rpc.posternlabs.com` unclaimed; the faucet has never run against a
live node and ships with payout disabled; and cross-network replay is prevented
**only by outpoint disjointness, not by protocol** — `spend_signing_root` carries
no chain id. That last one is a real defect, not a deployment gap: it means a
testnet rehearsal signature is not intrinsically confined to the testnet.

---

## 7. Founder decisions this workstream needs

1. **Send the §1 correction?** Text is written. PMO recommends yes, today,
   independent of every merge below.
2. **Fund ~0.001 BLCH for the mainnet spend rehearsal** (§5.2).
3. **Ratify `Withdraw = 0x08`** (registry C-4) — currently inherited from a merge
   conflict resolution, not decided.
4. **How much of the staking-deposit defect the exchange is told** (see the
   correctness-debt page) — the audit deliberately withheld operational detail
   and flags disclosure as a founder call.
5. **Who owns resolving §4** (does cold sync complete?) — and by when. This one
   is not a preference; nothing else in the workstream is safe to publish until
   it is answered.
