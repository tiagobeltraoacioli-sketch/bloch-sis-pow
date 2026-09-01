# WS0 — Transport, and why the exchange cannot run a node today

Written 2026-09-01, PMO. Supersedes item **1.3** of `PLANO-5-SETEMBRO.md`,
which is unsafe as written. Read this before acting on that plan.

## Summary

The exchange asked to run an independently validating node. Our Integration Book
tells them that is the correct deployment for crediting customer deposits, and it
is. **Both available ways to give them one are currently unsafe, for different
reasons.** This page states why, and what the bridge is.

---

## 1. The two transports are mutually exclusive, per process

`crates/bloch-pos-node/src/net.rs:73-77`:

```rust
/// The transport the engine holds. One of two, chosen at startup.
pub enum Net {
    Devnet(DevnetMesh),
    Libp2p(crate::p2p::Handle),
}
```

Selected by `--transport` at `main.rs:769-771`; **`devnet` is the default**
(`None | Some("devnet") => Transport::Devnet`). Constructed by the `match` at
`engine.rs:2806-2844`. There is no dual-stack to compile into.

## 2. Path A — give them libp2p. **Silent private fork.**

The live fleet is 100% devnet: 63 validators across 7 hosts plus 2 archival
observers. A libp2p node pointed at devnet peers negotiates nothing, ends with
**no peers**, and then proposes and applies its own blocks — printing ordinary
`applied … finalized` lines the whole time. Verified by measurement with three
local nodes.

This is the worst failure mode available to us, because **it does not look like
a failure.** An exchange watching block height climb and finality advance has
every ordinary indicator of a healthy node, and is crediting deposits against a
chain only it can see.

### 2.1 Our own CLI tells them to do this

`crates/bloch-pos-node/src/main.rs:148-150`, **on public `main` right now**:

> `libp2p` is the production stack: gossipsub on Genesis-4-only protocol ids,
> `gossip.rs` admission control, directed paginated sync.
> **Anything reachable from outside a firewall wants this.**

Every word of that is true as a description of the code and wrong as advice
today. An exchange is, definitionally, "reachable from outside a firewall". They
will read this line, pass `--transport libp2p`, and land on a private fork.

**This is the single highest-severity exchange-facing defect found. It is one
paragraph of help text and costs nothing to fix.** It must say that the live
Genesis-4 network runs the devnet transport, that libp2p currently has no peers
to find, and that a node with zero peers will still produce blocks.

## 3. Path B — give them devnet. **Unauthenticated port, and an O(N) fleet change.**

The devnet transport's own module doc, `net.rs:19-35`, is unambiguous:

> **This is not the production network layer.** … It has no authentication, no
> admission control, and it does not carry an `Origin`, so `gossip.rs`'s
> verdicts have nowhere to go on this path.

And `main.rs:157-160`: a routable bind **"MUST be firewalled to the known peer
addresses."**

Two consequences, both blocking:

1. **It is a static full mesh.** "Topology per peer pair: each side dials the
   other" (`net.rs:32`), with peers supplied as `--peers <host:port,...>`.
   Admitting participant 66 means editing the peer list and firewall of all 65
   existing nodes. That is an O(N) reconfiguration of the live fleet — founder
   action, not a PMO one, and not a small one.
2. **It would expose an unauthenticated consensus port to the public internet.**
   Anyone who finds the port can inject blocks and attestations with no
   admission control. We have already been hurt by exactly this: on 2026-08-09
   one stale external node dumped 1,270 old blocks in five minutes and **halted
   block production across the entire network**. The producer has been running
   `--listen 127.0.0.1` ever since. Path B proposes to undo the mitigation we
   adopted after an outage.

## 4. Therefore: `PLANO-5-SETEMBRO.md` item 1.3 must not be executed as written

That item says to bring ≥2 fleet nodes up on `--transport libp2p` with a routable
port and hand the exchange the resulting peer list. Given §1 and §2, those two
nodes **leave the devnet fleet the moment they switch** — they cannot talk to the
other 63. The exchange would then sync to a 3-node island that forks from
mainnet, and the plan's own deliverable (1.4) would hand them a fork.

The plan is not wrong about the deadline or the ordering. It predates the
measurement that the transports cannot interoperate.

## 5. The bridge, and why it is cheaper than it sounds

**A node that speaks both transports at once** — devnet to the fleet, libp2p to
outsiders — turns Path A and Path B from a dilemma into a deployment. The
exchange gets the authenticated, admission-controlled, firewall-friendly stack;
the fleet is not touched, not reconfigured, and not exposed.

The founder framed dual-stack as an open design question rather than a given.
The measurement says it is **cheap**, and it is the only option that requires no
change to the live fleet:

- **The engine is already transport-agnostic.** `net.rs:15-17` states it as an
  invariant — the engine talks to the transport through exactly two calls,
  `Net::broadcast` and `Net::report`, "so nothing in the consensus loop knows
  which transport it is running on." Verified: `Net` has those two methods and
  no others (`net.rs:84`, `net.rs:97`).
- **The engine branches on the variant in exactly one place.** `net: net::Net` is
  a single field (`engine.rs:603`), and the only `match` on the variant is the
  construction at `engine.rs:2806-2844`. The three other mentions
  (`:4575`, `:5235`, `:6524`) are test setup.
- Both transports already deliver inbound work as the same `NetEvent` into the
  same channel (`net.rs:63-71`).

So the shape is: add `Net::Both(DevnetMesh, p2p::Handle)`; `broadcast` fans out
to both; `report` forwards to the libp2p half (the devnet half is already a no-op
by construction — it carries no `Origin`); both halves feed the existing event
channel. One new construction arm.

**This is a design recommendation with a measured cost, not an endorsement to
build.** The decision is the founder's. What the measurement removes is the
assumption that dual-stack is expensive — it is substantially cheaper than
migrating 65 live validators.

### 5.1 What must be verified before anyone writes it

- **De-duplication.** With both transports live, a block arriving on devnet and
  again on libp2p must be idempotent at the engine. Likely already true (a
  replayed block is an ordinary case) but it must be asserted, not assumed.
- **No frame-byte drift between the halves.** `FRAME_*` and `SYNC_TAG_*` are the
  namespace with **no compiler diagnostic of any kind**
  (`docs/WIRE-NAMESPACE-REGISTRY.md` §2, §3). A bridge is the first thing that
  would encode with one numbering and decode with another. **The §8.1
  pairwise-distinctness test is a prerequisite for this work, not a follow-up.**
- **The `--p2p-listen` default is `/ip4/0.0.0.0/tcp/16400`**, which collides with
  the fleet's `16400+N` RPC convention. Change it before publishing any address,
  or the first thing the exchange dials is an RPC socket.

## 6. The zero-peer guard — independent of everything above

Whatever transport is chosen, **a validator with zero peers should not silently
propose.** That behaviour is what converts a configuration mistake into a
fork that looks healthy, and it will outlive this particular migration: it is
equally a trap for the next third-party operator, on any transport.

The guard is small and its absence is the reason §2 is severe rather than
merely annoying. **PMO ask: refuse to propose — loudly, and on every slot — while
the peer count is zero and the node is not explicitly launched as a single-node
devnet.** It needs an explicit opt-out flag because a genuine one-node local
devnet is a supported and frequently used configuration.

This is the one item on this page that helps the exchange **even if nothing else
ships by 5 September**, because it converts their most likely failure from
silent to loud.

---

## 7. Verification pass, 2026-09-01 — three corrections and one new bug

A full audit of `net.rs`, `p2p.rs`, `engine.rs` and all worktrees confirmed §1–§6
and changed three things. Corrections are recorded rather than silently folded in,
because the *reasons* they were wrong are reusable.

### 7.1 The dual-stack cost estimate holds, and is now exact

Confirmed: `Net` has two methods, and both variant `match`es are internal to
`net.rs` (`:84-89`, `:97-102`). The engine holds one private field
(`engine.rs:518`) and **never discriminates the variant** — the only
non-test construction sites are `engine.rs:2250` and `:2288`. Ten call sites
total, all plain method calls: `broadcast` at `engine.rs:954, 1139, 1386, 1848,
2549`; `report` at `:1745, 1796, 1798, 1803, 1807`.

`Net::Both` is **~10 lines inside `net.rs` and zero lines in the engine.**

*(Line numbers differ from §5 above — §5 cites the `pmo/wire-namespace-registry`
worktree, this cites mainline `validator-ops` @ `ad535739`. Same code.)*

### 7.2 NEW BUG — `inflight` underflows on the libp2p path

Not previously known, and it is a **blocker for dual-stack specifically**.

`net.rs:217` increments the `inflight` counter. `engine.rs:2573` decrements it
**unconditionally for every `EngineEvent::Net(_)`**. The libp2p path never
increments — `inflight` appears **zero times** in `p2p.rs`; libp2p events reach
the engine through the forwarder at `engine.rs:2238-2246`, which only wraps and
forwards.

The comment at `engine.rs:2568` asserts the opposite:

> `// Every EngineEvent::Net was counted into inflight by the transport;`
> `// releasing it here — after handling, not on dequeue — is what makes`
> `// the cap mean "work the engine has not done yet".`

Under `--transport libp2p` that invariant is false, and `AtomicUsize::fetch_sub`
**wraps**: after the first libp2p event `inflight` is `usize::MAX`.

Latent today, because the only reader (`net.rs:214`) belongs to the devnet mesh,
which is not running when libp2p is. **Under `Net::Both` it is immediately
fatal:** the shed check at `net.rs:214` is permanently true, so the devnet half
silently drops *every* inbound frame for the life of the process — and logs
nothing. A bridge node built without fixing this would look like it was running
and would relay nothing from the fleet.

**Fix before any `Both` variant exists.** This is a prerequisite, not a
follow-up. It also makes §5's estimate honest: ~10 lines *plus* this fix.

### 7.3 Two more things that must move with a bridge

- **The get-blocks arm must pick one transport, not both.** `engine.rs:2549`
  broadcasts `FRAME_GET_BLOCKS`. On devnet that is a real fan-out to every peer
  (`net.rs:183-193`); on libp2p `handle_command` turns it into a *directed*
  request to `SYNC_FANOUT` peers (`p2p.rs:995-1000`, `:1035-1043`), whose own doc
  records that broadcasting it was **the Genesis-3 root cause** — "O(peers ×
  blocks) amplification that stalled the chain". Fanning out on both per sync
  tick reintroduces that stall.
- **Duplicate delivery is absorbed, not free.** Both transports feed the same
  channel; `ingest` dedups by block id (`engine.rs:1145-1148`) and the
  attestation pool dedups. Correctness holds; the cost is a second decode per
  message. `report()` needs nothing — devnet attaches `Origin::none()`
  (`net.rs:287`) and `Handle::report` already no-ops on it (`p2p.rs:651-656`).

### 7.4 CORRECTION — the zero-peer failure is worse than §2 said

§2 called the silent fork "the worst failure mode available to us". That was an
understatement in one specific respect: **it is not merely undetectable, it
actively converges on looking healthy.**

- **The RPC has no peer surface at all, by design.** `getpeers` is in
  `RPC_ABSENT` (`rpc.rs:869`) — *"peer identities are not exposed on an
  unauthenticated port."* `getchaininfo`'s full field list (`rpc.rs:1565-1615`)
  has no peer count and no transport name. Mainline has **no metrics endpoint**
  (no `metrics`/`prometheus` anywhere in `crates/bloch-pos-node/src/`).
- The dial failure **is** logged loudly and repeatedly — `p2p.rs:1120-1131`
  prints `p2p: NO PEERS — dial failed`, retried every `REDIAL_INTERVAL = 10s`
  (`p2p.rs:298`). But it goes to **stderr only**. It appears on no queryable
  surface, so it is invisible to exactly the monitoring an exchange builds.
- **The two indirect tells both decay.** `behind_by_slots` (`rpc.rs:1614`)
  oscillates rather than growing, because a lone validator wins ~1/64 of
  proposer draws. `finalized.epoch` *should* freeze — one validator cannot make
  quorum — but `LEAK_RECOVERY_ACTIVATION_EPOCH = u64::MAX` (`params.rs:597`)
  means the quorum-denominator floor is **inert**: `finality.rs:366`'s
  `max(leak_adjusted, unleaked_total/2)` never runs, so with
  `INACTIVITY_LEAK_QUOTIENT = 64` (`params.rs:67`) the absent 63 leak toward zero
  and the denominator falls to the lone node's own stake. Meanwhile
  `LEAKED_ROSTER_ACTIVATION_EPOCH = 1400` **is armed** (`params.rs:244`, gated at
  `transition.rs:1666`), so past epoch 1400 the absent 63 leave the duty roster,
  the lone node proposes **every** slot, and `behind_by_slots` returns to ~0.

**The conclusion, and it is the reason this page exists.** Past the leak horizon
a transport-forked node becomes sole proposer *and* sole finalizer of a private
chain, while every machine-readable field an integrator is told to read reports a
healthy, finalizing node. And our own contract points straight at it:
`rpc.rs:1631-1650` tells integrators the honest replacement for confirmation
counts is the single boolean `Finality::Finalized` — **"Credit here."**

An exchange following our Integration Book exactly, on a node misconfigured in
the one way our own CLI help text invites (§2.1), would credit customer deposits
against a chain that exists only on their machine. **The finality signal we told
them to trust is the signal that fails.** This is the settlement guarantee that
does not hold, reached from the transport side.

*Verified:* the constants, gate conditions, absent floor, and the absence of every
peer surface. *Inferred:* the leak trajectory — the arithmetic was read, not run.
**Ask: run it.** A single simulation over epochs 1400+ turns the most important
claim on this page from inferred to measured, and it needs no fleet access.

### 7.5 The guard tests exist — merge, do not write

`agent-ad3f0cc77273711fd` (branch `integ/validator-opening`, 26 commits) is the
integration superset: the DNS-fallback transport fix, the C-1/C-2 collision
resolution, the pairwise guard tests (`net.rs:825`, `p2p.rs:1899`, `p2p.rs:1926`),
and a `bloch_pos_peers_connected` gauge on a Prometheus surface
(`rpc.rs:1604, 1661`) — **the missing detection surface for §7.4.**

Its `net.rs:77-81` documents the collision in its own words:

> **0x07, not 0x05.** The clock gate and checkpoint sync were written against the
> same base, independently, and BOTH claimed 0x05/0x06 — two consts with
> different names and the same value, which the compiler accepts in silence.

**It carries 5 `wip:` commits** (`e020c3c3`, `dd7529a2`, `6951df8d`, `1ad75761`,
`9071ebae`) and must be reviewed by delta, not by `git log`, before it is
endorsed.

Two caveats that change merge order:
- Landing `agent-a58dfe6cc066ef5b3` **independently re-introduces C-1/C-2** — it
  carries the colliding numbering and **no tag assertion of any kind.**
- Wiring the peers gauge into the duty gate (`engine.rs:2531-2541`, the
  boot-grace check, which is already the "may I perform duties" seam) is
  **unwritten in every tree.** The gauge is observability only; its own doc says
  so: *"nothing in consensus reads it."* §6's guard is still real work.

### 7.6 There is no unmerged discovery or bootnode code

Zero hits across all worktrees for `Net::Both`, `Kademlia`/`kad`, `autonat`, or
`dcutr` in node source. No unmerged dual-stack, discovery, or NAT-traversal work
exists. Those terms appear only in prose and ops files.

And the directory names lie, exactly as the standing rule predicts — recorded so
nobody re-derives it:

| Directory | Actual branch | What it really is |
| --- | --- | --- |
| `bootnode-syncfix` | `integ/ws-checkpoint-tooling` | WS-checkpoint tooling. **Zero** net/p2p changes. |
| `wt-exchange-pub` | `pub/exchange-bootnodes` | A carryover checksum fix. Nothing about bootnodes. |
| `wt-transporte-libp2p` | `ops/transporte-libp2p` | **Empty** — 0 commits ahead of mainline. |
| `dual-stack` | — | Identical to mainline on both files. |
| `agent-bootnode-onboarding` | `integ/bootnode-onboarding` | A gossipsub relay gate for slashing evidence; its bootnode content is a **devnet** list of 2 keyless observers. |

**`agent-bootnode-onboarding` independently confirms §1 and §2** — it ships
`deploy/bootnodes/bootnodes.txt` with an explicit note that `--transport libp2p`
against those hosts exchanges zero frames, and a `wip:` commit `49973df5`
described as *"experimento de 3 nós provando que libp2p e devnet são
exclusivos"*. The three-node experiment is preserved in the repo.

### 7.7 Worktree count: ~80, not 195

`git worktree list` reports 80 (64 under `.claude/worktrees/`, live and growing
during the scan, plus 16 registered elsewhere). All 16 outside `.claude/` are
identical to mainline in `net.rs` and `p2p.rs`. The "195" figure in
`INVENTARIO.txt` and in earlier registry revisions is stale. **Only 8 of 64 differ
from mainline in `net.rs`/`p2p.rs`; the other 56 are byte-identical on both.**
The transport surface is far smaller than the worktree count suggests.
