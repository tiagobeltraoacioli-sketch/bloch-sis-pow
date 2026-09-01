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
