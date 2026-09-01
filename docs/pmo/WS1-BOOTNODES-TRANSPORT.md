# WS1 — Bootnodes + routable transport

**Deadline item.** The exchange cannot run the independently-validating node our
own documentation tells them to run.
Status: **AT RISK — deliverable by 5 Sep, but only on a narrow path, and it has a
second deadline hiding behind it.**

## What exists (merged, mainline)

The libp2p transport is **not a stub**. `crates/bloch-pos-node/src/p2p.rs` (1720
lines) implements gossipsub with explicit `TopicScoreParams`, identify,
request-response directed sync, noise + yamux + connection limits, Genesis-4-only
protocol ids (`/bloch-g4/meshsub/1.1.0`), and persistent peer identity
(`load_or_create_identity`, `p2p.rs:680-699`, writes `<data-dir>/p2p_identity.bin`
at 0600). Zero `TODO`/`unimplemented!`/`panic!` in the code path. It is reachable
today via `--transport libp2p --p2p-listen … --p2p-peer …`.

`--transport devnet` remains the default at `main.rs:766-773`, and the comment
there is accurate about why: the 64-validator fleet finalized on devnet and the
same command must keep reproducing that run. **The live mainnet fleet runs devnet
today** — plain TCP full mesh, and `net.rs` documents its own lack of
authentication, admission control and scoring.

## What is missing

**The bootnode list. That is the whole blocker, and it is operational, not
engineering.** A repo-wide sweep of all 62 live worktrees found **no real
Genesis-4 multiaddr anywhere** — every real IP in the tree is a retired
Genesis-1/3 PoW address on port 16110. `--p2p-peer <multiaddr>` already consumes
a static list and re-dials on a timer, so no code is needed to *use* one.

Genuinely not built, and **not needed for this deliverable**: peer discovery of
any kind (no kademlia, mDNS, PEX or DNS seed), NAT traversal (no
autonat/relay/dcutr/upnp), external-address advertisement (`add_external_address`
is never called), peer persistence (`known_peers.json`). The Cargo manifest
excludes these deliberately and says why (`Cargo.toml:61-74`). A static bootnode
list satisfies an exchange; discovery is a later, larger programme.

Beware `docs/PROJECT-STATUS.md:94-100` — "every node is a seed", mDNS, PEX. That
paragraph describes the **dead Genesis-1/3 PoW node**, not Genesis-4. It has
already misled one reader.

## Built but unmerged

| Work | Where | State |
| --- | --- | --- |
| `deploy/OBSERVER-NODE.md` (344 lines) — **the exchange-facing observer document**, with real genesis digests, carryover hashes, the flag table, systemd unit, canonical-chain verification | `agent-a17bdf87e3c4e85d2` @ `eca224a0` | Complete. Also retires `deploy/fly/README.md` with a banner naming the `/ip4/<dedicated-ipv4>/…` placeholder as the thing that wasted a partner's time. |
| Checkpoint state-sync (`state_sync.rs` +869), clock gate (`time_check.rs` +398), `--json`, validator runbook, observability spec, `deploy/testnet/` kit | `agent-ad3f0cc77273711fd` / `agent-testnet-deliver` @ `40e22169`, branches `integ/validator-opening`, `agent/testnet-deliver` | 57 files, +13,956/−2,601. Includes a real routability fix: `with_dns` failure now downgrades to TCP-only with a warning instead of refusing to start, so `/dns4/…` peers work. |

Both are recoverable — they sit on branches, not detached. `agent-a17bdf87e3c4e85d2`
is based on an older root (`0e609f19`); **cherry-pick its docs, do not merge its
tree**, or you will revert `engine.rs`/`slashing.rs`.

## The second deadline

`OBSERVER-NODE.md` §6: `WS_PERIOD_EPOCHS = 2016` (≈22.4 days). While the chain is
younger than 2016 epochs the genesis manifest is its own subjectivity anchor and
cold sync is **fully trustless — no flags needed**. That window closes at epoch
2016, **≈ 2026-09-05 07:07 UTC**.

After it closes, a fresh node with an empty data dir **refuses to sync** without
`--ws-checkpoint` + `--ws-signer-set`. And:

- A real mainnet checkpoint for epoch 1536 has been derived and committed
  (`checkpoints/wscheckpoint-1536.{bin,json}` in `agent-a58dfe6cc066ef5b3`) — but
  it is **UNSIGNED**. Its README states `signer_set_id 1 (Phase A — keys DO NOT
  EXIST YET)`.
- The publication pipeline is **built** — `tools/ws-publisher/` (~69KB of Rust),
  `deploy/ws-publication/` timer + fan-out, `docs/specs/BLOCH-WS-PUBLICATION-PIPELINE.md`
  in `agent-a2ab11051392850db` — and blocked on the same thing: "first production
  ceremony pending the Phase A signer arrangement."

**This inverts the deadline's meaning.** 5 September is not an arbitrary date to
slip past — it is the last day the exchange can stand up a node the easy way. An
observer first synced **before** 2026-09-05 07:07 UTC needs nothing but a peer
list, permanently (it keeps its own anchor in `ws_latest.bin`). One stood up
after needs a signed checkpoint that does not yet exist and cannot exist without a
key ceremony only the founder can authorise.

## Honest date

**Bootnodes alone: 3 Sep, achievable.** The work is: bring up ≥2 fleet nodes on
`--transport libp2p` with a routable listen address, open the port, read the
printed peer ids (`engine.rs:2843`), fill the two `TODO(Postern Labs)` rows in
`OBSERVER-NODE.md` §5/§7, cherry-pick `eca224a0`'s docs and merge `40e22169`.
Half a day of engineering, one to two days of fleet operations — and **fleet
operations are founder-authorised; the PMO does not touch production nodes.**

Watch: `--p2p-listen` defaults to `/ip4/0.0.0.0/tcp/16400`, which **collides with
the fleet's `16400+N` RPC port convention**. Pick a different port before
publishing multiaddrs, or the first thing the exchange dials will be an RPC socket.

**Not achievable by 5 Sep: the checkpoint path.** The Phase A signer ceremony
involves generating key material and requires the founder. If the exchange has not
synced by 07:07 UTC on 5 Sep, this workstream's deadline becomes the ceremony's
deadline, and no amount of engineering shortens it.

**Escalation, today:** get the exchange pointed at a peer list *this week*, before
07:07 UTC on 5 Sep. That single act removes the entire checkpoint dependency for
this partner. It is worth more than any other item in this plan.
