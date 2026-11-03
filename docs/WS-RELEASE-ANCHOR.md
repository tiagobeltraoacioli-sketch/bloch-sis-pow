# Release-baked weak-subjectivity checkpoint

Node release A onward builds `bloch-pos` with the cargo feature
`ws-release-anchor` (the canonical `deploy/pos-release/Dockerfile` enables it
and checks the `+ws-release-anchor` marker in `--version`). Such a binary
carries one finalized checkpoint of the mainnet chain, compiled from
`crates/bloch-pos-node/src/ws_release_anchor.rs`. A node with an empty data
directory then boots with no flag and no signature, anchored at that epoch.

## What it is and what it trusts

- The constant `RELEASE_ANCHOR_HEX` is the hex of the 154 canonical checkpoint
  bytes (`ws.rs` `canonical_serialize`): mainnet network id `1228832244`,
  genesis `9953da73…e415`, epoch E, the boundary block (last canonical block
  strictly before slot `32·E`), that block's header `state_root`, a zero
  validator-set root, `issued_at`, and the reserved signer-set id
  `u32::MAX − 1` (4294967294). That id can never be signed or combined into an
  envelope.
- Its trust is the release binary's trust. The file is a `.rs` file inside the
  binary's source digest, so the `source-digest` printed by `--version` (and
  checked by the qualification kit) binds the anchor too.
- It never moves a running node. A node with its own finality cross-checks the
  anchor: a contradiction prints the `WS_CONFLICT` alarm and the anchor is not
  adopted. A node without finality (empty data dir) treats it as a hard
  anchor: when its own finality reaches epoch E and disagrees, or when it
  validates the anchor block with another state root, it exits 78. The anchor
  does not steer fork choice; a wrong anchor can only stop a node, never make
  it follow a branch it would not follow otherwise.
- The window is unchanged. A fresh node accepts the anchor only while
  `wall_epoch − E < 2016`. Past that, it refuses with
  `ERR_WS_REQUIRE_CHECKPOINT`, as today.

The same feature also turns on two node-local rules:

- **Restart during a checkpoint sync** (agent 181's finding): a node whose own
  finality is older than the window but behind a fresh stored anchor resumes
  under that anchor as a hard anchor instead of halting with
  `ERR_WS_STALE recovery halted`.
- **Same-fact rule**: a signed checkpoint and the release checkpoint naming
  the same block and state at one epoch are one fact, not an equivocation (so
  the owner's signed epoch-7168 bridge and a release that bakes 7168 coexist).

The unsigned operator inputs (`--checkpoint-sync-url`,
`--ws-trusted-checkpoint`, `--ws-trusted-root`) are a separate prototype
feature, `ws-auto-checkpoint`. Release builds refuse them.

## Validity of the anchor in release A2

| Item | Value |
|---|---|
| Baked epoch | see `ws_release_anchor.rs` and the release record |
| Fresh installs refused from | wall epoch E + 2016 |

For E = 7305 that is epoch 9321, 2026-11-25 11:07 UTC. A node that has synced
once keeps running on its own finality after that date; only new installs,
and nodes offline for more than 2016 epochs, need a newer anchor.

## Re-baking at a release freeze (for example 11-05)

Run this on the build machine, from a tree of the release commit. The RPCs are
read-only; every endpoint must report the epoch as finalized and agree on the
boundary block, or the tool refuses.

1. Read the newest finalized epoch from each public RPC:

```
curl -s -X POST http://80.240.16.185:8080 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}'
```
```
curl -s -X POST http://199.247.22.8:8080 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}'
```
```
curl -s -X POST http://139.180.173.231:8080 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}'
```

2. Take the lowest `finalized.epoch` of the three as E and mint (replace
   `<E>`; any `bloch-pos` build of the release line has the subcommand):

```
bloch-pos ws-checkpoint --release-anchor --genesis genesis/mainnet.manifest --rpc 80.240.16.185:8080,199.247.22.8:8080,139.180.173.231:8080 --epoch <E> --out release-anchor-<E>
```

3. The tool prints `RELEASE_ANCHOR_HEX = <hex>`. Put that hex into
   `crates/bloch-pos-node/src/ws_release_anchor.rs` as the value of
   `RELEASE_ANCHOR_HEX`, and commit it alone with the epoch and block root in
   the message.

4. Check the file before building:

```
cargo test --locked -p bloch-pos-node --bin bloch-pos --features ws-release-anchor -- the_compiled_anchor_is_the_hashed_file_and_names_mainnet release_anchor
```

5. Build the release with the canonical container (the source digest moves,
   because the anchor is inside it) on two hosts and compare byte for byte,
   as for any release.

6. Boot test (no flags, empty data dir, no peers, loopback only): the log
   must show `release-baked checkpoint adopted: epoch <E>` and
   `weak subjectivity: anchored at epoch <E> (…), WITHOUT own finality`. A
   restart on the same data dir must show `… is not newer than stored
   ws_latest (epoch <E>); ignored` and anchor at E again.

7. Qualification: boot a node that holds a mainnet chain copy past E with the
   release binary. It must not print `WS_CONFLICT` or `WS_STATE_CONFLICT`.
   This is the only check that compares the baked state root with a block
   the node validated itself.

Anyone with a synced node can re-derive the same bytes:

```
bloch-pos ws-checkpoint --release-anchor --genesis genesis/mainnet.manifest --rpc <their-node>:8080 --epoch <E> --issued-at <issued_at from the release notes> --out check-<E>
```

## Cadence

The anchor ages. Fresh installs of a release work for 2016 epochs (22.4 days)
after its baked epoch. Keeping fresh installs possible therefore needs a
release (or an anchor-only point release: one changed `.rs` file, a new
source digest and a new signing target) at least every ~3 weeks, or the
signed-checkpoint path (`docs/WS-CHECKPOINT-OWNER-RUNBOOK.md`) as a fallback.
Running nodes never need either.

## Rollback

A data dir that stored a release anchor in `ws_latest.bin` still boots on
fa980367: that binary reads `ws_latest.bin` without looking at the signer-set
id (test `a_stored_release_anchor_boots_a_default_build`). One difference
after a rollback: fa980367 has no same-fact rule, so supplying a signed
envelope for exactly the stored release epoch is refused there as
`WS_CONFLICT`; use a signed envelope of a newer epoch instead.
