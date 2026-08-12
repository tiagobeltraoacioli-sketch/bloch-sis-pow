# Fleet recovery — provenance of what is actually running

> **Redacted for publication.** Host addresses by role, SSH key filenames, Cloudflare
> account/zone/tunnel identifiers, per-box free disk and RAM, and firewall rule listings
> were replaced with placeholders. None of them were secrets — together they were an
> operational map of a three-box fleet, which is a different thing and not worth publishing.
> The technique is intact; the inventory is not. Operators substitute their own.


Captured 2026-08-11, before any deploy of the terminal-height rule.

## What the survey found

Three boxes, three different binaries, **none of which corresponds to a
committed source tree**:

| Box | Service | Binary | Source on the box |
|---|---|---|---|
| node4 `136.244.82.226` | `bloch-g3` | `~/bloch-regossip` | **none** |
| auxpow `PRODUCER_IP` | `bloch-auxpow` | `~/BlochSISPoW-project/target/release/bloch` | `g3-integration` @ `006c658`, **9 files dirty** |
| miner-box `RELAY_IP` | `bloch-g3` | `~/bloch-g3-flagday` | `~/bloch` on `g2/integrate` @ `6d16e34` (wrong branch, does not match the running binary) |

Both `bloch-regossip` and `bloch-g3-flagday` report `bloch 0.3.0-genesis2` and
have different md5s. The version string carries no commit hash, so what is
running cannot be identified from the binary.

## What was at risk

`auxpow-uncommitted.patch` — 1,616 lines, 8 files, ~300 insertions across
`src/consensus/mod.rs`, `src/main.rs`, `src/network/mod.rs`,
`src/network/sync_rr.rs` and the pool-proxy, plus one untracked file
(`pool-proxy/src/addr.rs`). These are consensus and network changes running on
a live mainnet producer that existed **only** in an uncommitted working tree.
One `git checkout .` from gone.

Base commit: `006c65819238deb9dcc1a77938b9cb42c1beceab`, which **is an ancestor
of `g3-integration` HEAD** (59 commits behind), so the patch can be rebased
rather than reconstructed.

## Why the deploy stopped here

Building the terminal-height rule from `g3-integration` and shipping it to
these boxes would overwrite binaries whose contents are unknown, discarding
whatever network fixes live in `bloch-regossip` and in the uncommitted tree.
The failure mode is not hypothetical for this project: the published release
has been the broken binary before, with the fixes existing only on the boxes.

## Safe order

1. Rebase and review `auxpow-uncommitted.patch` onto `g3-integration`; commit it.
2. Establish what `bloch-regossip` contains — diff its behaviour against a
   build of the rebased tree, or rebuild and compare, since the source is gone.
3. Build **one** binary from one known commit, with the commit hash compiled
   into `--version` so this survey never has to be done again.
4. Test the halt on a devnet: mine to the terminal height, confirm production
   stops and the node stays up and serves RPC.
5. Deploy that one binary to all three boxes, verifying by hash that what runs
   is what was built.
