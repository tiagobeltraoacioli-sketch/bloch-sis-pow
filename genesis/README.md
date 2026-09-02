# Genesis-4 mainnet genesis

`genesis/mainnet.manifest` is the file the 64 validators booted from. A node
that hashes to a different digest is on a different network, which is the point
of publishing it rather than describing it.

    size            247514 bytes
    SHA-256         7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd
    network digest  f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966
    genesis time    2026-08-13 21:31:19 UTC
    validators      64
    slot            30 s, 32 slots to an epoch

It commits to the carryover by digest, not by content — the 54 MB of balances
live in `carryover.tsv.gz` and are checked against the manifest at boot. Both
are needed; neither is useful alone.

## Running a node against it

Decompress the carryover first — the loader reads TSV, not gzip:

    gunzip -k carryover.tsv.gz

Then:

    bloch-pos run \
      --data-dir   ./data \
      --genesis    ./genesis/mainnet.manifest \
      --carryover  ./carryover.tsv \
      --transport  devnet \
      --listen 19100 --listen-addr 127.0.0.1 \
      --peers 139.180.166.5:19100,139.180.173.231:19100 \
      --rpc-port 16400 --rpc-bind 127.0.0.1

`--transport` and `--listen` are **not optional**: the transport defaults to
`devnet`, and the devnet transport exits with status 2
(`run: --listen <port> is required for the devnet transport`) if no listen port
is given. Without `--peers` the node starts but never finds the chain. An
earlier edition of this file printed a four-line command that had none of the
three, passed the `.gz` path, and lost `--rpc-port` to a missing line
continuation; it could not have run as written.

`--listen-addr 127.0.0.1` is deliberate — you dial out to the bootnodes and do
not need to accept inbound connections. See `docs/THIRD-PARTY-QUICKSTART.md` §5
for the full walkthrough and for what the first twenty minutes look like.

A data dir with no `validator.key` runs in observer mode: the node follows the
chain and serves RPC, and signs nothing.

## What to expect on a cold start, and what is still unproven

An earlier version of this section said a cold sync over the transport the live
fleet runs (`--transport devnet`) **does not complete**. That is no longer true,
and the mechanism it described was never quite right either. Both corrections
matter, so here is each.

**It completes.** Measured 2026-09-01 on an idle 2-vCPU / 7.9 GB Linux box,
release build, from genesis, dialling the two published bootnodes: `behind_by_slots`
reached 0 in **21.2 minutes** at height 33,602, peak resident memory 934 MB. The
defect this file was written about was a sync pump that released its request slot
on the first idle tick — a tick on which the head is *supposed* to look unchanged,
because a page of blocks takes minutes to drain — so a node asked once and then
never again. Fixed 2026-08-21 in `5e4841b7`, `crates/bloch-pos-node/src/net.rs`.
That fix is on `main`, on the release, and on the binary the fleet runs.

**But it never "followed the live tip", and that distinction is the reassuring
part.** A node behind the tip does not adopt gossiped blocks it cannot connect to
its own history. `Engine::path_to_canonical` returns `None` when a branch's
lineage is incomplete, and the caller sets `needs_sync` and keeps the chain it
has — *"a branch is adopted only after being replayed and validated in full."*
A stalled node froze at its own last validated block. **The head, height and
state root a node reports are always its own, produced by its own validation of
every block underneath them. They were never someone else's and were never
invented.** The observer that reported height 556 against a network at 1,511 was
stuck, not lying about someone else's chain.

### What is still true, and what we are not claiming

**The silent-divergence class is not closed, and we are not going to say it is.**

1. **The node never tells you it is behind.** There is no log line and no error.
   We checked: zero `println!`/`eprintln!` in `engine.rs` or `net.rs` mention
   being behind, stale, lagging or catching up. The only signal is
   `behind_by_slots` in `getchaininfo` (`crates/bloch-pos-node/src/rpc.rs:1241`)
   — a field you must poll. Nothing raises it for you.

2. **Worse, that field is least available exactly when you most need it.**
   During the 21-minute sync above, the node answered `getchaininfo` once at
   65 s and then **stopped answering for the rest of the replay**, because RPC
   work competes with the replay thread. So for ~20 of 21 minutes the single
   documented way to discover you are behind returned nothing at all. Monitoring
   built on polling that field cannot distinguish "catching up" from "hung" from
   "dead" over precisely the window where they differ. Watch the process — RSS
   and CPU — and the `applied` lines in the log.

3. **There is no test for any of this.** The only cold-start test,
   `crates/bloch-pos-node/tests/cold_start.rs`, runs `--transport libp2p` — not
   the devnet transport the fleet runs and this file is about — asserts three
   blocks rather than a completed sync, and is documented in its own comments as
   flaky (one failure in ten runs). `git grep` finds no test anywhere for
   `get_blocks`, `needs_sync`, or the devnet backfill path. The measurement above
   is one run on one machine; it is evidence, not coverage.

4. **A finalized checkpoint is not yet a single global fact.** Under partition,
   a node's two-thirds test is measured against a total already reduced by the
   inactivity leak, and that denominator can shrink to fit inside the minority
   the node still hears. Reproduced: three disjoint partitions of four validators
   each finalized epoch 25 under three different roots. The cure exists but is
   **not armed** — `LEAK_RECOVERY_ACTIVATION_EPOCH` is `u64::MAX`. See
   `docs/post-mortems/2026-08-24-finality-divergence.md`.

So: a cold sync completes, and the node will not invent a head. It also will not
volunteer that it is behind, has no test proving it catches up, and can finalize
alone if partitioned. Size your deployment for all four.

Note that `--transport libp2p` **does** still fail the way this file used to
describe: it finds no peers and then builds its own chain while printing
`applied` and `finalized`. Do not use it.
