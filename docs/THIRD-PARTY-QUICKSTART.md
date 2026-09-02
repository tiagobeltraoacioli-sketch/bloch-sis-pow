<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Running your own Bloch Genesis-4 node

For an exchange, custodian, or anyone who needs their **own** validated view of
the chain rather than someone else's RPC endpoint. Everything below was run
end to end against the live chain on 2026-09-01; where a step has a limit or a
cost, the measured number is stated instead of an estimate.

The node you end up with is an **observer**: it downloads every block, applies
every state transition itself, and answers your RPC locally. It holds no key,
proposes nothing, attests to nothing, and carries no consensus responsibility.
That is the right deployment for crediting customer deposits — you are trusting
your own validation, not our word.

---

## 0. Read this before you start

Three facts that decide whether this works for you. None of them is discovered
later in the document.

### The clock: 2026-09-05 07:07:19 UTC

Bloch is proof of stake, so it has a weak-subjectivity window. A validator set
that has already withdrawn its stake can sign an alternative history at no
cost, which means "internally valid" is not the same as "the real chain". The
window is `WS_PERIOD_EPOCHS` = `WITHDRAWAL_DELAY_EPOCHS (2048) − EXIT_DELAY_EPOCHS (32)`
= **2016 epochs ≈ 22.4 days** at 32 slots × 30 s.

Genesis-4 started at epoch 0. So:

| If your node's first sync starts | What it needs |
|---|---|
| **before epoch 2016** — i.e. before **2026-09-05 07:07:19 UTC** | the genesis manifest and nothing else. The genesis block is its own trust anchor. |
| **after** that instant | a **signed checkpoint** (`--ws-checkpoint` + `--ws-signer-set`) |

**No signed checkpoint exists today.** The signing keys have not been
generated — the ceremony is Phase A of `docs/specs/BLOCH-WEAK-SUBJECTIVITY.md`
§6.1 and it has not happened. A node started after the deadline with no
checkpoint **refuses to sync and says so**; it does not quietly follow a peer.

A node that completes its first sync *before* the deadline keeps its own
finality as its anchor from then on and never needs a checkpoint. **If you
intend to run a node in 2026, start it before 5 September.** This is the single
time-sensitive item in this document.

That instant is `genesis + 2016 × 32 × 30 s`, and you should derive it
yourself rather than take our word for it. Genesis-4 slot 0 was
**2026-08-13 21:31 UTC**; the two constants are `WITHDRAWAL_DELAY_EPOCHS = 2048`
and `EXIT_DELAY_EPOCHS = 32` in `crates/bloch-pos-committee/src/staking.rs`.
To re-derive it from the live chain, read `wall_slot` from any node and
subtract `wall_slot × 30 s` from your clock. Slots are 30 s, so an independent
derivation lands within about half a minute of the figure above — treat the
deadline as "07:07 UTC, give or take a slot", not as a value to cut fine.

**A full cold sync completed in 21 minutes on an idle 2-vCPU box (§5), so the
sync itself is not what puts the deadline at risk — but it is one measurement
on one machine, and the deadline is hard.** Leave yourself a day, not an hour:
if your first attempt misconfigures something you want room for a second.
An earlier edition of this document said 26 hours here. That figure was
extrapolated from a run that was stopped after 13 minutes; see §5.

You can watch the gate count down in your own node's boot log:

```
fresh node: syncing under the genesis anchor (age 1667 of 2016 epochs)
weak subjectivity: anchored at epoch 0 (9953da73), WITHOUT own finality
```

### The transport is `devnet`, and that is not a testnet

The flag is `--transport devnet`. The name is historical and misleading: it is
the transport the **live mainnet fleet runs today** — verified 2026-09-01
across all 7 fleet hosts (63 active validators) and both archival nodes.

Do **not** use `--transport libp2p`. See [Why not libp2p](#why-not-libp2p) —
it fails in the worst possible way, silently.

`devnet` has no authentication and no admission control. Consequences you must
design around:

- **Bind your P2P listener to loopback, or firewall it to the bootnodes.** An
  open devnet port is an unauthenticated path into your node's block handling.
- You do not need an inbound port to sync. Your node dials the bootnodes and
  its sync requests are answered on those same outbound connections.

### The RPC has no authentication — never expose it

No API key, no authorisation, no rate limiting. It also accepts
`sendrawtransaction`, so an exposed port is a **write** surface, not just a
read one.

**Bind it to `127.0.0.1` and leave it there.** If other hosts in your
infrastructure need it, put it behind your own authenticating reverse proxy on
a private network. Our own fleet's RPC is loopback-only for exactly this
reason — verified on both bootnodes on 2026-09-01. `--rpc-bind 0.0.0.0` on a
public host is the single most damaging mistake you can make with this
software.

It is also a denial-of-service surface, because RPC work competes with the
consensus thread. Measured against a live archival node on 2026-09-01,
`getbalance` costs **~1.7 ms median** — the same for an empty address and for
the heaviest address in the ledger (426,194 outputs), so the lookup is indexed
rather than a scan — with the **first, cold call ~22 ms**. That puts roughly
**500-600 calls/second** on one saturated core. There is no rate limiting in
front of it, so that ceiling is whatever your attacker chooses. Throttle it
yourself; nothing in the node will do it for you.

---

## 1. What you need

- **Linux x86-64**, 2+ vCPU, 8 GB RAM, 80 GB SSD. Replay is single-threaded
  and pins one core; extra cores let you run several nodes, they do not make
  one node faster. Everything measured in this document was run on **2 vCPU /
  7.9 GB** boxes, including a full cold sync from genesis, which peaked at
  **934 MB** resident. 8 GB is comfortable; we have not tested below it.
- **The node binary**, built from source (§2).
- **`mainnet.manifest`** (~247 KB) — the genesis manifest.
- **`carryover.tsv`** (~55 MB, 452,726 outputs) — the opening ledger carried
  over from Genesis-3.

Expected digests — **check these before you run anything**:

```
7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd  mainnet.manifest
84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6  carryover.tsv
```

The node independently re-checks the carryover against four separate fields
committed in the manifest — file digest, set root, output count and total —
before it admits a single balance, and refuses to start on any mismatch. The
`sha256sum` above is so *you* catch a bad download early, not so the node can.

## 2. Build the binary

Do not run a binary whose provenance you cannot check; a node on a different
consensus build can serve reads that disagree with the network.

```bash
git clone https://gitlab.com/blochsispow-group/bloch-pos.git
cd bloch-pos
git checkout g4-node-20260901            # the release tag — NOT `main`, see below
cargo build --locked --release -p bloch-pos-node
./target/release/bloch-pos --version    # must NOT say "+dirty"
./target/release/bloch-pos selfcheck    # verifies the frozen consensus params
```

> ### Build the release tag, not `main`
>
> **`main` is not a descendant of the commit the live fleet runs.** The two
> branches diverged on 2026-08-24, and `main` is missing six commits that the
> fleet has been running since — including `47f7644b`, four consensus
> corrections. A binary built from `main` therefore differs from the network
> in consensus-relevant code. Check it yourself:
>
> ```bash
> git merge-base --is-ancestor 46133196 HEAD && echo "descends from the fleet" \
>                                            || echo "DOES NOT — do not run this"
> ```
>
> `46133196` is the commit the fleet runs; the release tag descends from it and
> `main` does not. This check is the one that matters and it is cheap: run it on
> whatever you are about to build.

> **Use a release build.** A debug build is not merely slower — it makes the
> initial state construction take hours instead of minutes, because the
> Keccak permutation is unoptimised.

**The build is quick; earlier editions of this guide said otherwise.** The
release profile is `lto = true` with `codegen-units = 1`, which is deliberate —
it also carries `overflow-checks`, mandatory for a consensus build. This
document previously said "~40 minutes"; that was measured on a laptop with
other compiles competing for the CPU and is not what you should expect.

Measured 2026-09-01 on an idle 2-vCPU / 7.9 GB Linux x86-64 box, from a clean
clone, `cargo build --locked --release -p bloch-pos-node`:

| Box | Wall clock |
|---|---|
| A | **3 min 39 s** |
| B | **4 min 12 s** |
| C | **6 min 04 s** |

Call it **4 to 6 minutes** and provision for the slow end. Two vCPUs, not
eight. Do not "optimise" this by dropping LTO or building in
debug: both change the binary you validate with.

### Check what you built against what we published

**Three** independent boxes building this tag produced a **byte-identical**
binary, so you can compare digests rather than trust ours. The expected digest is
published as a **release manifest distributed with the tag**
(`RELEASE-g4-node-20260901.txt`), deliberately not inline in this file: the
commit hash is compiled into the binary, so a digest committed *inside* the
repository would change every time the file quoting it changed, and could never
be correct.

```bash
sha256sum target/release/bloch-pos      # compare against the release manifest
```

Three caveats that will otherwise waste your afternoon:

- **The commit hash is compiled into the binary.** `--version` prints
  `0.1.0-mainnet (<short sha>+nogit)`. Building the same source from a tarball
  or a source export rather than a `git` checkout yields a *different* digest,
  because the embedded identifier differs. Reproduce our build the way §2
  describes it — clone, checkout the tag — or the comparison is meaningless.
- **The toolchain is part of the input.** We build with **Rust 1.94.0**, the
  version `Dockerfile` pins, targeting `x86_64-unknown-linux-gnu`. A different
  Rust version gives a different digest. That is not a tampering signal on its
  own; it means you have not reproduced our build.
- A digest match proves you built the same source we did. It does **not** prove
  that source is correct — for that, the check that matters is the ancestry one
  at the top of this section.

## 3. Get the genesis files

**Both ship in the repository you just cloned** — you do not need to download
them separately:

```bash
ls -l genesis/mainnet.manifest     # 247,514 bytes
gunzip -k carryover.tsv.gz         # 17 MB compressed -> 54,780,151 bytes
sha256sum genesis/mainnet.manifest carryover.tsv   # compare against §1
wc -l carryover.tsv                # 452726
```

Then put them where §5 expects them, so the commands below run as written:

```bash
sudo mkdir -p /var/lib/bloch
sudo cp genesis/mainnet.manifest carryover.tsv /var/lib/bloch/
```

Verified 2026-09-01: both are byte-identical to what the live fleet runs
(checked against `/home/ubuntu/g4/` on archival node 139.180.166.5), and both
digests in §1 were reproduced from a clean clone of `main`.

> The R2 paths under `…r2.dev/node/genesis4/` referenced by older documents
> **return 404** — the artifacts were never uploaded there. Use the repository
> copies. When the signed bootstrap artifact is published, this section will
> point at it and at its minisign signature.

## 4. The bootnodes

The public entry points are in [`deploy/bootnodes/bootnodes.txt`](../deploy/bootnodes/bootnodes.txt):

```
139.180.166.5:19100
139.180.173.231:19100
```

Both are **keyless archival observers** operated by Postern Labs. They are the
only addresses published, deliberately: they are ours, and they do not move
when validators move. Validator addresses are never published — on the
unauthenticated devnet transport a validator address is a push surface into
consensus, and in August 2026 one stale node back-filling old blocks stopped
block production across the entire network.

Verify them yourself before trusting the list:

```bash
./deploy/bootnodes/verify-bootnodes.sh
```

Two bootnodes on one provider is a real single point of failure, and we say so
in the file rather than let you find out during an incident.

## 5. Run it

Run this from the repository root you built in §2 (the binary is
`./target/release/bloch-pos`; copy it onto your `PATH` if you prefer):

```bash
sudo mkdir -p /var/lib/bloch/data
sudo chown -R "$USER" /var/lib/bloch

./target/release/bloch-pos run \
  --data-dir   /var/lib/bloch/data \
  --genesis    /var/lib/bloch/mainnet.manifest \
  --carryover  /var/lib/bloch/carryover.tsv \
  --transport  devnet \
  --listen 19100 --listen-addr 127.0.0.1 \
  --peers 139.180.166.5:19100,139.180.173.231:19100 \
  --rpc-port 16400 --rpc-bind 127.0.0.1
```

Note what is deliberate here:

- **No `validator.key` in the data dir.** That is what makes this an observer.
  The node will confirm it: `observer mode: no keystore … It does not propose
  and does not attest.` If you do not see that line, stop — you have a key you
  did not mean to have.
- **`--listen-addr 127.0.0.1`** — you dial out to the bootnodes; you do not
  need to accept inbound connections to sync.
- **`--rpc-bind 127.0.0.1`** — see §0.

Run it under `systemd` with `Restart=always` and `systemctl enable`, so it
survives a reboot.

### What you will see, and how long it takes

Two phases, and the first one is silent — this is the part that looks like a
hang and is not:

**Phase 1 — genesis state construction (silent).** The node builds the sparse
Merkle tree over all 452,726 carryover outputs before it opens its RPC or
connects to any peer.

You get exactly **two lines within about five seconds**, and then nothing:

```
carryover: 452726 outputs, 1814640000000000000 sat carried … set root 7c756ee8
observer mode: no keystore in /var/lib/bloch/data. This node follows the chain,
applies every block and serves the RPC. It does not propose and does not attest.
```

> **Do not kill it after those two lines.** This is the part that looks like a
> hang and is not. Once they are printed there is **no further log output, no
> open RPC port, no answer to `getchaininfo` and no peer connection** until the
> tree is finished. Every signal you would normally use to tell "working" from
> "crashed just after startup" is absent, and the two lines it already printed
> make it look like it started and then died. **It is not stuck.**

**How long is very sensitive to spare CPU, so treat any single figure with
suspicion.** The construction pins one core and is not parallel. Measured on an
8-core M-series Mac: ~2 minutes on an idle machine, but **11 minutes** on the
same machine at load average ~60-90 with other builds running. Resident memory
climbs steadily throughout (~265 MB → ~800 MB) — that, and CPU, are the only
signals that move.

To confirm it is alive, look at the **process, not the files**: the data
directory does *not* change during this phase (`blocks.log` stays 0 bytes), so
`ls` there tells you nothing and looks like a dead node. Use
`ps -o %cpu,rss -p <pid>` and watch RSS climb.

A **debug** build turns this into hours (§2).

**Phase 2 — replay from genesis.** Blocks arrive from the bootnodes and are
applied one at a time, each one fully validated:

```
[slot 1] applied 1f65a776 by v46 — head root 17f80dfd, justified e0, finalized e0
```

**This is the slow part, and it decelerates within a run** — but it finishes,
and the previous edition of this document was badly wrong about how long it
takes. That edition printed a table of the first twelve minutes, extrapolated
`~35 slots/min` out to the head, and published **"about 26 hours"**. The run
behind that table **was stopped at 13 minutes and never reached the head**. The
extrapolation was never checked against a completed sync.

**Measured to completion, 2026-09-01.** Release build of the tag in §2, an idle
2-vCPU / 7.9 GB Linux box, from genesis, over the network, from the two
published bootnodes, with nothing else on the machine:

| | |
|---|---|
| Time from launch to `behind_by_slots = 0` | **21.2 minutes** (1,273 s) |
| Height reached | 33,602 |
| Peak resident memory | **934 MB** |

That is the whole sync: state construction, then every block from genesis
applied and validated. Not 26 hours.

**Treat this as one run on one machine, because that is what it is.** It is a
single measurement on a 2-vCPU box with no other load, taken at a chain height
of ~33,600. It is not a guarantee and it is not an average. What you should
take from it is the order of magnitude — tens of minutes, not tens of hours —
and the method: we ran it to completion and read the finishing time off the
clock, rather than extrapolating from the first few minutes.

Two things that will make your run slower than ours: a busy machine (the
initial state construction pins one core and does not share it), and a taller
chain than 33,600 by the time you start.

> **Why the old figure was so far out.** Two mistakes compounded. The run was
> on a laptop under heavy load — the same machine and session that took 11
> minutes over an initial state construction that needs about 2 minutes idle —
> so every rate it produced was a measure of CPU contention rather than of the
> software. And it was **stopped after 13 minutes**, so the slowest rate it
> ever reached was taken as the steady-state rate and multiplied out to a head
> 53,300 slots away. A contended partial rate extrapolated over the whole chain
> is how twenty-one minutes became twenty-six hours.
>
> The general lesson, which applies to the seeded path below as well: the
> node's progress line reports a **cumulative average** and a "time left"
> derived from it, and both drift throughout a run. Neither is a result. Only
> a completed run is.

> **Memory: what this release fixes, and what it does not.** Until this
> release, an epoch roll deep-copied the whole eUTXO ledger (452,726 entries),
> so a node catching up across a large gap paid that copy repeatedly. The
> ledger now sits behind an `Arc` with copy-on-write, and an epoch roll copies
> it zero times.
>
> Measured side by side on 2026-09-01 — two identical idle 2-vCPU / 7.9 GB
> boxes, cold sync from genesis over the network, launched within a second of
> each other and both run to `behind_by_slots = 0`:
>
> | Build | Time to caught up | Peak RSS | Outcome |
> |---|---|---|---|
> | This release (with the fix) | **21.2 min** | **934 MB** | completed, h=33,602 |
> | `main` (without the fix), run 1 | **30.3 min** | **1,014 MB** | completed, h=33,620 |
> | `main` (without the fix), run 2 | **29.5 min** | **1,016 MB** | completed, h=33,794 |
>
> The two unfixed runs were on different boxes and agree to within 3%, so the
> fix is worth about **1.4× on cold-sync wall clock** and a few percent on peak
> memory, on this shape of run.
>
> **Both fitted in 8 GB and neither was killed.** If you have read that an
> unfixed node gets OOM-killed on a cold sync over the network, that is not
> what we measured and we will not repeat it. The pathological case in the
> fix's own commit message — a ~93 GB transient — is a *single* re-roll across
> a ~1,550-epoch gap evaluated in one step, which is not the shape of an
> incremental network sync where the gap closes block by block. The fix is
> real, it is worth having, and it is why this release exists; the memory
> catastrophe is not the thing you would have hit here.

### Seeding from an archival node — an alternative, not a shortcut

**This document used to call this "the faster path — recommended", on the
strength of a 10-minute figure. Measured to completion, it is not faster.**

If you would rather not replay over the network, copy `blocks.log`, `meta.bin`
and `ws_latest.bin` from a healthy node's data directory and let your node
replay them locally.

Copy those three files **by name**. Measured 2026-09-01, `blocks.log` was
**469,561,433 bytes (448 MB)** at height 33,602, and it grows with the chain, so
treat that as a floor and check before you provision. A data directory may also
contain `.TRAVADO-*` files — operator-made snapshots of an earlier, stuck log.
Do not copy those and do not glob the directory; take the three names above.

**Measured to completion**, same idle 2-vCPU / 7.9 GB box, release build,
replaying a seeded `blocks.log` locally with no peers configured:

| | |
|---|---|
| Blocks replayed | 33,608 |
| Wall clock | **22.1 minutes** (1,328 s) |
| Lifetime rate | **25.3 blocks/s** |
| Peak RSS | 983 MB |

Set that beside the network sync measured the same day on an identical box:
**21.2 minutes**. Within noise of each other, and if anything the seeded path
was *slower* — it still has to apply and validate every block; it only saves
fetching them.

> **Where "52 blocks/s" and "10 minutes" came from, because it is worth
> knowing.** The node's progress line prints a **cumulative average** rate and
> a `~N min left` derived from it. Both decay steadily as the replay deepens,
> because fork choice does work proportional to the depth it walks. In the run
> above the same counter printed:
>
> | Progress | Rate it reported |
> |---|---|
> | 4.6% | 82.5 blocks/s → *"~7 min left"* |
> | 22.8% | 54.6 blocks/s |
> | 41.9% | 41.3 blocks/s |
> | 87.4% | 29.3 blocks/s |
> | done | **25.3 blocks/s, 22.1 min actual** |
>
> "52 blocks/s" is what that counter reads at roughly one-fifth of the way in,
> and "10 minutes" is the estimate it derives there. Neither was ever a
> property of a completed run. **Do not quote the progress line's rate or its
> time-remaining as a result** — wait for the `replayed N blocks:` line.

**So which path should you use?** On these numbers, either — pick on
operational grounds, not speed:

- **Replay over the network** if you want no dependency on a donor. Your node
  fetches from the bootnodes and validates everything itself.
- **Seed from an archival copy** if the bootnodes are unreachable or you are
  provisioning many nodes and would rather move one file than re-fetch the
  chain N times.

Both re-apply every transition and recompute every state root, so neither is a
weaker validation than the other.

Copy from an **archival** node, never from a validator's data directory: a
validator's directory contains `validator.key`, and copying a live validator
key to a second machine makes it a second signer for the same validator index.
That is equivocation, and there is no safe version of it.

One correction to how we used to justify that, because the advice is right and
the reason we gave was not: we said equivocation "is slashable". **It is not,
on Genesis-4 today** — slashing evidence cannot be decoded on any ingress path,
so the penalty cannot be applied to anyone (see the retraction on `Finality` in
`crates/bloch-pos-node/src/rpc.rs`). What *is* live is fork choice's
equivocator bar: a validator observed signing two blocks at one height stops
counting toward finality. So the deterrent is real but it is exclusion, not a
fine, and it does not return your stake to you.

Seeding is a genuine trade: you are trusting the donor for the block data.
You are *not* trusting them for validity — your node re-applies every
transition and recomputes every state root, and diverges loudly if the data is
wrong. What it cannot detect on its own is a *complete and internally
consistent* alternative history, which is exactly what §0's weak-subjectivity
anchor is for.

## 6. How your node actually reaches the chain

Worth understanding before you depend on it, because it decides what your
monitoring should watch. Verified against the code and the live hosts on
2026-09-01.

The bootnodes are **leaves**: each dials all 63 validators outbound, no
validator dials them, and the two do not dial each other. You hang off a leaf.

**Blocks reach you by pulling, not by being pushed.** A block is broadcast only
by the node that proposed it, so an observer never re-broadcasts one to you.
Instead your node issues a periodic get-blocks request whenever it is behind
and two slots have passed. This works — it is how the bootnodes themselves
follow the chain — but it means:

- You will normally sit **0–2 slots behind** the head, not exactly at it.
  `behind_by_slots` of 0–1 is healthy; a number that climbs and stays up means
  your peers stopped answering.
- Your liveness depends entirely on a bootnode answering your requests. With
  both configured you have two independent paths; if one goes away the other is
  unaffected, because they do not depend on each other.

**Your transactions do propagate outward.** A transaction that arrives by
gossip goes through the same admission path as one submitted to the local RPC,
and is re-broadcast on the receiving node's outbound connections. So a
withdrawal you submit to your own node reaches the bootnode, and the bootnode
passes it to the 63 validators it dials. Receiving and sending both work.

There is no acknowledgement for a submitted transaction — confirmation is
seeing it in a block. Poll for it; do not assume acceptance.

## 7. Prove you are on the real chain

**Same height is not agreement.** Two forked nodes happily report the same
height with different roots, and a forked node answers RPC normally. Compare
the **finalized root**:

```bash
curl -s -X POST http://127.0.0.1:16400 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' | jq '.result.finalized'
```

Compare that `{epoch, root}` against both bootnodes **at the same finalized
height**. They must be byte-identical to *each other*.

**The root below is not a constant to match.** It advances every epoch — about
every 16 minutes — so by the time you read this it will have moved many times.
The test is agreement between the nodes you are comparing at one finalized
height, never equality with a value printed in a document. A worked example
measured 2026-09-01 06:58 UTC, both bootnodes at finalized height 32356
(epoch 1666):

```
139.180.166.5    finalized root 0ac677b83b9b566b761bbbfa639824ab3b35defe59eb2fbda65c40735235a4cd
139.180.173.231  finalized root 0ac677b83b9b566b761bbbfa639824ab3b35defe59eb2fbda65c40735235a4cd
```

If the two finalized heights differ, you have not learned anything yet — the
roots are only comparable at equal height. Re-read both and compare again.

> **You cannot run this comparison against our bootnodes, and the guide used to
> tell you to.** The published bootnodes bind their RPC to loopback — which §0
> tells you to do too, and which is correct — so `getchaininfo` on
> `139.180.166.5:16400` from your machine gets no answer. The worked example
> above was collected *on* those hosts. Verified 2026-09-01: from a third-party
> box, neither bootnode answers RPC.
>
> `./deploy/bootnodes/verify-bootnodes.sh --deep` is therefore an **operator**
> tool, not a third-party one: it also tries to `ssh` into each host to confirm
> it is keyless, which you cannot do either. Run it without `--deep` — that
> checks reachability and exits 0 — and expect `--deep` to report
> `FAIL … keyless: unknown (ssh failed)` for reasons that say nothing about the
> chain. (Until this release `--deep` additionally died with a bash error,
> `line 125: [: 0\n0: integer expression expected`, and skipped the fork check
> in silence. Both are fixed here; the skip is now stated out loud.)
>
> **What to do instead.** The comparison is sound; only the counterparties are
> wrong. Run **two nodes of your own**, ideally seeded differently — one cold
> from genesis, one from an archival copy — and compare *their* finalized roots
> at equal finalized height. Two nodes you control that agree is a stronger
> statement than one node agreeing with ours, because it is not a claim you are
> taking on our word.

Also check `behind_by_slots` in `getchaininfo`: 0–1 means you are at the head.

Do this **before** you credit anything to a customer, and keep doing it — a
node that silently diverges is the failure mode that costs money.

## 8. Once a signed checkpoint exists

Not yet available — no signer keys exist. When the Phase A ceremony has
happened, a fresh node past the window adds two flags:

```bash
./bloch-pos run \
  ... \
  --ws-checkpoint  /var/lib/bloch/wscheckpoint-<epoch>.envelope.bin \
  --ws-signer-set  /var/lib/bloch/signer-set-1.bin
```

- `--ws-checkpoint` takes the **envelope** (checkpoint + quorum signatures),
  not the bare 154-byte checkpoint.
- `--ws-signer-set` takes the signer arrangement. Release builds will hard-code
  the published sets and the flag becomes an override.

Understand what this does and does not buy you. The checkpoint is **32 bytes
of trust about one fact**: which finalized root is real at one epoch. It is a
*floor and a cross-check*, **not a sync shortcut** — checkpoint-sync state
download does not exist, so your node still replays and revalidates every
block. A checkpoint that contradicts finality your node reached on its own is
raised as `WS_CONFLICT` and **cannot** reorganise you; only a genuinely fresh
or long-offline node can be moved by the signers.

Verify the envelope's digest across at least two independent publication
channels (the R2 bucket, the git repositories, and posternlabs.com carry it)
before trusting it. Agreement between two channels is what makes a compromised
third detectable.

## Why not libp2p

The node has a second transport, `--transport libp2p`, which is the better
stack: authenticated Noise sessions, gossipsub, peer scoring, admission
control. **Do not use it.** The live fleet does not speak it yet, and the two
transports are mutually exclusive per process — `net.rs` defines
`enum Net { Devnet | Libp2p }`, "one of two, chosen at startup". There is no
dual-stack mode and no bridge.

A libp2p node pointed at a devnet peer does not fail cleanly. Measured
2026-09-01:

```
p2p: NO PEERS — dial failed: Failed to negotiate transport protocol(s)
p2p: publish blocks: NoPeersSubscribedToTopic
[slot 26] proposing block 39906305 …
[slot 26] applied 39906305 by v2 — head root f0ff00ad, justified e0, finalized e0
```

It negotiates nothing, finds no peers, and then **builds its own chain while
printing "applied" and "finalized"** — looking healthy while being alone on a
fork. If you point a libp2p node at these bootnodes you will get a node that
appears to work and is not on Bloch.

This changes when the fleet migrates transport. Until that happens, `devnet` is
not the recommended option; it is the only one.

## What does not work today

Stated here rather than left for you to discover:

| | |
|---|---|
| **Running a validator** | Closed at the node level. New deposits are refused at mempool admission because bonded stake is not funded from the eUTXO set, so a deposit would mint stake from nothing. The set is fixed at the 64 genesis validators. |
| **`--transport libp2p`** | The fleet speaks `devnet`; see above. |
| **A signed WS checkpoint** | No signer keys exist yet. Sync before 2026-09-05 07:07:19 UTC and you will not need one. |
| **Checkpoint-sync state download** | Not implemented. Every node replays and revalidates from its anchor. |
| **`gettransaction` / transaction index** | No txid at this layer; deposit detection is UTXO polling. |
| **HSM support for the PQ keys** | No HSM signs ML-DSA‖Falcon. Relevant to custody design. |

---

## Reference

- `docs/specs/BLOCH-POS-NODE-INTEGRATION.md` §4.2 — cold start: what an
  independent operator can verify and what they must trust
- `docs/specs/BLOCH-WEAK-SUBJECTIVITY.md` — the window, the ceremony, the
  four boot states
- `deploy/bootnodes/` — the published entry list and its verifier
