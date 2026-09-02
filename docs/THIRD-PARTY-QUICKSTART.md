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

**A full cold sync takes about 26 hours (§5), so the last safe moment to
start is roughly 2026-09-04 05:00 UTC — and that leaves no margin for a
restart.** Starting "on the 4th" is not starting in time; start now.

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

- **Linux x86-64**, 4+ vCPU, 8 GB RAM, 80 GB SSD. Replay is single-threaded
  and pins one core; extra cores let you run several nodes, they do not make
  one node faster.
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

**Build the tag, not `main`.** This matters more than it looks:

```bash
# The GitLab origin currently requires credentials — measured 2026-09-02,
# `GET .../info/refs?service=git-upload-pack` returns 401 unauthenticated.
# The GitHub mirror is public and carries the same tag at the same commit.
git clone https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow.git bloch-pos
cd bloch-pos
git checkout g4-node-20260901          # published 2026-09-02
git describe --tags --exact-match      # must print g4-node-20260901
cargo build --release -p bloch-pos-node
./target/release/bloch-pos --version    # must NOT say "+dirty"
./target/release/bloch-pos selfcheck    # verifies the frozen consensus params
```

> **Why the tag and not the default branch.** `main` is **not a descendant of
> the commit the fleet runs** (`46133196`) — six commits are missing from it,
> including four consensus corrections. The divergence is not dormant: on
> `main`, `Engine::seed_for_attestation` reads the seed from epoch E−2 while
> the transition admits against E−1, so a node built there derives **different
> committees every epoch** and can publish a `finalized` view that disagrees
> with the network. There is no activation gate in that path to wait for, and
> `selfcheck` cannot catch it — it compares the *set* of consensus constants,
> which is identical, not the behaviour behind them.
>
> The tag `g4-node-20260901` (commit `7a83ca89`) descends from the fleet tip and
> carries those corrections. Verify it yourself rather than trusting this
> paragraph:
>
> ```bash
> git merge-base --is-ancestor 46133196 g4-node-20260901 && echo "on-lineage"
> ```
>
> Nothing in the tag is armed that is not already live on the network: both
> `ANCESTRY_SEED_ACTIVATION_EPOCH` and `LEAK_RECOVERY_ACTIVATION_EPOCH` remain
> `u64::MAX`, and every activation constant is byte-identical to the fleet's.

> **Use a release build.** A debug build is not merely slower — it makes the
> initial state construction take hours instead of minutes, because the
> Keccak permutation is unoptimised.

**Budget time for the build itself.** The release profile is `lto = true` with
`codegen-units = 1`, which is deliberate — it also carries `overflow-checks`,
mandatory for a consensus build — and it makes the final link slow and
single-threaded. Re-measured 2026-09-02 on three 2-vCPU cloud boxes building
the tag from a clean clone: **3m07s, 3m40s, 4m12s**. Run-to-run variance on
shared vCPUs is around 40% — the same box gave 6m04s and then 4m12s for the
same work — so provision for the slow end. The "~40 minutes" this document
carried until today was measured on a laptop running several other compiles. Do not "optimise" this by dropping LTO or building
in debug: both change the binary you validate with. Start the build before you
need it.

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
digests in §1 were reproduced from a clean clone of the tag
`g4-node-20260901`. The binary that tag produces is
`sha256 ac79e2fabfab40c627b0381d8f1c05b06407553db51a75801e968664ccf92654`
(7,347,832 bytes), reproduced byte-identically on three machines by two
independent checkout paths — a clone of a bundle and an incremental fetch onto
an already-built tree. A tarball build differs, because the commit hash is
compiled in.

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

**This is the slow part, and it decelerates.** Measured 2026-09-01, release
build, idle machine, syncing from the two published bootnodes:

| Elapsed | Slot | Epoch | Rate |
|---|---|---|---|
| 3 min | 528 | 12 | 408 slots/min |
| 5 min | 620 | 12 | 37 slots/min |
| 7 min | 664 | 18 | 22 slots/min |
| 9 min | 734 | 20 | 37 slots/min |
| 12 min | 846 | 24 | 83 slots/min |

The rate falls by **more than an order of magnitude within the first 20
epochs**, then settles, minute to minute erratic (0–83), averaging
**~35 slots/min** over a sustained window.

The chain itself only advances 2 slots/min, so your node does still gain and
will converge. But at 35 slots/min a full sync to a head near slot 53,300 is
about **26 hours** — a day, not an afternoon. Plan for it, and note that the
figure grows as the chain does: every day you wait adds roughly another 40
minutes of catch-up on top.

If you are syncing to beat the weak-subjectivity deadline in §0, **26 hours of
sync inside a four-day window means starting now, not on 4 September.**

> **Read this before you trust the 26 hours.** The deceleration is a **known
> open defect**, not a property of the chain: each epoch boundary does work
> proportional to the whole ledger.
>
> The table above was measured with a partial fix applied (`fix(catch-up):
> share the eUTXO map so an epoch roll stops paying the ledger`,
> `Arc<BTreeMap>` copy-on-write). **That fix is in the tag `g4-node-20260901`**
> and is not on `main` — one more reason §2 now tells you to check out the tag.
>
> The 26-hour figure itself was wrong and is withdrawn. Re-measured 2026-09-02
> on a 7.9 GB / 2-vCPU box: `main` completed a cold sync **twice**, in 29.5 and
> 30.3 minutes, peaking at ~1,015 MB and never being OOM-killed; the tag does it
> in **21.2 minutes at 934 MB**. The "26 hours" came from a contended laptop run
> that was stopped at 13 minutes and extrapolated. An earlier warning in this
> document that an 8 GB box would be OOM-killed did not reproduce, in either
> direction, and is withdrawn with it.
>
> Two facts that do survive, and that an integrator should plan around. First,
> §5's archival-seed path is not faster than syncing from the network — measured
> 22.1 minutes against 21.2 — so choose it for provenance reasons, not for
> speed. Second, **a node restart costs a full local replay of its block log,
> and the RPC is closed for the whole of it**: during a 21-minute sync the node
> answered `getchaininfo` once, at 65 seconds, and then not again. Monitoring
> that treats an unanswered RPC as a dead node will page you on every restart.

### The faster path: seed from an archival node — recommended

Given the numbers above, this is the path to use unless you have a specific
reason to replay from genesis.

If a full replay does not fit your window, copy `blocks.log`, `meta.bin` and
`ws_latest.bin` from a healthy node's data directory and let your node replay
them locally instead of over the network — measured at **52 blocks/s**.

Copy those three files **by name**. Measured on an archival node on
2026-09-01: `blocks.log` was **453 MB** (`meta.bin` and `ws_latest.bin` are a
few dozen bytes each), and it grows with the chain, so treat the figure as a
floor and check before you provision. A data directory may also contain
`.TRAVADO-*` files — operator-made snapshots of an earlier, stuck log. Do not
copy those and do not glob the directory; take the three names above.

At 52 blocks/s a local replay of the current chain (height ~32,450) is roughly
**10 minutes**, against ~26 hours or more over the network. That is the whole
reason this path is the recommended one.

Copy from an **archival** node, never from a validator's data directory: a
validator's directory contains `validator.key`, and copying a live validator
key to a second machine risks double-signing, which is slashable.

This path is a genuine trade: you are trusting the donor for the block data.
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
`./deploy/bootnodes/verify-bootnodes.sh --deep` does exactly this comparison
and fails loudly on a mismatch.

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
