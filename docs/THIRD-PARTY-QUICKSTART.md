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

### The clock: 2026-09-05 07:07 UTC

Bloch is proof of stake, so it has a weak-subjectivity window. A validator set
that has already withdrawn its stake can sign an alternative history at no
cost, which means "internally valid" is not the same as "the real chain". The
window is `WS_PERIOD_EPOCHS` = `WITHDRAWAL_DELAY_EPOCHS (2048) − EXIT_DELAY_EPOCHS (32)`
= **2016 epochs ≈ 22.4 days** at 32 slots × 30 s.

Genesis-4 started at epoch 0. So:

| If your node's first sync starts | What it needs |
|---|---|
| **before epoch 2016** — i.e. before **2026-09-05 07:07 UTC** | the genesis manifest and nothing else. The genesis block is its own trust anchor. |
| **after** that instant | a **signed checkpoint** (`--ws-checkpoint` + `--ws-signer-set`) |

**No signed checkpoint exists today.** The signing keys have not been
generated — the ceremony is Phase A of `docs/specs/BLOCH-WEAK-SUBJECTIVITY.md`
§6.1 and it has not happened. A node started after the deadline with no
checkpoint **refuses to sync and says so**; it does not quietly follow a peer.

A node that completes its first sync *before* the deadline keeps its own
finality as its anchor from then on and never needs a checkpoint. **If you
intend to run a node in 2026, start it before 5 September.** This is the single
time-sensitive item in this document.

You can watch the gate count down in your own node's boot log:

```
fresh node: syncing under the genesis anchor (age 1637 of 2016 epochs)
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
reason. `--rpc-bind 0.0.0.0` on a public host is the single most damaging
mistake you can make with this software.

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

```bash
git clone https://gitlab.com/blochsispow-group/bloch-pos.git
cd bloch-pos
cargo build --release -p bloch-pos-node
./target/release/bloch-pos --version    # must NOT say "+dirty"
./target/release/bloch-pos selfcheck    # verifies the frozen consensus params
```

> **Use a release build.** A debug build is not merely slower — it makes the
> initial state construction take hours instead of minutes, because the
> Keccak permutation is unoptimised.

## 3. Get the genesis files

**Both ship in the repository you just cloned** — you do not need to download
them separately:

```bash
ls genesis/mainnet.manifest        # 247 KB
gunzip -k carryover.tsv.gz         # 17 MB compressed -> 55 MB
sha256sum genesis/mainnet.manifest carryover.tsv   # compare against §1
```

Verified 2026-09-01: both are byte-identical to what the live fleet runs
(checked against `/home/ubuntu/g4/` on archival node 139.180.166.5).

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

```bash
mkdir -p /var/lib/bloch/data

./bloch-pos run \
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

**Phase 1 — genesis state construction (~10 minutes, no output).** The node
builds the sparse Merkle tree over all 452,726 carryover outputs before it
opens its RPC or connects to any peer. Measured at **10 minutes** on an
M-series Mac, release build. Nothing is printed and no port is open while this
runs. It is not stuck.

**Phase 2 — replay from genesis.** Blocks arrive from the bootnodes and are
applied one at a time, each one fully validated:

```
[slot 1] applied 1f65a776 by v46 — head root 17f80dfd, justified e0, finalized e0
```

Your node gains on the live chain the whole time — the chain advances 2 slots
per minute, and replay is far faster than that — so it converges.

> **Known defect, check your build.** Builds before the catch-up fix
> (`fix(catch-up): share the eUTXO map so an epoch roll stops paying the
> ledger`) clone the entire eUTXO set on every epoch boundary. Replay starts
> near 3 slots/s and **decays to ~0.25 slots/s** within 25 epochs, which turns
> a few hours into days. Measured on an unfixed build 2026-09-01. Confirm your
> build contains that commit before starting a long sync.

### The faster path: seed from an archival node

If a full replay does not fit your window, copy `blocks.log`, `meta.bin` and
`ws_latest.bin` (~202 MB) from a healthy node's data directory and let your
node replay them locally instead of over the network — measured at
**52 blocks/s**, about 4 minutes for 15,000 blocks.

Copy from an **archival** node, never from a validator's data directory: a
validator's directory contains `validator.key`, and copying a live validator
key to a second machine risks double-signing, which is slashable.

This path is a genuine trade: you are trusting the donor for the block data.
You are *not* trusting them for validity — your node re-applies every
transition and recomputes every state root, and diverges loudly if the data is
wrong. What it cannot detect on its own is a *complete and internally
consistent* alternative history, which is exactly what §0's weak-subjectivity
anchor is for.

## 6. Prove you are on the real chain

**Same height is not agreement.** Two forked nodes happily report the same
height with different roots, and a forked node answers RPC normally. Compare
the **finalized root**:

```bash
curl -s -X POST http://127.0.0.1:16400 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' | jq '.result.finalized'
```

Compare that `{epoch, root}` against both bootnodes at the same finalized
height. They must be byte-identical. A worked example from 2026-09-01, both
bootnodes at finalized height 31462:

```
139.180.166.5    finalized root bb9fe9828f9d70ed9bb5f488835755f44cb97d9ea655ef262b9e267b2b5a5670
139.180.173.231  finalized root bb9fe9828f9d70ed9bb5f488835755f44cb97d9ea655ef262b9e267b2b5a5670
```

Also check `behind_by_slots` in `getchaininfo`: 0–1 means you are at the head.

Do this **before** you credit anything to a customer, and keep doing it — a
node that silently diverges is the failure mode that costs money.

## 7. Once a signed checkpoint exists

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
| **A signed WS checkpoint** | No signer keys exist yet. Sync before 2026-09-05 07:07 UTC and you will not need one. |
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
