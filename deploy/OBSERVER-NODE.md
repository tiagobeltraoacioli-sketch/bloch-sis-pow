<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Run an independently validating observer node — Bloch Genesis-4 (PoS)

**Audience:** exchanges and integrators who need a node that validates the
chain itself, so that `finalized` — the settlement signal — is a fact the
node computed, not a claim it relayed. The shared public RPC endpoint is fine
for development and cross-checking; it is **not suitable as the source of
truth for crediting customer deposits**. This document is how you stop
depending on it.

**Distribution:** delivered to integration partners as a file. Do not publish
it on the public website or as a shared link.

**Status of this document:** verified against the source tree on 2026-08-31
(`crates/bloch-pos-node/src/main.rs` is the authority for every flag below).
Values that cannot be stated yet are marked **`TODO`** in bold — a `TODO` is
missing information, never a value to type in literally. Everything *not*
marked `TODO` is real and current.

---

## 1. What you are deploying

| | |
|---|---|
| Chain | Bloch **Genesis-4**, proof of stake (live mainnet since 2026-08-13) |
| Binary | `bloch-pos` (crate `bloch-pos-node`, version `0.1.0-mainnet`) |
| `--version` prints | `bloch-pos-node 0.1.0-mainnet (<commit-12>) (Genesis-4, block version …)` |
| Slot | 30 s; epoch = 32 slots (16 min) |
| Genesis time | 2026-08-13 21:31:19 UTC |
| Network digest | `f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966` |
| Signatures | hybrid ML-DSA-65 ‖ Falcon-1024 (post-quantum); consensus hashing SHA3 |

An **observer** is the same binary as a validator, run over a data directory
that contains **no `validator.key`**. The node detects this at startup, prints
`observer mode: no keystore in <dir>`, and then follows the chain, fully
validates every block (signatures, state root, body root, attestation
quorum — nothing is lighter because a block arrived via sync), and serves the
RPC. It never proposes and never attests. This is the correct mode for an
exchange: no stake, no slashing surface, no consensus duty — just an
independent verdict on what is final.

Do **not** run your deposit-crediting node from a keystore-bearing data dir,
and do not accept a pre-built data directory from anyone as your source of
truth (see §7 for the one bounded exception).

## 2. Prerequisites

- Linux x86_64 or aarch64 (the fleet runs both), 2 cores, 8 GB RAM, 20 GB
  disk. Replay/sync is single-threaded (~one core pinned); more cores only
  help if you run several nodes on one box.
- Rust `1.94.1` — pinned by `crates/bloch-pos-node/rust-toolchain.toml`;
  rustup will select it automatically.
- Outbound TCP to the peer endpoints (§5). Inbound is optional for an
  observer.

Build from source and verify the stamp:

```bash
git clone <this repository>
cd BlochPOS
# TODO(Postern Labs): pinned release commit + reference sha256 of the canonical
# binary for the current flag-day level. Until published here, build repo HEAD
# of the default branch and confirm the --version stamp with your Postern
# contact before going live — a node behind a consensus flag day forks off.
cargo build --release -p bloch-pos-node --locked
./target/release/bloch-pos --version    # must print 0.1.0-mainnet + a commit, and NOT "+dirty"
./target/release/bloch-pos selfcheck    # asserts the frozen consensus constants; prints "self-check passed"
```

`deploy/RELEASE-INTEGRITY.md` describes the reproducible-build discipline
(the release triple, `+dirty` marking, `BLOCH_BUILD_COMMIT`) if you want to
reproduce the fleet binary bit-for-bit.

## 3. Artifacts you need (both ship in this repository)

Both files are required; neither is useful alone. The manifest commits to the
carryover **by digest**, and the node refuses to start on any mismatch.

**`genesis/mainnet.manifest`** — the genesis the 64 validators booted from.

    size       247,514 bytes
    SHA-256    7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd

**`carryover.tsv`** — the Genesis-3 terminal snapshot (every unspent output
at G3's final height 39,918), the opening balances of Genesis-4. Ships
compressed as `carryover.tsv.gz`; the node reads the uncompressed TSV.

    rows          452,726
    uncompressed  54,780,151 bytes
    SHA-256       84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6
    SHA3-256      3d67246e94881a17d302b464f79fee55886d8068794e76fed43081117fbe308d   ← what the node checks
    set root      7c756ee8ffff9529b40c124b36bd3e1a9934a15f063affe5596913fb858efbdf
    total         18,146,400,000 BLOCH

```bash
sha256sum genesis/mainnet.manifest                  # 7eef82a7…
gzip -dk carryover.tsv.gz                           # produces carryover.tsv, keeps the .gz
gzip -dc carryover.tsv.gz | sha256sum               # 84ddbbac…
gzip -dc carryover.tsv.gz | wc -l                   # 452726
```

Two hash pitfalls that have each already cost someone real time:

- **SHA-256 ≠ SHA3-256.** The node verifies the SHA3-256; `sha256sum`
  reproduces the SHA-256. Both are listed above so either tool agrees.
- **An older snapshot exists.** Until 2026-08-14 this repo (and
  `docs/CARRYOVER.md`) carried the **Genesis-1** carryover — 413,743 rows,
  SHA-256 `88f29fd3…`. If your hashes come out to those values you have the
  wrong file for the wrong chain, and the node will refuse it. The
  authoritative description of the current snapshot is
  `CARRYOVER-SNAPSHOT.md` at the repo root.

## 4. The `run` flags, exactly as the binary parses them

`bloch-pos run` — flags from `crates/bloch-pos-node/src/main.rs`:

| Flag | Required | Meaning |
|---|---|---|
| `--data-dir <dir>` | **yes** | Chain data lives here (`blocks.log`, `meta.bin`, `ws_latest.bin`) and is replayed — with full validation — on restart. **No `validator.key` in this dir ⇒ observer mode.** |
| `--genesis <file>` | **yes** | The genesis manifest (`genesis/mainnet.manifest`). A node on a manifest with a different digest is on a different network, by construction. |
| `--carryover <snapshot.tsv>` | **yes on mainnet** | The uncompressed carryover TSV. Required exactly because the mainnet manifest carries a carryover commitment; checked against all four committed fields (file digest, set root, count, total) before a single balance is admitted. Against a manifest with no commitment the flag is refused. |
| `--transport devnet\|libp2p` | no (default `devnet`) | `devnet` = the plain TCP full mesh the live fleet runs: **no authentication, no admission control** — a routable bind must be firewalled to known peers. `libp2p` = the production stack (gossipsub on Genesis-4-only protocol ids, admission control, directed paginated sync); see §5 for which to pick today. |
| `--listen <port>` | **yes for devnet** | Devnet-transport TCP listen port. Fleet convention: `19000+N`. |
| `--listen-addr <ip>` | no (default `127.0.0.1`) | Bind address for the devnet listener. Loopback by default on purpose; `0.0.0.0` is a deliberate act **plus a firewall**. An outbound-only observer can leave this at the default. |
| `--peers <host:port,...>` | no, but needed to sync | Comma-separated devnet-transport peer endpoints; the node dials them and keeps re-asking for history (paginated, 512 blocks/page, from 2 peers at a time) until caught up, then stays current the same way. |
| `--rpc-bind <ip>` | no (default `127.0.0.1`) | **The RPC has no authentication** and `sendrawtransaction` is a write. Keep it on loopback behind your own proxy; if you bind a routable address you must firewall it to the intended clients. |
| `--rpc-port <n>\|off` | no (default `16310`) | JSON-RPC 2.0 over HTTP POST. Fleet convention: `16400+N`. `off` disables. A malformed value refuses to start rather than falling back. |
| `--ws-checkpoint <file>` | situational — §6 | Signed weak-subjectivity checkpoint envelope (`BLOCH-WEAK-SUBJECTIVITY.md` §4.1). |
| `--ws-signer-set <file>` | with `--ws-checkpoint` | The checkpoint signer arrangement. This build bakes none in, so the two flags travel together. |

Libp2p-transport-only flags, for when §5's TODO resolves to multiaddrs:
`--p2p-listen <multiaddr>[,…]` (default `/ip4/0.0.0.0/tcp/16400` — **note
this default collides with the fleet's `16400+N` RPC convention**; set it
explicitly if you use both), `--p2p-peer <multiaddr>[,…]` (dialled as
`/ip4/<host>/tcp/<port>/p2p/<peer-id>`; the node prints its own peer id at
startup), `--max-peers <n>` (default 64), `--behind-proxy` (zeroes the
IP-colocation score penalty when a mesh shares one proxy address).

There is also `--stop-at-slot <n>` (halt at a slot; testing only). There is
no `--mine`, no `--archive`, no `--genesis3`, no `--carryover-snapshot`, no
multiaddr `--listen` — those are Genesis-1/3 flags of the retired `bloch`
PoW binary, and any document that shows them is describing a dead chain.

## 5. Ports and peers

| Surface | Fleet convention | Observer guidance |
|---|---|---|
| P2P (devnet transport, TCP) | `19000+N` per validator | Pick any port (e.g. `19100`). **Outbound-only is sufficient**: the sync pump polls its peers every ~5 s, which more than keeps up with 30 s slots. If you do open it inbound, firewall it to the known peer IPs — this transport authenticates nothing. |
| RPC (HTTP JSON-RPC) | `16400+N` per validator | Loopback only (`--rpc-bind 127.0.0.1`), reached through your own reverse proxy with your own auth. Never expose it raw. |

> **TODO(Postern Labs): bootstrap peer endpoints.** The `--peers` list
> (devnet transport `host:port` entries) and, once the libp2p mesh is opened
> to third parties, `--p2p-peer` bootnode multiaddrs, are provided directly
> during integration and will be pinned here when the public endpoints are
> stable. **There is deliberately no example value in this row** — an earlier
> revision of these docs carried the template
> `/ip4/<dedicated-ipv4>/tcp/16110/p2p/<peer-id>`, which read like a real
> multiaddr and wasted a partner's time. Until this TODO is resolved, request
> the current peer list from your Postern Labs contact.

Which transport: the live fleet inter-validates over `--transport devnet`
today, so **`devnet` + the provided peer list is the configuration that
works now** and is what the rest of this document assumes. `libp2p` is the
production transport an internet-facing node ultimately wants (it is the one
with admission control); switch when the bootnode TODO above is resolved to
multiaddrs.

## 6. Weak subjectivity — read this before first boot, the date matters

Cold-syncing validates that the chain is *internally* correct; in PoS it
cannot by itself prove it is *the* chain (long-range problem). Genesis-4's
answer has exactly two regimes (`WS_PERIOD_EPOCHS` = 2016 epochs ≈ 22.4
days):

1. **Chain younger than 2016 epochs → no flags needed.** The genesis
   manifest is its own subjectivity anchor and cold sync is fully trustless.
   For this network that window ends at epoch 2016, **≈ 2026-09-05 07:07
   UTC**.
2. **After that, a node with an empty data dir requires
   `--ws-checkpoint` + `--ws-signer-set`** and will refuse to sync without
   them — that refusal is the mechanism working, not a fault. The checkpoint
   is a real, named trust input: 32 bytes you can compare across independent
   publication channels, trusted only for *which* finalized root is real at
   one epoch. Every block after it is still downloaded and re-validated
   locally, and a checkpoint contradicting finality your node reached on its
   own alarms instead of reorganizing it.

A node that has already synced keeps its own anchor in
`ws_latest.bin` and needs no checkpoint as long as it stays reasonably
current. Practical consequence: **an observer first synced before
2026-09-05 needs nothing; one stood up after needs a checkpoint file.**

> **TODO(Postern Labs): checkpoint publication channel.** Where the signed
> weak-subjectivity checkpoint envelopes and the signer-set file are
> published (they are produced on a cadence with ~7.8× margin against the
> window). Until pinned here, request both files from your Postern Labs
> contact — and verify the 32-byte root against at least one independent
> channel.

## 7. Bring-up

```bash
sudo useradd -r -m -d /var/lib/bloch bloch
sudo install -o bloch -m 0644 genesis/mainnet.manifest /var/lib/bloch/mainnet.manifest
gzip -dc carryover.tsv.gz | sudo -u bloch tee /var/lib/bloch/carryover.tsv >/dev/null
sudo -u bloch mkdir /var/lib/bloch/data        # stays empty: no validator.key ⇒ observer

# TODO — the --peers value below is NOT real; obtain the current list (§5).
sudo -u bloch bloch-pos run \
  --data-dir  /var/lib/bloch/data \
  --genesis   /var/lib/bloch/mainnet.manifest \
  --carryover /var/lib/bloch/carryover.tsv \
  --transport devnet \
  --listen    19100 \
  --peers     TODO-OBTAIN-FROM-POSTERN \
  --rpc-bind  127.0.0.1 --rpc-port 16400
```

First lines to expect, in order: the carryover admission (all four commitment
fields checked), `observer mode: no keystore in /var/lib/bloch/data`, then
`bloch-pos node — observer (no keystore, signs nothing), genesis …
(state root …), network digest f47d3e49…`. **Check the digest**: anything
other than the prefix of `f47d3e498ff978e3…` means a different manifest and a
different network.

Initial sync downloads every block from peers and validates each one, and a
restart replays the local log through the same full validation. Applying is
single-threaded; replay was measured at 52 blocks/s at height ~15k
(2026-08-26, after the state-tree rework), i.e. minutes, not hours — but the
rate falls as state grows, so measure your own. Sizing note: ~202 MB of chain
data at height 15k, growing with the chain.

*Bounded shortcut, stated honestly:* copying `blocks.log`, `meta.bin` and
`ws_latest.bin` from another node you operate lets replay (which re-validates
every block against the genesis you verified yourself) stand in for network
download. Blocks that fail validation are refused, so a tampered log cannot
sneak state in — but take the copy from infrastructure you control, and never
let anyone "donate" you a whole data directory as a convenience.

Systemd:

```ini
[Unit]
Description=Bloch Genesis-4 observer node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bloch
ExecStart=/usr/local/bin/bloch-pos run --data-dir /var/lib/bloch/data \
  --genesis /var/lib/bloch/mainnet.manifest --carryover /var/lib/bloch/carryover.tsv \
  --transport devnet --listen 19100 --peers TODO-OBTAIN-FROM-POSTERN \
  --rpc-bind 127.0.0.1 --rpc-port 16400
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

## 8. Verify you are on the canonical chain

Do all three, at bring-up and continuously from monitoring.

**a. Network digest** (once, at startup): the banner's `network digest` must
be `f47d3e49…` (§7).

**b. Are you current:**

```bash
curl -s -X POST http://127.0.0.1:16400 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}'
```

`behind_by_slots` of 0 or 1 is current. `height` is the head;
`finalized_height` is what is safe; the gap between them is normally 1–2
epochs' worth of blocks.

**c. Same chain as a second source:** pick a recent **finalized** slot and
compare `block_id` and `state_root` for that slot against a second source —
your own second node in another facility, or the shared endpoint you used
during integration (fine as a *cross-check*; never as the crediting source):

```bash
curl -s -X POST http://127.0.0.1:16400 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockbyslot","params":[35242]}'
# → {"slot":35242,"height":…,"block_id":"…","state_root":"…","finalized":true,…}
```

Identical `block_id` **and** `state_root` at the same slot ⇒ same chain, same
balances. A matching `block_id` with a differing `state_root` (or vice versa)
is not "close enough" — treat it as divergence, stop crediting, and
escalate. Alarm too if your `finalized_height` ever *decreases*, or if
`behind_by_slots` grows without bound while peers answer.

Compare at the same **slot**, not the same height: slots can be empty, so two
honest nodes at "height 15,130" are only comparable if that height sits at
the same slot on both.

> **TODO(Postern Labs): pinned public cross-check endpoint.** The shared
> RPC hostname handed over during integration belongs here once it is
> stable. Whatever it is, its only role in production is corroboration —
> crediting reads come from your own observer.

## 9. Finalized vs head — the settlement rule

- `getchaininfo` reports both: `height`/`slot`/`epoch` are the head — the
  best block your node has validated, still reorganizable. `finalized_height`
  and `finalized:{epoch,root}` are the finality checkpoint your node
  computed from the attestations it verified itself.
- Every block response carries `"finalized": true|false`. **That boolean is
  the settlement guarantee.** Genesis-4 has no depth-as-security: there is no
  number of confirmations that substitutes for it, and counting them buys
  nothing.
- Credit a deposit when the block containing it reports `finalized: true`
  (equivalently, when `getchaininfo.finalized.epoch` ≥ the block's epoch).
  Finality typically lands 1–2 epochs (16–32 min) after inclusion.
- The full deposit/withdrawal integration contract (script hashes, amount
  parsing, fee reads) is `docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md`;
  this document only stands up the node it tells you to read from.

## 10. Consensus flag days — the one ongoing obligation

Genesis-4 upgrades consensus by flag day: a constant armed at a future epoch,
shipped in the binary ahead of time. A node on an old binary past a flag-day
epoch **forks off silently** — it keeps running and keeps answering RPC on a
chain of its own. Two are already behind us (epoch 800 —
`deploy/FLAG-DAY-EPOCH-800.md` — and epoch 1400). Subscribe to release
announcements with your Postern Labs contact and treat "update before epoch
E" notices as hard deadlines; verify after every update that `--version`
matches the announced stamp and that §8c still agrees with the second source.

---

*Retired documents:* everything else under `deploy/` that describes joining
a network (`fly/`, `akash/`, `genesis2/`, `docker-compose.yml`, the SDL
files, `hardening/`'s examples) predates Genesis-4 and is kept as historical
record only — each is banner-marked. If a command mentions `--mine`, ports
`16110/16210`, or the binary `bloch`, it is about a retired proof-of-work
chain and will not connect you to anything.
