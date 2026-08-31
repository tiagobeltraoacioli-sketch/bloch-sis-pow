<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Genesis-4 — Validator Runbook

**Audience:** a competent operator who has never seen this chain. This document
is the complete path from nothing to a validating, monitored, exitable stake —
and it is also the honest test of the network's readiness: every step that
cannot be completed today is marked **GAP** inline and collected in §15. If a
step you need is in §15, the network is not ready for you yet on that step, and
this document says so rather than pretending.

Companion tooling, in `tools/validator-ops/`:

| tool | what it does | runbook step |
|---|---|---|
| `blochv-keygen.sh` | validator keystore with a safe layout, custody rules enforced | §7 |
| `blochv-preflight.sh` | "will this machine keep up" — run before depositing | §5 |
| `blochv-health.sh` | the health check to alarm on, exit codes 0/1/2 | §11 |

---

## 0. Read this first

Statements you are entitled to before bonding 25,000 BLCH for a minimum of
~23 days:

- **The code is unaudited.** The chain relaunched as proof-of-stake on
  2026-08-13. It has had consensus incidents since launch, some found by its
  own operators mid-flight. The post-mortems are in this repo; read
  `docs/post-mortems/` before you stake.
- **Stake and supply are concentrated.** The genesis cohort is 64 validators
  and the founder's carried-over balance dominates existing supply. The
  activation queue (4 validators/epoch, §9) makes takeover slow and visible;
  it does not make the present distribution decentralized.
- **The coin has no listed market.** Acquiring BLCH to stake means receiving a
  transfer from an existing holder. There is no faucet, no exchange listing,
  no market price (§8.1).
- **Slashing is real and correlation-priced** (§14). A key-management mistake —
  the same key live on two machines — is indistinguishable from an attack, by
  design, and costs you 3× more if others are being slashed in the same
  4,096-epoch window.
- **Your validator key cannot live in any hardware wallet** (§2). If your
  custody policy requires an HSM, you cannot run this validator. That is the
  full sentence.

---

## 1. The chain in numbers

| parameter | value | source |
|---|---|---|
| Ticker / decimals | BLCH, 8 (1 BLCH = 100,000,000 sat) | `tokenomics_v4.rs` |
| Total supply | 100,000,000,000 BLCH, hard cap | `TOTAL_SUPPLY_BLOCH` |
| Slot | 30 s | `params.rs` |
| Epoch | 32 slots = 16 min (90 epochs/day) | `params.rs` |
| Settlement | Casper finality (a boolean, not a confirmation count) | §6.6 |
| Signatures | hybrid ML-DSA-65 ‖ Falcon-1024, AND-composed | `staking.rs` |
| Minimum deposit | 25,000 BLCH (`MIN_DEPOSIT_SAT`, staking.rs:97) | §8.2 |
| Per-validator cap | max(1% of active stake, 25,000 BLCH) | §8.2 |
| Activation delay | 8 epochs (~2.1 h) after inclusion | `ACTIVATION_DELAY_EPOCHS` |
| Activation queue | 4 validators admitted per epoch | `MAX_ACTIVATIONS_PER_EPOCH` |
| Exit delay | 32 epochs (~8.5 h) until duties stop | `EXIT_DELAY_EPOCHS` |
| Withdrawal delay | 2,048 epochs (~22.8 days) until stake is spendable | `WITHDRAWAL_DELAY_EPOCHS` |
| Weak-subjectivity period | 2,016 epochs (~22.4 days), derived as 2048 − 32 | `ws.rs:140` |
| Slashing correlation window | 4,096 epochs, 3× multiplier | §14 |
| Whistleblower reward | 1/32 of the slashed amount | §14 |
| Validator emission | 42,853,600,000 BLCH over 40 years, halving schedule | `tokenomics_v4.rs` |
| Genesis time | 2026-08-13 21:31:19 UTC | `genesis/README.md` |
| Genesis validators | 64, active stake 61,771,071 BLCH (measured 2026-08-30) | `getchaininfo` |

---

## 2. Custody reality — decide this before anything else

The validator key is **hybrid ML-DSA-65 ‖ Falcon-1024** — two lattice secret
keys, together ≈ 6.3 KB, plus a 32-byte RANDAO seed, in one `BPOSKEY1`
keystore file. Consequences you must accept before generating one:

1. **No hardware wallet or HSM can hold it.** No shipping Ledger, Trezor,
   YubiKey, cloud KMS, or enterprise HSM signs ML-DSA-65 or Falcon-1024, and
   the hybrid needs BOTH signatures on every message ("AND, not OR" —
   `staking.rs` §6.2). Post-quantum hardware signing is research-grade
   everywhere. Your custody plan is therefore **file custody**: filesystem
   permissions, disk encryption, offline backups, and the discipline in §7.
   Operators always ask; this is the complete answer, and it changes custody
   plans, so it is stated here rather than discovered later.
2. **The validator key is hot by construction.** The node signs attestations
   every epoch and walks the RANDAO reveal chain to propose. It cannot be
   air-gapped while validating.
3. **The withdrawal credentials are a separate, colder key.** The 32-byte
   address the stake returns to is committed at deposit time and can never be
   changed (`staking.rs`: a compromise of the hot key must not redirect the
   principal). It should never touch the validator machine. It cannot live in
   a hardware wallet either — the spending key is the same hybrid suite.
4. **One key, one machine, forever.** Running the keystore on two machines at
   once is slashable equivocation. There is no "high-availability" mode; the
   doppelganger watch (§9.3) exists to catch exactly this mistake before it
   completes.

---

## 3. Obtain and verify the binary

A `bloch-pos` release is the triple **(source commit, version stamp, sha256 of
the binary)** — `deploy/RELEASE-INTEGRITY.md` is the governing document.
Nothing that cannot state all three is a release.

Build from source (the path that trusts the least):

```sh
git clone https://gitlab.com/blochsispow-group/bloch-pos.git && cd bloch-pos
# rustup honours crates/bloch-pos-node/rust-toolchain.toml → Rust 1.94.1
cargo build --release --locked --manifest-path crates/bloch-pos-node/Cargo.toml
./crates/bloch-pos-node/target/release/bloch-pos --version
./crates/bloch-pos-node/target/release/bloch-pos selfcheck
```

Verify before trusting:

- `--version` must print `bloch-pos-node <version> (<commit-12>) …`. A
  `+dirty` or `unknown+nogit` stamp is a hard failure — an unidentifiable
  binary is how the Genesis-3 fleet became unauditable, and the release gate
  treats it that way.
- `selfcheck` verifies the frozen consensus parameters this binary links.
- The commit in the stamp must be the commit you checked out.
- `scripts/pos-release-integrity.sh` is the full gate the project itself runs
  (toolchain pin, locked dependency graph, stamp).

> **GAP (G5).** The binary a stranger downloads is not yet the binary this
> runbook describes. The slashing-protection store and doppelganger watch,
> the peer-time clock gate, and the cold-sync replay fix landed on
> 2026-08-31 on integration branches and are **not yet merged and released**.
> Until a release ships containing all three, a from-`main` build will not
> have the `--accept-new-signing-history`, `protection-export/import`, or
> `--doppelganger-epochs` surface, and will not refuse a grossly wrong clock.
> Check `bloch-pos --help` for those flags; if absent, you are early.

---

## 4. Genesis artifacts

Two files define the network; both ship in this repo:

| file | size | sha256 |
|---|---|---|
| `genesis/mainnet.manifest` | 247,514 B | `7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd` |
| `carryover.tsv.gz` (decompress before use) | 17 MB → ~55 MB TSV | pinned in `carryover.tsv.gz.sha256` |

The manifest commits to the carryover **by digest** (file digest, set root,
count, total — all four checked at boot before a single balance is admitted).
Network digest `f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966`;
a node hashing to anything else is on a different network. The carryover is
the Genesis-3 closing state: 452,726 outputs, 18,146,400,000 BLCH.

Verify both digests yourself before first boot. Do not accept these files
from a chat, a pastebin, or another operator's tarball without re-hashing.

---

## 5. Machine preflight

Reference sizing, measured on the live fleet: **2 dedicated cores, 8 GB RAM,
20 GB disk per node** — and one validator per failure domain. The fleet's own
worst outages were self-inflicted undersizing: five to six validators sharing
one box's RAM, one alive at a time.

Run the tool; it enforces the numbers and explains each one:

```sh
tools/validator-ops/blochv-preflight.sh --data-dir /var/lib/bloch/data
```

What it checks: binary identity and `selfcheck` (§3), cores/RAM/disk floors,
a single-core throughput proxy for the ~81 ms/block replay budget (replay is
single-threaded and pins a core — post the 2026-08-31 fix that removed the
per-epoch eUTXO clone which previously made cold starts unconditionally
fatal), NTP discipline (the node's own boot gate refuses gross clock-vs-peer
skew, §6.3 — find out here, not there), open-file limits, and port hygiene.
Exit 0 = proceed, 1 = read the warnings, 2 = do not deposit from this machine.

---

## 6. Stand up a node and sync

Start as an **observer** (a data dir with no `validator.key`): the node
follows the chain, validates every block itself, serves RPC, and signs
nothing. Do not put a keystore anywhere near the machine until §9.

```sh
bloch-pos run \
  --data-dir  /var/lib/bloch/data \
  --genesis   /var/lib/bloch/mainnet.manifest \
  --carryover /var/lib/bloch/carryover.tsv \
  --transport devnet \
  --listen 19100 --listen-addr 0.0.0.0 \
  --peers <ip:port,…> \
  --rpc-bind 127.0.0.1 --rpc-port 16400
```

### 6.1 Who do you connect to — the topology today

The live fleet runs the `devnet` transport: a TCP full mesh with **no
authentication and no admission control**, on the 19xxx port range,
firewalled to known peer addresses (a 2026-08-09 incident — one stale node's
backfill flood halted all production — is why inbound is closed). The
`libp2p` transport (gossipsub, admission control, directed paginated sync) is
the production stack in the binary, but it is not what the fleet runs.

> **GAP (G4).** There is no published bootstrap peer list and no public P2P
> entry point. A stranger has no one to dial: joining today requires
> coordinating with an existing operator for peer addresses and a firewall
> exception. Closing this needs either the fleet's move to the libp2p
> transport with published bootstrap multiaddrs, or a published, maintained
> peer list plus an inbound-tolerant edge — neither exists today.

### 6.2 Syncing, and the weak-subjectivity boundary — dated

Two ways to arrive at the tip:

1. **Sync from genesis.** Supported; every block is validated locally. Replay
   is single-threaded at ~81 ms/block (~12 blocks/s; the fleet measured 4
   minutes for 15,000 blocks). This was unconditionally fatal before the
   2026-08-31 per-epoch-clone fix; this runbook assumes a binary containing
   that fix (§3 GAP note).
2. **Copy a data dir** (`blocks.log`, `meta.bin`, `ws_latest.bin`) from an
   operator you trust, then replay it locally. Faster; trust-shifted onto the
   donor until replay re-validates.

Proof-of-stake has an honesty boundary PoW does not: once the chain is older
than the weak-subjectivity period, an exited validator can sign a conflicting
history at zero cost, so "just sync from genesis" stops being trustless.
`WS_PERIOD_EPOCHS` = 2,016 epochs ≈ 22.4 days (derived: withdrawal delay
minus exit delay, `ws.rs:140`).

**Genesis + 2,016 epochs = 2026-09-05 07:07:19 UTC.** Before that instant, a
fresh node boots with the genesis anchor as its first checkpoint and needs no
ceremony. **After it, a fresh node with no checkpoint REFUSES to sync** —
that is the mechanism working, not a fault. It must be started with:

```sh
  --ws-checkpoint <envelope-file> --ws-signer-set <signer-set-file>
```

where the envelope is the signed checkpoint of `BLOCH-WEAK-SUBJECTIVITY.md`
§4.1 (< 25 KB, travels as a file) and the signer set is the published signer
arrangement it verifies against.

> **GAP (G3) — hard, with a date attached.** No weak-subjectivity checkpoint
> has ever been published, and no signer arrangement exists for
> `--ws-signer-set` to point at. The spec's cadence (a signed checkpoint
> every 256 finalized epochs ≈ 2.8 days) is not operating. **From
> 2026-09-05 07:07:19 UTC, a stranger cannot start a fresh node at all** —
> the node will correctly refuse. Standing up the checkpoint ceremony and a
> publication channel is the single most date-urgent item in §15.

### 6.3 The clock gate

At boot the node compares its clock against the median of the peers **it
dialed** and refuses to start when |median skew| exceeds half an epoch. This
is node-local policy (it cannot cause a fork) aimed at the cheap attack: an
NTP-spoofed or rolled-back clock would otherwise let a fresh node bypass the
weak-subjectivity gate entirely and sync a forged history. If the node
refuses: fix NTP, do not look for an override.

### 6.4 The RPC is unauthenticated — treat a routable bind as an incident

The JSON-RPC surface has **no authentication, no rate limiting, and no
per-method authorisation**, and `sendrawtransaction` is a write. The only
thing that makes this safe is the `127.0.0.1` default bind. This is not
hypothetical hygiene: on 2026-08-30 all 64 fleet nodes were found answering
RPC on routable addresses. Bind loopback; if a remote client must read your
node, put your own authenticating proxy in front. `blochv-health.sh` alarms
CRIT on a wildcard bind (§11).

### 6.5 Supervise it

```ini
[Unit]
Description=Bloch Genesis-4 validator
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bloch
ExecStart=/usr/local/bin/bloch-pos run --data-dir /var/lib/bloch/data …
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Change flags via the unit (or one drop-in), never by hand-launching — the
Genesis-3 fleet became unauditable through stacked drop-ins and ad-hoc
`setsid` launches. One unit, one node, one data dir.

### 6.6 Verify you agree with the network

`getchaininfo` on your node and on a second node you trust:

- same height ⇒ **`state_root` must be identical**;
- `behind_by_slots` 0 or 1 is current;
- `finalized.epoch` advances every epoch or two.

A forked node still answers, still looks locally healthy, and diverges only
under comparison — the 2026-08-30 fork had 15 nodes on one head and 33 alone,
each confident. Settlement is the `finalized: true` boolean on a block, never
a confirmation count; `height` is the number that is *not* the guarantee.

---

## 7. Generate the validator key

On an **air-gapped machine at its console** — not over SSH, not in CI, not in
an AI-agent session (the script refuses all three; that is
`BLOCH-GENESIS-KEYS.md` rule zero):

```sh
tools/validator-ops/blochv-keygen.sh --dir ~/bloch-validator
```

Layout produced: `keys/validator.key` (0600, the hybrid secret + RANDAO
seed), `public/validator.pub.tsv` + `public/MANIFEST` (the only bytes that
may leave the machine — carry these to the online machine), `data/` (becomes
`--data-dir`). Then, before anything else:

1. **Back up `validator.key` to two offline media, two places**, and verify
   each copy's sha256 against `public/MANIFEST`.
2. Generate the **withdrawal key separately and colder** (§2.3). Its 32-byte
   address goes into the deposit and can never be changed.
3. Never let the keystore exist on two machines that could both run a node.

---

## 8. Fund and submit the deposit

> **GAP (G1) — this section cannot be executed on mainnet today.** The
> current `Deposit` transaction (`transition.rs:1977`) carries **no funding
> inputs**: it registers a validator and conjures `amount_sat` into stake
> without debiting anyone's coins. That is safe only while the validator set
> is the closed genesis cohort, so validator entry is **closed** until the
> eUTXO-funded bonding upgrade — deposits and withdrawals with real inputs
> and outputs on the ledger — activates on a flag day. That upgrade, plus
> `Exit`/`Delegate` hardening, is in flight as of 2026-08-31; no activation
> epoch is scheduled yet. Everything below is written against the deposit
> rules that ARE in consensus today, so it becomes executable the day the
> flag day passes.

### 8.1 Getting BLCH

There is no market and no faucet. Stake arrives as a `Transfer` from an
existing holder to your (transparent) address. Deposits must be funded from
**transparent** outputs only — a bond must be attributable for slashing to
mean anything; shielded coins cannot stake without unshielding first.

### 8.2 How much — the cap arithmetic, honestly

A deposit must satisfy `MIN ≤ amount ≤ cap` where MIN = 25,000 BLCH and
cap = **max(1% of committed active stake, 25,000 BLCH)**.

State the scaling fact plainly: **below 2.5M BLCH of total active stake the
1% cap is smaller than the minimum deposit, so the band collapses and every
deposit is forced to be exactly 25,000 BLCH.** Equivalently: with validators
at the minimum bond, the 1% cap is unsatisfiable below 100 validators — the
`max(..., MIN)` floor exists precisely so the bootstrap doesn't deadlock.
If this network ever restarts its stake economy from near zero, expect your
deposit to be exactly 25,000 BLCH, no more, until the set is ~100 strong.

On today's mainnet the genesis cohort already stakes 61,771,071 BLCH, so the
measured band is 25,000 ≤ amount ≤ ~617,710 BLCH. Re-derive it at deposit
time from `getchaininfo.total_active_stake_sat`.

A second deposit for an already-registered pubkey is refused — there is no
top-up path.

### 8.3 What goes into the deposit

Per `PosTransaction::Deposit` and §7.1 of the migration design:

- `pubkey` — your suite-tagged hybrid public key (3,745 bytes of key
  material, from `public/validator.pub.tsv`);
- `amount_sat`;
- `randao_commitment` — `c_0`, the head of your SHAKE-256 reveal chain (in
  the keystore's public row);
- `withdrawal_credentials` — the 32-byte cold address of §7.2, immutable
  forever after;
- `commission_bps` — the commission you will charge delegators, declared
  here and committed by consensus (visible, therefore priced by delegators;
  deliberately uncapped);
- a **proof of possession** signed by BOTH halves of the hybrid key ("AND,
  not OR") over the deposit signing root.

> **GAP (G2).** No tooling constructs, signs, or submits a `Deposit` (or
> `Exit`, or `Delegate`). `bloch-pos submit-tx` deliberately emits `Transfer`
> only. A deposit CLI — build the transaction, produce the PoP signing root
> for offline hybrid signing, attach the funding inputs once G1 lands,
> submit via `sendrawtransaction` — must exist before flag day, or the first
> third-party deposits will be hand-rolled bytes, which is how withdrawal
> credentials get set wrong irreversibly.

### 8.4 The index-binding wrinkle

The keystore records a 4-byte validator index. A genesis-cohort operator knew
theirs; **a deposit-era operator has no index until activation assigns one**
(deterministically: next free index in the registry). Generate the keystore
with the default index 0; the key material is index-independent.

> **GAP (G6).** There is no `bloch-pos` command to rewrite the keystore's
> index after activation, and the node does not discover its index by
> matching its pubkey against the registry. One of the two must ship with
> the G1 flag day; until then a deposit-era operator cannot correctly bind
> the keystore to the assigned index without hex-editing 4 bytes.

---

## 9. Activation, and going live without getting slashed on day one

### 9.1 The queue

After inclusion your deposit waits `ACTIVATION_DELAY_EPOCHS` = 8 epochs
(~2.1 h) and then joins the activation queue, which admits **4 validators per
epoch**. Watch your state move `queued → active`:

```sh
curl -s -X POST http://127.0.0.1:16400 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getvalidator","params":[<index>]}'
```

The queue is a security property, not an inconvenience: it makes buying a
majority take many epochs of publicly visible queue traffic. (Honest limit,
from the spec: it raises the cost and visibility of capture; it does not
prevent it.)

### 9.2 First start with the key — slashing protection

Move the keystore into the data dir only now. The node keeps
`<data-dir>/signing_history.bin` — the highest slot ever proposed and highest
source/target epochs ever attested, fsynced **before** any signature is
released — and refuses to sign at or below those watermarks. A keystore with
no history file **refuses to start** rather than signing blind:

- brand-new key, first start ever: pass `--accept-new-signing-history` once.
  Only if this key has genuinely never signed on this network, anywhere.
- migrated key: **never** pass it — see §12.

### 9.3 The doppelganger watch — and its launch pitfall

On each start (default `--doppelganger-epochs 2`) the node stays **silent for
two epochs**, listening for its own validator index signing elsewhere; if it
hears itself, it shuts down instead of completing the equivocation. Cost:
~32 minutes of missed duties per restart. Two facts to plan around:

- **Coordinated launches:** the watch is skipped only when booting exactly at
  the chain's slot 0. A node booting a *few slots after* genesis — which is
  every real node in a coordinated (re)launch — arms the watch and goes
  silent for two epochs while the network waits for its attestations. A
  coordinated launch must therefore start validators with
  `--doppelganger-epochs 0`, explicitly, as a stated launch-plan decision.
- Solo restarts of one validator: keep the default. The 32 minutes is cheap
  insurance against the one mistake that is both fatal and common.

---

## 10. Duties and rewards

Once active, every validator has duties **every epoch**: committees are a
partition of the active set across the epoch's 32 slots — one attestation per
epoch, and block proposals whenever the stake-weighted sampler draws you
(proposing requires walking your RANDAO reveal chain; that is why the key is
hot). Attestations are admitted only for `{wall_epoch, wall_epoch+1}` — a
node that is behind or clock-skewed produces attestations the network refuses,
which looks in your logs like `Reject`s from peers.

Economics: the validator emission is 42,853,600,000 BLCH over 40 years on a
halving schedule; each epoch's issuance is distributed **pro-rata to active
stake** (the Solana shape — inflation goes to stake, not to block producers;
`rewards.rs`), with your declared commission applied to delegators' shares. Being offline costs you through the
**inactivity leak** — while finality is stalled, non-participating stake
bleeds toward the participating set — so uptime is the whole game. Fees,
during the emission era: half the base fee is burned, the other half and all
priority fees go to the block producer; after emission ends, no burn — every
fee to the producer (`fee_market::split_fees_at`).

---

## 11. Monitor — what to alarm on

```sh
# every minute from a systemd timer; alert on exit code >= 1, page on 2
tools/validator-ops/blochv-health.sh \
  --rpc http://127.0.0.1:16400 \
  --index <your-index> \
  --reference http://<second-node-you-run-or-trust>:16400
```

The five alarms and why exactly these:

1. **Liveness** — RPC answers. A dead validator leaks stake from the first
   missed epoch.
2. **Sync** — `behind_by_slots ≤ 3`. Under PoS this field *is* "am I synced";
   there is no work to infer it from.
3. **Finality advances** — the finalized epoch must move between runs
   (default stall alarm: 60 min). Height rising while finality is stuck is
   the signature of every stall this network has had; height is not the
   guarantee.
4. **Divergence** — same finalized epoch as the reference ⇒ same finalized
   root. **This is the alarm local metrics cannot give you.** A forked node
   answers, attests, and reports itself healthy; only comparison exposes it.
   Run the check against a node in a different failure domain.
5. **Validator state** — `active`, not `slashed` (CRIT: stop the node
   immediately; §14), not unexpectedly `exiting`.

Plus **exposure**: CRIT if the RPC port is listening on a wildcard bind
(§6.4). Log-side, additionally watch for slashing-protection refusals
("refusing to sign") — each one is the protection working and a process
error on your side to find.

---

## 12. Restarts, migration, and moving the key

- **Plain restart, same machine:** just restart the unit.
  `signing_history.bin` and the doppelganger watch cover you. Chain data
  replays from the data dir (~81 ms/block).
- **Migrating to a new machine — the order is the protection:**
  1. stop the old node; **disable the unit** (`systemctl disable --now`) so a
     reboot cannot resurrect it;
  2. `bloch-pos protection-export --data-dir <old> --out history.txt`;
  3. carry keystore + history together; verify the keystore's sha256 against
     `public/MANIFEST`;
  4. `bloch-pos protection-import --data-dir <new> --from history.txt`
     (merging only ever raises watermarks);
  5. start the new node **without** `--accept-new-signing-history`, with the
     doppelganger watch at its default — it is your last line if step 1
     silently failed.
- An empty signing history on a used key is how validators get slashed. When
  in doubt, wait two epochs with the old machine verifiably powered off
  before starting the new one.

---

## 13. Exit and withdraw

Exiting is slow, in two deliberate stages — plan liquidity accordingly:

1. **Exit** (`PosTransaction::Exit`, signed by the validator key): after
   `EXIT_DELAY_EPOCHS` = 32 (~8.5 h) duties stop. The delay exists so an exit
   cannot dodge duties — or slashing for duties already assigned.
2. **Withdrawal**: the stake becomes spendable at the committed withdrawal
   credentials only after `WITHDRAWAL_DELAY_EPOCHS` = 2,048 (~22.8 days).
   This *is* the weak-subjectivity margin — it must outlast the window in
   which your exited key could sign a conflicting history for free —
   shortening it would be a consensus-security decision, not UX.

Keep the node running and monitored until `getvalidator` reports `exited`;
you carry duties (and slashability) through the whole exit delay.

> **GAP (G1/G2, same dependencies as §8).** Today `Exit` reaches consensus
> but no tooling constructs one, and withdrawal cannot pay out at all —
> paying the credentials a real UTXO is part of the funded-bonding upgrade.
> Until its flag day, an exit is a one-way door out of duties with **no
> mechanism returning the stake**. Do not exit before the upgrade activates
> unless you mean exactly that.

---

## 14. Slashing — what an offence costs

Offences: double-signing blocks (equivocation) and contradictory attestations
(Casper surround/double votes). Evidence is a transaction any node can
include, re-verified by every node.

- Base penalty, amplified by **correlation**: your penalty scales 3×
  (`CORRELATION_MULTIPLIER`) with the total stake slashed in the surrounding
  **4,096-epoch window** (~45 days). One clumsy operator alone loses little;
  anything that looks like a coordinated event — including a popular
  misconfigured setup script — is priced as an attack, for everyone caught
  in the window.
- The **whistleblower** (in practice the including proposer) receives
  **1/32** of the slashed amount. Reporting your own offence nets you −31/32:
  still a penalty.
- A slashed validator is removed from every roster immediately and can never
  rejoin with that key. If `blochv-health.sh` ever prints `SLASHED`, stop the
  node; every further signature can only add correlation cost.

---

## 15. The gaps ledger — what a stranger cannot do today, and why

Every item below is a step of this runbook that cannot be completed on
2026-08-31. Each names its blocker. This list is the readiness test; the
runbook is done when this section is empty.

| # | blocked step | what is missing | why / dependency |
|---|---|---|---|
| **G1** | §8, §13 — deposit, funded exit, withdrawal | The eUTXO-funded bonding upgrade. Today's `Deposit` conjures stake with no funding inputs (`transition.rs:1977`) and nothing pays a withdrawal out. | Upgrade + `Exit`/`Delegate` hardening in flight (2026-08-31); **no activation epoch scheduled or announced**. Validator entry is closed until its flag day. |
| **G2** | §8.3, §13 — building the transactions | No tool constructs/signs/submits `Deposit`, `Exit`, or `Delegate`; `submit-tx` emits `Transfer` only; the hybrid PoP has no offline-signing CLI. | Must ship before the G1 flag day or first deposits are hand-rolled bytes with irreversible fields (withdrawal credentials). |
| **G3** | §6.2 — fresh sync after **2026-09-05 07:07:19 UTC** | No weak-subjectivity checkpoint has ever been published; no signer arrangement exists for `--ws-signer-set`; the every-256-epochs ceremony is not operating. | After the date, a fresh node correctly **refuses to sync**. Date-urgent: 5 days from the writing date. |
| **G4** | §6.1 — connecting at all | No published bootstrap peers, no public P2P entry point. Fleet runs the unauthenticated devnet mesh, firewalled to known IPs; the libp2p production transport is built but not deployed. | Joining requires private coordination with an existing operator. Needs the fleet's libp2p migration + published multiaddrs, or a maintained public peer edge. |
| **G5** | §3, §9, §12 — the binary itself | Slashing protection + doppelganger, the clock gate, and the cold-sync replay fix live on unmerged 2026-08-31 branches; no release contains them. | Merge + release + `pos-release-integrity` pass. Until then the shipped binary lacks the safety surface this runbook instructs. |
| **G6** | §8.4 — index binding | No way to bind a deposit-era keystore to its assigned index (no rewrite command, no pubkey→index discovery in the node). | Small, but a validator that cannot identify itself does no duties. Ship with G1. |
| **G7** | §8.1 — acquiring stake | No market, no faucet, no listed venue; supply is concentrated in the founder's carryover. | 25,000 BLCH is obtainable only by private transfer from an existing holder. Economic/legal workstream, not code. |
| **G8** | §8.2 — deposit sizing at low stake | Below 2.5M BLCH total active stake the cap band collapses: every deposit is forced to exactly 25,000 BLCH (1% cap unsatisfiable below ~100 minimum-bond validators). | Consensus constant interaction, known and accepted (`max(…, MIN)` floor); stated so operators size expectations, not a bug to fix silently. |
| **G9** | §6.4, §11 — serving anyone but yourself | RPC has no authentication/rate-limit/authorisation; safe only on loopback. All 64 fleet nodes were exposed on 2026-08-30. | Any multi-tenant or public read service needs an authenticating proxy in front; in-node auth is future work. |
| **G10** | §14 — reporting an offence | Slashing evidence is consensus-valid but has no submission tooling, and its canonical encoding cannot travel through `submit-tx` at all. | The 1/32 whistleblower incentive is real but unreachable for anyone who is not a block proposer with hand-built bytes. |

---

*Written 2026-08-31 against commit `e4083f96` plus the 2026-08-31 integration
branches (sync-stall fix, slashing protection, clock gate). Numbers marked
"measured" are from the live chain on 2026-08-30 and drift; re-derive from
`getchaininfo` before relying on them.*
