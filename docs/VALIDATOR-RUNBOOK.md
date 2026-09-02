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
- **Slashing is specified and correlation-priced, but CANNOT BE APPLIED
  today** (§14). A key-management mistake — the same key live on two machines —
  is indistinguishable from an attack by design, and the schedule prices it 3×
  if others are slashed in the same 4,096-epoch window. That schedule has never
  run: no evidence transaction can reach a verifier on this network (§14.1), so
  every equivocation to date is logged and unpunished. Operate as if the
  penalty were live — it is designed to arrive, arriving is a flag day, and a
  key that equivocated before the flag day is a key you should already have
  retired.
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
20 GB disk per node** - and one validator per failure domain.

The memory number is a **measured limit, not a recommendation**, and it is a
*cold-start* number rather than a steady-state one:

- replaying mainnet history from genesis peaked at **>7.5 GiB RSS** on the
  2026-08 chain and OOM-killed past it;
- on 2026-08-21, 22 fleet validators on 8 GB machines were OOM-killed 55 s
  after boot, at 7.9 GB;
- the fleet's own worst outages were self-inflicted undersizing: five to six
  validators sharing one box's RAM, one alive at a time.

So 8 GB is the floor, and the floor is where the fleet died. A node that runs
happily once synced can still be killed the first time it has to replay from
cold - which is every restart after a long stop. The number also grows with
history: re-measure rather than trusting this line a year from now.

```sh
tools/validator-ops/blochv-preflight.sh \
  --data-dir /var/lib/bloch/data \
  --peers <ip:port,...>
```

What it checks: binary identity and `selfcheck` (SS3); cores, total RAM,
**available** RAM against the measured cold-start peak, and free disk; a
single-core throughput proxy for the ~81 ms/block replay budget (replay is
single-threaded and pins a core - post the 2026-08-31 fix that removed the
per-epoch eUTXO clone, which previously made cold starts unconditionally
fatal); NTP discipline **and a measured clock offset in seconds**; open-file
limits; port hygiene; and **whether this machine can actually open a TCP
connection to a peer**. Exit 0 = proceed, 1 = read the warnings, 2 = do not
deposit from this machine.

Two things the port and clock checks will tell you that are easy to get wrong:

- **RPC port 16400 is also the libp2p transport's default listen port**
  (`/ip4/0.0.0.0/tcp/16400`). The fleet serves RPC there and this runbook
  documents it, but the binary's own RPC default is **16310**. Running
  `--transport libp2p` without moving one of them means one will fail to bind.
- The node's clock gate is **half an epoch - 480 s on mainnet**, symmetric,
  and it refuses to *start* (`ERR_CLOCK_SKEW`). That is a backstop against a
  spoofed clock bypassing the weak-subjectivity gate; it is **not** your duty
  margin. Attestations are admitted only for `{wall_epoch, wall_epoch+1}`, so
  seconds matter long before minutes do - and with zero peer samples the node
  proceeds anyway, loudly. Preflight measures the offset so you find out here.

If your build has it, `bloch-pos doctor` (alias `preflight`) is the better
authority for the machine checks - it reads your real config instead of this
script's guesses - and the shell tool tells you to run it when it is present.
It is absent from the currently released binary.

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

This is the check that has no local symptom, so do it by comparison or not at
all. `blochv-health.sh` automates exactly this; by hand:

- pick a slot a few behind the shallowest head among you and two independent
  nodes, and call `getblockbyslot` on all three. The `block_id` **and**
  `state_root` must be identical. (A slot with no block answers `-32007` -
  that is a missed proposal, not an error; step back a slot and retry.)
- a node whose head is past that slot but which reports *no* canonical block
  there disagrees with you about what is canonical. That is a fork, not lag.
- `finalized.epoch` must advance every epoch or two, and at the same
  `finalized.epoch` your `finalized.root` must match theirs. Two conflicting
  finalized roots at one epoch is a safety failure.

**Do not use `behind_by_slots` for this.** It is `wall_slot - your own head
slot`: a node that forks keeps proposing on its own branch, so its own head
keeps pace with the wall clock and the field reads 0 permanently while it
agrees with nobody. The 2026-08-30 fork had 15 nodes on one head and 33
alone, each confident, each reading behind = 0.

`finalized: true` on a block — never a confirmation count — is the strongest
state this chain reports; `height` is a weaker number still. This paragraph
used to call that boolean "settlement". CORRECTED 2026-09-01: it is not one.
No slashing penalty backs it (§14.1) and it is not a latch. An integrator's
rule is in `docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md` §5.

---

## 7. Generate the keys - two of them, in this order

There are two keys and the difference between them is the whole security
argument. Generate the **withdrawal** key first, because the validator tool
refuses to run without its credentials.

**Step 1 - on a cold machine that never goes online:**

```sh
tools/validator-ops/blochv-keygen.sh \
  --role withdrawal --dir /media/cold/bloch-withdrawal
```

It prints 32 bytes: `withdrawal_credentials`. Those bytes are public - carry
them freely. The key behind them must never follow.

**Step 2 - on an air-gapped machine at its console** (not over SSH, not in
CI, not in an AI-agent session; the script refuses all three, which is
`BLOCH-GENESIS-KEYS.md` rule zero):

```sh
tools/validator-ops/blochv-keygen.sh \
  --role validator --dir ~/bloch-validator \
  --withdrawal-credentials <64-hex from step 1>
```

Layout produced: `keys/validator.key` (0600, the hybrid secret + RANDAO
seed), `public/pubkey.tsv`, `public/DEPOSIT-FIELDS`, `public/MANIFEST` (the
only bytes that may leave the machine), `data/` (becomes `--data-dir`).

**Why the tool refuses things.** The validator key is hot by construction -
the node holds it unlocked to attest every epoch and to walk the RANDAO chain
when it proposes - so assume a machine compromise is a compromise of that key.
The withdrawal credentials are the one thing a stolen hot key must not be able
to redirect, and the deposit makes them immutable *forever*. That property
only holds if the two keys are genuinely different, so the script refuses:

- **W3** - withdrawal credentials equal to the validator key's own script
  hash. That would make the hot key and the withdrawal path the same secret,
  and the deposit's one-way door would be protecting the thief instead of you.
  It is the one mistake here that cannot be fixed afterwards: not by exiting,
  not by re-depositing.
- **W2** - missing, malformed, or all-zero credentials, checked *before* any
  key material is generated.
- **S1/S2** - a target on network or shared storage (two machines that can
  mount one key can both run it - that is slashable equivocation), or on
  tmpfs or under `/tmp` (a key that evaporates on reboot leaves activated
  stake that can never do duties again).
- **S3/S4** - a group- or world-writable ancestor directory, or a umask that
  would create the key readable by others.
- **K1** - overwriting an existing keystore. Ever.

No key material is printed, echoed, stored in a shell variable, or passed as
an argument; only public halves are ever read back.

**No hardware wallet can hold either key.** The suite is hybrid ML-DSA-65 ||
Falcon-1024 (secret ~6.3 KB). No shipping HSM, Ledger, Trezor, or cloud KMS
signs either algorithm. Custody is *file* custody: this layout, these
permissions, and the backup below are the entire plan.

Then, before anything else:

1. **Back up `validator.key` to two offline media, two places**, and verify
   each copy's sha256 against `public/MANIFEST`. There is no recovery phrase.
2. Re-read the withdrawal credentials in `DEPOSIT-FIELDS` character by
   character against the cold machine's `WITHDRAWAL-CREDENTIALS` file.
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

Run the guard first. It is the only tool here whose failure mode costs money
rather than uptime:

```sh
tools/validator-ops/blochv-guard.sh \
  --data-dir /var/lib/bloch/data \
  --rpc http://127.0.0.1:16400 \
  --doppelganger-epochs 2
```

It refuses to bless a start when: the keystore or data dir is group/world
readable; the data dir is on network or shared storage that a second machine
could mount; the signing history binds a *different* public key than the
keystore beside it (the classic migration error); another process already
holds the data dir; the doppelganger watch is being disabled without an
explicit coordinated-launch acknowledgement; or — the check that matters most
— **the chain says this validator is already `active` while this machine has
no signing history**, which is exactly the situation in which
`--accept-new-signing-history` would be a false claim.


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
  --reference http://<a-node-someone-else-runs>:16400 \
  --reference http://<a-second-independent-node>:16400
```

**Two references are mandatory and the tool refuses to print OK without
them.** This is not caution, it is the shape of the failure: `behind_by_slots`
is `wall_slot - your own head slot`. A node that forks keeps proposing on its
own branch, so its own head keeps pace with the wall clock and that field
reads 0 — permanently, while it agrees with nobody. On 2026-08-30, 15 fleet
nodes sat on one head and 33 sat alone, and every one of them was healthy by
its own numbers. Divergence has no local symptom. Only comparison has one.

"Independent" means a different operator, host and network path. Three nodes
you run in one rack are one reference wearing three hats: they will agree with
each other while all three are wrong.

The alarms, and why exactly these:

1. **Liveness** — RPC answers. A dead validator leaks stake from the first
   missed epoch, and the leak is not refunded.
2. **Agreement** — at a common anchor slot a few behind the shallowest head,
   your `block_id` **and** `state_root` must equal the reference majority's.
   The anchor steps back over empty slots (a slot with no block is a missed
   proposal, not a fault) until every endpoint can answer the same one. A
   reference whose head is past that slot but which reports *no* canonical
   block there is also divergence, not lag. If the references disagree among
   *themselves*, the network is partitioned and no verdict about your node
   alone is available — the tool says so rather than picking a winner.
3. **Lag** — your head slot against the reference majority's, not against
   your own clock. Being behind and being forked are different incidents with
   different responses.
4. **Finality advances** — the finalized epoch must move between runs
   (default stall alarm: 60 min), and your finalized root must match the
   references' at the same finalized epoch. Two conflicting finalized roots at
   one epoch is a safety failure, not a lag problem. Height rising while
   finality is stuck is the signature of every stall this network has had.
5. **Validator state** — `active`, `slashed: false` (CRIT: stop the node
   immediately; §14), not unexpectedly `exiting`.
6. **Exposure** — CRIT if the RPC port is on a wildcard bind (§6.4).

`behind_by_slots` is still printed, as an advisory line that says what it
actually measures. It is never allowed to produce an OK verdict by itself.

Log-side, additionally watch for slashing-protection refusals ("refusing to
sign") — each one is the protection working and a process error on your side
to find.

> **Field-name note.** `getvalidator` returns `state` and a separate `slashed`
> boolean — not `status`. The richer `getvalidatorstatus` (which exposes the
> signing guard's watermarks and the doppelganger state directly) exists in
> the observability branch but is **not** in the binary the live fleet runs
> today; `blochv-health.sh` uses `getvalidator` so it works against both.

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
  4b. `blochv-guard.sh --data-dir <new> --migration` — it hard-refuses a
     migration with no signing history in the destination, and refuses a
     history that binds a *different* public key than the keystore beside it,
     which is the way the right key gets carried with the wrong history file;
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

## 14. Slashing — what an offence is specified to cost

Offences: double-signing blocks (equivocation) and contradictory attestations
(Casper surround/double votes). Everything in this section is the **designed**
schedule. Read §14.1 first: none of it can be applied on the network as it runs
today.

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

### 14.1 None of §14 is enforceable today — CORRECTED 2026-09-01

This section used to open "Evidence is a transaction any node can include,
re-verified by every node." **No node can include it.** Four independent
breaks, any one sufficient:

1. Evidence carries wire tag `0x05`, and
   `PosTransaction::from_canonical_bytes` returns
   `TxDecodeError::EvidenceNotDecodable` for it unconditionally, with no gate.
   The encoder folds the two nested messages in as the *signing roots* they
   were signed over — hashes — so the envelopes are unrecoverable by
   construction. The codec documents this as deliberate.
2. That decoder is the only one on every ingress path: block body, gossip, and
   `sendrawtransaction`. So a block carrying evidence is rejected by every
   peer, and a proposer who hand-built the bytes would produce a block nobody
   can import — which is why G10 below is stronger than "no tooling".
3. Nothing constructs the transaction outside tests. The node detects
   equivocation and prints `EQUIVOCATION captured: … (slashing pipeline NOT
   wired — evidence is logged, not prosecuted)`.
4. There is no activation constant to arm: `SLASHING_EVIDENCE_ACTIVATION_EPOCH`
   does not exist in the repository.

Measured on the live chain at epoch 1726, from two archivals agreeing on head
and root: 64 validators, 64 active, every record `slashed: false` and
`exit_epoch: null`. Equivocation on this fleet is *detected* — the node captures each pair and logs it — and none of it has ever been prosecuted. (A figure of 48 double-signing validators has been reported internally; no RPC exposes equivocation history, so this note does not re-derive it, and the conclusion does not rest on the number.) `slashing.rs` is complete and correct;
nothing can reach it.

Two consequences an operator must hold at once:

- **Do not relax key hygiene.** Enforcement is a flag day away, the evidence
  is already on chain and permanent, and a §7.3 wire shape that carries whole
  envelopes would make historical offences prosecutable in principle. Treat
  every equivocation as a permanently retired key.
- **Do not price your risk off §14 either.** Nobody has been slashed and
  nobody can be, so the correlation window and the 1/32 whistleblower reward
  are schedules, not experience.

This subsection is deleted when the §7.3 path is reachable and armed.

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
| **G10** | §14 — reporting an offence | **Slashing cannot be applied at all** (§14.1). Evidence is consensus-valid *inside* `apply_slashing_evidence`, but wire tag `0x05` is undecodable on every ingress path by construction, nothing builds the transaction outside tests, and no activation constant exists. | Not a tooling gap. A block proposer with hand-built bytes cannot do it either — the block would be unimportable by every peer. Needs a new §7.3 wire shape carrying both envelopes whole, then a flag day. Until then the 1/32 whistleblower incentive is unreachable by anyone, and `slashed: false` on all 64 records is the expected reading, not a healthy one. |
| **G11** | §5, §6 — the RPC port | The runbook, the fleet and the tooling use **16400** for RPC; the binary's `DEFAULT_RPC_PORT` is **16310**, and 16400 is the libp2p transport's default *listen* port. An operator following this document with `--transport libp2p` gets a bind conflict. | Cosmetic to fix (move one default, or document one number), load-bearing to get wrong at 03:00. `blochv-preflight.sh` warns on the collision rather than letting you discover it. |
| **G12** | §11 — richer health | `getvalidatorstatus`, `getmetrics`, `/metrics` and `/health` — which expose the signing-guard watermarks and the doppelganger state directly — exist in the observability branch but **not in the binary the live fleet runs** (verified against a fleet node on 2026-08-31: `method not found`). | Same dependency as G5: merge + release. Until then the tooling reads `getvalidator` only, and the doppelganger/slashing state is observable on disk and in logs, not over RPC. |
| **G13** | §9.2 — proving a key is unused | `blochv-guard.sh` refuses `--accept-new-signing-history` when the chain says the validator is already `active`, which catches the common case. It cannot prove the *negative*: a key that signed and then had its history lost, on a validator not yet activated, still looks new. | No protocol mechanism attests "this key has never signed". The residual risk is carried by operator discipline (disable the old unit, not just stop it) and by the doppelganger watch. |

---

*Written 2026-08-31 against commit `e4083f96` plus the 2026-08-31 integration
branches (sync-stall fix, slashing protection, clock gate, operator
observability). Numbers marked "measured" are from the live chain on
2026-08-30/31 and drift; re-derive from `getchaininfo` before relying on
them. RPC field names and error codes in this document were verified
against a live Genesis-4 fleet node on 2026-08-31.*
