# Becoming a Bloch Genesis-4 validator — the newcomer's road

Written against tag **`g4-node-20260901`** (`7a83ca89`), the release lineage.
Everything below was walked, not imagined. Where the road ends, it says so and
names the file and line that ends it.

**Read [§1](#1-the-short-version) before you spend money or time.** The road
does not currently reach the end.

---

## 1. The short version

You can build the node, get the genesis files, sync from the public bootnodes,
and run an **observer** that follows the chain and serves RPC. That part works
and is documented in `docs/THIRD-PARTY-QUICKSTART.md`, which is the right
document for it and which this one does not duplicate.

You **cannot** become a validator. Not "it is hard", not "it needs a form" —
the node refuses the transaction:

```
crates/bloch-pos-node/src/engine.rs:3220   admissible()
    PosTransaction::Deposit { .. } => Err(
        "deposits are not accepted: bonding is not yet funded from the UTXO set,
         so a deposit would create stake without spending coins",
    ),
```

`admissible()` is called from `on_transaction` (`engine.rs:1787`), which is the
single admission path for **both** the RPC `sendrawtransaction` and peer gossip
(that unification is deliberate — a second path with its own checks is the
defect the module docs call "the `expected_bits` defect with a URL in front of
it"). `Delegate` (`0x04`) and `Exit` (`0x03`) are refused in the same function.
Only `Transfer` and `TransferV2` are admitted.

So the validator set is the 64 it launched with, and nothing a stranger can
send changes that.

### Why it is closed, which is the part worth understanding

The refusal is not bureaucratic. At the tag, `PosTransaction::Deposit`
(wire tag `0x02`) **spends nothing**. Its apply arm
(`crates/bloch-pos-committee/src/transition.rs:2049`) checks exactly three
things — the key is not already registered, the amount is at least
`MIN_DEPOSIT_SAT`, and the amount is at most 1% of committed active stake —
and then registers a validator holding that stake. It consumes no inputs. It
never calls `staking::validate_deposit`, so the proof of possession is never
verified.

Stake is therefore **minted from nothing, by unauthenticated request**. The
node's own comment prices the attack: 25,000 BLCH per request, "roughly
forty-six requests to a third of the active stake and stop finality, a hundred
and eighty to two thirds and take the chain."

The mempool refusal is a node-side patch over that hole. It is explicitly
**not** a consensus rule — a block that already carries a deposit still
applies it — so it closes the path anyone can reach, and nothing more.

---

## 2. What you would be signing up for, stated as fact

These are properties of the shipped lineage, not warnings, and each is
checkable at the tag.

- **A bond is one-way.** There is no `Withdraw` transaction on this lineage.
  `PosTransaction` has five variants and none of them returns stake.
  `staking::validate_withdrawal` exists as pure math with no production caller.

- **An exit carries no signature.** `PosTransaction::Exit` is
  `{ validator: u32 }` and nothing else. Its transition arm checks the registry
  and the clock, never authorisation. If the mempool refusal were lifted
  without fixing this, any stranger could exit any validator, or all 64.
  (`engine.rs:3382` refuses it today for exactly this reason.)

- **There is no anti-double-sign protection worth the name.** No slashing
  protection database, and no `flock`, lock file, or exclusion of any kind on
  the keystore or the data directory — `git grep` at the tag finds none. The
  only thing keeping a node from signing a slot twice is two local variables,
  `last_attested` and `last_built` (`engine.rs:2969-2970`), **both initialized
  from the head slot on every process start** and consulted at `:3011-3018`.
  A second process does not share them and a restart resets them; the only
  other guard is a two-slot boot grace, which is a heuristic, not a fence. The node's own comment on observer mode names the hazard:
  pointing a second process at "a spare copy of a validator's keystore ... is
  how you equivocate and get slashed. There is no safe version of that."
  Running two processes against one data directory produced **five real
  proposer equivocations** on the published binary. Nothing stops you doing it
  by accident; a restart script that does not wait for the old process to die
  is enough.

- **The node never tells you it is behind.** No log line, no error. The only
  signal is `behind_by_slots` in `getchaininfo` — a field you must poll — and
  during the ~21-minute cold replay the node **stops answering RPC entirely**,
  because RPC competes with the replay thread. For roughly 20 of those 21
  minutes the one documented way to discover you are behind returns nothing.
  Watch the process (RSS, CPU) and the `applied` log lines instead.

- **`--transport libp2p` does not work**, despite the built-in help calling it
  "the production stack". It finds no peers and then builds its own chain while
  cheerfully printing `applied` and `finalized`. Use `--transport devnet`,
  which is what all 63 fleet validators and both archival nodes run. Note what
  that means: the live transport has **no authentication and no admission
  control**, so a routable bind must be firewalled to known peers.

- **A finalized checkpoint is not yet a single global fact.** Under partition
  the two-thirds test is measured against a total already reduced by the
  inactivity leak, and that denominator can shrink to fit the minority a node
  still hears. Three disjoint partitions of four validators each finalized
  epoch 25 under three different roots. The cure exists and is **not armed**
  (`LEAK_RECOVERY_ACTIVATION_EPOCH = u64::MAX`).

---

## 3. The clock

**2026-09-05 07:07 UTC.** A node whose first sync begins after that instant
refuses to sync at all, with `ERR_WS_REQUIRE_CHECKPOINT`, and needs a signed
weak-subjectivity checkpoint to start. **No signed checkpoint is published.**

The deadline is derived, not chosen:

```
WS_PERIOD_EPOCHS = WITHDRAWAL_DELAY_EPOCHS − EXIT_DELAY_EPOCHS = 2048 − 32 = 2016
                                            (crates/bloch-pos-committee/src/ws.rs:140)
epoch 2016 begins at slot 2016 × 32 = 64512
genesis 2026-08-13 21:31:4x UTC + 64512 × 30 s   →   2026-09-05 07:07 UTC
```

Verified against the live chain on 2026-09-02 (wall slot 56961, epoch 1779):
the computed instant lands within 23 seconds of the figure in circulation, the
difference being slot-boundary rounding. Before the deadline a fresh node
anchors on genesis and syncs unaided; after it, the genesis anchor is older
than the window and is no longer a defense, because validators who exited and
withdrew can sign a complete forged history for free.

**This is a hard gate on newcomers specifically.** Existing nodes have their
own recent finalized history and are unaffected. It closes the door on exactly
the population this runbook is for, in under three days from writing.

---

## 4. Hardware and time

One measurement, from `genesis/README.md` at the tag, with its box beside it —
it is evidence, not coverage:

| | |
|---|---|
| Box | idle 2-vCPU / 7.9 GB Linux |
| Build | release |
| Sync | from genesis, dialling the two published bootnodes |
| Result | `behind_by_slots` reached 0 in **21.2 minutes** at height 33,602 |
| Peak RSS | **934 MB** |
| Measured | 2026-09-01 |

Caveats the source states itself: it is **one run on one machine**; there is no
test anywhere for `get_blocks`, `needs_sync`, or the devnet backfill path; and
the only cold-start test (`crates/bloch-pos-node/tests/cold_start.rs`) exercises
`libp2p` — not the transport the fleet runs — asserts three blocks rather than a
completed sync, and is documented in its own comments as flaky.

Budget disk for the build, not just the chain: a debug build of the node plus
its dependency graph is several GB.

---

## 5. The road, step by step

Placeholders in `<angle brackets>`. **Use disposable keys for every rehearsal.**

### Step 1 — Build  ✅ verified

```sh
cargo build --release -p bloch-pos-node
```

Verify what you built against what was published: `deploy/RELEASE-INTEGRITY.md`.

### Step 2 — Get the genesis files  ✅ verified

Both are needed; neither is useful alone.

```
genesis/mainnet.manifest    247514 bytes
  SHA-256  7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd
carryover.tsv.gz            (decompress first; the loader reads TSV)
```

The manifest commits to the carryover **by digest**, and the loader checks all
four of its fields — file digest, set root, count and total — before admitting
a single balance. A node that hashes to a different manifest digest is on a
different network, which is why the file is published rather than described.

### Step 3 — Run a node  ✅ verified locally; not run against the bootnodes

A data directory with **no `validator.key`** runs in observer mode: it follows
the chain, serves RPC, and signs nothing.

```sh
bloch-pos run \
  --data-dir  <data-dir> \
  --genesis   <path>/mainnet.manifest \
  --carryover <path>/carryover.tsv \
  --transport devnet \
  --peers     139.180.166.5:19100,139.180.173.231:19100 \
  --rpc-port  <port>
```

Those two bootnodes are keyless **archival observers** run by Postern Labs —
the correct thing for a third party to peer with. Validator addresses are never
published: on an unauthenticated transport a validator address is a push
surface into consensus, and on 2026-08-09 one stale node dumped 1,270 old
blocks and stopped block production across the entire network.

They are independent **leaves** — each dials the 63 validators outbound, no
validator dials them, and they do not dial each other. So publishing both is
redundancy *for you*, not mutual reinforcement, and neither can cover for the
other's rot. Your node follows by **pulling**; expect to sit 0–2 slots behind
the head rather than exactly at it.

**Never expose the RPC.** It has no authentication, no rate limit and no
per-method authorisation. Bind it to `127.0.0.1`.

### Step 4 — Generate a validator key  ✅ verified (devnet keys only)

```sh
bloch-pos keygen --dir <keystore-dir> --index <i>
```

Writes `<keystore-dir>/validator.key`, mode 0600: a hybrid ML-DSA-65 ‖
Falcon-1024 keypair plus a 32-byte RANDAO seed. The built-in help calls these
**throwaway devnet keys**; production keys follow `BLOCH-GENESIS-KEYS.md`.

The public halves — and only those — leave an air-gapped machine:

```sh
bloch-pos keygen-public --dir <keystore-dir>
```

That prints `index`, hybrid public key, and RANDAO commitment. It deliberately
leaves `stake_sat`, `withdrawal_credentials` and `commission_bps` **empty**:
they are decisions, not derivations. Step 5 is where you make them.

### Step 5 — Derive your identity and credentials  ✅ verified

**This is where a stranger loses money.** Four facts, each verified at the tag:

1. **Identity is `SHA3-256(pubkey)`, 32 bytes.** That one digest is three
   things at once: the registry's key for your validator
   (`transition.rs`, `pubkey_hash`), the **native** `script_hash`, and — via
   its first 20 bytes — your address.

2. **The 20-byte form is `SHA3-256(pubkey)[..20]`.** It is **not** Bitcoin's
   `hash160`. There is no RIPEMD160 anywhere on this path. A signer that
   reaches for `hash160` derives a different address and the chain will never
   pay it. (`crates/bloch-crypto/src/address.rs:56`)

3. **`bloch1q…` is not bech32.** It is a literal prefix plus 48 hex characters:
   `hex(hash20 ‖ checksum4)`, checksum `SHA3-256(SHA3-256(hash20))[0..4]`.
   No error correction — a typo is simply a different address.

4. **The checksum does not cover the network prefix.** It is computed over the
   20-byte hash alone. **A mainnet payload therefore parses cleanly as a
   testnet address and vice versa**, and nothing downstream catches it.
   Demonstrated, not asserted — the identical 48 hex characters under both
   prefixes both validate and yield the identical `hash20`:

   ```
   bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073   → valid, mainnet
   bloch1te986db5149cff7499b282a048272a09aff0af4ff84242073   → valid, testnet
   both → hash20 e986db5149cff7499b282a048272a09aff0af4ff
   ```

   `bloch-onboard` therefore **requires** `--network` explicitly and has no
   default, and refuses when the prefix disagrees with it.

**The derivation is confirmed against the live chain, end to end.** Validator
0's public key was read out of the published `genesis/mainnet.manifest` (offset
84, 3,749 bytes) and hashed:

```
SHA3-256(pubkey)  f396b7333e20dc1c449f6c25baed028ce4c297db12f32f30957e4b07ffccddc1
getvalidator(0)   f396b7333e20dc1c449f6c25baed028ce4c297db12f32f30957e4b07ffccddc1   ✓
hash20            f396b7333e20dc1c449f6c25baed028ce4c297db
address           bloch1qf396b7333e20dc1c449f6c25baed028ce4c297db4d5c1919
script_hash carried  f396b7333e20dc1c449f6c25baed028ce4c297db000000000000000000000000
```

Two things this pins. The hash is taken over the **suite-enveloped** key — all
3,749 bytes, whose first four are `b1 0c 01 00` (frame magic `0xb10c`, suite
`0x0001`) — not over the bare 3,745-byte hybrid key. And the manifest in the
repository is demonstrably the one the live fleet booted from, since a key read
out of it matches what the chain reports today.

```sh
bloch-onboard identity    --keystore <keystore-dir> --network <mainnet|testnet>
bloch-onboard credentials --address  <bloch1…>      --network <mainnet|testnet>
```

**The two `script_hash` forms.** `transition::owns` (`transition.rs:1433`)
opens an output two ways, and both are derived from the same digest:

- **native** — all 32 bytes equal `SHA3-256(pubkey)`. Every output a Genesis-4
  transaction creates.
- **carried** — first 20 bytes match and the last 12 are zero. Balances minted
  under the Genesis-3 convention. 160 bits of preimage resistance instead of
  256 — exactly what those coins already had, but the two tiers are real and
  the weaker one is the older one.

Both are spendable by the same key, but they are **different 32-byte values**,
so they are different destinations. `bloch-onboard identity` prints both, so
you choose rather than guess.

### Step 6 — Construct the deposit  ✅ verified (the bytes are correct)

```sh
bloch-onboard deposit \
  --keystore            <keystore-dir> \
  --network             <mainnet|testnet> \
  --amount-sat          <n> \
  --withdrawal-address  <bloch1…> \
  --commission-bps      <n>
```

Emits the canonical `PosTransaction::Deposit` bytes (wire tag `0x02`),
round-tripped through the real decoder before you are handed them, plus a
proof of possession over `staking::DepositTx::signing_root` which the tool
signs and then verifies against your own public key before printing.

Bounds, as consensus applies them:

| | |
|---|---|
| `MIN_DEPOSIT_SAT` | 2,500,000,000,000 sat = 25,000 BLCH |
| maximum | 1% of committed active stake, floored at the minimum |
| on 2026-09-02 | active stake 14,429,690,880,268,813 sat → cap ≈ 144,296,908,802,688 sat |
| `ACTIVATION_DELAY_EPOCHS` | 8 |
| `MAX_ACTIVATIONS_PER_EPOCH` | 4 |

The maximum is a function of live chain state, so it cannot be checked offline
and the tool does not pretend to; it reports the rule.

Three things consensus does **not** check, which the tool checks for you,
because a value committed to state wrongly is unfixable without a withdrawal
path that does not exist:

- **the public key.** The `0x02` arm accepts any byte string. Its own test
  registers `vec![0xAA; 8]` — eight bytes — and activates it. Such a validator
  could never sign a block.
- **the withdrawal credentials' width.** `ValidatorRecord::withdrawal_credentials`
  is an unvalidated `Vec<u8>` whose own doc comment calls the width an open
  point; the `0x02` test stores 4 bytes. The tool enforces 32.
- **the proof of possession.** Never verified by the released apply arm.

> **Correction to a fact in circulation:** it is *not* true that
> `withdrawal_credentials` "must already be the 32-byte script-hash form" on
> this lineage. Nothing enforces it. There are in fact **two different
> `DepositTx` types shipping at the tag** — `staking::DepositTx`, whose
> `withdrawal_addr` is a fixed `[u8; 32]`, and `interfaces::DepositTx`, whose
> `withdrawal_credentials` is an opaque `Vec<u8>` documented as an open point.
> Only `staking::DepositTx` is re-exported at the crate root (`lib.rs:152`);
> the other is reachable as `bloch_pos_committee::interfaces::DepositTx`. Only
> the fixed-width one has a signing root, so it is the only one a signature can
> bind to — reach for the wrong one and there is nothing to sign. 32 bytes is
> the right thing to write; the chain simply will not make you.

### Step 7 — Submit it  ❌ **THE ROAD ENDS HERE**

This was executed, not inferred. A node was built from the tag, given a
four-validator devnet genesis and a disposable key, and started locally; the
3,854-byte deposit from step 6 was submitted to it over
`sendrawtransaction`:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32008,"message":
 "deposits are not accepted: bonding is not yet funded from the UTXO set,
  so a deposit would create stake without spending coins
  — this transaction cannot be admitted; retrying the same bytes will not help"}}
```

The node was healthy in every other respect at that moment — `getvalidatorcount`
returned `{"total":4,"active":4}` and `getmempoolinfo` answered normally — so
the refusal is the deposit, not the node.

Note the tail of the message: **"retrying the same bytes will not help."** The
refusal is permanent and deterministic, not a rate limit or a transient. There
is no way to submit a deposit to any node running the released binary;
`sendrawtransaction` and gossip both reach `on_transaction` → `admissible()`.

`bloch-onboard` prints `"submittable": false` and this refusal string rather
than a `curl` line that would fail.

### Step 8 — Watch for activation  ⚠ the instrument works, there is nothing to watch

The RPC for this **does** exist and answers correctly — it is only the deposit
that never lands. `getvalidator` is how you would watch:

```sh
curl -s -X POST http://127.0.0.1:<rpc> -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getvalidator","params":[<index>]}'
```

Verified against the live chain on 2026-09-02, index 0:

```json
{"index":0,"pubkey_hash":"f396b733…","pubkey_bytes":3749,"state":"active",
 "own_stake_sat":"487669230338794","effective_stake_sat":"239080924654617",
 "commission_bps":"0","slashed":false,
 "activation_epoch":0,"exit_epoch":null,"withdrawable_epoch":null}
```

Match on `pubkey_hash` — it is the `SHA3-256(pubkey)` from step 5, and it is the
only field that ties the registry entry to your key. Note `pubkey_bytes: 3749`,
not 3745: the stored key is **suite-enveloped**, four bytes ahead of the bare
hybrid key. `bloch-onboard` accepts either form and strips the envelope before
hashing.

Had a deposit applied, the path would be `deposit_queue` →
`ACTIVATION_DELAY_EPOCHS` (8) → the activation queue, which admits at most
`MAX_ACTIVATIONS_PER_EPOCH` (4) per epoch, at which point `activation_epoch`
stops being `u64::MAX` and `state` becomes `active`.

An index that is not registered gives a clean error rather than a silence,
which is the right behaviour for a poller:

```json
{"code":-32001,"message":"validator 64 is not in the committed registry (64 registered)"}
```

Today every newcomer's index is that error, because the registry is the 64 it
launched with.

### Step 9 — Confirm you are attesting  ❌ unreachable, and uninstrumented

Not reached. Worse, there is no instrument for it even in principle:
`getvalidator` reports `state`, stake and the lifecycle epochs, but **nothing
on this RPC surface reports whether a validator is actually attesting** — no
participation record, no last-seen slot, no per-validator liveness. The full
method set at the tag is `getchaininfo`, `getblockcount`, `getblockbyslot`,
`getblockbyid`, `getvalidator`, `getvalidatorcount`, `getbalance`, `gettxout`,
`getutxos`/`listunspent`, `getmempoolinfo`, `sendrawtransaction`
(`gettransaction` and `getnewaddress` exist only to return errors).

So "am I attesting?" is answered by reading your own logs, and "is my validator
being counted?" is answered by watching `effective_stake_sat` move — not by
asking the node a question shaped like the one you have.

---

## 6. What has to land before this road opens

In dependency order. Numbers 1 and 2 are the hard gates.

1. **A funded, authenticated deposit.** A transaction variant that carries
   inputs (`Vec<UtxoRef>`), the hybrid proof of possession, and 32-byte
   withdrawal credentials; an apply arm that calls `staking::validate_deposit`
   **and debits the inputs**; an epoch-gated activation constant sitting at
   `u64::MAX` until a flag day is armed. Work on this exists off the release
   lineage as `DepositV2`.

   **Wire tag: unassigned, deliberately, and the mess is worse than it looks.**
   `0x01`–`0x06` are taken at the tag (`0x01` Transfer, `0x02` Deposit, `0x03`
   Exit, `0x04` Delegate, `0x05` SlashingEvidence, `0x06` TransferV2), leaving
   `0x07`–`0x09` free **on the release lineage only**. Off-lineage, a survey of
   all 1,321 refs found `0x07` carrying **four different meanings** —
   `DepositV2`, `FundedDeposit`, `DepositFunded`, and `SignedExit` — and
   `0x08`/`0x09` swapping `Withdraw` against `ExitV2`/`SignedExit` between two
   lineages that were *both* still being committed to on 2026-09-02. Even
   `0x06` is not safe: one branch (`090fb32c`) assigns it `FundedDeposit`.

   Concretely: a deposit built by the `staking-cli` on `validator-ops`
   (`0x07 = DepositV2`) would decode as a **different transaction type** on
   `demo/final-writeoff-ruled` (`0x07 = FundedDeposit`). Every one of these
   formats is inert behind a `u64::MAX` flag day, so renumbering is free
   **today** and stops being free the moment any flag day is armed. The number
   is the founder's to pick. Guessing it is a chain split.

2. **A signed weak-subjectivity checkpoint, before 2026-09-05 07:07 UTC.**
   The verifier exists (`ws.rs`, `ws_boot.rs`); there is no tool that signs
   one. After the deadline, every newcomer needs an artifact nobody can
   currently produce.

3. **An authenticated exit.** `ExitTx` and its signing root exist in the
   consensus crate; **no `PosTransaction` variant carries an `ExitTx`**, so a
   signed exit has nothing to travel in. That single missing carrier is the
   whole distance between "signed exit exists" and "signed exit reaches a
   block".

4. **A withdrawal path.** `validate_withdrawal` is pure math with no
   production caller. Until it has one, a bond is one-way, and step 5's
   credentials are written to state without anything ever reading them.

5. **Slashing protection on disk, and a lock on the data directory.** Two local
   variables and no mutual exclusion is not protection; it is a convention that
   a second process ignores.

   **Both halves already exist off the lineage, and neither has landed.** A
   persistent signing history (`signing_history.bin`, magic `BSIGHIS1`) is on
   ~67 trees including the tip of `validator-ops`. And the real fence —
   `crates/bloch-pos-node/src/slashdb.rs`, which takes
   `flock(LOCK_EX | LOCK_NB)` on the data directory, persists its marks with
   `fsync` *before* the signing closure runs, and refuses to sign when it
   cannot persist — exists on **exactly one commit in the repository**,
   `59984eea` (`safety/slashing-protection`, 2026-09-02). Its own commit
   subject calls it *"proposta, nao aplicada"* — proposed, not applied. It is
   the only `flock` anywhere in the repository.

6. **`tools/staking-cli` into the workspace.** It already implements the
   funded, authenticated lifecycle and is the tool that should survive. It is
   not a workspace member and does not compile against the release lineage —
   see [§7](#7-tooling-what-exists).

---

## 7. Tooling: what exists

**`tools/staking-cli`** (binary `bloch-stake`) — plan/sign/broadcast for funded
deposit, signed exit, funded delegation and the withdrawal crank. It is **in
the repository** (on 131 of 1,321 refs), is **absent from the release
lineage**, and **does not compile** against the tag: it imports seven symbols
the released consensus crate does not define —

```
staking::parse_framed_pubkey          staking::FRAMED_HYBRID_PK_BYTES
staking::validate_deposit_fields      transition::deposit_cap_sat
params::DEPOSIT_FUNDING_ACTIVATION_EPOCH   params::SIGNED_EXIT_ACTIVATION_EPOCH
params::FUNDED_STAKING_ACTIVATION_EPOCH    params::WITHDRAWAL_ACTIVATION_EPOCH
```

Two things a survey of all refs turned up that matter for landing it:

- It is **not** frozen at one version. The newest `staking-cli`,
  `validator-ops` and `VALIDATOR-RUNBOOK.md` are on the tip of the
  `validator-ops` branch (2026-09-02), not on the older commit that first
  introduced them. Anyone landing this should take the tip, not the first
  copy they find.
- It appears in the root `Cargo.toml` `members` list on **exactly one ref in
  the repository** (`e2280ab4`, `wt/withdraw-refusals`). Everywhere else —
  including `validator-ops` and the tag — it is invisible to
  `cargo build --workspace`, which is precisely the failure mode the
  workspace manifest's own comment warns about: *"that is how the entire PoS
  consensus once went untested at the root."*

It is the right tool and it should land with the streams it was written
against. It is not a substitute for anything below, and nothing below is a
substitute for it.

**`tools/validator-onboard`** (binary `bloch-onboard`) — this directory. It
exists only because the above does not compile today. It builds against the
release lineage as shipped, and it covers exactly steps 5 and 6: derive the
identity and address material correctly, and construct the `0x02` deposit with
the checks consensus omits. It refuses to invent the funded format and refuses
to assign it a wire tag.

---

## 7b. Provenance — what was run, and what is relayed

A runbook that does not say which of its steps its author actually executed is
a wish list. This one separates them.

**Executed for this document, on 2026-09-02:**

- The all-refs survey of `tools/staking-cli` (131 of 1,321 refs) and its
  compile against the tag — the seven missing symbols in §7 are the compiler's
  output, not a reading of the source.
- `bloch-onboard` built against the tag and every violation in §8 run.
- Steps 5 and 6 in full, including the cross-check of the derivation against
  the live registry (§5) and the address/network collision (§8, V1).
- The live-chain reads: `getchaininfo` and `getvalidator` against both
  bootnode IPs on port 8080, which agreed byte for byte.
- The §3 deadline arithmetic, recomputed from the live chain's own wall slot.
- The reading of `admissible()`, `apply_transaction` and `owns()` at the tag
  that establishes §1, §2 and §5.

**Relayed from the repository at the tag, not independently reproduced:**

- The 21.2-minute cold-sync measurement and its 934 MB peak RSS
  (`genesis/README.md`) — one run on one machine, and the source says so.
- That `--transport libp2p` finds no peers (`genesis/README.md`,
  `docs/THIRD-PARTY-QUICKSTART.md`).
- The three-way partition that finalized epoch 25 under three roots
  (`docs/post-mortems/2026-08-24-finality-divergence.md`).
- The attack arithmetic on unfunded deposits — 46 requests to stop finality,
  180 to take the chain (`engine.rs:3210`).

**Not executed, deliberately:** step 3 was not run against the live bootnodes.
Syncing a fresh node would have opened connections to fleet infrastructure,
which was out of scope for this work. Step 3 is therefore relayed from
`docs/THIRD-PARTY-QUICKSTART.md`, which is the document written for it and
which does report having been run.

---

## 8. Verification log

Every check in `bloch-onboard` was broken on purpose and confirmed to fail,
then restored. Run 2026-09-02 against the tag, with disposable keys, from a
clean directory.

| # | Check | Violation | Result |
|---|---|---|---|
| V0 | valid mainnet address | — | accepted (baseline) |
| V1 | checksum ignores the prefix | same 48 hex under `bloch1t` | **both valid, identical `hash20`** — the defect, demonstrated not asserted |
| V2 | network must match | testnet address, `--network mainnet` | refused |
| V2b | same, through `deposit` | testnet withdrawal address on a mainnet deposit | refused |
| V3 | checksum | last 2 hex corrupted | refused, "checksum mismatch" |
| V4 | `--network` has no default | flag omitted | refused |
| V5 | funded format | `deposit --funded` | refused; no wire tag assigned |
| V6 | amount floor | `--amount-sat 1` | refused, naming `MIN_DEPOSIT_SAT` |
| V7 | hybrid key suite | keystore rewritten with a 64-byte pubkey | refused: "envelope suite 0x0001, body 60 bytes … requires a 3745-byte body (1952 + 1793)" |
| V8 | PoP self-verify | signature checked against its own pubkey before printing | enforced in-path |
| V9 | canonical round-trip | decoded via the real decoder, equality asserted, tag `0x02` pinned | enforced in-path |
| V10 | credentials width ≠ 32 | — | **not reachable from the CLI**: credentials are always derived from a parsed 20-byte address, so the check is defensive only. Stated rather than claimed as tested. |

**End-to-end walk**, same run: `bloch-pos keygen` → `bloch-onboard identity` →
`bloch-onboard deposit` (3,854 bytes) → a locally built node from the tag on a
four-validator devnet genesis → `sendrawtransaction`. The node answered
`-32008` with the refusal in §7 while `getvalidatorcount` and `getmempoolinfo`
answered normally. The road ends where this document says it ends.

**Not tested:** everything downstream of step 7, because nothing gets past it —
activation, attestation, exit and withdrawal are unreachable by construction,
not merely unverified.
