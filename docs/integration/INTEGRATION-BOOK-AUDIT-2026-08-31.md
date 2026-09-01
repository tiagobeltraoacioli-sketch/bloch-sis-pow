# Integration Book — claim-by-claim audit, 2026-08-31

```
Document:   INTEGRATION-BOOK-AUDIT-2026-08-31
Audits:     docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md
            as it stood at main @ e4083f9
Against:    main @ e4083f9 (the released binary)
Status:     INTERNAL AND PARTNER-DELIVERED. Never published, never a shared
            artifact. Delivered to integrators as a file.
```

## Why

An exchange integrating against Genesis-4 read the Integration Book closely
against `main` @ `e4083f9` and found three things we had not told them:

1. `validate_deposit` has no production call site.
2. `unlock_epoch` does not appear in `bloch-pos-committee`.
3. The epoch-800 block payload cap doubling to 524,288 — which they found
   themselves, from the code.

All three are correct. This document is the result of auditing **every**
factual claim in the book against the code rather than only the three they
caught, so that the next audit finds nothing.

Their framing of why the third one matters is the organising principle of the
revision:

> *"Conservation is an equality, so a stale fee assumption is a hard rejection
> rather than a slow confirm."*

## Verdicts

- **VERIFIED** — the code supports the claim as written.
- **STALE** — true once, or true but materially incomplete in a way that
  misleads.
- **WRONG** — the code does not support it; a client built on it fails.
- **ASPIRATIONAL** — describes something that does not exist in the released
  binary, whether or not it exists on a branch.
- **UNREACHABLE** — the code exists, compiles and is tested, and nothing on the
  wire can reach it. Distinguished from ASPIRATIONAL because the failure is
  different: the capability is real and gated, not absent.

Line references are to the pre-revision book. All code references are `main` @
`e4083f9`.

---

## A. The three findings the integrator reported

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| A1 | Funded validator bonding is real; deposits are validated | **ASPIRATIONAL** | `staking::validate_deposit` defined `staking.rs:285`, exported `lib.rs:151`, declared on the trait `interfaces.rs:795`. Callers: **tests only** (`staking.rs:576–703`). Zero production call sites in `bloch-pos-node`. Closed on `wt/signed-exit-wire` et al., where the funded path routes through `staking::validate_deposit_fields` from the transaction dispatch — **not on `main`** |
| A2 | Genesis vesting is enforced by consensus (`unlock_epoch`) | **ASPIRATIONAL** | `unlock_epoch` occurs **zero times** in `crates/bloch-pos-committee/`. It exists only in the genesis manifest (`bloch-pos-node/src/genesis.rs:167`, `:757`, `:867`, `:1076`), whose own doc comment claims it "is what makes the vesting consensus". Nothing enforces it on this branch. The enforcement `if entry.unlock_epoch > self.epoch` exists on the same branches as A1 |
| A3 | "Block payload 524,288 bytes", stated flat | **STALE** | Correct today, false before epoch 800. `fee_market.rs:65` `MAX_BLOCK_TX_BYTES = 262_144`; `:85` `MAX_BLOCK_TX_BYTES_V2 = 524_288`; switch at `params.rs:308` `BLOCK_BYTES_V2_ACTIVATION_EPOCH = 800`. The book gave no era, so a reader replaying history or checking freshness had nothing to check against |

---

## B. Chain parameters (§1)

| Claim | Verdict | Evidence |
|---|---|---|
| Decimals 8, 1 BLCH = 100,000,000 sat | VERIFIED | `tokenomics_v4.rs:41` |
| Slot time 30 s | VERIFIED | `params.rs:34` |
| Epoch 32 slots (16 min) | VERIFIED | `params.rs:30`; 32 × 30 s = 16 min |
| Block gas 60,000,000 | VERIFIED | `fee_market.rs` `BLOCK_GAS_LIMIT`. Book omits that the price controller moves against the **target** (30,000,000), not the cap |
| Amounts are decimal strings | VERIFIED | `rpc.rs` `Json::sat` for `total_active_stake_sat` and both base-fee fields |
| Genesis carryover 452,726 outputs / 18,146,400,000 BLCH | VERIFIED (not re-measured) | consistent with `docs/CARRYOVER.md`; chain-state figure, not a constant |
| "Validators 64" presented as a chain parameter | STALE | 64 is the live population of the genesis set, not a protocol constant. `params.rs:17` `COMMITTEE_SIZE = 128` |

---

## C. RPC surface (§3)

| Claim | Verdict | Evidence |
|---|---|---|
| `getchaininfo` field list | STALE | All listed fields exist; **7 omitted**: `block_id`, `slot_in_epoch`, `slots_per_epoch`, `state_root`, `previous_justified`, `next_base_fee_millisat_per_gas`, `wall_slot`. The book sends readers to `getmempoolinfo` for a price that is on `getchaininfo` too |
| `getblockbyslot` field list | STALE | 4 omitted: `attestation_root`, `coherence_root`, `finalized` (bool), and `height` may be `null`. `version` is the raw magic `0xB10C0005` = 2970353669, **not** 4 |
| `getblockbyslot` on an empty slot | **WRONG (by omission)** | Returns `-32007 SLOT_EMPTY`, not an empty result. Missed proposals are normal under PoS; the book's error table has no `-32007`, so a scanner alerts continuously |
| `getbalance` → `script_hash`, `balance_sat`, `utxo_count`; count is a true total | VERIFIED | `rpc.rs` `balance_json`; the count is taken over the whole committed set, uncapped |
| `getutxos [script_hash, limit, offset]` | **WRONG** | **There is no `offset`.** Only positions 0 and 1 are read; a third argument is silently ignored. There is no cursor, so an address past the limit cannot be fully enumerated |
| `getutxos` returns `at_slot` per output | **WRONG** | Elements carry `txid`, `vout`, `value_sat`, `script_hash`. No `at_slot` |
| "Returns up to 1,000 outputs per call" | STALE | Max is 1,000; **default is 100**. Values clamp into `1..=1000` silently — `limit: 5000` returns 1,000, `limit: 0` returns 1 |
| `listunspent` same shape as `getutxos` | VERIFIED | Literally the same dispatch arm |
| `gettxout` → `txid`, `vout`, `unspent`, `utxo`, `at_slot` | VERIFIED | `vout` optional, defaults 0. Nested `utxo` also carries `script_hash` |
| `sendrawtransaction` → `{accepted, txid}` | **WRONG** | There is **no `txid` key**. Returns `accepted`, `status`, `kind`, `bytes`, `tx_hash`, `tx_hash_note`, `confirmation`. `tx_hash` is SHA3-256 of canonical bytes and is explicitly *not* a consensus id — no block commits to it. `accepted` is hardcoded `true`; failure is an error object |
| `getmempoolinfo` → `size`, `max`, `bytes`, `next_base_fee…`; `max` = 4096 | VERIFIED | `engine.rs:158` `MEMPOOL_MAX = 4_096` |
| Error table of 5 codes | **WRONG / incomplete** | `-32000` is **`BLOCK_NOT_FOUND`**, not "general node error". **7 codes omitted**: `-32700`, `-32600`, `-32603`, `-32003 MEMPOOL_FULL`, `-32004 NODE_UNAVAILABLE`, `-32005 NO_TRANSACTION_INDEX`, `-32006 NO_WALLET`, `-32007 SLOT_EMPTY`, `-32008 TX_REFUSED`. `-32003` and `-32008` are opposites; conflating them gives an infinite retry loop |
| "Parameters are positional arrays" | STALE | Positional **or** named objects are accepted |
| (omitted) methods served but undocumented | STALE | `getcapabilities`, `getblockcount`, `getblockbyid`, `getvalidator`, `getvalidatorcount`; plus `gettransaction`/`getnewaddress`, which exist and permanently fail with dedicated codes rather than `-32601` |
| (omitted) transport constraints | STALE | **No CORS at all** — a browser cannot call this cross-origin; `OPTIONS` → HTTP 405. **No authentication of any kind**, on a port that accepts `sendrawtransaction`. No batch (`-32600`), no keep-alive, 64 connections, 1 MiB body, 16 KiB headers, `Content-Length` required, 30 s socket / 10 s engine timeouts |

---

## D. Addresses (§4)

| Claim | Verdict | Evidence |
|---|---|---|
| Address is `bloch1q…`, bech32-like | **WRONG** | Not bech32. `address.rs:63–97`: `prefix ‖ hex(20-byte hash) ‖ hex(4-byte checksum)`, checksum `SHA3-256(SHA3-256(hash20))[..4]`. No bech32 charset, no BCH checksum. Independently confirmed in `tools/indexer/src/address.ts:46–65` |
| "take the 20 bytes that follow the `bloch1q` prefix" | **WRONG** | **48 hex characters** follow the prefix: 40 hex (the 20-byte hash) plus 8 hex of checksum. Implemented literally, produces a wrong `script_hash` |
| Right-pad with zeroes to 32 bytes | VERIFIED | `genesis.rs:398–426`, `:596–600`; regression test `the_address_is_zero_extended_to_the_right` |
| Zero-extension presented as *the* derivation | STALE | `transition.rs:1330–1365` (`fn owns`) has **two** forms: *carried* Genesis-3 outputs match on the first 20 bytes with the last 12 zero (160-bit); *native* Genesis-4 outputs use all 32 bytes of `SHA3-256(pubkey)` (256-bit). Handing out zero-extended hashes yields the weaker tier — an accepted design choice, but a risk team must be told |
| Responses echo `script_hash` | VERIFIED | `rpc.rs` `balance_json`, `utxos_json`; each element echoes its own |
| (omitted) no RPC accepts a bare address | STALE | 64-hex only. No `validateaddress` on this chain; `getnewaddress` permanently refuses because "no address format is frozen" — which sits awkwardly with the book presenting a frozen derivation |

---

## E. Settlement (§5)

| Claim | Verdict | Evidence |
|---|---|---|
| Finality is explicit and published in `getchaininfo` | VERIFIED | `finality.rs` module docs; Casper-style justification + consecutive justification |
| "typically 1–2 epochs (16–32 minutes)" | **WRONG** | Casper k=1. A tx in epoch `E` is first covered by checkpoint `E+1` (`engine.rs:936`, `:787–810`); `close_epoch` fires on the first block of the next epoch (`transition.rs:3200–3201`); finalization needs consecutive justification (`finality.rs:458`). So checkpoint `E+1` justifies at the first block of `E+2` and finalises at the first block of **`E+3`**. Best case just over 2 epochs, worst ~3 — **32–48 minutes**, unbounded under degraded participation |
| Credit on `finalized` gives "a cryptographic settlement guarantee" | **STALE — materially** | The guarantee is conditional and the book stated it unconditionally. See F and F2 |
| (omitted) quorum fraction | — | 2/3, **active and ungated**: `weight * 3 >= total_active * 2` (`finality.rs:435`). Not to be confused with `MIN_QUORUM_DENOMINATOR_NUM/DEN = 1/2`, which is a floor on the *denominator* and is inert (F) |

---

## F. The finality caveat the book did not carry

Not a claim in the book — an omission serious enough to be its own section, and
the single most important correction in this revision.

| Fact | Evidence |
|---|---|
| The quorum denominator is **leak-adjusted**: unheard validators' stake is subtracted. Active and unconditional | `finality.rs:320–345` |
| The leak accumulator has **one write path, accrual — no decay, no reset, no removal**. The denominator shrinks monotonically and never recovers | `params.rs` docs on `INACTIVITY_LEAK_RECOVERY_QUOTIENT` |
| Consequence: once enough stake has leaked, "a handful of nodes — one, even — held two thirds of what remained and finalized entirely alone" | same |
| This is not hypothetical: **2026-08-24, three nodes finalised epoch 986 under three different roots** and no arriving blocks reunified them | same |
| Leak **recovery** (quotient 16) is **UNREACHABLE** | `params.rs:597` `LEAK_RECOVERY_ACTIVATION_EPOCH = u64::MAX` |
| The **quorum-denominator floor** (1/2 of unleaked total) is **UNREACHABLE**, behind the same gate | `params.rs:147–149`, `finality.rs:355–360` |
| Whether the leak reaches the **duty roster** is **SCHEDULED**, not live | `params.rs:244` `LEAKED_ROSTER_ACTIVATION_EPOCH = 1400` |

**Effect on the book:** "credit on `finalized` and you have a cryptographic
settlement guarantee" is true only while participation is healthy. The revision
now instructs integrators to require **two independent nodes to agree on the
finalized root** — which is what our own public RPC front end already does
internally, and it was indefensible to hold integrators to a weaker standard
than we hold ourselves.

---

## F2. Finality can move backwards — a second, independent defect

Also not a claim in the book. Distinct from F because the mitigation for F does
not cover it.

| Fact | Evidence |
|---|---|
| Within `FinalityState` the finalized checkpoint **is** monotone — replaced only by a strictly higher one | `finality.rs:458`, `source.epoch > self.finalized.epoch` |
| The node does not own a `FinalityState` across a reorg. `Engine::do_reorg` takes an ancestor's state, folds the branch onto it, and adopts **unconditionally** | `engine.rs:1609`, `:1622`, `:1661` — no comparison of incoming vs outgoing finalized anywhere in `do_reorg`, `advance` or `ingest` |
| The only mention of finalized on the adopt path is a log line, one-directional **by accident** — a downward move is simply not printed | `engine.rs:1511` |
| Fork choice walks from the **justified** root, never the finalized one; there is no `filter_block_tree` equivalent and nothing prunes by finalized checkpoint | `forkchoice.rs:184`, fed from `engine.rs:1229–1238` |
| `enforce_ws_anchor` is not a ratchet: only fires with an anchor configured, compares one epoch, and its non-fatal branch prints "Own finality stands" **after** `do_reorg` already adopted | `engine.rs:833–882`, called at `:1715` |
| Consensus-side `TransitionError::FinalityRegression` does not help — it only requires a header to carry its own parent's roots; an older finalized root is valid on a competing branch | `transition.rs:3265–3273` |

**Mechanism:** the justified root `J` for epoch `E` is a block in epoch `E−1`,
and the state committed at `J` predates the boundary walk that finalized
checkpoint `E−1`. A reorg to `J` installs a state whose finalized epoch is
about `E−3` while the node had been reporting `E−1`. `finalized_height()`,
`finality_of()` and the RPC `finalized` boolean all read that field directly, so
a block previously returned as `finalized: true` flips back.

**No ratchet-shaped test exists in either crate.** This matches the prior
"finality rewind" observation; it was never closed on this branch.

**Effect on the book:** §5.4 added. Crucially, the §5.3 mitigation (two nodes
agreeing) **does not cover this** — both can rewind, independently. The only
mitigation that does is a depth margin past finality plus re-verification
before release, and the book now says so.

---

## F3. Staking transactions: refused by policy, applied by consensus

**Not written into the partner document in full — see the escalation note
below.**

| Fact | Evidence |
|---|---|
| `validate_deposit`, `validate_exit`, `validate_withdrawal` have **zero** production callers; every call site is `#[cfg(test)]` | `staking.rs:285`, `:459`, `:503`; tests `staking.rs:576–841`, `ws.rs:692–744` |
| The `StakingLifecycle` trait declaring them has **no implementor in the workspace** | `interfaces.rs:795` |
| The wire decoder accepts `0x02 Deposit`, `0x03 Exit`, `0x04 Delegate` | `transition.rs:762`, `:769`, `:770` |
| `apply_transaction` has **live, non-rejecting arms** for all three, with inline rules that are *not* `staking::validate_*` | `transition.rs:1977–2072` |
| The `Deposit` arm inserts a validator record and **spends no UTXO and verifies no signature** | `transition.rs:1977–2027`; the node's own comment measures the exposure at `engine.rs:2727–2735` |
| The mempool refuses all three at admission — **node-local policy, stated verbatim as "not a consensus rule: a block that already carries a deposit still applies it"** | `engine.rs:2737–2742`, `:2746`, `:2904` |
| `ACTIVATION_DELAY_EPOCHS` / `MAX_ACTIVATIONS_PER_EPOCH` are enforced at every epoch boundary but their input `deposit_history` has no reachable writer — vacuous | `staking.rs:103`, `:108`, `:371`, `:374`; called at `transition.rs:2939–2951` |

**Net:** no staking transaction can be submitted through any public interface,
but a proposer that includes one has it accepted by every node in the fleet.
The validator set is held fixed **by policy, not by protocol**.

### Escalation — founder decision required

The partner document (§8.1) states the risk posture — "held fixed by operator
policy rather than by the protocol", "the lifecycle described in the
specification is not the lifecycle the released binary enforces", "treat the
validator set as fixed and externally administered", and an invitation to raise
it with us directly. It deliberately **does not** describe the unauthenticated
mint path in operational detail.

That line was drawn by the agent writing this audit, not by a decision anyone
has made. It is the conservative reading of the standing rule that partner
material is delivered narrowly, and of the fact that spelling out the mechanism
in a document that leaves the building is a different act from recording it
here. **How much of F3 an exchange is told is a founder call, and it should be
made explicitly rather than inherited from this file.** The same applies to
whether F3 should be fixed before any listing conversation proceeds.

---

## G. Fees and sizing (§6)

| Claim | Verdict | Evidence |
|---|---|---|
| "A transfer is valid at exactly one price point" | VERIFIED | `transition.rs:2189` and `:2397` — `if spent_value != created + fee` → `ValueNotConserved`. Equality, both arms. Overpayment is rejected too |
| The fee comes from the market, never the transaction | VERIFIED | `transition.rs:2096–2100`; `fee_market::charge` derives gas from class and declared bytes |
| Gas formula constants 5,000 / ×16 / 72,748 | VERIFIED | `TX_FLAT_GAS`, `GAS_PER_BYTE`, `HYBRID_VERIFY_GAS` = `HYBRID_VERIFY_INSTRUCTIONS / INSTRUCTIONS_PER_GAS` = 7,274,849 / 100 |
| V1 ceiling 61 inputs | VERIFIED (approx.) | Byte-bound under the 512 KiB cap at ~8,560 B per V1 input. Exact figure varies — Falcon signatures are variable length |
| **V2 ceiling 815 inputs**, and "use 815 in any planner" | **WRONG** | The formula mixes two cost models. Byte term `8,649 + 40n` is single-owner V2; verify term `72,748 × n` is V1 per-input. `transition.rs:2380–2388` charges `TxClass::Eutxo { inputs: keys.len() }` — **per distinct owner key**, not per input. Single-owner 815 inputs uses <¼ of the gas cap and is bytes-bound roughly an order of magnitude higher; 815 *distinct owners* needs a ~6.8 MB witness table against a 524,288-byte cap and cannot be encoded at all. Real distinct-owner ceiling ≈ 62 |
| Per-stage ceiling "20,000,000 BLCH" | **ASPIRATIONAL / not a protocol fact** | Appears nowhere in consensus code. A reference-wallet policy figure presented in a protocol context |
| "the base fee is baked into the change output" | STALE | True but incomplete: transfers carry `tip_millisat_per_gas` on the wire and the settled fee is `base_fee_sat + priority_fee_sat`. Both round **up independently** — a wallet folding the prices before dividing can be one satoshi short, which under `!=` is a hard rejection |
| "Read the price immediately before building, broadcast promptly" | STALE | Correct instruction, no magnitude given. The bound is ±1/8 per block (`BASE_FEE_CHANGE_DENOMINATOR = 8`), and only blocks move it — skipped slots leave it unchanged. Floor 10 msat/gas is absorbing |

---

## H. Running a node (§7)

| Claim | Verdict | Evidence |
|---|---|---|
| Binary `bloch-pos-quatro` | **WRONG** | `Cargo.toml:41–43` declares `name = "bloch-pos"`. `bloch-pos-quatro` appears nowhere but the book. The invocation gives `command not found` |
| Subcommand `run` | VERIFIED | `main.rs:104` |
| All 8 flags spelled correctly | VERIFIED | `main.rs:761–841` |
| No required flag omitted | VERIFIED | `--data-dir`, `--genesis` required; `--listen` required under devnet; `--carryover` required against the mainnet manifest |
| `--transport devnet` is valid | VERIFIED | `main.rs:769–776`; values are `devnet` \| `libp2p` |
| "Expose P2P" | **STALE — unsafe as written** | `main.rs:155–159`: the devnet transport authenticates nothing and a routable bind **must** be firewalled to known peers. The book prescribes `--listen-addr 0.0.0.0` with no such warning |
| "P2P uses the 19xxx range, RPC the 16xxx range" | **WRONG** | RPC default is **16310** (`main.rs:77`); libp2p P2P default is **16400** (`main.rs:794`) — P2P defaults *into* 16xxx. 19xxx is a local devnet-script convention only. The book's own example puts RPC on 16400, the libp2p P2P default |
| "Syncing from genesis is also supported" | **WRONG for the recommended transport** | `genesis/README.md:29–45`: over `--transport devnet` cold sync does not complete, **and fails silently** — the node reports a head, height and state root as if caught up. Reproduced 2026-08-14 at height 556 against a network at 1,511 |
| Bootstrap files `blocks.log`, `meta.bin`, `ws_latest.bin` | VERIFIED | `store.rs:46`, `:78`; `ws_boot.rs:233`. `meta.bin` and `ws_latest.bin` auto-create if absent, so only `blocks.log` is strictly needed |
| (omitted) `p2p_identity.bin` | STALE | Exists (`p2p.rs:713`, `:680–699`); a copied data dir carries a duplicate PeerId. Already warned about in `docs/SNAPSHOT-BOOTSTRAP.md:60`; absent here. Latent under devnet, real under libp2p |
| (omitted) `validator.key` | **STALE — slashing hazard** | `engine.rs:466–471`: a spare copy of a validator keystore is how you equivocate and get slashed, "there is no safe version of that". The book says "copy these three files" without saying "and nothing else" |
| No keystore → observer mode | VERIFIED | `engine.rs:2164–2176`. Not silent — prints `observer mode: no keystore in …`; banner reports `observer (no keystore, signs nothing)`. The file is `validator.key` (`keys.rs:70`) |
| `state_root` agreement check | VERIFIED, incomplete | Correct method. A single reference that has itself stopped agrees about a stale height and tells you nothing; divergent nodes answer RPC normally |
| (omitted) the parser ignores unknown flags | STALE | Hand-rolled parser (`main.rs:412`), not clap. A typo'd flag is silently ignored and the default silently applies |

---

## I. Validators (§8)

| Claim | Verdict | Evidence |
|---|---|---|
| 64 active validators, active since genesis | VERIFIED | Genesis manifest decoded: 64 validators, `activation_epoch: 0` (`transition.rs:1401`); pinned by `genesis.rs:1877` |
| "6,177,107,126,034,566 sat of active stake" | STALE (as presented) | Nowhere in code or manifest. **Genesis active stake is 160,000,000,000,000 sat** (64 × 2,500,000,000,000). The quoted figure is ~38.6× that — a live reading after 1,101 epochs of reward accrual (`transition.rs:2926–2928`), and it grows every epoch. Valid as a timestamped measurement, misleading as a parameter |
| "committee of 64" implied to rest on `COMMITTEE_SIZE` | **STALE — dead constants** | `COMMITTEE_SIZE = 128` (`params.rs:17`) and `SLOT_SUBCOMMITTEE_SIZE = 8` (`params.rs:27`) are names from a **superseded sampled-committee design**, replaced by a partition in finding F1 (`lib.rs:5–15`). Their only consumers are two functions the node never calls. **The node reads neither.** Sizing anything from "8 × 32 = 256 seats" is meaningless — there are 64 seats per epoch |
| "Committees are a partition … every validator has duties every epoch" | VERIFIED | `committees::epoch_committees` (`committees.rs:275–350`) sorts, dedups, shuffles and cuts into `SLOTS_PER_EPOCH` contiguous chunks; no stake filter. Guarded unconditionally in the release binary by `consensus_invariant!` (`transition.rs:2968–2985`). At n=64 that is 2 seats per slot |
| (omitted) the roster is not frozen for the epoch | STALE | `apply_slashing_evidence` can set `slashed` mid-epoch, shrinking the roster and re-sorting the partition under votes already admitted (`transition.rs:1600–1605`, `:2745–2791`). The guard is a `debug_assert!` — deliberately not in the release binary |
| "Validator entry ... activates on a scheduled flag day" | **ASPIRATIONAL** | There is **no such constant**. Every gate in `params.rs` is enumerated in §1.2 of the revision and none concerns validator entry. "Scheduled" implied a date a reader could look up; there is none |
| "Until that upgrade the committee is the genesis set" | VERIFIED, but for a different reason than implied | True — but because the mempool refuses staking transactions as policy, not because consensus forbids them. See F3 |

---

## J. Summary

| Verdict | Count |
|---|---|
| VERIFIED | 25 |
| STALE | 24 |
| WRONG | 10 |
| ASPIRATIONAL | 4 |
| UNREACHABLE | 6 |

The ten WRONG claims break a client outright: the binary name, the address
derivation, `getutxos`' phantom `offset` and `at_slot`, `sendrawtransaction`'s
phantom `txid`, the error table, the V2 input ceiling, the port ranges,
sync-from-genesis, and the 1–2 epoch settlement figure.

The six UNREACHABLE items are the three gates below plus
`staking::validate_deposit`, `validate_exit` and `validate_withdrawal` — public,
tested, and with no production caller and no trait implementor (F3).

**Three findings are more serious than anything the integrator reported**, and
none of them was a claim in the book — they are omissions:

- **F** — the quorum denominator shrinks monotonically with no floor and no
  recovery, both mitigations inert. Three nodes finalised epoch 986 under three
  different roots on 2026-08-24.
- **F2** — the finalized checkpoint is not a latch across a reorg. Nothing
  compares incoming to outgoing on the adopt path, and two-node agreement does
  not mitigate it.
- **F3** — the staking lifecycle validators are dead code; `Deposit`, `Exit` and
  `Delegate` are refused by mempool policy but applied by consensus. **Carries a
  founder escalation.**

The three UNREACHABLE gates are `LEAKED_ROSTER_ACTIVATION_EPOCH` (1,400 —
scheduled), `LEAK_RECOVERY_ACTIVATION_EPOCH` (`u64::MAX` — inert) and, in a
category of its own, `ANCESTRY_SEED_ACTIVATION_EPOCH` (`u64::MAX`, and
**unreferenced** — the code it guarded was made unconditional on 2026-08-24, so
it gates nothing and is dead rather than pending).

## What now pins this

- `crates/bloch-pos-committee/tests/integration_book_claims.rs` — 10 tests,
  each naming the book section it pins. A consensus-parameter change that moves
  a published figure now fails in CI with the document named.
- `docs/integration/CONSENSUS-CHANGELOG-DISCIPLINE.md` — the rule that a
  constant, its test and its document move in one commit.
- `getcapabilities` on the node — the machine-readable wire surface, which
  cannot go stale the way this document can. Clients should branch on it and
  not on §3.
