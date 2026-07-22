# `minting.rs` — native minting/burn policies (Cardano-style), the Supply substrate

Status: **reference / unaudited, not consensus-wired.** This note describes
`crates/bloch-euvm/src/minting.rs` as currently written (894 lines). At the time of
writing, `crates/bloch-euvm` is a real (optional, `euvm`-feature-gated) member of the
root workspace, but nothing in this module — or in `lib.rs` — is reachable from
`accept_block` or any other node code path. Note on wiring, precisely: as of this
review `lib.rs`'s working tree (uncommitted) already carries `pub mod minting;` and
`#[path = "src/batcher.rs"] mod batcher;` — the one-line integration edits the dev's
own report describes as a *later* step have, in fact, already landed locally,
apparently from concurrent integration work on this same branch. `git diff` against
the last commit confirms the change is exactly those lines (5 insertions, one file).
Running `cargo test -p bloch-euvm --lib` directly (no edits required) reproduces
**44 passed, 0 failed**: 17 pre-existing `lib.rs` tests + 10 `batcher.rs` tests + 17
`minting.rs` tests — independently confirming the dev's reported 17/17 green.

## The model (Cardano / Ergo native tokens)

An asset's identity **is** the hash of the program that governs its supply. A
`MintingPolicy` is nothing more than a validator program (`Vec<Op>`, the same `Op`
`lib.rs` already runs) keyed to exactly one `AssetId` — and that id is *defined* as
`policy_asset_id(policy) = validator_hash(policy)`. So an asset cannot exist without a
policy, and authorising any change to its supply means revealing a program that (a)
hashes to that asset's id and (b) runs to `true` over a small, fixed minting context.
This is the same "asset id = hash of its minting policy" rule `lib.rs` already states
for `AssetId`; `minting.rs` is the machinery that makes it enforceable.

A `MintAction { asset_id, delta: i128 }` is a **net signed** request: `delta > 0`
mints, `delta < 0` burns, `delta == 0` is a no-op that is still type-checked (the
policy still runs). A `MintRequest { policy, redeemer, action }` bundles the action
with the revealed policy and the redeemer values that seed its stack.

## What `validate_tx_with_mint` does

It mirrors `lib.rs::validate_tx`'s per-asset conservation and per-input validator run
— without editing that function — but relaxes each asset's balance by precisely the
net authorised mint/burn for that asset:

```
in_sum + net_mint_delta  ==  out_sum + fee     (fee is BLCH-only, as in lib.rs)
```

with `net_mint_delta` defaulting to `0` for any asset with no presented policy, so an
untouched asset still balances **exactly** — identical to the current node invariant.
Concretely, in three passes over one shared `gas: &mut u64` budget:

1. **Authorise.** For every `MintRequest`: reject `BLCH` outright (before any gas is
   spent); reject if `validator_hash(policy) != action.asset_id`
   (`PolicyAssetMismatch`); reject a second request for the same asset
   (`DuplicatePolicy`, checked *before* running its policy, so an ambiguous duplicate
   doesn't waste the gas of re-running it); then run the policy over a purpose-built
   `Ctx` (see below) sharing the tx's gas budget, and finally check
   `prior_supply + delta >= 0` with checked `i128` (`SupplyNegative` /
   `MintOverflow`). Accepted deltas accumulate in a `BTreeMap<AssetId, i128>`
   (`net_mint`) — one net delta per asset, canonically ordered.
2. **Conserve.** Gather every asset touched by any input, output, or `net_mint` entry
   (plus `BLCH`, always), and for each, check the relaxed equation above with checked
   `i128` throughout (`ValueNotConserved` / `MintOverflow`).
3. **Spend.** Run every input's validator exactly as `validate_tx` does, against the
   whole tx, sharing the same `gas`.

Returns total gas used (`gas_limit - gas`), or the first `MintTxError` encountered.

## The minting-context ABI

A minting policy is a *transaction-level* validator — it isn't spending a specific
output — so it runs over a small fixed `Ctx` instead of `[datum, redeemer…]`:

| Field | Index | Constant | Contents |
|---|---|---|---|
| sighash | `ctx.fields[0]` | `MINT_CTX_SIGHASH` | `tx.sighash`, `Val::Bytes` — same slot `validate_tx` uses, so `VerifySig` works unchanged |
| delta | `ctx.fields[1]` | `MINT_CTX_DELTA` | the signed `Val::Int` delta *being authorised* |
| height | `ctx.fields[2]` | `MINT_CTX_HEIGHT` | `mctx.height`, `Val::Int` |
| prior_supply | `ctx.fields[3]` | `MINT_CTX_PRIOR_SUPPLY` | `mctx.prior_supply[asset]` (0 if absent), `Val::Int` |

`ctx.tx_outputs` is the real `tx.outputs` (so a policy can inspect what the tx
creates, same as any spend validator). `ctx.self_validator_hash` is set to the
*asset id being minted* rather than a spent output's validator hash — a deliberate
reuse of that field's storage slot to expose "which asset is this policy running
for," not its usual meaning; `ctx.self_value` is left empty (`Value::new()`) since a
policy isn't spending a UTXO with reserves. This overload is documented in the code
but is worth flagging explicitly (see Honest status) since `Op::SelfValidator` means
something different here than everywhere else `Ctx` is used.

## Reference policy constructors

- `fixed_supply_cap_policy(cap)` — `prior_supply + delta <= cap`, i.e.
  `PushInt(cap+1); Lt` on the summed value. Burns always satisfy it (the caller-side
  `SupplyNegative` check is what actually bounds burns).
- `authorized_minter_policy(minter_pubkey)` — `VerifySig(sighash, minter_pubkey, sig)`
  where `sig` is the sole redeemer value. Runs through the exact same host
  `SigVerifier` callback `lib.rs` defines — in production, the real hybrid
  ML-DSA-65‖Falcon-1024 verifier from `bloch-crypto`, unchanged. This is the
  Cardano/native-token analogue of P2PKH-for-issuance: whoever holds the minter key
  may mint or burn any amount of *this one asset*, with the actual net amount bound
  by the transaction's own conservation math (the signature authorises "this tx", not
  a specific number — the delta is whatever the accompanying output/input values make
  it, checked in pass 2 above).
- `height_gate_policy(unlock_height)` — `height >= unlock_height` (vesting /
  scheduled-issuance window).

Because a policy's parameters are baked into its program bytes, distinct parameters
(different cap, different pubkey, different unlock height) yield distinct
`policy_asset_id`s — exactly the property that makes the policy *be* the asset's
identity, and the property the first test (`asset_id_is_policy_hash_and_params_change_it`)
pins down directly.

## Determinism properties

- **No new nondeterminism source.** No `HashMap`/`HashSet` (only `BTreeMap`/
  `BTreeSet`, both canonically ordered), no float, no I/O, no wall-clock, no
  thread/allocation-order dependence — matching `lib.rs`'s own stated bar.
- **Checked `i128` throughout.** Every fold (`in_sum`, `out_sum`, `prior + delta`,
  `in_sum + delta`, `out_sum + fee`) uses `checked_add`; overflow is a hard
  `MintOverflow`/`MintTxError`, never a silent wrap. `u64` value amounts widen to
  `i128` losslessly (`u64::MAX` is far inside `i128`'s range), so the cast itself
  cannot be the overflow source — a summation would need on the order of `10^19`
  max-amount inputs before `i128` could overflow, i.e. not reachable in practice.
- **Deterministic ABI, deterministic ordering.** The mint-context field layout is a
  fixed, documented index scheme (0–3); `net_mint` and the asset-iteration set are
  both `BTreeMap`/`BTreeSet`, so multi-asset transactions process assets in the same
  canonical order on every node. `deterministic_mint_check` re-runs the same call 100
  times and asserts byte-identical results, matching the pattern `lib.rs`'s own
  `deterministic` test uses.
- **No new dependency surface.** `minting.rs` adds no new crate dependency; it only
  imports items already present and `pub` in `lib.rs`.

## Gas properties

`validate_tx_with_mint` shares **one** `gas: &mut u64` budget across every policy run
*and* every input-validator run, in that order — a malicious mint request cannot get
a separate, unbounded budget for its policy program; it draws from the same DoS bound
`validate_tx` already enforces via `lib.rs`'s per-op `gas_cost` schedule
(`VerifySig`/`VerifyEcdsa` 1000, hashing 60, arithmetic 4, everything else 1). No new
gas model or cost schedule is introduced; policies pay exactly what any other
validator program pays per op, through the same `run()`.

## Mapping to Ustav

Not directly applicable, and this note says so rather than stretching a connection:
`minting.rs` governs *fungible native-asset supply* (mint/burn a bare `AssetId` amount)
via a single validator-program-as-policy; it has no contact with `state.rs`'s
sparse-Merkle registry/holder-set/snapshot/allow-deny machinery for the "hard Ustav
problem" (an Ustav token's non-per-UTXO state, committed as a 32-byte root). The two
modules *compose* rather than overlap: an Ustav-governed asset could use exactly this
module's `MintingPolicy` mechanism to authorise its issuance/redemption (e.g. a policy
that both checks an `authorized_minter_policy`-style signature *and* asserts against a
`state.rs` registry root passed through `ctx.fields`/`tx_outputs`), while `state.rs`
separately governs that asset's holder-set/allow-deny/snapshot state on the spending
side. Neither module currently references the other; wiring them together is future,
unbuilt integration work, not something this note should claim already works.

## Honest status

- **Reference / unaudited / not consensus-wired**, exactly as the module's own header
  states. Designed ≠ built ≠ booted: nothing here is reachable from `accept_block`,
  and the crate itself sits behind the workspace's optional `euvm` feature (off by
  default).
- **`lib.rs` needed zero new `pub` items** — verified independently by reading
  `lib.rs`: every symbol `minting.rs` imports (`run`, `spend`, `validator_hash`,
  `value_get`, `AssetId`, `BLCH`, `Value`, `Ctx`, `Val`, `ExtOutput`, `EuTx`,
  `EuTxInput`, `SigVerifier`, `TxError`, `VmError`, `blch`) was already `pub` before
  this module existed. Confirmed by static cross-check of every call site's argument
  types against `lib.rs`'s signatures, and empirically by the passing build above.
- **Hard invariants hold as claimed**, traced through the code: `BLCH` is rejected
  first, before any gas is debited (the `asset == BLCH` check precedes the `run()`
  call in the loop body); every arithmetic step is checked `i128`; a burn cannot drive
  `prior_supply + delta` negative; a policy only authorises the one asset whose id it
  hashes to.
- **Test-coverage gap: 3 of 8 `MintTxError` variants are never exercised.**
  `MintOverflow`, `PolicyVm`, and `Tx(TxError::ValidatorRejected | Vm)` are all
  constructed in the code but never triggered by any of the 17 tests — in particular,
  there is no test where a policy *passes* but an input's own spend validator then
  *rejects* the transaction (the interaction between the two error families this
  module introduces), and no test where a policy program itself returns `Err`
  (`PolicyVm`) rather than `Ok(false)`. Worth adding before this graduates past
  reference status.
- **`authorized_minter_policy(pk)` is 1:1 with exactly one asset, by construction of
  the model, not a bug — but non-obvious enough to call out.** Since
  `policy_asset_id = validator_hash(policy)` and the policy's bytes are wholly
  determined by `pk`, the *same* `minter_pubkey` always produces the *same* asset id.
  A minter who wants authority over a second, distinct asset needs a second, distinct
  program (e.g. salted with a label/nonce baked into the policy bytes) — reusing
  `authorized_minter_policy(pk)` verbatim for two different intended assets is not
  possible; it would just be the same policy authorising the same one asset twice.
  This is the correct Cardano-style behavior (policy *is* identity) but is easy for an
  integrator to trip over if they expect "one minter key → many tokens" without
  reading this closely.
- **`ctx.self_validator_hash` is overloaded to carry the asset id, not a validator
  hash, inside a mint context.** Documented in the code's own comment, but flagged
  here because it means `Op::SelfValidator` behaves differently when read from a
  mint-policy program versus a spend-validator program — a policy author reusing a
  spend-validator snippet that trusts `Op::SelfValidator`'s usual meaning would get a
  silently different (but well-defined) value.
- **The per-asset supply ledger itself is entirely the caller's responsibility.**
  `MintCtx.prior_supply` is a plain, caller-supplied `BTreeMap` passed in fresh on
  every call — this module does not read, persist, or update any cross-block supply
  state. A real integration must maintain that ledger (accumulate every accepted
  `net_mint` into a persistent per-asset running total across blocks) outside this
  module; `validate_tx_with_mint` only *consumes* whatever `prior_supply` it is handed
  and never mutates it. This is an honest, load-bearing gap, not an oversight: it's
  the same "the hook only reads, never persists" framing `harness.rs`'s own note uses
  for its aggregate-only commitment.
- **The authorising signature does not bind to the specific `delta`.**
  `authorized_minter_policy` signs over `ctx.fields[0]` (the tx sighash) only — the
  redeemer signature says "the minter approves this transaction," not "the minter
  approves minting exactly N of this asset." The actual minted amount is bound
  separately and correctly by pass 2's conservation check (the delta the policy
  authorised must equal the transaction's real net change in that asset, or
  `ValueNotConserved` fires) — so this is not exploitable as written, but it does mean
  the signature's scope is coarser than "signs the mint amount," and depends on
  `tx.sighash` actually committing to `tx.outputs` upstream (that commitment is built
  elsewhere, outside this module, and is not something `minting.rs` verifies).
