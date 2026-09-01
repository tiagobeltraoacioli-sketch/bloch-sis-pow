# bloch-withdraw — reference withdrawal client for Bloch Genesis-4

**Distribution: partner/integrator delivery only. Do not publish publicly.**

A Rust library an exchange copies (or wraps) to send BLCH withdrawals with
**at-most-once** semantics on a chain that has no transaction ids, commits
every transfer to exactly one base fee, and drops missed transactions from
the mempool without notice. The design argument — the double-payment race
and the two rules that close it — is in
[`DOUBLE-PAYMENT-RACE.md`](DOUBLE-PAYMENT-RACE.md). Read it first; this file
is the how-to.

The crate deliberately depends on the chain's own consensus crates
(`bloch-pos-committee`, `bloch-crypto`): canonical bytes, txids, signing
roots, fee arithmetic and signatures are the code the validators run, not a
re-implementation that can drift.

## The semantics you are integrating against

| Chain fact | Consequence for you |
|---|---|
| Conservation is an equality against `gas x base_fee_of_including_block` | a transfer is valid at exactly one base fee; when the fee moves, those bytes are dead forever |
| Base fee moves at most 1/8 per block, clamped at a floor (10 msat/gas) | on a quiet chain it sits on the floor; rebuilds are rare but MUST be handled correctly |
| Missed transactions are dropped from the mempool silently | absence proves nothing; only the eUTXO set speaks |
| No txid at the RPC (`gettransaction` refuses, `-32005`) | confirmation = watching outpoints via `gettxout`/`listunspent`/`getbalance` by `script_hash` |
| Crediting line is `finalized`, not head | branch on the finality fields; never count confirmations |
| Sub-dust outputs have poisoned blocks historically | this library never emits an output below 546 sat |

`script_hash` for an address `bloch1q<40 hex hash><8 hex checksum>` is the
20 hash bytes, zero-padded to 32. `address::script_hash_of_address_str` does
this (with checksum validation) for you.

## Quickstart

```rust
use bloch_withdraw::{FileStore, HttpNode, KeyMaterial, Status, Withdrawer};

// 1. The three pieces you own.
let node  = HttpNode::new("127.0.0.1:16400");        // a node YOU validate
let store = FileStore::open("/var/lib/exchange/blch-withdrawals")?;
let key   = KeyMaterial::from_seed(&hot_wallet_seed)?; // >=32 bytes

let w = Withdrawer::new(&node, &store, &key);
println!("hot wallet address: {}", key.address());

// 2. Register the withdrawal under YOUR id (your idempotency key).
//    Pure bookkeeping: no coins move here. Calling it again with the same
//    terms is a no-op; with different terms it errors loudly.
w.create("wd-2026-08-31-000123", "bloch1q89747fe8bda0f0fbad1f107d9852bb5523d446e0db89ce31", 40_000_000)?;

// 3. Drive it. Once per slot (30 s) is plenty. Serialize ticks per id.
loop {
    let outcome = w.tick("wd-2026-08-31-000123")?;
    match outcome.status {
        Status::Paid { .. }      => break,           // credit the user's ledger NOW, not before
        Status::Cancelled { .. } => break,           // recipient was NOT paid; coins are back
        _                        => std::thread::sleep(std::time::Duration::from_secs(30)),
    }
}
```

`tick` is a state machine step, safe to repeat forever:

- pins coins to the id (durably, before signing anything),
- builds/signs an attempt at the fee the **next** block will charge
  (`next_base_fee_millisat_per_gas`) and submits it,
- on later ticks: probes whether the pinned coins are spent;
  - unspent + fee unchanged → resubmits the same bytes (idempotent),
  - unspent + fee moved → **rebuilds over the same pinned coins** (this is
    the step naive clients get wrong; see the race doc),
  - spent → waits for the finalized boundary to pass the observation, then
    re-checks and terminalizes.

Terminal states are terminal. A record never leaves `Paid` or `Cancelled`.

### Cancelling

```rust
w.cancel("wd-...")?;   // then keep ticking
```

Cancellation is not a deletion — bytes already broadcast cannot be recalled.
It builds a *sweep* (same pinned coins, paying only the hot wallet) that
conflicts with the in-flight payment; whichever finalizes is the terminal
state, and it is exactly one of `Paid` / `Cancelled`. Only treat the
withdrawal as refunded when you see `Cancelled`.

### Errors worth branching on

| Error | Meaning | Action |
|---|---|---|
| `NodeStale { behind_by_slots }` | your node admits it is behind | fix the node; retry later |
| `WalletShort { available, needed }` | the whole hot wallet cannot fund amount + fee | top up; retry later |
| `IdMismatch` | an id was reused with different recipient/amount | bug in YOUR layer — investigate, never override |
| `Rpc(..)` / `Store(..)` | transport / persistence trouble | retry later; the state machine lost nothing |

Everything else `tick` handles internally (mempool full, node refusals, fee
movement, reorgs).

## Wiring it into a real exchange

**Store.** `FileStore` (one JSON file per id, atomic rename) is the
reference. For production, implement the 3-method `Store` trait over your
database. The contract that matters: `save` durable-before-return, `load`
reads the last save, `list_ids` sees every record (coin reservation walks
it). Run `tick` for a given id under your per-id lock.

**Hot wallet discipline.** The library must be the only spender of the hot
wallet key's coins. Coins pinned by one withdrawal — and outputs its
attempts would create — are reserved from other withdrawals automatically,
but nothing can protect against an out-of-band spender with the same key.
Consolidate deposits into the hot wallet as ordinary withdrawals to your own
address if you need coin shaping.

**Node.** Run your own `bloch-pos` node and point `HttpNode` at its RPC
(default bind `127.0.0.1:16400`; the port is unauthenticated — never expose
it). Do not point this library at a shared public endpoint: those may be
load-balanced across nodes on different branches, and every guarantee here
is a statement about one honest node's committed state. The
`max_behind_slots` guard (default 4) refuses a node that is not keeping up.

**Deposits** are the same primitives in reverse: issue each user an address
from your own wallet, poll `getbalance`/`listunspent` on its script hash,
and credit only what is below the finalized boundary (same rule `tick` uses:
observe at slot `S`, wait until `finalized_epoch * 32 > S`, re-check).

**Amounts** are satoshis (1 BLCH = 10^8 sat) and arrive from the RPC as
decimal **strings** — never parse them as floats; this crate never does.

## Trying it read-only

```sh
cargo test -p bloch-withdraw                 # includes the race suite
cargo run -p bloch-withdraw --example probe -- <host:port> [bloch1q-address]
```

The example prints the chain info a withdrawal decision reads (head vs
finalized, both base fees, staleness) and a balance. It sends nothing.

## What this crate is not

- Not a wallet: no key ceremony, no mnemonic handling, no balance UI. Keys
  come in as a seed or as suite-enveloped key bytes
  (`KeyMaterial::from_parts`).
- Not a node client framework: nine typed calls over the node's HTTP/1.1
  JSON-RPC, nothing more.
- Not audited. Like the workspace it lives in — stated, not hidden. The race
  suite (`tests/race.rs`) is the strongest evidence it carries: the
  double-payment schedule is executed against the consensus arithmetic and
  loses.
