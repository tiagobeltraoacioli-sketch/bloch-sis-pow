# euvm-tooling

Developer tooling for **`bloch-euvm`** — the deterministic, gas-metered **eUTXO
validator VM** (validators/BaaS study, §5-quater). This crate wraps the VM's public
API in ergonomic components so you never hand-write raw `Op` vectors or juggle
`&mut u64` gas counters: an **assembler**, an **encoder/decoder**, an instrumented
**simulator**, a **transaction builder**, and a gallery of worked **example
contracts** — all runnable off-chain.

> **Status of the underlying VM:** FOUNDATION / reference. `bloch-euvm` is a
> standalone, tests-only library and is **NOT wired into node consensus**. Any real
> activation is a coordinated, height-gated hard fork. Everything here exercises the
> model off-chain — the fastest possible edit → assemble → simulate loop for contract
> authors.

---

## The mental model — eUTXO in one screen

- An **output** (`ExtOutput`) carries a multi-asset `value`, a **`validator_hash`**
  (the identity of the program that guards it), and a **`datum`** (its local state).
- To **spend** an output you *reveal* the validator program — it must hash to
  `validator_hash` — and supply a **redeemer**. The VM runs the program with the stack
  seeded `[datum, redeemer...]`; the spend is authorized **iff the program finishes
  with a truthy `Int` on top of a non-empty stack**.
- A validator can **introspect the spending transaction** through `Ctx` — the sighash,
  the outputs the tx creates, its own reserves — which is what makes *stateful*
  contracts (a pool that recreates itself with updated reserves) possible.

No account state, no clock, no I/O. Determinism is by construction: checked `i128`
arithmetic, canonical `BTreeMap` value ordering, and signature verification pushed out
to a host callback (`SigVerifier`).

The VM is re-exported at one canonical path:

```rust
use euvm_tooling::euvm;                              // == crate `bloch_euvm`
use euvm_tooling::euvm::{Op, Val, ExtOutput, Ctx};
```

---

## Install & build

This is a **standalone crate with its own `[workspace]`** (it is deliberately *not*
part of the node's root workspace). It depends on `bloch-euvm` by path.

```bash
cd euvm-tooling
cargo build
cargo test        # 230 tests + 3 doc-tests, all green
```

---

## Quickstart — write your first contract

We'll build a **hash-lock** (an HTLC preimage gate): spendable by anyone who reveals a
secret `preimage` whose `SHA-256d` equals a committed `lock`. Three steps —
**assemble → simulate → build the tx** — each using one tooling component.

### Step 1 — assemble the validator (`asm`)

The `Asm` builder has one chainable method per opcode; `build()` yields a plain
`Vec<Op>` that drops straight into an output or a tx input. `hash()` is the program's
on-chain identity.

```rust
use euvm_tooling::asm::Asm;
use sha2::{Digest, Sha256};

fn sha256d(b: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(Sha256::digest(b));
    let mut out = [0u8; 32]; out.copy_from_slice(&d); out
}

let preimage = b"the-secret-preimage";
let lock = sha256d(preimage);

// Stack seed is [preimage]; finish with Int(sha256d(preimage) == lock).
let program = Asm::new()
    .sha256d()                    // [ sha256d(preimage) ]
    .push_bytes(lock.to_vec())    // [ hash, lock ]
    .eq()                         // [ (hash == lock) ]
    .build();

let vh = Asm::from_ops(program.clone()).hash();   // the validator_hash it locks to
```

> The same program is also available ready-made as
> [`examples::hashlock(lock)`](#the-example-gallery).

### Step 2 — simulate it (`sim`)

`sim::run_program` runs a program against an initial stack and a `Ctx`, reporting the
verdict **and** the gas consumed — no node, no block. `SimResult::accepted()` /
`rejected()` / `errored()` classify the outcome. `MockVerifier` is the crate's shared,
deterministic `SigVerifier` (this contract has no signature, so `never()` is fine).

```rust
use euvm_tooling::euvm::{Ctx, Val};
use euvm_tooling::sim::{self, MockVerifier};

let ctx = Ctx::default();
let v = MockVerifier::never();

// Correct preimage → ACCEPT
let ok = sim::run_program(&program, vec![Val::Bytes(preimage.to_vec())], &ctx, &v, 10_000);
assert!(ok.accepted());

// Wrong preimage → REJECT (a clean falsy finish, not an error)
let bad = sim::run_program(&program, vec![Val::Bytes(b"wrong".to_vec())], &ctx, &v, 10_000);
assert!(bad.rejected());

println!("accepted in {} gas", ok.gas_used);
```

Accept vs. reject vs. error:
- **accept** — `Ok(true)`: finished truthy.
- **reject** — `Ok(false)`: finished cleanly but falsy / non-truthy.
- **error** — `Err(VmError)`: a fault (out-of-gas, type error, `Assert`, hash mismatch…).

### Step 3 — lock coins behind it and build the spending tx (`tx`)

`tx::ext_output(value, &program, datum)` is the single choke point that binds
`validator_hash = validator_hash(program)` — the hash can never desync from the program
that must later be revealed. `TxBuilder` composes inputs/outputs/fee/sighash into an
`EuTx` ready for `sim::simulate_tx` (a.k.a. `euvm::validate_tx`).

```rust
use euvm_tooling::euvm;
use euvm_tooling::tx::{TxBuilder, ext_output, ext_output_blch};

// DEPLOY: lock 100 BLCH behind the hash-lock.
let locked = ext_output(euvm::blch(100), &program, Val::Int(0));

// SPEND: reveal the program + preimage redeemer, recreate 99 BLCH, pay 1 fee.
let tx = TxBuilder::new()
    .sighash(b"tx-sighash".to_vec())
    .fee(1)
    .spend_input(locked, program.clone(), vec![Val::Bytes(preimage.to_vec())])
    .output(ext_output_blch(99, &program))
    .build();

// Validate the whole tx (value conservation + every input's validator) off-chain.
let gas_used = sim::simulate_tx(&tx, &v, 1_000_000).expect("tx accepts");
```

`TxBuilder::build_checked()` additionally enforces the structural resource ceilings
(input/output counts, distinct assets, operand bytes) before you validate.

---

## The example gallery (`examples`)

Every program below is a plain `Vec<Op>` and is proven — in `tests/` — to **accept on a
valid witness and reject on an invalid one** through the simulator. Each also ships a
`demo_*()` that returns a `SimResult` for the green path.

| Contract | Builder | Idea |
|---|---|---|
| **N-of-M multisig** | `multisig_n_of_m(&pubkeys, threshold)` | count verifying sigs, gate on a threshold; fail-closed sentinel `[PushInt(0)]` on degenerate configs (dup keys, zero-threshold-with-members, M>253) |
| **Absolute time-lock** | `absolute_timelock(unlock_height)` | spendable once `ctx.fields[FIELD_HEIGHT] ≥ unlock_height` |
| **Relative time-lock** | `relative_timelock(min_age)` | spendable once `height − creation_height ≥ min_age`; creation height carried in the `datum` |
| **Minimal Ustav charter** | `minimal_ustav_charter(name, cap, issuer, [g;3])` / `compile_minimal_ustav_charter(…)` | a fixed-cap Supply (mint) module + a 2-of-3 Governance multisig, compiled to a validator set via `euvm::modules::compile_charter` |
| **P2PKH-as-contract** | `p2pkh(pubkey_hash)` | hash-check a revealed pubkey, then verify its signature over the sighash |
| **Hash-lock / HTLC** | `hashlock(lock)` | reveal a preimage whose `sha256d` equals `lock` |
| **Continuation counter** | `continuation_counter()` | spend only if the tx recreates the same contract with `datum + 1` — the stateful self-recreation pattern |
| **Constant-product AMM** | `constant_product_amm(asset_a, asset_b)` | recreate the pool such that `new_a·new_b ≥ old_a·old_b` (Uniswap invariant); no tx can drain it |

### Ctx field convention (shared with `euvm::modules`)

Auth/stateful validators read fixed `ctx.fields` slots:

| Slot | Const | Contents |
|---|---|---|
| `fields[0]` | `FIELD_SIGHASH` | the tx sighash (`Bytes`) a signature signs |
| `fields[1]` | `FIELD_HEIGHT`  | the current block height (`Int`) |

A host running these validators must populate them. The `sim` helpers and the
`examples` demos do this for you.

```rust
use euvm_tooling::examples;
use euvm_tooling::euvm::Val;

// A 2-of-3 multisig accepting two valid signatures runs green through the simulator:
assert_eq!(examples::demo_multisig_n_of_m().result, Ok(true));

// A minimal Ustav charter compiles deterministically; its policy id is the
// Supply module's validator hash.
let token = examples::compile_minimal_ustav_charter(
    "USTAV", 1_000_000, b"issuer".to_vec(),
    [b"gov-1".to_vec(), b"gov-2".to_vec(), b"gov-3".to_vec()],
);
assert!(token.policy_id().is_some());
```

---

## Component reference

| Module | What it gives you |
|---|---|
| **`asm`** | `Asm` chainable builder (one method per opcode) + the `prog![…]` macro. `build()` → `Vec<Op>`, `hash()` → `validator_hash`, `encode()` → canonical bytes. |
| **`encode`** | hex/text codecs: `program_to_hex` / `hex_to_program`, `decode_program` (the hand-written inverse of `encode_program`), `val_to_string` / `parse_val`, `op_to_string` / `program_to_asm` disassembly, `ext_output_to_string`. All fallible codecs return `EncodeError`. |
| **`sim`** | `run_program`, `run_spend`, `simulate_tx`; the `SimResult { result, gas_used, gas_limit }` verdict; and the shared `MockVerifier` (`always()` / `never()` / `accepting(triples)` / `.with_triple(…)`). |
| **`tx`** | `ext_output` / `ext_output_blch` (hash-binding output constructors) and the fluent `TxBuilder` (`sighash`, `fee`, `spend_input`, `output`, `output_blch`, `build`, `build_checked`). |
| **`examples`** | the worked validator gallery above, plus `demo_*()` green-path runners. |

Because `Op` derives `Clone, Debug` **only** (no `PartialEq`/`Eq`), you cannot `==` two
programs — compare by `validator_hash` or `encode::program_to_hex(a) == …(b)`.

---

## Opcode reference

Stack top is on the **right**. "Gas" is the *base* cost; byte-copying ops add
`⌈len/32⌉` per operand word (see [Gas model](#gas-model)). 25 opcodes total; index ops
carry a `u8` (indices 0–255).

**Push / literals** — `PushInt(i128)` `→ n` (gas 1); `PushBytes(Vec<u8>)` `→ b`
(gas `1+⌈len/32⌉`).

**Stack** — `Dup` `a → a a` (`1+⌈len/32⌉`); `Drop` `a →` (1); `Swap` `a b → b a` (1);
`Pick(u8)` copy the element `n` below the top to the top, `Pick(0)==Dup` (`1+⌈len/32⌉`).

**Arithmetic** (checked `i128`, Ints only; `Overflow` on wrap) — `Add` / `Sub` / `Mul`
`a b → (a∘b)` (gas 4).

**Comparison / logic** — `Eq` `a b → Int(a==b)` (Int **or** Bytes, structural); `Lt`
`a b → Int(a<b)` (Ints only); `Not` `a → Int(a==0)` (Int only). All gas 1.

**Hashing / size** — `Sha256d` / `Shake256` `b → h(32)` (gas `60+⌈len/32⌉`); `Size`
`b → Int(len)` (`1+⌈len/32⌉`).

**Context introspection** (gas 1) — `CtxField(u8)` push `ctx.fields[i]`
(`BadCtxField` if OOB); `TxOutDatum(u8)` / `TxOutValidator(u8)` / `TxOutValue(u8)` read
`ctx.tx_outputs[i]` (`BadTxOut` if OOB); `SelfValidator` push own validator hash;
`SelfAsset` pop a 32-byte asset id → push its amount in `self_value`; `TxOutAsset(u8)`
same for `tx_outputs[i]`.

**Signatures & assertion** — `VerifySig` `msg pk sig → Int(ok)` (gas 1000, PQ
ML-DSA-65‖Falcon-1024 via `SigVerifier::verify`); `VerifyEcdsa` same via
`verify_ecdsa` (secp256k1, hybrid BTC-key contracts); `Verify` `a →` pop top and
**abort with `Assert`** if not truthy (gas 1).

`VerifySig`/`VerifyEcdsa` **push a boolean** (they never abort). Follow with `Verify`
to make a bad signature reject, or sum several booleans for an n-of-m threshold.

### Tag bytes (for hand-encoding)

`PushInt 0x01`, `PushBytes 0x02`, `Dup 0x10`, `Drop 0x11`, `Swap 0x12`, `Pick 0x13`,
`Add 0x20`, `Sub 0x21`, `Mul 0x22`, `Eq 0x30`, `Lt 0x31`, `Not 0x32`, `Sha256d 0x40`,
`Shake256 0x41`, `Size 0x42`, `CtxField 0x50`, `VerifySig 0x60`, `Verify 0x61`,
`VerifyEcdsa 0x62`, `TxOutDatum 0x70`, `TxOutValidator 0x71`, `TxOutValue 0x72`,
`SelfValidator 0x73`, `SelfAsset 0x74`, `TxOutAsset 0x75`.

Operands: `PushInt` = `i128::to_le_bytes` (16 bytes); `PushBytes` = `u32` LE length +
bytes; index ops = 1 byte. `validator_hash = SHA-256d(encode_program(program))`.

---

## Gas model

Gas is charged up-front, before each op, from a caller-supplied budget (`&mut u64`);
underflow aborts with `VmError::OutOfGas`. Base costs: sig checks **1000**, hashes
**60**, arithmetic **4**, everything else **1**. Byte-copying ops (`PushBytes`, `Dup`,
`Pick`, `Sha256d`, `Shake256`, `Size`) add **one gas per 32-byte word** so a 1-byte and
an 8-MB operand can't cost the same — e.g. hashing 100 bytes = `60 + 4 = 64`.
`sim` computes `gas_used = gas_limit − remaining` for you.

**Hard ceilings** (fail-closed, deterministic): `MAX_OPERAND_BYTES` 16 MiB →
`OperandTooLarge`; `MAX_PROGRAM_OPS` 100 000 → `ProgramTooLarge`; `MAX_TOTAL_BYTES`
32 MiB live stack → `MemoryLimitExceeded`. Tx-level (via
`check_tx_resource_limits`, before any gas): `MAX_TX_INPUTS`/`MAX_TX_OUTPUTS` 1024,
`MAX_TX_DISTINCT_ASSETS` 4096, `MAX_TX_BYTES` 1 MiB → `TxError::ResourceLimit`.

---

## Errors

`VmError` (per-program): `OutOfGas`, `StackUnderflow`, `StackTooDeep`,
`TypeError(&str)`, `Overflow`, `BadCtxField(u8)`, `BadTxOut(u8)`,
`ValidatorHashMismatch`, `Assert`, `EmptyResult`, `MemoryLimitExceeded`,
`OperandTooLarge`, `ProgramTooLarge`.

- An **empty final stack** is `EmptyResult`; a **`Bytes` on top** at the end is a
  `TypeError` (truthiness needs an `Int`). Popping from an empty stack mid-run is
  `StackUnderflow`.

`TxError` (whole-tx): `ValueNotConserved { asset, in_sum, out_plus_fee }`,
`ValidatorRejected(idx)`, `Vm(idx, VmError)`, `OutOfBlockGas`,
`ResourceLimit { what }`.

`EncodeError` (codecs): `BadHex`, `BadLength(exp, got)`, `BadValSpec`, `BadInt`,
`UnexpectedEof`, `UnknownTag(u8)`, `OperandTooShort { want, have }`.

---

## Crate layout

```
euvm-tooling/
├── Cargo.toml            # standalone [workspace]; depends on ../crates/bloch-euvm by path
├── README.md             # this quickstart (consolidates the former DOCS.md + EXAMPLES-*.md)
├── src/
│   ├── lib.rs            # module decls + `pub use bloch_euvm as euvm`
│   ├── asm.rs            # Asm builder + prog! macro
│   ├── encode.rs         # hex/text codecs + decode_program (inverse of encode_program)
│   ├── sim.rs            # run_program / run_spend / simulate_tx + MockVerifier
│   ├── tx.rs             # ext_output / ext_output_blch + TxBuilder
│   └── examples.rs       # the worked validator gallery + demo_*()
└── tests/                # per-component integration tests, all from the public surface
    ├── asm_tests.rs      encode_tests.rs   sim_tests.rs
    ├── tx_tests.rs       examples_tests.rs  docs_tests.rs
```

`license = "AGPL-3.0-or-later"`.
