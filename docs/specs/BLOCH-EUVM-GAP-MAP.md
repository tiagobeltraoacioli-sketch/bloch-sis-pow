# BLOCH-EUVM-GAP-MAP — what `bloch-euvm` actually is, what was closed, what remains

Status:      measured, not estimated. Every count in this document was produced by
             running the code at the commit this document ships in.
Scope:       `crates/bloch-euvm/` only. Zero lines outside that directory (and this
             `docs/` tree) were touched.
Relation:    builds on `docs/specs/BLOCH-L1-EVM-REUSE-AUDIT.md` §7.1, which
             inventories this crate file-by-file. This document does not repeat that
             inventory; it records the **instruction set**, closes four of the audit's
             findings, and states plainly what is still open.

---

## 0. The framing correction that governs everything below

**`bloch-euvm` is not an Ethereum EVM.** The name misleads; the code does not.

It is a deterministic, gas-metered **stack machine for eUTXO validators**: ~30
instructions, `i128` checked arithmetic, SHA-256d and SHAKE-256 hashing, a read-only
transaction context, and signature verification delegated to a host callback. It has
**no jumps, no loops, no calls, no contract storage, no accounts, no addresses, no
`msg.sender`, no keccak-256, and no secp256k1 key model.** (It can *verify* a
secp256k1 signature via the host — `Op::VerifyEcdsa` — for hybrid BTC-key custody;
that is not an account model.)

Consequently there is **no map of "missing Ethereum opcodes and precompiles"** to
produce here, and producing one would be a category error. `ADD`/`MUL` exist because
a stack machine needs arithmetic, not because this is the EVM. There is no `SSTORE`
to be missing, because there is no contract storage to store into — non-local state
is a *commitment* (§2 below), which is a different design, not an incomplete one.

Building an actual Ethereum EVM at L1 — opcodes, precompiles, keccak-MPT accounts,
secp256k1 authorization, Ethereum gas — is the **E-track**: `ADR-040` accepts the
direction, and `BLOCH-L1-EXECUTION-PLAN.md` gate **E0** makes the authorization model
a founder decision, with **SR-2** allowing the `StateRoots` component list to be
re-frozen exactly once. Adding Ethereum semantics to this crate would decide E0/E1 by
implementation. It is out of scope by rule, not by preference.

The same rule bounds this crate the other way: it is **standalone software**. It is
referenced zero times by `bloch-pos-node` and `bloch-pos-committee`, it is an
optional dependency behind an off-by-default `euvm` feature, and nothing in this work
changes that. A live PoS chain runs from this repository.

---

## 1. The instruction set, measured

Every variant of `Op` in `src/lib.rs`, with its **base** cost (`gas_cost`) and its
**real** cost (`op_gas`, the F2 length-proportional charge actually deducted in
`run`). `words(len) = ceil(len / 32)`.

| Op | Encoding tag | Base gas | Real charge | Notes |
|---|---|---|---|---|
| `PushInt(i128)` | `0x01` | 1 | 1 | |
| `PushBytes(Vec<u8>)` | `0x02` | 1 | `1 + words(len)` | operand ≤ `MAX_OPERAND_BYTES` |
| `Dup` | `0x10` | 1 | `1 + words(top)` | the amplification vector F2 prices |
| `Drop` | `0x11` | 1 | 1 | |
| `Swap` | `0x12` | 1 | 1 | |
| `Pick(u8)` | `0x13` | 1 | `1 + words(picked)` | top-relative; see `ExpectDepth` |
| `ExpectDepth(u8)` | `0x14` | 1 | 1 | asserts exact stack depth; **part of `validator_hash`** |
| `Add` / `Sub` | `0x20` / `0x21` | 4 | 4 | `i128` checked → `Overflow` |
| `Mul` | `0x22` | 4 | 4 | checked |
| `Eq` | `0x30` | 1 | 1 | structural equality over `Val` |
| `Lt` | `0x31` | 1 | 1 | ints only |
| `Not` | `0x32` | 1 | 1 | ints only |
| `Sha256d` | `0x40` | 60 | `60 + words(top)` | |
| `Shake256` | `0x41` | 60 | `60 + words(top)` | 32-byte XOF read |
| `Size` | `0x42` | 1 | `1 + words(top)` | |
| `CtxField(u8)` | `0x50` | 1 | 1 | out of range → `BadCtxField` |
| `VerifySig` | `0x60` | 1000 | 1000 | host `SigVerifier::verify` (ML-DSA‖Falcon) |
| `Verify` | `0x61` | 1 | 1 | abort on falsy |
| `VerifyEcdsa` | `0x62` | 1000 | 1000 | host `verify_ecdsa` (secp256k1) |
| `TxOutDatum(u8)` | `0x70` | 1 | 1 | |
| `TxOutValidator(u8)` | `0x71` | 1 | 1 | |
| `TxOutValue(u8)` | `0x72` | 1 | 1 | BLCH amount only |
| `SelfValidator` | `0x73` | 1 | 1 | continuation checks |
| `SelfAsset` | `0x74` | 1 | 1 | pops a 32-byte asset id |
| `TxOutAsset(u8)` | `0x75` | 1 | 1 | pops a 32-byte asset id |

**Deliberately absent — design, not gaps:**

- **No control flow** (no jump, branch, loop, or call). Straight-line programs are
  why gas is a *static* upper bound and why the machine cannot diverge. Adding jumps
  would require a halting bound and change the whole DoS argument. Cardano-style
  validators do not need it; conditionals are expressed arithmetically.
- **No `Div`/`Mod`.** See §5 — this one is a real decision, and it is left open.
- **No state-writing instruction.** The VM decides *whether* a spend is authorized;
  it never mutates anything. State lives in the eUTXO set and in commitments.

**F2 ceilings** (`lib.rs`, enforced fail-closed before and during execution):
`MAX_STACK` 1024 · `MAX_OPERAND_BYTES` 16 MiB · `MAX_PROGRAM_OPS` 100 000 ·
`MAX_TOTAL_BYTES` 32 MiB · `MAX_TX_INPUTS` 1024 · `MAX_TX_OUTPUTS` 1024 ·
`MAX_TX_DISTINCT_ASSETS` 4096 · `MAX_TX_BYTES` 1 MiB.

---

## 2. What was closed in this pass

Four of the five findings in `BLOCH-L1-EVM-REUSE-AUDIT.md` §7.1 concerned
`src/state.rs`. Three are now closed; the fourth is unchanged and documented.

### 2.1 Finding 1 — non-incremental root (CLOSED)

The tree rebuilt itself on every `root()` call: re-hash every key and leaf, then
recurse all 256 levels. Because `Registry::set` / `HolderSet::set_balance` /
`MembershipList::add` each call `root()` after mutating, **building an n-entry
structure was quadratic.** Measured, release build, on the dev machine:

| entries | before | after | |
|---|---|---|---|
| 50 | 3.81 s | 0.12 s | |
| 100 | 21.3 s | 0.59 s | |
| 200 | 87.4 s | 1.28 s | **68×** |
| 400 | (not measured — >10 min) | 2.46 s | |

Growth went from quadratic to linear in the number of mutations.

The rewrite keeps the hash discipline byte-identical (same `KEY`/`LEAF`/`NODE` tags,
same ladder, same canonical order) and maintains three things incrementally: the
`key_hash → leaf_hash` entry set, a `BTreeMap`-keyed cache of internal-node hashes
named by the stable `(depth, prefix)` pair, and an eagerly-recomputed root. A
mutation invalidates exactly the 256 nodes on the mutated key's path. Single-entry
subtrees are never cached; they are recomputed by a closed-form spine fold, which
keeps cache memory `O(n)` rather than `O(n · 256)`.

**Roots are a committed identity** — they ride in the harness's `"EUV1"` block
section (`src/harness.rs:194` `eutxo_state_root` → `:232` `encode_eu_section`) — so
"faster" is only correct if it is also *byte-identical*. Two guards, both written
**before** the refactor:

- `tests/euvm_pinned_roots.rs` — nine tests pinning five SMT root fixtures, the
  proof shape, a `key_hash`, six `validator_hash`es and a `charter_id`, all as
  hex constants measured from the pre-refactor code.
- `tests/smt_differential_oracle.rs` — the **pre-refactor algorithm carried verbatim**
  as an independent oracle, asserting agreement at every step of a 184-mutation
  script. `#[ignore]`d for runtime only (it is quadratic by construction — that is
  what was removed); run it with
  `cargo test -p bloch-euvm --release --test smt_differential_oracle -- --ignored`.

### 2.2 Finding 5 — allow/deny gates do not bind identity (CLOSED, additively)

`gate_allows` checks only that a proof is internally consistent with the root and has
the right polarity. It never binds `proof.key` to *who is transacting*, so:

- a sanctioned party passes a deny-gate by proving non-membership of a key **they
  invented on the spot** — the sanctions list is inert; and
- a non-member passes a KYC allow-gate by **relaying a member's public proof**.

Both were already pinned as *working attacks* in `tests/audit_stateproof.rs`. Those
two tests are **unchanged**: they document what the unbound API does and does not
promise, and they are the control half for the fix.

The fix is additive: `gate_allows_bound(gate, root, proof, authenticated_id) ->
Result<(), GateError>` refuses unless `proof.key` is exactly the identity the caller
already authenticated, reporting `KeyMismatch` (an attack signature) separately from
`WrongPolarity` and `ProofInvalid`. `gate_allows` is left in place and unchanged —
it is the correct primitive when the binding genuinely happens elsewhere.

**The caller's obligation does not disappear.** This crate cannot authenticate
anyone. `authenticated_id` must be an identity the caller established itself — in a
validator that means a redeemer pubkey that just passed `Op::VerifySig`, never a
self-declared field from the spender. Passing an attacker-supplied `authenticated_id`
reintroduces the bypass one level up. That is why the binding is an explicit
parameter rather than a hidden default.

### 2.3 Finding 3 — 8 KiB uncompressed proofs (CLOSED, as a transport format)

Every `Proof` carried 256 × 32 B = 8192 B regardless of tree size, though in a tree
of `n` entries only about `log2(n)` siblings are real; the rest are empty-ladder
values the verifier can regenerate from nothing.

`CompressedProof` = a 256-bit `present` bitmap + the non-empty hashes in depth order.
A single-entry tree's witness goes from 8192 B to **32 B**. `compress`/`expand`
round-trip byte-for-byte; `verify_compressed` expands and calls the **unchanged**
`verify` rather than duplicating the fold, so the two paths cannot drift.

This is deliberately a **format beside the committed one**, not a replacement:
roots, `Proof`, and `verify` are pinned identities. `expand` refuses a witness whose
bitmap popcount disagrees with `nodes.len()`, which is what stops a truncated witness
from silently expanding into a *different* well-formed proof.

### 2.4 The un-audited compile path (documented, not removed)

`modules::compile_charter` compiles whatever it is handed — an unsatisfiable quorum,
an ambiguous minting policy, a corrupt emitted validator — into validator hashes that
become asset ids and output addresses. `compile_charter_audited` runs the
`kirpich` audit first and refuses on any `Deny` finding.

It is now documented at the definition site as the un-audited path, with the reason,
and `compile_charter_audited` named as the entry point for new code. It is **not**
marked `#[deprecated]`: downstream consumers exist, the attribute would break their
builds over a policy choice, and `kirpich.rs:16` explicitly records that the gate
never blocks this function.

### 2.5 Finding 4 — `subtree_hash` slot collisions (UNCHANGED)

The audit notes the old `subtree_hash` silently kept `entries[0]` on a ≈2⁻²⁵⁶ key-hash
collision. The incremental engine has the same property at `depth == TREE_DEPTH`
(it returns the first entry in range) and the same comment. This was left alone
deliberately: at 2⁻²⁵⁶ the branch is unreachable, and turning it into an error would
change a total function into a fallible one across the whole public surface for no
reachable benefit. It remains an assumption, now stated in two places.

---

## 3. Test-suite state, measured

Baseline at `main@751afdae`: **331 passing.** After this work: **358 passing**
(+27) plus 1 `#[ignore]`d oracle. `cargo test -p bloch-euvm --offline`.

Per file (source unit tests + integration tests):

| file | tests | | file | tests |
|---|---|---|---|---|
| `src/state.rs` | 36 | | `tests/audit_stateproof.rs` | 9 (4 + **5 new**) |
| `src/kirpich/emitted.rs` | 39 | | `tests/euvm_pinned_roots.rs` | **15 new** |
| `src/kirpich/completeness.rs` | 36 | | `tests/euvm_compressed_proofs.rs` | **7 new** |
| `src/kirpich/params.rs` | 34 | | `tests/audit_conservation.rs` | 7 |
| `src/minting.rs` | 30 | | `tests/audit_gas.rs` | 5 |
| `src/modules.rs` | 25 | | `tests/audit_panics.rs` | 5 |
| `src/kirpich/conflicts.rs` | 25 | | `tests/audit_activation.rs` | 4 |
| `src/batcher.rs` | 24 | | `tests/audit_batcher.rs` | 4 |
| `src/lib.rs` | 17 | | `tests/audit_determinism_commitment.rs` | 4 |
| `src/harness.rs` | 17 | | `tests/audit_determinism.rs` | 3 |
| `src/kirpich.rs` | 6 | | `tests/kirpich_gate.rs` | 3 |
| | | | `tests/audit_modules_supply.rs` | 2 |
| | | | `tests/audit_modules.rs` | 1 |
| | | | `tests/smt_differential_oracle.rs` | 1 (ignored) |

Dependencies remain exactly two: `sha2`, `sha3`. Nothing was added.

---

## 4. Mutation results

A green suite is not evidence that the suite tests anything. Every rule claimed above
was disabled at its source and the suite re-run: **29 mutants over three rounds — 1
null control (survived, as required) and 28 real mutations, of which 27 died on first
exposure.**

The one survivor is a first-order finding and is stated here as well as in the log:
**changing an opcode's encoding tag — which silently re-addresses every eUTXO and
renames every token whose `policy_id` derives from an affected module — was invisible
to all 352 tests**, because `compile_charter` emits only 14 of the 26 encoding tags
and nothing pinned the other 12. It is now killed by four new tests, one of which
fails to *compile* if an `Op` variant is added without being pinned.

Two defects in the mutation harness itself (fail-fast truncation, and an
mtime-preserving restore that left a stale mutant binary) are documented in the log
rather than quietly fixed: both reported all-green while measuring the wrong thing.

Full tables, per-mutant killers, and reproduction details:
`docs/specs/BLOCH-EUVM-MUTATION-LOG.md`.

---

## 5. What remains open — deliberately

Listed because a partially-correct VM that advertises completeness is worse than one
that declares its holes.

1. **No `Div`/`Mod` in the instruction set.** This is a real limitation with a
   visible consequence: `batcher.rs`'s constant-product AMM computes
   `dy = floor(dx·(10000−fee)·ro / (ri·10000 + dx·(10000−fee)))` in **Rust, outside
   the VM** (`amm_out`, `src/batcher.rs`), because the VM cannot divide. An on-chain
   AMM validator therefore cannot recompute its own price; it can only check invariants
   a multiplication can express (`new_k >= old_k`). Adding checked `Div`/`Mod` is
   tractable — division-by-zero → `VmError`, floor semantics for negatives pinned
   explicitly, gas at the `Mul` tier — but it changes the instruction set, hence every
   `encode_program` tag space and thus **`validator_hash` identity**, so it is a
   versioning decision, not a patch. **Not done. Specified here, not implemented.**

2. **No persistence for the SMT.** The backing store is still an in-memory
   `BTreeMap`, per audit finding 2. The incremental engine makes a persistent
   backing store *possible* (nodes are now named by a stable `(depth, prefix)` key,
   which is exactly what a disk index needs) but does not provide one. Doing it
   properly means a backing-store trait and almost certainly an embedded KV
   dependency; this crate has a deliberate two-dependency culture (`sha2`, `sha3`)
   and adding RocksDB unjustified would violate it. **Not done.**

3. **`ExpectDepth` coverage is thin.** Mutating it to a no-op is caught by exactly
   one test. The rule is baked into `validator_hash`, so it is identity-relevant;
   broadening its coverage means new fixtures across the module compiler and was
   judged larger than this pass should take on. See
   `BLOCH-EUVM-MUTATION-LOG.md` round 3. **Not done.**

4. **`Ctx.fields` index semantics are convention, not contract.** Which field means
   the sighash, which the committed root, which a height, is agreed only by how each
   module happens to compile. `CtxField(i)` out of range fails closed, but a *wrong*
   in-range index silently reads the wrong value. Pinning the convention as a
   documented, tested contract is worth doing. **Not done.**

5. **The compressed-proof format has no wire encoding.** `CompressedProof` is a Rust
   struct with a canonical shape, not a serialization. Anything shipping it across a
   boundary needs a byte format with its own version byte and its own KATs.
   **Not done.**

6. **`survive` / `absorb` / `die` for this crate under Genesis-4 is not decided here.**
   `ADR-040` reserves it. This pass deliberately leaves `bloch-euvm` exactly what it
   was — standalone, un-wired, off-by-default — only faster, better bounded, and
   more honestly documented.

7. **Nothing here is consensus-wired, and nothing here was made consensus-wired.**
   Zero lines changed in `bloch-pos-node` or `bloch-pos-committee`. The `state_root`
   the Genesis-4 committee actually computes is a *different* SMT with a *different*
   hash (`bloch-pos-committee/src/state_root.rs`, SHA3-256, `DS_STATE`), sharing no
   code with this one. `BLOCH-L1-EVM-REUSE-AUDIT.md` §7.1's table of three
   incompatible commitment structures remains accurate and remains unresolved.
