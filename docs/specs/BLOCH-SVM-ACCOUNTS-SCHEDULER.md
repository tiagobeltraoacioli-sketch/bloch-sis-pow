<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch SVM Front 2 — Account Model and Deterministic Parallel Execution

```
Document:   BLOCH-SVM-ACCOUNTS-SCHEDULER
Status:     SPEC — Front 2 of the SVM-like execution effort. No code exists.
            Nothing in this document is consensus-active; activation follows
            the LEAKED_ROSTER_ACTIVATION_EPOCH idiom (params.rs:106) and the
            single-re-freeze rule of BLOCH-L1-EXECUTION-PLAN §0 (SR-2).
Created:    2026-08-21
Owner:      Front 2 lead (accounts + scheduler). The bytecode/loader/verifier
            surface is explicitly NOT owned here — see §1.2.
Normative:  BLOCH-POS-INTERFACES.md (purity + u128 arithmetic contracts),
            crates/bloch-pos-committee/src/state_root.rs (§5.5 discipline,
            foreign-root-leaf pattern), BLOCH-L1-FEE-MARKET.md (one fee
            market), BLOCH-L1-EXECUTION-PLAN.md (SR-2, X1 re-freeze)
Relates:    ADR-040 (EVM-at-L1 direction — see §10, this overlaps and the
            overlap is escalated, not hidden), docs/FLEET-BRIEF-2026-08-11.md
            (the "Solana is not natively EVM" premise correction)
```

## 0. Honest scope statement — read first

Solana's SVM is a bytecode VM (SBF), a verifier, a JIT, ~150 syscalls, a
calibrated compute-unit schedule, native programs, and a production parallel
scheduler, built over six years. **This front does not deliver that and does
not claim to.** It delivers the two things that make the SVM architecturally
different from the EVM, specified to consensus grade:

1. an **account model** where state is partitioned into addressable entries a
   transaction must *declare* before touching, and
2. a **scheduler** that exploits those declarations to execute
   non-conflicting transactions in parallel while producing **byte-identical
   results to sequential execution in canonical order**, on any thread count.

Program execution itself is an interface (`ProgramExecutor`, §6) behind which
v0 ships only *native* Rust programs (a System-program subset). No SBF
bytecode runs. Therefore, binding rule:

> **The words "Solana-compatible" are banned from every document, comment,
> and commit message of this effort** until a real program compiled to SBF
> executes under this runtime — and if that day comes, the claim must name
> the exact program and the exact limits. Addresses here are SHA3-256 hashes
> of PQ hybrid keys, not ed25519 points (§3.1); no Solana wallet, SDK, or
> tool will ever talk to this plane unmodified. "SVM-shaped", not
> "SVM-compatible".

The list of everything deliberately missing is §11. It is part of the spec,
not an appendix of shame.

## 1. Position in the stack

### 1.1 What exists today (verified 2026-08-21)

- Genesis-4 L1 (live mainnet) has **no VM and no contracts**: the transaction
  set is closed (Transfer, Deposit, Exit, Delegate, SlashingEvidence) and an
  output's `script_hash` is SHA3-256 of a pubkey (`transition.rs`, `owns()`).
  There is nowhere for a program to live without a consensus change.
- The only running VM in the stack is `l2/bloch-l2-evm` (bloch-protocol
  repo), self-described "SCAFFOLD, UNAUDITED, not a working L2".
- `crates/bloch-euvm` (this repo) contains the Ustav/Kirpich charter
  machinery — documented "FOUNDATION, tests-only, NOT consensus-wired" in
  BLOCH-L1-EXECUTION-PLAN §3/U0 (with a known stale-doc conflict against the
  fleet brief, flagged there). It is not an SVM and this front does not
  touch it.
- No file in either repo mentions SVM/SBF/eBPF/sealevel. This is greenfield.

### 1.2 Front boundary

Front 2 owns: account representation and commitment (§3–§4), transaction
format and the access-enforcement boundary (§5–§6), the scheduler (§7),
the compute meter *accounting rules* (§6.3), and the determinism test
obligations (§8). Front 2 does NOT own: the bytecode format, verifier, or
interpreter (another front, or absent — either way behind `ProgramExecutor`);
the eUTXO↔SVM value bridge (§9.2, needs an E1-point-4-style ruling); RPC;
fee-market *constants* (owned by `fee_market.rs`, §9.3).

## 2. The property that governs everything

This plane will one day sit under consensus: two nodes executing the same
block MUST produce the same bytes. This codebase already paid for violating
that once — `expected_bits` read node-local mutable state and split the
mainnet on 2026-08-08 with identical binaries — and `state_root.rs` §5.5 now
makes the rule structural. Every design decision below is downstream of:

> **D-0.** The post-state of a block is a pure function of
> (parent committed state, ordered block body). No clock, no I/O, no cache
> whose staleness can differ between nodes, no iteration order that depends
> on memory layout, no float, no thread-count-dependent result.

Concrete bans, enforced by lint and review in the future crate:
`f32`/`f64` (`#![deny(clippy::float_arithmetic)]`, and a `cargo deny` ban
on the usual float-bearing maths crates, because a dependency's float is
still a float); `HashMap`/`HashSet` anywhere a result is derived from iteration
(BTreeMap/BTreeSet only); unchecked arithmetic (checked or explicitly
saturating with a written argument, sums in `u128` per the interfaces
contract); `panic!`/`unwrap` in the execution path (typed errors only —
a panic in one node's execution path is a liveness split); recursion whose
depth is input-controlled (v0 has no CPI, §11, and instruction decoding is
iterative).

## 3. The account

### 3.1 Addresses — the PQ divergence from Solana, stated up front

A Solana address IS a 32-byte ed25519 public key. A Bloch hybrid key
(ML-DSA‖Falcon) is ≈3.7 KB, so the address cannot be the key. Following the
exact trick the eUTXO plane uses (`script_hash` stores the hash; the ≈3.7 KB
key only hits the wire when spending — `TransferInput.pubkey`):

```
wallet address:  SHA3-256(DS_SVM_ADDR ‖ 0x00 ‖ hybrid_pubkey_bytes)
PDA:             SHA3-256(DS_SVM_ADDR ‖ 0x01 ‖ program_id ‖ seed_count:u8
                          ‖ (len:u16_le ‖ seed)* )
```

`DS_SVM_ADDR = *b"BLCH4:SVMADDR\0\0\0"` — 16 bytes, the params.rs §6.1
convention, no tag a prefix of another. Why the marker byte: Solana keeps
PDAs unspendable by requiring the address to be *off-curve*; hashes have no
curve, so the guarantee is rebuilt by domain separation — a PDA lives in the
`0x01` preimage space, a wallet address in `0x00`, and producing a hybrid key
whose `0x00`-tagged hash equals a given PDA is a second-preimage attack on
SHA3-256. Seeds are length-prefixed individually because `["ab","c"]` and
`["a","bc"]` must not collide (a real bug class in seed schemes). No bump
search in v0: the PDA is whatever the hash says; there is no on-curve case to
skip, so Solana's find-bump loop has nothing to do here. (`create_with_seed`
compatibility is consequently out — §11.)

### 3.2 Representation

```rust
/// One SVM-plane account. Field order is the canonical serialization order.
pub struct Account {
    /// Balance in satoshis. u64 per entry — the same width the committed
    /// EutxoEntry uses — because no single account may hold more than
    /// u64::MAX sat; SUMS are u128 end-to-end (interfaces.rs arithmetic
    /// contract: the danger was always the products/totals, not one entry).
    pub balance_sat: u64,
    /// The program that owns this account. Only the owner may debit
    /// balance_sat or mutate data (§6.2). SYSTEM_PROGRAM_ID for wallets.
    pub owner: [u8; 32],
    /// Replay protection for fee payers (§5.3). Increments on every
    /// transaction this account fee-pays, aborted or not.
    pub nonce: u64,
    /// True if this account is a program. v0: only genesis-registered
    /// native programs; immutable thereafter (no deploy path — §11).
    pub executable: bool,
    /// Program-owned bytes. Hard cap MAX_ACCOUNT_DATA = 10 KiB in v0 —
    /// deliberately small; raising it is a parameter change with a fee
    /// argument attached (§4.2), not a tweak.
    pub data: Vec<u8>,
}
```

Canonical serialization: fixed field order as above, integers little-endian
fixed width, `data` prefixed by `u32` length, decoder rejects trailing bytes
— the `transition.rs` codec idiom exactly. No floats exist in the structure,
so "how do two architectures serialize this" has one answer.

What is deliberately NOT here: `rent_epoch` (no rent clock — the state-growth
cost is a bond, §4.2, precisely because a rent *clock* is a consensus input
this design refuses to add); Solana's `executable_data` split and loader
versioning (no loaders — §11).

## 4. Commitment — where the linear state-root cost bites

### 4.1 One foreign root leaf

The SVM plane commits as **one leaf** in the existing consensus SMT — the
pattern `state_root.rs` already uses three times (`TAG_TAINT_ROOT`, the two
Coherence roots): a root of a tree another module owns.

```
consensus SMT leaf:  key = derive_key(TAG_SVM_ROOT, &[]),
                     value = hash_value(&svm_root)
```

`TAG_SVM_ROOT` is a §Boundary-7 change to the closed component list, and the
plan's SR-2 rule binds: it lands **in the single X1 re-freeze round** of
BLOCH-L1-EXECUTION-PLAN §4, alongside the EVM and charter leaves (or the
X1 escape hatch applies: shipped reserved-zero, the `taint_root` precedent).
Until that round, every Front-2 KAT pins `svm_root` itself, never the outer
`state_root` — so this front cannot leak churn into anyone else's KATs.

The inner tree ("SVM tree") reuses the **identical construction** as the
consensus SMT — fixed depth 256, no path compaction, leaf/node/empty/key/
value preimage markers — under its own domain separator
`DS_SVM_STATE = *b"BLCH4:SVMSTATE\0\0"`. Same construction because the
compact-SMT soundness bugs `state_root.rs` documents (extension-node rules)
do not get less dangerous the second time; own separator because an SVM leaf
must never be presentable as a consensus leaf in a proof. Preference order:
export and reuse `state_root::Smt` (it is already `pub`); only if that drags
frozen surfaces, copy it — and then a KAT cross-checks both implementations
against the same vector set forever.

Tree key: the account address, used directly after key derivation
(`SHA3(DS_SVM_STATE ‖ MARK_KEY ‖ TAG_SVM_ACCOUNT ‖ address)`). Leaf value:
`SHA3(DS_SVM_STATE ‖ MARK_VALUE ‖ canonical_serialization(account))`.

### 4.2 The cost model, from the measured numbers

The consensus state root is **linear in entry count and rebuilt per block**:
measured 2026-08-21 at 0.59 s/block for 452,726 eUTXO entries
(engine.rs:1609), with a perf profile putting 50.7% of a replaying
validator's CPU in the keccak permutation. Three consequences are load-
bearing design decisions, not optimizations to do later:

1. **Per-account leaf caching is in-spec from day one**, on the exact
   precedent of `build_state_tree_with_eutxo_leaves`: a leaf is a pure
   function of one account, the tree fold recomputes the root from leaves
   every time, and no cached *root* ever outlives its leaves. §5.5 stays
   intact — what is cached is re-derivable per-entry data, and the
   determinism test suite (§8) includes a "cold rebuild equals cached
   rebuild" property test as the control.
2. **State growth is priced as a refundable bond, not rent.** Creating an
   account locks `ACCOUNT_BOND_FLAT + data.len() * ACCOUNT_BOND_PER_BYTE`
   satoshis in the account (unspendable below the bond floor); deleting the
   account (balance to zero, data freed, owner consents) refunds it. Every
   entry makes every future block ~1.3 µs slower for every validator
   forever (0.59 s / 452,726), so the thing being priced is *entry-count
   and byte-count*, and a bond prices exactly that without introducing a
   rent clock into consensus. Constants live in `fee_market.rs` and are
   priced there with a written derivation, not invented here.
3. **An incremental (persistent-node) SMT is declared future work, not
   assumed.** At v0 account counts (thousands) a full fold of cached leaves
   is well under a millisecond of the block budget; the moment measurements
   say otherwise, the incremental tree is a performance change that must
   ship with a "incremental root == cold-recomputed root" property test as
   its consensus-safety argument. Writing this down now prevents the
   classic failure: someone adds a node cache under deadline pressure
   without the equivalence test, and that cache is `expected_bits` again.

## 5. The transaction

### 5.1 Format

```rust
pub struct SvmTransaction {
    /// Format version. 0. Bump = consensus change, flag-day rules.
    pub version: u8,
    /// Compute units requested (§6.3). Capped by MAX_TX_COMPUTE_UNITS;
    /// priced into gas up front (§9.3). Declared, not discovered, so the
    /// scheduler and fee market know the worst case before running.
    pub compute_budget: u32,
    /// Replay protection: must equal the fee payer's committed nonce (§5.3).
    pub nonce: u64,
    /// The flat, DEDUPLICATED account list. Canonical section order:
    ///   [ writable signers | readonly signers | writable | readonly ]
    /// accounts[0] is the fee payer and MUST be a writable signer.
    pub accounts: Vec<AccountMeta>,     // AccountMeta = { address: [u8;32] }
    /// Section boundaries, Solana-header style: (n_ws, n_rs, n_w) — the
    /// readonly tail is implied. Redundant encodings of the same boundary
    /// are impossible because the counts ARE the encoding.
    pub header: (u8, u8, u8),
    pub instructions: Vec<Instruction>, // { program_index: u8,
                                        //   account_indices: Vec<u8>,
                                        //   data: Vec<u8> }
    /// One hybrid (ML-DSA‖Falcon) witness per signer section entry, in
    /// section order. pubkey travels here — the state stores only hashes.
    pub witnesses: Vec<Witness>,        // { pubkey: Vec<u8>, sig: Vec<u8> }
}
```

Signing root: `SHA3-256(DS_SVM_TX ‖ canonical_bytes_without_witnesses)`,
`DS_SVM_TX = *b"BLCH4:SVMTX\0\0\0\0\0"`. Txid: `SHA3-256(DS_SVM_TXID ‖
signing_root)` — mirroring the DS_SPEND/DS_TXID split and its rationale.

### 5.2 Structural validity (mempool AND block validation — both, always)

Reject, with typed errors, any transaction where: an address appears twice
in `accounts` (the readonly-and-also-writable aliasing dodge — a real
Solana CVE class — dies here, at parse time); any `program_index` or
`account_indices` entry is out of range; the program account is not
`executable`; a signer witness pubkey does not hash (with the `0x00`
address tag) to its section's address; the fee payer section is empty;
counts in `header` are inconsistent with `accounts.len()`; serialization
has trailing bytes; `compute_budget > MAX_TX_COMPUTE_UNITS`;
`data.len()`, `accounts.len()`, or `instructions.len()` exceed their hard
caps (v0: 64 accounts, 16 instructions, 1 KiB instruction data — small on
purpose; each raise needs a cost argument).

### 5.3 Replay protection: nonce, not recent-blockhash

Solana's recent-blockhash window imports a consensus-visible sliding time
window and a queue of recent hashes into validation. A per-account `u64`
nonce on the fee payer is strictly simpler and has no window edge cases:
tx valid iff `tx.nonce == fee_payer.nonce`; commit (success OR abort)
increments the nonce and debits the fee. Cost accepted knowingly: one
fee payer cannot have two transactions in flight that don't serialize —
which the scheduler already forces anyway, because the fee payer is
writable in both (§7.2). Durable-nonce ergonomics: §11.

## 6. Execution and the access-enforcement boundary

**This section is the entire security model of the parallel plane.** The
scheduler (§7) proves nothing on its own: its equivalence theorem takes as a
*premise* that a transaction touches only what it declared. If enforcement
leaks, parallelism is state corruption. Hence two independent layers — one
structural, one verified — and the rule that no future change may weaken
either without strengthening the other.

### 6.1 Layer 1 — capability-style structural enforcement

The executor never sees the state. For each transaction the runtime builds a
`TxContext` containing **copies** of exactly the declared accounts:

```rust
pub trait ProgramExecutor {
    /// Pure. No clock, no I/O, no state beyond the arguments. `env` carries
    /// slot/epoch READ from the parent's committed state — never wall time.
    fn execute(
        &self,
        program_id: &[u8; 32],
        instruction_data: &[u8],
        accounts: &mut [AccountHandle<'_>],  // only the declared ones exist
        meter: &mut ComputeMeter,
        env: &ExecEnv,
    ) -> Result<(), ProgramError>;
}
```

`AccountHandle` is the capability: for a readonly-declared account it is
constructed without the mutation methods ever being reachable (type-level —
a `View` never coerces to a `Mut`); for a writable account, mutators enforce
the owner rules (§6.2) on every call. There is no API — none — through which
a program names an address and receives an account. Undeclared state is not
"forbidden", it is *unrepresentable* in the interface. This is the property
that must survive every future interpreter front: SBF, if it ever lands,
gets its account slice from this same context.

### 6.2 Owner rules (the Solana subset that is kept)

Enforced by the mutators, checked again at commit: only the owner program
may debit `balance_sat`, mutate `data`, or reassign `owner` (reassign only
with data zeroed — the Solana rule, kept because reassigning nonempty data
transfers meaning between trust domains); anyone may credit a **writable**
account; crediting a readonly account is impossible (layer 1) and rejected
(layer 2); system-owned accounts (wallets) are debited only with their
holder's signature present in the signer sections. `executable` accounts
are fully immutable in v0.

### 6.3 Compute meter

Deterministic integer accounting, charged **before** each unit of work
(charge-then-do, so exhaustion cannot depend on how far a non-deterministic
"do" got): per-instruction-dispatch flat cost, per-syscall-equivalent costs
for the native-program helper set, per-byte costs for data reads/writes and
hashing. Exhaustion is a typed abort at an exactly reproducible meter
reading — §8 tests pin this. The schedule is v0-honest: calibrated well
enough to bound worst-case block time, NOT claimed equivalent to Solana's
CU schedule (§11). Overflow anywhere in the meter = abort, never wrap.

### 6.4 Layer 2 — commit-time verification (defense in depth)

After `execute` returns, before anything merges into state, the runtime
verifies over the `TxContext`:

1. **Readonly integrity**: SHA3 of each readonly account's canonical
   serialization, taken before execution, equals the hash after. Layer 1
   should make drift impossible; layer 2 makes a *runtime bug* a detected
   abort instead of silent corruption. Belt and suspenders is the correct
   posture at a consensus boundary — this is the check that turns "we
   believe the type system" into "we verified the bytes".
2. **Conservation**: `Σ pre(balance of writable set) == Σ post(...) +
   fee_burned_or_paid` in `u128`. The SVM plane mints nothing, ever;
   value enters only via the (future, §9.2) plane bridge. A program that
   conjures a satoshi is an abort, not a feature.
3. **Bond floor**: every surviving account respects §4.2's bond; every
   deleted account's bond was refunded to a declared writable account.

Any failure ⇒ **transaction-level abort** (fee still charged, nonce still
bumped, all other effects discarded). Never block-level: a block-level
reject would let one adversarial transaction halt the chain — the same
liveness argument U1 point 2 records for charters.

Whole-state protection is by construction: the commit step merges back
*only* the writable entries of the `TxContext`. There is no code path that
writes an address the transaction did not declare — the merge iterates the
declared-writable list and nothing else.

## 7. The scheduler

### 7.1 Conflict relation

Over **declared** sets only (execution outcomes must not influence the
schedule — determinism): `W(t)` = writable addresses, `R(t)` = readonly
addresses. `conflict(a, b) ⟺ W(a)∩W(b) ≠ ∅ ∨ W(a)∩R(b) ≠ ∅ ∨
R(a)∩W(b) ≠ ∅`. Read-read never conflicts — that is the entire point of
declaring.

### 7.2 Wave layering — deterministic by being a pure function of the list

Canonical order = transaction order in the block body, indices 0..n.

```
wave(t_i) = 1 + max{ wave(t_j) : j < i, conflict(t_j, t_i) }   (max ∅ = -1)
```

Longest-path layering of the precedence DAG: a pure function of (list,
declared sets). No timing, no thread identity, no work-stealing order can
enter the schedule, because the schedule is computed *before* any execution
starts. Aborted transactions keep their declared sets in the layering — the
schedule cannot depend on outcomes (a node that knew the outcome early would
schedule differently ⇒ split).

Execution: waves run strictly in order; within a wave, transactions run on
however many threads exist — 1 or 128 — and results are **committed in
canonical index order** after the whole wave completes. Within a wave the
writable sets are pairwise disjoint and no one reads what another writes
(enforced sets, §6), so merge order provably cannot matter; committing in
canonical order anyway costs nothing and removes the temptation for any
future aggregate to be order-sensitive. Block-level aggregates (fee total to
the proposer ledger) fold in canonical index order for the same reason:
u128 addition commutes today; the *rule* is what stops a non-commutative
aggregate from sneaking in tomorrow.

Fee payers are writable signers (§5.1), so two transactions sharing a fee
payer conflict and serialize across waves — which is exactly what the nonce
scheme (§5.3) needs to stay coherent without any special case.

### 7.3 The equivalence theorem, and what it stands on

> **Claim.** For any block body, parallel execution under §7.2 produces a
> post-state byte-identical to sequential execution in canonical order,
> for every thread count ≥ 1.
>
> **Sketch.** Induction over waves. Transactions in wave k conflict only
> with transactions in waves < k (layering definition), which are fully
> committed before wave k starts. Within wave k, any two transactions have
> disjoint write sets and neither reads the other's writes **because the
> runtime confines each to its declared sets (§6)** — so as state
> transformers they commute, and any interleaving, including the canonical
> sequential one, yields the same merged post-state. Commit order within a
> wave is fixed canonically besides. ∎
>
> The bolded premise is the whole theorem. The scheduler is exactly as
> correct as the access-enforcement boundary — which is why §6 carries two
> independent layers and why §8's adversarial tests attack the boundary,
> not the scheduler.

An **undeclared conflict** is therefore not a scheduling concern at all: it
is an enforcement event. A transaction that tries to reach outside its
declaration is aborted by §6 before its effects exist; it cannot corrupt a
concurrently executing transaction because it never held a handle to any
shared undeclared state — there is nothing to race on.

### 7.4 What the scheduler refuses to do

No dynamic re-scheduling on abort, no optimistic execution with rollback
(Block-STM), no priority lanes, no local fee markets. Each is real
engineering with real determinism hazards; each is listed in §11 with what
adopting it would require. v0 is the provable core.

## 8. Test obligations (spec-level; the crate does not merge without them)

Per the repo rule, **every negative test carries a control half** — the same
scenario with the one illegal ingredient made legal, passing — so the
negative cannot pass for the wrong reason. No test touches network or clock.

1. **Sequential/parallel equivalence (property test).** Generated workloads
   with tuned conflict density (including all-conflict and no-conflict
   extremes), executed with 1, 2, 4, 8 threads and sequentially: identical
   `svm_root` bytes and identical per-tx result codes. Thread count is part
   of the test matrix, not the machine's accident.
2. **Undeclared write attack.** A test-native program that, handed handles,
   attempts mutation of a readonly-declared account through every reachable
   surface ⇒ typed abort, layer named. **Control:** identical program,
   account declared writable ⇒ succeeds, state changes verified.
3. **Undeclared read is unrepresentable.** Compile-fail test (trybuild)
   pinning that `AccountHandle` for an undeclared address cannot be
   constructed by an executor. **Control:** the declared construction
   compiles.
4. **Aliasing rejection.** Duplicate address across sections ⇒ structural
   reject. **Control:** same two-account transaction, distinct addresses ⇒
   accepted.
5. **Meter determinism.** A program whose budget exhausts mid-stream aborts
   at an identical meter reading and identical post-root across thread
   counts and repeated runs. **Control:** budget + exact-cost-of-next-step
   ⇒ completes.
6. **Conservation attack.** Test-native program crediting itself from thin
   air ⇒ commit-time abort. **Control:** balanced transfer ⇒ commits.
7. **Layering KAT.** A fixed 12-transaction body with a designed conflict
   graph ⇒ pinned wave assignment bytes. Any scheduler change that moves a
   transaction between waves is a visible KAT change, therefore a review
   event.
8. **Leaf-cache equivalence.** Cold full tree rebuild == cached-leaf
   rebuild for randomized account sets (the §4.2-1 control), plus the
   iteration-order test inherited from `state_root.rs`: same accounts
   inserted in shuffled orders ⇒ same root.
9. **Serialization canonicity.** Round-trip plus trailing-byte rejection
   plus a mutation sweep (every field perturbed ⇒ root changes) — the
   `state_root.rs` test idiom, reused.

## 9. Consensus integration — all inert until flag-day

1. **Activation.** `SVM_ACTIVATION_EPOCH: u64 = u64::MAX` in `params.rs`,
   the exact `LEAKED_ROSTER_ACTIVATION_EPOCH` idiom: compiled-in, dead by
   default, one constant flipped at a coordinated flag-day with the fleet
   rebuilt first as a precondition. Below the epoch, SVM transactions are
   invalid in blocks and `TAG_SVM_ROOT` (if already frozen by X1) commits
   the empty-tree constant.
2. **Value flow between planes** (eUTXO ↔ SVM accounts) is the analog of
   E1 point 4 and is NOT decided here: it needs the same
   supply-conservation-across-planes invariant and a founder-visible
   ruling. v0 development and tests fund accounts from a genesis-style
   manifest only.
3. **One fee market.** SVM compute units convert to L1 gas
   (`INSTRUCTIONS_PER_GAS` precedent, fee_market.rs:104) and SVM
   transactions pay the same base fee the committed state fixes — never a
   second fee constant (the E1 point-2 rule, adopted verbatim). New
   `TxClass::Svm` variant priced in `fee_market.rs` with a written
   derivation, alongside the account bond (§4.2).
4. **`PosTransaction` growth** (a new variant carrying an SVM batch) and
   the body-root change it implies are X2-shaped work: they land in the
   change-controlled transition files, in one scheduled PR, against
   X1-frozen commitments — never piecemeal.

## 10. The overlap this spec does not hide

ADR-040 and BLOCH-L1-EXECUTION-PLAN record a standing founder direction:
**EVM at L1** (Track E), including a frozen plan for the single StateRoots
re-freeze. An SVM-shaped plane is a *second* execution plane pointed at the
same L1. These are not technically exclusive — the foreign-root-leaf pattern
holds any number of planes — but they compete for: the X1 re-freeze slot
(whose whole point was "exactly once"), the fee-market surface, DEV
attention, and the public story of what Bloch's execution layer is. **This
is a PMO/founder-level decision that must be taken explicitly**: SVM
replaces Track E, joins it, or one of them is shelved. This spec is written
to be droppable into the X1 round if the answer is "joins"; it makes no
claim to have won that argument, and building both to consensus grade in
parallel should be priced honestly as two consensus surfaces.

## 11. Declared missing — the boundary of the claim

Absent, by decision, with what adoption would cost:

- **SBF/eBPF bytecode, verifier, JIT, syscall surface** — the actual
  Solana program runtime. Behind `ProgramExecutor`; adopting it is its own
  multi-quarter front with a verifier soundness burden. Until then only
  genesis-registered native programs execute.
- **Solana compatibility of any kind** — addresses (PQ hash vs ed25519),
  signatures (hybrid PQ vs ed25519), tx wire format, RPC, SDKs, Anchor.
  None of it. See §0.
- **CPI (cross-program invocation)** — v0 instructions call one program
  each, no nesting. CPI multiplies the enforcement surface (privilege
  inheritance, signer extension, reentrancy) and lands only with its own
  spec revision and adversarial tests of the extended boundary.
- **Program deployment/upgrade at runtime** — no loader, no upgrade
  authority; programs are genesis-registered and immutable. A deploy path
  is a consensus change with its own governance questions.
- **Rent/rent-epoch mechanics** — replaced by the §4.2 bond, deliberately.
- **Durable nonces / recent-blockhash windows** — plain per-account nonce
  only (§5.3).
- **Address lookup tables, versioned transactions** — v0 has one version
  and flat account lists under small caps.
- **Sysvars beyond `ExecEnv`** — slot/epoch from the parent's committed
  state only; no clock sysvar semantics, no stake-history sysvar.
- **Block-STM / optimistic scheduling, local fee markets, priority lanes**
  — §7.4; each requires its own determinism proof and KAT set.
- **Incremental SMT** — §4.2-3; gated on measurement plus an equivalence
  property test.
- **A calibrated compute-unit schedule** — §6.3's schedule bounds block
  time; it does not claim Solana-equivalent pricing.

## 12. Proposed crate skeleton (for the implementation phase — not built yet)

`crates/bloch-svm/` — new crate, own directory, pure (no clock, no I/O, no
network), same posture as the E2/U2 plan crates. Modules: `address.rs`,
`account.rs` (+canonical codec), `tree.rs` (SVM SMT, leaf cache, KATs),
`tx.rs` (format + structural validation), `meter.rs`, `runtime.rs`
(TxContext, handles, layer-2 verification, commit), `scheduler.rs` (waves),
`native/system.rs` (System-program subset: CreateAccount, Transfer, Assign,
Allocate, Delete-with-refund), `errors.rs` (typed, `#[non_exhaustive]`).
Test-only: `native/adversarial.rs` (the §8 attack programs — in-tree,
clearly marked, because the negative tests are spec obligations, not
afterthoughts).
