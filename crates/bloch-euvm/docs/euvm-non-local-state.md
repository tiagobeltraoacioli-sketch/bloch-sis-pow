# `state.rs` — committed non-per-UTXO state (sparse Merkle root) for Ustav

Status: **reference / unaudited, not consensus-wired.** Nothing in this note or the
module changes live consensus.

> **CORRECTION (this note was stale on two counts).**
>
> 1. It claimed `lib.rs` "does not declare `mod state;`" and lists only `batcher` and
>    `minting`. That is **false today**: `src/lib.rs:779` declares `pub mod state;`
>    (alongside `batcher`, `harness`, `kirpich`, `minting`, `modules`). The module is
>    crate-wired and its tests run in the normal suite. It is still not *consensus*-
>    wired — `bloch-euvm` is referenced zero times by `bloch-pos-node` and
>    `bloch-pos-committee` — which is the claim that actually matters and remains true.
> 2. The implementation it describes has since been **rewritten as an incremental
>    SMT** (memoized node hashes, eager root), the allow/deny gates gained an
>    identity-bound variant, and a compressed proof format was added. Roots and the
>    existing `Proof` format are byte-identical and pinned
>    (`tests/euvm_pinned_roots.rs`, `tests/smt_differential_oracle.rs`).
>
> The design description below is still accurate. For current status, the measured
> instruction set, and what remains open, read
> **`docs/specs/BLOCH-EUVM-GAP-MAP.md`**, which supersedes this note's "Honest
> status" section.

I independently re-verified the module against the *real* `lib.rs`, not just the
dev's shim: in a scratch copy of the crate I added `mod state;` to `lib.rs` and ran
`cargo test`. All 17 `state::tests::*` compiled against the actual `Val` / `Op` / `Ctx`
/ `run` / `SigVerifier` and passed. (One unrelated pre-existing failure showed up —
`batcher::tests::scratch_saturating_add_probe`, a probe test that panics by design —
it is untouched by this module and out of scope here.)

## The problem it solves

An eUTXO datum (`crate::Val`, an `Int` or a `Bytes` blob) can only carry a small,
fixed-shape value. Several things an Ustav-governed security token needs are *not*
naturally per-UTXO or bounded in size:

- a **registry** (arbitrary `key -> value` metadata: symbol, decimals, issuer fields),
- a **holder-set** with a hard, jurisdiction-style `max_holders` cap,
- a **dividend snapshot** (balances frozen at a point, for pro-rata distribution),
- **allow-list / deny-list** gating (KYC allow-lists, sanctions deny-lists).

None of these fit in a fixed-size datum as a raw map. The standard answer (the same
one Cardano/Ergo-style "stateful" contracts use) is a cryptographic **commitment**:
keep the map off-datum, carry a single 32-byte root in the datum, and let anyone
prove a specific key's membership or non-membership from `root + key + (value?) +
path` alone, without shipping the whole map.

## What it does

A canonical **sparse Merkle tree** (SMT), fixed depth 256, keyed by
`SHAKE-256(0x02 ‖ key)`:

- Reuses `lib.rs`'s exact `Op::Shake256` hashing discipline byte-for-byte:
  `sha3::Shake256` → `update` → `finalize_xof` → read exactly 32 bytes. Roots computed
  here are therefore roots a validator running the real VM could recompute on-chain
  from the same primitive.
- Three 1-byte domain tags (`KEY 0x02`, `LEAF 0x00`, `NODE 0x01`) as the first byte of
  every hash input, so the key-hash, leaf-hash, and node-hash pre-image spaces are
  disjoint by construction — no cross-space second-preimage games.
- A precomputed **empty-subtree ladder** (`empty[256] = EMPTY_LEAF`, `empty[d] =
  H(empty[d+1], empty[d+1])`) gives the empty tree's root directly and lets
  non-membership proofs terminate without walking real data.
- `Proof { key, value: Option<Vec<u8>>, siblings: Vec<Hash> }` — `value = Some(_)` is a
  membership proof, `None` is non-membership (the key's slot is the empty leaf).
  `verify(root, proof)` recomputes the path from the proof alone (no tree access) and
  accepts iff it reproduces `root`.
- Four typed wrappers over the same SMT, one per Ustav need: `Registry`, `HolderSet`
  (checked `max_holders` bound), `Snapshot` (frozen balances + floor-division dividend
  math), `MembershipList` + `Gate::{Allow,Deny}` + `gate_allows`.
- `root_as_val` / `val_as_root` move a root in and out of `crate::Val::Bytes`, so a
  validator program can do `Op::CtxField(i)` (the root the spending tx asserts) then
  `Op::Eq` against the datum root — proven end-to-end in
  `root_fits_in_val_and_validator_asserts_it`, which runs the real `crate::run` VM.

## Determinism properties

- **Pure function of the entry set, not insertion order.** The backing store is a
  `BTreeMap` (canonical key ordering); `root()` re-derives the sorted
  `(key_hash, leaf_hash)` list and folds it bottom-up every call. Two trees built from
  the same map via different insert/overwrite/remove sequences produce byte-identical
  roots (`determinism_insertion_order_independent`).
- **No I/O, no clock, no float, no `HashMap`.** Every count/sum that could overflow
  (`HolderSet`'s holder count, `Snapshot`'s total supply, its dividend numerator) goes
  through `checked_add`/`checked_mul` and surfaces `StateError` rather than wrapping
  or panicking.
- **Proof soundness under tampering** is exercised directly, not just asserted:
  flipping the claimed value, flipping one sibling, or relabeling a valid
  non-membership proof as membership each independently fail `verify`
  (`tampered_value_fails`, `tampered_sibling_fails`,
  `forged_membership_of_absent_key_fails`), and a proof of the wrong length is
  rejected outright (`wrong_length_proof_rejected`).
- **Collision assumption, not a hard check.** `subtree_hash` assumes that at
  `depth == TREE_DEPTH` at most one entry lands in a slot (a 256-bit `SHAKE-256`
  key-hash collision is the only way two distinct keys could share a leaf); if that
  assumption were ever violated it would silently keep `entries[0]` and drop the
  colliding second entry from the root rather than erroring. This is the standard,
  accepted assumption for any keyed-hash Merkle structure (collision probability
  ~2⁻²⁵⁶) and not something this review treats as a live bug — but it is worth naming
  as exactly that: an assumption, not an assertion.

## Gas

`SHAKE256_GAS = 60` is a **hand-copied** literal chosen to match `lib.rs`'s private
`fn gas_cost(op: &Op) -> u64` returning 60 for `Op::Shake256`/`Op::Sha256d`. It is
correct today (verified above), but nothing ties the two together at compile time or
in a test — `gas_cost` is a private fn, not exported, so there is no automated
tripwire if `lib.rs`'s Shake256 gas price ever changes. `verify_gas()` returns
`SHAKE256_GAS * (TREE_DEPTH + 2)` = 15,480 as a fixed upper-bound estimate for
verifying one proof (key-hash + up to 256 node-hashes + one optional leaf-hash); it is
a *conservative* constant (it always charges as if the leaf-hash ran, even for a
non-membership proof that skips it), not a metered, per-call count — advisory only,
as the module's own doc comment says. Note also that `root()` recomputes the entire
sorted entry list and refolds the whole tree from scratch on every call (`O(n log n)`
in the number of entries) — fine for a reference implementation exercised with a
handful of entries in tests, but not an incremental/persistent structure, and a real
integration would need to either cache the root or restructure for incremental
updates before it saw production-sized holder sets.

## Proof size

A proof carries the full depth: 256 siblings × 32 bytes = 8 KiB, regardless of how
sparse the tree actually is. This is correct and simple, not size-optimized; a
production build would compress runs of siblings that are known empty-ladder values
rather than serializing them. The module's own doc comment says this plainly; this
review confirms it's an accurate characterization, not an omission.

## Mapping to Ustav

This module *is* the answer to what `docs/euvm-harness.md` calls "the hard Ustav
problem": an Ustav-governed asset's non-per-UTXO state (registry / holder-set /
snapshot / allow-deny list) committed as a single 32-byte root that fits in one
`Val::Bytes` datum slot. Concretely, an Ustav validator would:

1. Carry the current root in its own datum (`Registry::root()` /
   `HolderSet::root()` / `Snapshot::root()` / `MembershipList::root()`, moved into the
   datum via `root_as_val`).
2. On spend, take a `Proof` (built off-chain, passed in as a redeemer field via
   `Op::PushBytes`/`Op::CtxField`) for whichever key the transaction concerns (a
   transferring holder, a KYC id being checked against an allow-list, ...).
3. Run `verify(&datum_root, &proof)` — or for allow/deny gating,
   `gate_allows(gate, &datum_root, &proof)` — inside the validator to decide whether
   the transaction is legal, and require the transaction's output carry the *new*
   root (computed off-chain the same way, checked by the validator via `Op::Eq`
   against `TxOutDatum`) if the state changes.

None of this is wired: there is no Ustav validator program in this crate yet that
actually calls `verify`/`gate_allows` as part of an on-chain spend path — `state.rs`
supplies the primitive and proves (in `root_fits_in_val_and_validator_asserts_it`)
that the `Val`/`Op::CtxField`/`Op::Eq` plumbing it needs already exists in the real
VM, nothing more.

## Honest status

- **Reference only, not consensus-wired.** (The earlier text here said the module was
  "not even crate-wired" because `lib.rs` had no `mod state;`. That is out of date:
  `src/lib.rs:779` declares `pub mod state;`. See the correction at the top.) What
  remains true, and is the load-bearing claim: `bloch-euvm` is an optional dependency
  behind an off-by-default `euvm` feature and is referenced **zero times** by
  `bloch-pos-node` and `bloch-pos-committee`, so no line of it is reachable from the
  node's state-transition path. `INTEGRATION.md`'s "plan → feature-gated wiring →
  consensus tests → audit → hard fork" order is untouched by this module.
- **The gates now have an identity-bound variant.** `gate_allows` alone does not bind
  `proof.key` to the caller, and the two bypasses that follow from that are pinned as
  working attacks in `tests/audit_stateproof.rs`. `gate_allows_bound` closes them for
  callers that can supply an already-authenticated identity; see
  `docs/specs/BLOCH-EUVM-GAP-MAP.md` §2.2 for the caller obligation that does *not*
  go away.
- **No lib.rs changes required or made.** `Val`, `Op`, `Ctx`, `run`, `SigVerifier` were
  already `pub`; this review re-confirms that (grep of `lib.rs`'s `pub` items) and
  confirms none of them needed to change.
- **PQ posture is inherited, not new.** `SHAKE-256` (SHA-3 XOF family) is the same
  primitive `lib.rs`'s own `Op::Shake256` already uses; a 32-byte digest gives ~128-bit
  security against a generic Grover preimage/collision search, the same margin the
  rest of this crate's hashing already assumes. This module introduces no new
  cryptographic primitive and no new PQ exposure.
- **Gas-constant duplication** (above) and **`root()`'s O(n log n) full-recompute**
  (above) are the two concrete things worth fixing before this graduates past
  "reference": neither is a correctness bug in what's here today, but both are exactly
  the kind of gap that's cheap to close now and expensive to discover at
  integration/audit time.
- **No Ustav validator exists yet that calls this module.** `state.rs` is the
  commitment/proof primitive only; wiring an actual Ustav spend path (a redeemer
  carrying a `Proof`, a validator calling `verify`/`gate_allows`, a required root
  transition on continuation) is separate, later work, not started here.
