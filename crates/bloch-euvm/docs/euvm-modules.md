# `modules.rs` — the Ustav module compiler (charter → eUTXO validator set)

Status: **reference / unaudited, not consensus-wired.** This note describes
`crates/bloch-euvm/src/modules.rs` as currently written (760 lines, in worktree
`wf_2b65b17d-75a-30`). `lib.rs` does not declare `pub mod modules;` — the file sits
untracked and unwired, exactly as `docs/euvm-harness.md`, `docs/euvm-batcher.md`, and
`docs/euvm-non-local-state.md` describe for their own modules on this branch.

I independently re-verified the dev's claims rather than taking the report at face
value: in a scratch copy of the crate I appended `pub mod modules;` to a copy of the
real, tracked `lib.rs` and ran `cargo test` and `cargo clippy --all-targets`.

- **`cargo test`: 27 passed, 0 failed** — confirmed. But the reported *breakdown*
  ("15 original + 12 new") is wrong even though the total is right: `lib.rs` actually
  carries **17** pre-existing tests, and `modules.rs` adds **10**, not 12
  (`17 + 10 = 27`). Worth a correction, not a retest — nothing here suggests the extra
  tests don't exist; the dev just miscounted.
- **`cargo clippy --all-targets`: clean for `modules.rs`.** The only two warnings
  (`useless_vec` at `lib.rs:799` and `lib.rs:802`, inside `lib.rs`'s own
  `pick_reaches_under_top` test) are pre-existing and outside this file, exactly as
  reported.

## What it does

`modules.rs` is a pure compiler: `TokenCharter { token_name, modules: Vec<ModuleKind> }`
in, `CompiledToken { charter_id, validators: Vec<CompiledModule> }` out, via
`compile_charter`. Each of the six `ModuleKind` variants (`Supply`, `TransferPolicy`,
`ComplianceKycGate`, `Vesting`, `Governance`, `Custody`) carries a small typed config
and a hand-written `.compile() -> Vec<Op>` emitter that lowers straight to the `lib.rs`
VM's existing instruction set — no new opcodes, no changes to `lib.rs` at all. A
charter's validator set is the ordered concatenation of its modules' compiled
programs; each program's `validator_hash` is what an `ExtOutput` guarded by that
module would carry, and (per the eUTXO convention `lib.rs` already establishes) the
**Supply** module's hash doubles as the token's `AssetId`/policy id
(`CompiledToken::policy_id()`).

The six emitted validator shapes, each over the standard `spend()` stack seed
`[datum, redeemer...]`:

| Module | Guard | Redeemer shape |
|---|---|---|
| Supply | `requested ≤ cap` (hard assert) **then** issuer PQ-sig | `[requested:Int, sig]` |
| TransferPolicy | `frozen == 0` **or** authority sig (OR-gate, both legs always run) | `[sig]` |
| ComplianceKycGate | `sha256d(witness) == ctx[FIELD_KYC_ROOT]` | `[witness]` |
| Vesting | `height ≥ unlock` (hard assert) **then** beneficiary sig | `[sig]` |
| Governance | count of verifying `VerifySig`s `≥ threshold`, over `m` signers | `[sig_1..sig_m]` |
| Custody | ECDSA(BTC) leg (hard assert) **and** PQ leg — hybrid 2-of-2 | `[ecdsa_sig, pq_sig]` |

The VM is a straight-line stack machine with no branching, so "OR"/"AND" gates are
built arithmetically (sum booleans, compare against a threshold) rather than with
jumps — the same pattern `lib.rs`'s own `multisig_2_of_3` test already uses. A
consequence worth naming: legs that use `Op::Verify` (a hard assertion) abort the
whole spend with `VmError::Assert` if they fail, while legs that leave a bare 0/1 on
the stack reject "softly" (`Ok(false)`). Supply's cap check, Vesting's height check,
and Custody's ECDSA leg are hard asserts; every signature check that's meant to be
one leg of an OR/AND is soft. This asymmetry is inherited directly from `lib.rs`'s own
`hybrid_ecdsa_and_pq_validator` test convention, not introduced here — but it means a
host surfacing failures to a user needs to handle two different error shapes
(`Err(Assert)` vs `Ok(false)`) for what is conceptually "the same kind of no."

## Determinism

Compilation is a pure function of the charter: same `TokenCharter` value in →
byte-identical `Vec<Op>` programs, identical `validator_hash`es, identical
`charter_id`, every time. This is verified directly, not just asserted:
`determinism_same_charter_identical` compares `encode_program` output byte-for-byte;
`distinct_charters_distinct_hashes` confirms a changed cap, a changed name, and a
reordered module list all move the id while untouched modules keep their hash. The
charter-id preimage (`"USTAV-CHARTER-v1" ‖ len(name) ‖ name ‖ (tag_byte ‖
validator_hash)*`) length-prefixes only the variable-length name; each per-module
chunk is a fixed 33 bytes, so the framing is unambiguous and two structurally
different charters cannot collide by realignment. All configs are plain scalars,
`Vec<u8>`, and `Vec<Vec<u8>>` — no float, no `HashMap`, no wall-clock — so the
"sacred" determinism property `lib.rs` itself requires is preserved here.

## Gas

No module introduces a new op, so gas cost is exactly `lib.rs`'s existing schedule
applied to the emitted program. Signature verification (`VerifySig`/`VerifyEcdsa`,
1000 gas each) dominates every module's cost; everything else (`PushInt`, `Pick`,
`Lt`, `Not`, `CtxField`, ...) is 1 gas, with `Add`/`Sub`/`Mul` at 4 and
`Sha256d`/`Shake256` at 60. Concretely, per compiled module:

| Module | Approx. gas | Driven by |
|---|---|---|
| Supply | ~1,008 | 1 × `VerifySig` |
| TransferPolicy | ~1,012 | 1 × `VerifySig` |
| ComplianceKycGate | ~62 | 1 × `Sha256d` |
| Vesting | ~1,008 | 1 × `VerifySig` |
| Governance (m signers) | ~`1007·m + 4` | `m` × `VerifySig` (linear in signer count) |
| Custody | ~2,008 | 1 × `VerifyEcdsa` + 1 × `VerifySig` |

Governance is the one module whose cost (and, see below, whose correctness) scales
with a charter-supplied parameter (`signers.len()`), so a host budgeting gas per
charter should size its ceiling off `m`, not treat all modules as fixed-cost.

## Mapping to Ustav

Ustav's core idea — a token is an ordered composition of independent modules, each
*is* a concrete eUTXO validator — is exactly what `compile_charter` produces: one
`CompiledModule` per `ModuleKind`, concatenated in charter order, sharing the `ctx`
field convention (`FIELD_SIGHASH=0`, `FIELD_HEIGHT=1`, `FIELD_KYC_ROOT=2`) a host must
populate to run any of them. This is a real, useful foundation for the standard.

It is worth being precise, though, about how much of "Ustav" this file actually is,
because two sibling reference modules already exist on this same branch that bear
directly on two of these six module kinds:

- **Supply vs. `minting.rs`.** `docs/euvm-minting.md` describes a considerably more
  complete Supply substrate already in this crate: a real `MintingPolicy` with signed
  net `delta`, a `prior_supply` ctx field, and `validate_tx_with_mint` enforcing
  `prior_supply + delta ≥ 0` across the whole transaction. `modules.rs`'s
  `ModuleKind::Supply` does *not* build on it — it's a simpler, independent "per-mint
  cap + issuer sig" check with **no running/global supply counter at all**. Read
  literally, `SupplyConfig.cap` bounds one mint call, not the token's total issuance;
  calling the Supply validator repeatedly, each time under `cap`, has nothing in this
  file stopping total minted supply from growing unboundedly. That's a fair scope cut
  for a first pass, but the doc comment's phrasing ("a minting policy... fixed cap")
  reads more like a monetary-policy guarantee than it delivers — worth tightening
  before anyone treats `ModuleKind::Supply` as sufficient on its own.
- Compounding that: the two files' `ctx.fields` numbering **conflicts**.
  `modules.rs` defines `FIELD_HEIGHT = 1` (an `Int`, block height) and
  `FIELD_KYC_ROOT = 2` (`Bytes`, a registry root); `minting.rs` independently defines
  `MINT_CTX_DELTA = 1` (an `Int`, the signed mint delta) and `MINT_CTX_HEIGHT = 2`
  (an `Int`, block height). Both only agree that `fields[0]` is the sighash. Neither
  is "wrong" in isolation — they're deliberately different `Ctx` instances built for
  different call shapes (a generic spend vs. a purpose-built minting context) — but
  there is no single canonical "Ustav ctx layout" across the crate yet, and an
  integrator who assumes one exists will wire the wrong field.
- **ComplianceKycGate vs. `state.rs`.** `docs/euvm-non-local-state.md` describes a
  real sparse-Merkle-tree membership/non-membership substrate
  (`MembershipList`/`Gate::{Allow,Deny}`) built for exactly the KYC/allow-list problem
  this module names. `modules.rs`'s honest-limits note says the gate can only check a
  single-item commitment "because the opcode set has no byte-concatenation op, so a
  full Merkle path cannot be walked in-VM yet" — but `state.rs`'s pattern doesn't need
  one: it verifies the Merkle proof host-side (in Rust) and has the on-chain validator
  assert only `ctx_root == datum_root` via `Op::Eq`, the same shape `modules.rs`
  already uses. So the real gap isn't a missing opcode; it's that
  `ComplianceKycGate::compile` doesn't build on `state.rs` at all, and its
  `sha256d(witness) == root` check only really works for a one-entry "registry" (the
  witness *is* the whole preimage of the root), not membership in a real multi-entry
  set. The honest-limits note should say that plainly rather than attribute the gap to
  the opcode set.

None of this is a defect in what `modules.rs` claims for itself — its own doc comment
is careful to say "composes minting/state conceptually... depends only on lib.rs" —
but the design note format asks for how it maps to Ustav, and the honest answer is:
it's the *composition layer*, and two of its six modules (Supply, ComplianceKycGate)
have a stronger sibling substrate sitting right next to them on this branch that a
later integration pass should reconcile them with, rather than let three independent
"Supply" and two independent "KYC" stories ship side by side.

## Honest limits (as stated by the module, confirmed accurate)

- Not consensus-wired; `lib.rs` doesn't declare the module.
- Minting/state composed conceptually only; no cross-file wiring to `minting.rs` or
  `state.rs` in this phase (confirmed above — there genuinely is none).
- KYC gate is single-commitment inclusion, not a real Merkle path (confirmed, though
  see above for *why* — it's not actually blocked on a missing opcode).
- Unaudited. Designed ≠ built ≠ booted.

## Additional issues found in this review (not self-disclosed)

1. **Degenerate `GovernanceConfig` compiles silently to a no-auth validator.**
   `compile()` is infallible (`Vec<Op>`, no `Result`) and does not validate
   `threshold ∈ 1..=signers.len()` or `signers` non-empty. Verified directly: a
   charter with `GovernanceConfig { signers: vec![], threshold: 0 }` compiles to a
   validator that returns `Ok(true)` on a spend with **zero** redeemer values and a
   verifier that accepts nothing — i.e. an always-spendable "governance" gate with no
   authorization at all. `threshold: 0` with a non-empty `signers` list has the same
   problem (spendable with zero valid signatures). Recommend `compile_charter` (or a
   separate `TokenCharter::validate`) reject `threshold == 0` or `threshold >
   signers.len()` before compiling, rather than emitting a silently-broken guard.

2. **`Pick` depth for Governance truncates silently past ~252 signers.**
   `compile_governance` computes `depth = (m + 3 - i) as u8` where `m =
   signers.len()`. `Op::Pick` takes a `u8`, so once `m + 3 - i > 255` (i.e. roughly
   `m > 252`, for the earliest signers checked) the cast wraps instead of erroring.
   Confirmed empirically: with `m = 254` signers, the first signer's checked `Pick`
   depth is mathematically `256`, which the `as u8` cast truncates to `0` — reaching
   the wrong stack slot and producing a governance validator that does not check what
   it was configured to check. All of this file's own tests use `m ≤ 5`, so the path
   is untested. Low likelihood in practice (250+ on-chain governance signers is an
   unusual charter), but it's an unchecked, silent truncation rather than a bounds
   check — worth either asserting `signers.len() <= 252` in `compile()` or widening
   the depth arithmetic.

3. **Reported test-count breakdown is wrong (total is right).** See the top of this
   note: it's 17 + 10 = 27, not 15 + 12 = 27. Purely a reporting-accuracy nit,
   independently corrected above; does not affect the code.

4. **Minor nit:** `CompiledModule::validator_hash` and `CompiledToken::policy_id()`
   return raw `[u8; 32]` where `crate::AssetId` (also `[u8; 32]`) exists and is the
   type the doc comment's own prose names ("its native `AssetId`"). Purely cosmetic —
   the types are structurally identical — but using the alias would make the identity
   between "policy id" and "AssetId" a type-level fact instead of a comment.

None of the above are `PartialEq`/PQ-wiring concerns — the dev's one disclosed
API trade-off (`CompiledModule`/`CompiledToken` not deriving `Eq` because `crate::Op`
doesn't) is correctly reasoned and requires no change. PQ verification is exactly as
honest as `lib.rs` already is: a host `SigVerifier` callback, no real ML-DSA/Falcon
wired in here, which is stated and true.
