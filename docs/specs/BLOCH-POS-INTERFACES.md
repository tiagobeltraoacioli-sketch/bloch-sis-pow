<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch PoS — Frozen Consensus Interfaces

> **PARCIALMENTE SUPERADO — 2026-08-11.** Esta analise foi escrita contra o
> estado do projeto naquele dia e depende de premissas que mudaram DEPOIS:
>
> - **a maquinaria de taint** — dissolvida: o carryover atravessa como um conjunto so, sem lista de exclusao, entao nao ha classe de moeda a marcar.
> - **o comite amostrado (128 por epoca + 8 por slot)** — substituido por particao do conjunto ativo: o quorum amostrado nao tinha denominador coerente (achado F1).
> - **o supply de 100 bilhoes** — revertido para 21 bilhoes, o nominal da V2.
> - **a fase hibrida de PoW** — apagada: a Genesis-3 para na altura 80.000 e a Genesis-4 nasce de uma snapshot.
> - **o "L2 anchor" como consumidor** — decisao do fundador (2026-08-11): EVM na base (L1), sem rollup; o `bloch-l2-evm` sera substituido, entao onde este doc lista "L2 anchor" como consumidor de `FinalityGadget`/checkpoints, leia o EVM nativo e demais consumidores internos.
>
> O texto NAO foi reescrito, de proposito: o raciocinio que produziu cada
> achado tem valor mesmo quando a premissa mudou, e reescrever apagaria a
> trilha. Leia os achados; confira as premissas contra
> `BLOCH-TOKENOMICS-V4.md` e `BLOCH-POS-SHA3-LATTICE-MIGRATION.md`, que sao
> os normativos.


```
Document:   BLOCH-POS-INTERFACES
Status:     FROZEN — Phase-1 interface freeze (§9.2 of the migration design)
Created:    2026-08-11
Code:       crates/bloch-pos-committee/src/interfaces.rs
Relates to: BLOCH-POS-SHA3-LATTICE-MIGRATION.md, BLOCH-TOKENOMICS-V4.md
```

§9.2 of the migration design requires that "interfaces between the three
[developers] are frozen at the end of Phase 1 as Rust traits with no
implementations; every later phase codes against them." `interfaces.rs` is
that freeze; this document explains each boundary, who owns which side of it,
and the contracts that bind every implementation.

---

## 1. The two contracts that bind every trait

### 1.1 Purity (§5.5)

Every method is a pure function of its explicit arguments. `&self` may carry
only configuration fixed at genesis — never a clock, cache, database handle,
or mutable state. Chain data reaches a consensus rule only through a
`StateReader` obtained from the **parent block's committed state**.

This rule has a body count: `expected_bits` was derived from node-local
mutable state instead of ancestry, and nodes running identical binaries split
consensus at retarget heights on 2026-08-08. The interfaces are shaped so that
the compiler is on the reviewer's side — a method that has no parameter
through which local state could arrive cannot quietly read it. A4's checklist
item ("does this read local mutable state?") applies to every implementation
and is a merge blocker.

### 1.2 Arithmetic (`u128`, Tokenomics V4 §8.1)

Every stake, balance, reward or penalty in these signatures is `u128`
satoshis. At 8 decimals, the 100 B supply is 10^19 sat = 54% of `u64::MAX`;
the sum of two large balances overflows `u64` — silently in release builds —
and a silently wrapped consensus value is a chain split. The interface
carries `u128` end-to-end (including individual amounts that would fit in
`u64`) so no implementation is one refactor away from an accumulator in the
wrong width. The compile-time assertion pinning this lives in
`tokenomics_v4.rs`.

### 1.3 Change control

Signatures are frozen. A change after Phase 1 requires the §9.4 two-reviewer
rule (one other DEV plus A4) and a PMO-recorded reason. The single sanctioned
cheap extension is adding a variant to a `#[non_exhaustive]` error enum.

---

## 2. The seven boundaries

| Trait | Implements | Consumes | Spec |
|---|---|---|---|
| `ProposerDuties` | DEV-1 | DEV-3 (gossip/RPC), slashing evidence | §5.3, §6.3–6.4 |
| `StateTransition` | DEV-1 | DEV-3 (sync/RPC), A2/A3 harnesses | §5.5 |
| `RandomnessBeacon` | DEV-2 | DEV-1, committee sampling | §6.3 |
| `FinalityGadget` | DEV-1 | DEV-3, L2 anchor | §5.1, §6.5.2 |
| `StakingLifecycle` | DEV-3 | DEV-1 transition, wallet/RPC | §7.1–7.2, §4.1, §6.6.3 |
| `SlashingRules` | DEV-3 | DEV-1 transition, A4 review | §7.3 |
| `StateCommitment` | DEV-2 | everyone | §5.4, §5.5, §6.1 |

Plus three injected capability traits that keep the crate standalone:

| Trait | Role |
|---|---|
| `KeyVerifier` | Hybrid signature verification by raw pubkey (deposits, evidence). The registry-index flavour already existed as `attestation::SignatureVerifier`. The PQ stack is never linked here; the verifier stays a caller decision. |
| `StakeEligibility` | DEV-3's taint tracking behind one question: `deposit_input_status(utxo) → Eligible / Tainted / Shielded / Unknown`. Answers must come from the taint state committed at the parent block (`StateRoots::taint_root`). |
| `StateReader` | Read access to one block's committed state — the **only** door consensus rules may reach through for chain data. Its method list is deliberately closed: a rule that needs a value not exposed must first make that value committed state (visible under `StateRoots`), which is §5.5 expressed as an API. |

### 2.1 `ProposerDuties` — block production

`proposer()` draws the slot leader from the beacon mix and the parent-committed
validator set — public sortition, deliberately, because no standardised PQ VRF
exists and hashing a non-unique ML-DSA/Falcon signature would hand proposers a
grinding lever (§6.4). `proposal_signing_root()` signs the header under a
dedicated `DS_PROPOSE` domain (see §4.1 below). `validate_proposal()` checks
scheduled proposer, version, RANDAO reveal, then the 4.6 KB hybrid signature
**last** — cheap rejections first, the same DoS ordering as attestation
validation.

### 2.2 `StateTransition` — the transition function

`apply_block(pre, envelope, attestations, txs) → State` and
`process_epoch(pre) → State`. Two associated types (`State: StateReader`,
`Transaction`) mark exactly the two things the standalone crate cannot define:
DEV-1's concrete state object and the node's eUTXO transaction format (out of
scope per §1.2 of the design). Epoch processing is a separate method because
it must run even when the boundary slot is empty — a withheld proposal must
not skip the epoch's reward and queue accounting. Error **order** is declared
part of the frozen contract: which reject a node reports is consensus-visible.

### 2.3 `RandomnessBeacon` — commit-reveal

`verify_reveal`, `mix`, `chain_length`, `is_exhausted`,
`recommit_signing_root`. Uniqueness comes from preimage binding — the property
no lattice signature offers. Chain exhaustion is a checked state with a
re-commit path, per the §6.3 exhaustion note (A1 owns the exhaustion test).

### 2.4 `FinalityGadget` — justification and finality

`is_supermajority` exists so the ≥ 2/3 rounding boundary has exactly one
definition — a quorum-boundary rounding disagreement is a consensus split.
`process_epoch_votes` advances a `FinalityState` (which carries
`previous_justified` because two-round finalization and surround slashing are
both judged against it). `inactivity_penalty_sat` is the liveness-recovery
bleed (quadratic after 4 epochs). Only the 128-member epoch committee's votes
enter this trait; the 8-member slot subcommittee feeds LMD-GHOST weight only.

### 2.5 `StakingLifecycle` — deposit / exit / withdrawal

Deposit validation takes the per-validator cap and any existing record as
**explicit inputs** (the cap is 1% of a moving total resolved by
`delegation::Registry::cap_sat` — recomputing it from hidden state would break
purity). Inputs must be transparent and untainted (`StakeEligibility`), the
suite tag must be `SUITE_MLDSA65_FALCON1024`, and the proof of possession must
verify under both halves. `activation_epoch` encodes both the activation delay
and the `MAX_ACTIVATIONS_PER_EPOCH` throttle; `withdrawable_epoch` encodes the
weak-subjectivity margin — stake must remain slashable for the whole window in
which an exited validator could cheaply sign a conflicting history.

Delegation is **not** trait-ified: it is already implemented and tested in
`delegation.rs`, and wrapping a single existing implementation would be
indirection without a boundary.

### 2.6 `SlashingRules` — offences, evidence, penalties

Classification (pure predicates over pairs of messages) is separated from
evidence validation (which re-verifies both signatures — otherwise forged
evidence could eject an honest validator). `penalty_sat` takes the correlated
slashed stake in the same window, because without amplification an entity
running a thousand validators is punished no more per coin than an unlucky
solo operator, and correlated failure is the signature of an attack.
`Offence` is a **closed** enum: adding an offence class is a hard fork, not an
enum extension.

### 2.7 `StateCommitment` — hashing and identity

`block_id`, `body_root`, `attestation_root`, `state_root`. These four
functions are the only place consensus bytes become digests; every one is a
consensus constant in function form and is pinned by A1 KATs. `BlockId` is a
newtype with, in spirit, a single constructor (`StateCommitment::block_id`) —
the type-level ban on the `pow_hash`/`block_hash` split that stalled tip
selection (§5.4); A2 owns the property test. `StateRoots` is the closed list
of committed components (§5.5), including the two Coherence roots, which are
**carried, never recomputed** — the accumulator is C1-frozen and incremental,
and re-rooting it would retroactively de-anonymise the pool (§6.6.1).
Attestations get their own tree, separate from transactions, so a finalized
epoch's signatures can be pruned (§6.5.1) without disturbing the transaction
commitment.

---

## 3. Design decisions taken in the freeze

1. **`u128` everywhere, including fields the spec sketched as `u64`**
   (`DepositTx.amount`). The arithmetic contract wins; the crate already
   carries amounts as `u128` in delegation and rewards.
2. **Proposer signature in the envelope, not the header** — per §5.3, so
   header sync never carries 4.6 KB signatures. `ProposalEnvelope` freezes
   that shape.
3. **`u64::MAX` as "not scheduled" in `ValidatorRecord` epochs** instead of
   `Option<u64>`: committed state wants one fixed-width encoding, not a
   serialisation choice.
4. **Signature-last validation order** declared for proposals (and already
   practiced for attestations): membership and structural checks before the
   hybrid verify, for DoS resistance.
5. **Capability injection over linkage**: `KeyVerifier`, `StakeEligibility`
   and `StateReader` keep the crate free of the PQ stack, the taint index and
   the node's storage — the same posture `attestation::SignatureVerifier`
   already took.
6. **`DS_PROPOSE` added** (see §4.1) and the remaining §6.1 tags
   (`DS_BLOCK/BODY/STATE/RANDAO/DEPOSIT/SLASH`) frozen in `params.rs` beside
   the two that existed.
7. **Error enums `#[non_exhaustive]`**, offence enum closed — cheap extension
   where extension is safe, hard fork where it is not.
8. **Rewards trait deliberately absent.** Reward *distribution* is concrete in
   `rewards.rs` (Solana model, adopted per Tokenomics V4 §6.3), and the epoch
   issuance arrives at `StateTransition::process_epoch` implementations as a
   value from the tokenomics module — freezing an emission-curve trait would
   have baked in a founder decision that Tokenomics V4 records as decided but
   whose spec text still contains three curves (see §4.3).

---

## 4. Ambiguities found — need a human decision

These surfaced while freezing and are **not resolved by the interface**; each
needs an owner and a ruling before Phase-2 exit.

### 4.1 No domain tag for the proposer signature (spec gap)

§6.1 assigns `BLCH4:BLOCK` to block identity but no tag to the proposer's
signature over the header. Signing the identity bytes would work, but a
signature domain that doubles as an identifier domain invites cross-protocol
confusion. **Decision taken here:** a distinct `DS_PROPOSE` tag
(`BLCH4:PROPOSE`) frozen in `params.rs`. **Needs:** ratification and a row
added to the §6.1 table, plus an A1 KAT. Similarly, voluntary exits reuse
`DS_SLASH` (fixed-width fields make the uses non-colliding) — if a dedicated
`DS_EXIT` is preferred, now is the moment.

### 4.2 Exit/withdrawal delays conflict between spec and implemented delegation

§5.1 fixes validators at `EXIT_DELAY_EPOCHS = 32` **plus**
`WITHDRAWAL_DELAY_EPOCHS = 2,048` (~22.8 days, the weak-subjectivity margin).
`delegation.rs` gives delegators a single `COOLDOWN_EPOCHS = 32` (~8.5 h) to
withdrawable. If delegated stake is slashable (rule 3 of §6.3.1) it must also
sit inside the weak-subjectivity window, or delegators can flee a validator
that is about to be slashed for a long-range signature. Either delegator
cool-down gains a withdrawal delay, or the asymmetry is accepted and recorded.

### 4.3 Emission curve: "decided" but triply implemented

Tokenomics V4 §6.1 records 10%/year decay as **adopted**, yet §7A's gate
analysis argues for the halving curve, and `tokenomics_v4.rs` deliberately
ships all three (`flat`, `halving`, `decay`) with a comment refusing to alias
one as "the" reward. The interface dodges it (issuance is an input, §3.8), but
the node cannot: one curve must be named canonical, and §7A re-run against it.

### 4.4 Reward split: migration spec §7.4 contradicts the adopted model

§7.4 still specifies the Ethereum shape (7/8 attesters, 1/8 proposer);
`rewards.rs` and Tokenomics V4 §6.3 implement the Solana model (pro-rata to
stake scaled by credits, commission, fee split with burn). The migration spec
text needs the §7.4 paragraph superseded explicitly — two specs disagreeing on
who gets paid is how a "consensus-adjacent documentation" bug becomes a real
one (the `VALIDATOR_SHARE_BPS` comment precedent).

### 4.5 Address / withdrawal-credential format

The standalone crate cannot see the node's address type, so
`withdrawal_credentials` is frozen as opaque bytes. Before DEV-3 wires
deposits, the concrete format (address hash width, version byte, whether a
script hash is admissible) must be fixed and a KAT added. The freeze
deliberately does not guess.

### 4.6 Deposits and taint under the Genesis-4 relaunch

§7.1 ("deposits are accepted on the PoW chain during the hybrid phase") and
much of §4.1's taint machinery predate the 2026-08-10 halt-and-relaunch
decision (§8 superseded note; chain halts at 80,000, Genesis-4 launches ~6
months later). The ruling this section left pending is now made (founder
decision, 2026-08-11): **the taint set does not survive into Genesis-4, and it
is not repurposed.** It starts empty and stays empty — a carried-over balance
that is liquid is also stakeable, the founder's included, and the vesting
locks on the founder/VC/team/marketing allocations are enforced as
spendability of the genesis outputs, not as a coin class. For this contract
that means: conforming `StakeEligibility` implementations never return
`Tainted` (the variant stays, frozen and inert), `StateRoots::taint_root` is a
reserved all-zero slot, and `DepositReject::TaintedInput` is unreachable in
Genesis-4. The decision is pinned by
`staking.rs::carryover_liquid_balance_is_stakeable` and
`tests/committee.rs::carryover_liquid_balance_delegates_as_stake`; its gate
arithmetic is `BLOCH-TOKENOMICS-V4.md` §4A.1.

### 4.7 Which committee's attestations count where

`AttestationData` is shared by slot-subcommittee and epoch-committee votes.
The freeze rules that only epoch-committee votes feed `FinalityGadget` (a
quorum of 8 must never justify anything), and slot votes feed fork choice
only. But the reverse question is open: do the 128 epoch-boundary votes
*also* contribute LMD-GHOST weight (they carry a `head`)? Ethereum's answer
is yes. Recommended yes here too, but it changes `Store` weight accounting
and should be decided, tested and recorded rather than inherited silently.

### 4.8 Inactivity-leak parameters

§5.1 says "quadratic after 4 epochs" — no rate constant, no floor, no
recovery definition. `inactivity_penalty_sat` freezes the *shape* of the
call; the constants need the standard treatment (KAT + devnet sweep) before
Phase-3 exit, and the 4-epoch trigger should be a named constant with a
rationale.

### 4.9 Second deposit to the same pubkey

Frozen as a rejection (`PubkeyAlreadyRegistered`): top-ups would need
defined interaction with the activation queue, the stake cap and the
per-epoch throttle. If top-ups are wanted, they need their own message type
and rules — cheaper to add explicitly later than to un-ship an ambiguity.

---

## 5. Verification

- `cargo check` and `cargo test` clean on the standalone crate (77 tests,
  zero warnings) with the interfaces compiled in.
- The traits contain no implementations, no clocks, no I/O, and no `u64`
  balance arithmetic — the two §1 contracts are auditable by reading the one
  file.
