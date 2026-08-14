<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# BLOCH-L1-EVM-STATE-MODEL — how account state coexists with eUTXO at L1

> **Genesis-4 is live.** Bloch has been running under **proof of stake** since
> 21:31:19 UTC on 2026-08-13, when Genesis-3 (proof of work) stopped
> permanently at height **39,918**. 30 s slots, 32-slot epochs, Casper-style
> justification/finalisation by epoch, hybrid ML-DSA-65 ‖ Falcon-1024
> signatures on every consensus path. Nothing in this document that describes
> mining, hashrate, difficulty, retargeting or proof-of-work depth describes
> the current network.
>
> **The live security question is concentration, not hashrate.** All 64
> validators are operated by a single entity; 93.94% of the carryover
> (17,046,829,380 of 18,146,400,000 BLOCH) sits at one address and carried
> balances are stakeable, so if that balance stakes the Nakamoto coefficient
> is 1; and 56,046,829,380 of the 57,146,400,000 BLOCH issued at slot 0 is
> held by the founder and the Foundation, leaving 1.92% of genesis supply in
> third-party hands. One operator can halt the chain and one holder can outvote
> every other. The live transport is a point-to-point TCP full mesh with a
> fixed peer list, **no discovery and no authentication**, and
> `Deposit`/`Delegate` are refused at every node's mempool — which is why a
> third party cannot yet join the network or become a validator.

Status: **design, wave 2026-08-11.** The state-root changes described in §2 are
implemented and tested in `crates/bloch-pos-committee` (see §8 for exactly what
is and is not done). Everything else is normative design for the wiring waves.

Companion decisions this document does **not** make: the authorisation model
(secp256k1 vs PQ vs dual) is DEV-2's; §7 lists every point where this design
depends on it. The premise correction in `docs/FLEET-BRIEF-2026-08-11.md`
(Solana is not natively EVM; the instruction means *one global state machine at
L1, no rollups*) is taken as given.

## 1. Decision summary

| Question | Decision |
|---|---|
| One state root or two? | **One.** `BlockHeaderV4.state_root` stays the single commitment; the header layout does not change (`ENCODED_LEN` untouched). |
| New leaves? | **Exactly one**: a singleton `EvmCommitment` leaf under component tag `0x09`, the same carried-foreign-root posture as the taint and Coherence leaves. Per-account EVM state does **not** enter the SMT. |
| EVM tx spends a UTXO? | **No.** Value crosses through two native protocol operations — deposit outputs and a withdrawal precompile — with a deterministic per-block phase order (§4). |
| Contract receives from the shielded pool? | **Not directly.** Coherence is C1-frozen; the path is unshield → transparent → deposit, two transactions (§4.4). |
| EVM implementation | **revm**, exact-version pinned, `SpecId::CANCUN`, single-threaded in body order; a version bump is a height-gated hard fork with regenerated KATs (§5). |
| `bloch-euvm` | **Survives, scope-frozen**: it remains the spend-predicate layer for transparent outputs; all global-state programmability moves to the EVM. Its unwired non-per-UTXO SMT (`state.rs`) does not graduate (§6). |

## 2. One root, one new leaf

### 2.1 Why the closed list opens here — and closes again

The `state_root` leaf list is closed on purpose, and the closure rule states
its own amendment procedure
(`crates/bloch-pos-committee/src/interfaces.rs::StateRoots`): *"a consensus
rule that needs a value not represented here must first add its component —
visibly, in a spec change."* This document is that spec change. The list is
not being made open-ended; it is being amended once, from seven components to
eight, and is closed again at eight.

The precedent is already inside the tree: the taint root and the two Coherence
roots are *carried foreign roots* — commitments maintained by another
subsystem, committed here as single leaves so that finality covers them
(`state_root.rs`, the comment above the three singleton inserts). The EVM
commitment is the fourth member of exactly that class: the execution layer
owns a keccak-256 Merkle-Patricia trie; consensus commits its digest, never
its contents.

### 2.2 What the leaf is

`crates/bloch-pos-committee/src/state_root.rs::EvmCommitment`, committed under
`TAG_EVM_COMMITMENT = 0x09` with an empty entry key (singleton), value-hashed
over a fixed-width canonical serialization (80 bytes):

- `account_root: [u8; 32]` — keccak-256 MPT root of the EVM account trie
  (address → nonce, balance, code hash, storage root) after this block's EVM
  segment.
- `receipts_root: [u8; 32]` — keccak-256 MPT root over this block's receipts.
- `gas_used: u64` — gas consumed by this block's EVM segment.
- `base_fee_per_gas: u64` — the base fee (satoshi per gas) this block's EVM
  transactions were charged.

`gas_used` and `base_fee_per_gas` are committed for the §5.5 reason the whole
`state_root` module exists: the next block's base fee is **derived from the
parent's committed pair** (EIP-1559 rule, §5.3 below). A base fee read from
node-local execution bookkeeping would be `expected_bits` again — an
uncommitted retarget input, the exact shape of the 2026-08-08 consensus
split. One structured leaf rather than four tags because the four values
change together, are consumed together, and one leaf costs one 256-level SHA3
path per block instead of four.

### 2.3 What deliberately does NOT happen

- **No per-account leaves in the SMT.** Expanding accounts into the SHA3 SMT
  would commit the same state twice (once in the keccak MPT the tooling
  needs, once here), would make every `SSTORE` cost a 256-level SHA3 path on
  top of its MPT path, and would turn every EVM-heavy block into thousands of
  SMT updates inside the consensus crate. The Coherence precedent is
  explicit that re-rooting a foreign incremental structure is rejected; the
  same argument holds here without the privacy component.
- **No new header field.** `BlockHeaderV4` already carries `coherence_root`
  for gossip-time filtering; the EVM commitment needs no such fast path — its
  consumers (fee derivation, light clients) read committed state, which the
  existing `state_root` field already pins. `ENCODED_LEN` and every header
  KAT stay valid.
- **No second state root.** A dual-root design (consensus root + EVM root
  side by side in the header) is two commitments that can disagree about one
  chain — the `pow_hash`/`block_hash` failure family, at the state layer.

### 2.4 Why keccak-256 inside the leaf is acceptable

Keccak-256 is used strictly as a hash. Its quantum exposure is
Grover-generic, the same margin as the SHA-3/SHAKE family the rest of the
protocol already assumes (it *is* the Keccak permutation under pre-NIST
padding). The C1 freeze bans elliptic-curve ZK, not hash choices. What keccak
buys is the entire EVM proof ecosystem: `eth_getProof`, MPT light clients,
and byte-compatibility with the audited `alloy-trie` implementation already
exercised in `~/dev/bloch-protocol/l2/bloch-l2-evm/src/stateroot.rs`
(`compute_keccak_mpt_state_root`, `stateless_new_root`) — which is the code
this design reuses. `bloch-l2-evm` is replaced *as a service*; its execution
core is retained *as code*.

A proof of an EVM fact against a finalized Bloch block is two-stage:
`verify_inclusion` (SHA3 SMT, `state_root.rs`) proves the `EvmCommitment`
leaf under `state_root`; a standard keccak MPT proof then proves the account
or storage slot under `account_root`. The first stage is Bloch-specific and
tiny; the second is what every Ethereum tool already speaks.

## 3. The account state itself

The account trie is Ethereum-shaped on purpose (nonce, balance, code hash,
storage root, RLP-encoded, keccak MPT): the point of EVM-at-L1 is that
deployed contracts, compilers, and indexers behave identically. Balance is
denominated in **wei**, with a fixed scale to the satoshi:

```
WEI_PER_SAT = 10^(18 − 8)
```

(the exponent 8 is `tokenomics_v4::SAT_PER_BLOCH`'s decimal count — one BLCH
displays as 10^18 wei, the universal EVM tooling assumption; the constant
itself will live in the execution crate and be imported, never restated).
Value enters and leaves the EVM domain only in whole-satoshi multiples
(§4.2–4.3); sub-satoshi wei can only ever arise *inside* the EVM domain from
gas arithmetic, and only shrinks the domain total when burned, so the supply
invariant (§4.5) stays exact in u128.

## 4. The eUTXO ↔ EVM boundary

### 4.1 The rule and the phase order

An EVM transaction never names a UTXO; a transparent transaction never names
an account. The two systems meet only through protocol-defined crossings,
applied in a fixed per-block phase order:

1. **Transparent segment** — eUTXO transactions validate against the parent's
   committed UTXO set (parallel, as today). Deposit outputs (§4.2) are
   collected in body order.
2. **EVM segment** — revm executes the block's EVM transactions in body
   order, single-threaded, against the account state committed at the parent
   (`account_root` of the parent's `EvmCommitment`).
3. **Deposit crediting** — the segment-1 deposits credit their target
   accounts, *after* the EVM segment.
4. **Withdrawal materialisation** — withdrawal records emitted during the EVM
   segment (§4.3) become new eUTXOs.

The `EvmCommitment` of block *N* commits the state after phases 2–3.
Ordering deposits after execution means an EVM transaction's balance and gas
checks depend only on the parent commitment plus earlier transactions in the
same segment — no cross-layer intra-block dependency, nothing for a block
builder to grind. The price is stated plainly: a deposit is spendable by EVM
transactions **one block later** (one slot, `params::SLOT_DURATION_SECS`).

### 4.2 Deposit: transparent → EVM

A new transparent output kind, `EvmDeposit { evm_address: [u8; 20] }`. It is
not a spendable output: at phase 3 its value leaves the UTXO domain and
credits `evm_address` with `value × WEI_PER_SAT`. Spend authorisation for the
*inputs* funding a deposit is the existing transparent rule (the PQ hybrid
suite today) — this crossing is deliberately independent of DEV-2's EVM
authorisation answer, so PQ-held coins can fund EVM accounts under every
option on the table.

### 4.3 Withdrawal: EVM → transparent

A precompile at a protocol-reserved address. Calling it with
`(script_hash, value_wei)`:

- requires `value_wei` to be a whole multiple of `WEI_PER_SAT` (reject
  otherwise — the UTXO domain must never be asked to represent sub-satoshi
  value);
- burns the wei from the caller and appends `(script_hash, value_sat)` to the
  block's ordered withdrawal list;
- at phase 4 each record becomes a UTXO whose outpoint is synthesized as
  `txid = SHA3-256(DS_EVM_WITHDRAW ‖ parent_block_id ‖ slot_le ‖ index_le)`,
  `vout = 0`.

The synthetic txid is derived from the **parent** id, the slot, and the
list index — all fixed before the state root is computed. Deriving it from
the block's own id would be circular (the id covers `state_root`, which
covers the UTXO set, which contains the output). `(parent, slot)` is unique
per block in a single-parent chain, so outpoints cannot collide across
blocks; the index disambiguates within one. `DS_EVM_WITHDRAW` is a new §6.1
domain tag, to be added to `params.rs` when the execution layer is wired
(not added now — see §8).

The `script_hash` is whatever lock the recipient chooses — normally a
hybrid-suite lock, so value returning from the EVM domain lands under PQ
authorisation regardless of what DEV-2 decides for the EVM side.

### 4.4 Shielded pool: no direct path, by C1

Coherence is C1-frozen: SHAKE-256 commitments, frozen circuit statements,
leaf positions are consensus. A direct shielded→contract or contract→shielded
edge would be a new circuit statement and new leaf semantics — a C1 break,
which this design refuses. The paths are:

- shielded → EVM: unshield to a transparent output (existing C1 operation),
  then deposit (§4.2) — two transactions;
- EVM → shielded: withdraw (§4.3), then shield — two transactions.

Usability cost, stated: one extra transaction and one extra block of latency
in each direction, and the unshield→deposit pair is linkable at the boundary.
That linkability is not new — an unshield to a transparent address has always
been visible; the pool's privacy properties are unchanged because the EVM
never touches the accumulator or nullifier set. The Coherence roots' leaf
positions and the accumulator's carried-never-recomputed rule are untouched
by this entire design (the new tag `0x09` derives a fresh SMT key; existing
leaf keys — which are what "leaf positions are consensus" pins — are
byte-identical before and after).

### 4.5 Conservation invariant

At every block:

```
total_utxo_value (u128, sat)
  + evm_domain_total / WEI_PER_SAT (u128; the division is exact
      up to the sub-sat residue created by intra-EVM burns)
  + shielded_domain_total (sat)
  + cumulative burns
  = supply emitted by tokenomics_v4 at that slot
```

Deposits and withdrawals move value between the first two terms and sum to
zero. Sums are u128 for the same overflow argument as
`state_root::total_utxo_value`. The devnet gets an invariant-checking
harness before any public network does (§8).

## 5. Determinism

### 5.1 The engine and the pin

**revm, exact-version pinned, `SpecId::CANCUN`.** The pin discipline is
already written and proven in `~/dev/bloch-protocol/l2/bloch-l2-evm/Cargo.toml`
(`revm = "=41.0.0"`, with the rationale that re-executors must run
byte-identical code); the L2's chainId reservation (chainspec, same crate)
carries over so existing tooling configuration survives the migration. At L1
the pin hardens from "documented program upgrade" to **consensus constant**:

- the exact revm version and `SpecId` are part of the protocol definition;
- changing either is a height-gated hard fork (the same flag-day idiom as
  every other consensus change in this codebase), never a routine bump;
- enforcement is threefold: the `=` requirement plus committed `Cargo.lock`;
  a block-level KAT in CI that executes a fixed EVM block and asserts the
  exact `account_root`, `receipts_root`, and `gas_used` (catches semantic
  drift that a version string cannot); and the existing reproducible-build
  manifest (`REPRO.md`) for toolchain drift.

Execution is single-threaded in body order. Parallel EVM scheduling is
explicitly out: the eUTXO segment is where Bloch's parallelism lives, and a
deterministic parallel EVM is a research project this chain does not need to
run first.

### 5.2 Block environment mapping

Every EVM-visible environment value is derived from committed state or the
header — nothing node-local:

| EVM opcode/env | Source |
|---|---|
| `NUMBER` | block height of the G4 linear chain (contiguous — empty slots do not consume numbers, which is what Ethereum tooling assumes) |
| `TIMESTAMP` | `genesis_time + slot × SLOT_DURATION_SECS` (both already protocol values; wall clocks never enter) |
| `PREVRANDAO` | the parent header's `randao_mix` — committed, unbiased-enough for the same reasons it seeds sortition, and carrying the same caveat: the proposer of the parent had one bit of withhold-influence over it |
| `COINBASE` | the zero address during the fee-burn era (§5.3); revisited when fees stop burning |
| `GASLIMIT` | `EVM_BLOCK_GAS_LIMIT`, a new consensus parameter fixed by devnet sweep (lives in the execution crate; sized against the slot time and the transparent segment's existing budget) |
| `BASEFEE` | derived from the parent's committed `(gas_used, base_fee_per_gas)` pair by the CANCUN EIP-1559 rule |
| `BLOCKHASH(n)` | the `BlockId` of the ancestor at height *n* — the single §5.4 derivation, no second identity |
| `CHAINID` | the id already reserved for the Bloch EVM (chainspec above) |

### 5.3 Gas versus the V4 fee model

EVM transactions pay gas in satoshi (`base_fee_per_gas` is sat-denominated).
The V4 rule — fees burn during emission, then go to validators
(`tokenomics_v4`) — applies to the EVM segment unchanged: **both base fee and
priority fee burn during the emission era.** This deliberately supersedes the
L2 chainspec's vault routing ("never burn"), which was correct for a
zero-issuance rollup and is wrong for the L1: at L1 the EVM is not a separate
fee economy, and giving EVM fees a different sink than transparent fees would
create a consensus-visible incentive to route activity by fee treatment.
Priority fees burning too is unusual (Ethereum pays them to the proposer) and
is the honest reading of the V4 rule; if the founder wants proposer priority
fees during emission, that is a one-line change to this section, priced as a
small continuous transfer from holders to proposers. The post-emission switch
(fees → validators) is four decades out (`EMISSION_YEARS`); its EVM-side
mechanism — accrue to a protocol account, sweep whole satoshis per epoch into
the existing `pending_fee_rewards` path — is sketched here so the leaf layout
(§2.2) provably does not need to change for it, and is otherwise deferred.

## 6. What happens to `bloch-euvm`

**Verdict: survives, scope-frozen. Two VMs is the decision, and here is the
shape of it:** one *local* VM (eUTXO spend predicates: parallel, stateless
between outputs, PQ-native via `SigVerifier`) and one *global* VM (EVM:
serial, account-model, the ecosystem target). They meet only at the §4
crossings. That division of labour — script layer plus account layer — is
coherent in a way "two general-purpose VMs" would not be.

- **What euvm keeps**: spend-predicate validation of transparent outputs.
  `EutxoEntry.script_hash` is already committed state; multisig custody,
  HTLC/atomic-swap, and covenant-style locks are capabilities the transparent
  layer needs regardless of the EVM (the PQ-vault and any bridge custody sit
  here). It is consensus-active on Genesis-3 from height 0
  (`src/euvm/mod.rs::euvm_activation_height`), so the capability is already
  real, audited (audit F3 lineage), and PQ-wired.
- **What euvm loses**: its ambition as the general contract layer. Tokens,
  AMMs, registries, and everything Ustav-shaped move to the EVM, where the
  entire existing ecosystem of contracts and tools lands for free. The
  unwired non-per-UTXO SMT (`crates/bloch-euvm/src/state.rs`, described in
  `crates/bloch-euvm/docs/euvm-non-local-state.md`) **does not graduate**:
  every one of its use cases (registry, holder set, snapshot, allow/deny
  gating) is account-shaped, and the datum-root-plus-proof pattern it
  implements is the workaround a chain uses when it *lacks* global state.
  The Ustav-at-L1 work on this wave should spec against the EVM account
  model, not against `state.rs`.
- **Alternatives priced and rejected**:
  - *Kill euvm*: regresses transparent outputs to fixed templates, deletes a
    consensus-active, PQ-native capability the custody paths need, and makes
    the treatment of any script-locked Genesis-3 carryover undefined.
  - *Absorb (compile euvm programs to EVM)*: two semantics on one engine
    plus a translation layer that itself becomes consensus surface — the
    worst of both columns.
- **Costs owned, not hidden**: two gas meters with independent per-block
  ceilings (the resources genuinely differ: parallel validation vs serial
  execution), two audit surfaces, and a block builder that budgets both
  segments. The scope freeze is what keeps this bounded: euvm's opcode set
  and gas table do not grow anymore.
- **Open question flagged, not decided here**: whether the Genesis-3 →
  Genesis-4 carryover flattens script-locked outputs to plain balances
  (the V4 carryover is balance-shaped). If it does, euvm carries zero live
  state across the transition and the scope freeze is free; if any
  script-locked value must cross intact, the carryover procedure — owned by
  the ecosystem-migration track — must say how. This document's verdict does
  not depend on the answer.

## 7. Where this design depends on DEV-2 (authorisation)

This state model is deliberately invariant across all three authorisation
options in the fleet brief. The dependency surface, exhaustively:

1. **Sender identity.** The model needs one function,
   `sender(tx_envelope) → Address` — recovery (secp256k1), declaration plus
   PQ verification, or both. Accounts, deposits (§4.2), and withdrawals
   (§4.3) are keyed by `Address` and never look at keys.
2. **Transaction envelope and intrinsic gas.** A ~4.6 KB hybrid signature
   changes tx size and therefore intrinsic gas and the practical
   `EVM_BLOCK_GAS_LIMIT`; the devnet sweep (§5.2) must run *after* DEV-2's
   envelope is fixed.
3. **Receipts/tx hashing.** If MetaMask-compatible RLP envelopes are
   accepted, `receipts_root` and tx hashes follow Ethereum byte-for-byte; a
   PQ envelope needs its own canonical tx hash. Either way the *leaf layout*
   (§2.2) is unchanged.
4. **Dual-model marking.** If the answer is "both", each account may need a
   key-class marker. That marker lives inside the account trie (an account
   field under `account_root`), not in the consensus SMT — decided here so
   the closed list does not reopen for it.
5. **`ecrecover` the precompile** is orthogonal to authorisation (contracts
   verifying secp256k1 signatures in-EVM) and stays, whatever DEV-2 picks.

The two boundary crossings are authorisation-independent by construction:
deposit inputs are spent under the existing transparent PQ rule, and
withdrawal outputs are locked by caller-chosen (normally PQ) scripts.

## 8. What is implemented, and what is not

**Implemented on this wave (all in `crates/bloch-pos-committee`, 271 tests
green from the crate directory):**

- `state_root.rs`: `TAG_EVM_COMMITMENT = 0x09`, the `EvmCommitment` struct
  with canonical 80-byte serialization, the singleton leaf insert, the
  `ConsensusState.evm` field; tests extended — per-field load-bearing
  mutations for all four fields, plus `evm_commitment_fields_do_not_alias`
  (root-pair swap and u64-pair swap must move the root).
- `derive.rs` / `produce.rs`: `ChainState.evm` carried through
  `post_chain_state` and the producer/validator shared-derivation seam.
- `transition.rs`: `CommittedState` carries the commitment;
  `CommittedState::genesis` takes it as an explicit input (it is execution-
  layer data, so consensus receives it, never invents it).
- `interfaces.rs`: `StateRoots` gains the `evm` component with the
  carried-never-recomputed contract in its doc. **This amends the frozen
  interface**; flagged here per the fleet brief rather than done silently.
- `docs/specs/BLOCH-POS-NODE-INTEGRATION.md`'s `state_roots` storage-row size
  updated to include the 80-byte commitment.

**Not done, deliberately, and needing follow-up:**

- No execution crate. Porting `bloch-l2-evm`'s executor/stateroot core into
  this repo, the deposit/withdrawal transaction kinds, the phase-order
  engine, and `DS_EVM_WITHDRAW` in `params.rs` are wiring-wave work; I added
  no dead constants for unwired paths.
- No setter on `CommittedState` for advancing the EVM commitment per block —
  the node-integration wave should add one visible mutation path for all four
  carried components at once, not four ad-hoc ones.
- No KAT vector file pinning the new `state_root` output. None existed for
  the previous 7-leaf layout either (the e2e suite recomputes rather than
  pins); the A1 KAT task should freeze vectors for the 8-leaf layout
  directly.
- `EVM_BLOCK_GAS_LIMIT`, the base-fee bounds, and intrinsic-gas numbers are
  unfixed pending DEV-2's envelope (§7.2) and a devnet sweep.
- The conservation-invariant harness (§4.5) is specified, not built.
- I did not modify `bloch-euvm` (the scope freeze is a decision recorded
  here, not an edit), and I did not touch the Coherence crates — §4.4 argues
  no change is needed, which an adversarial C1 review should confirm.
