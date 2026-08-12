<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch L1 EVM — Threat Model (design under construction)

```
Document:   BLOCH-L1-EVM-THREAT-MODEL
Status:     DRAFT — adversarial review, Assistant A3
Created:    2026-08-11
Owner:      A3 (Adversarial review — EVM at L1)
Reviews:    FLEET-BRIEF-2026-08-11.md (§"EVM at L1, no L2"),
            BLOCH-POS-SHA3-LATTICE-MIGRATION.md (§5.3–5.5, §6.1, §6.6, §7),
            BLOCH-COHERENCE-UNDER-POS.md (leaf-position consensus, F8),
            crates/bloch-euvm/{src/lib.rs,src/state.rs,src/batcher.rs,
              tests/audit_gas.rs} (the existing eUTXO VM and its gas findings),
            crates/bloch-pos-committee (finality, sortition, churn — the PoS base
              the MEV findings ride on).
Companions: BLOCH-L1-EVM-STATE-MODEL.md, BLOCH-L1-EVM-AUTHORIZATION.md,
            BLOCH-L1-FEE-MARKET.md — being written in parallel this wave.
Scope:      the *design* of EVM at the base layer. There is NO EVM, secp256k1,
            revm, keccak, or account-model code in the tree today (grep is clean);
            every finding here attacks a design premise, not shipped code. That is
            the cheapest possible time to find these.
```

## How to read this

This follows the contract of `BLOCH-POS-THREAT-MODEL.md` and its second pass.
Each finding gives **the attack**, the **spec section / code path it lands on**,
the **attacker cost**, and **what would close it**, and carries an honest
verdict:

- `[CONFIRMED]` — I can anchor it to a committed fact: shipped code in this
  tree, arithmetic I checked, a normative spec sentence, or a fixed property of
  the EVM/secp256k1/keccak that any conforming implementation must exhibit.
- `[PLAUSIBLE]` — design-level reasoning about a component that is not written
  yet (the state model, the authorization model, the fee market, the account↔
  UTXO bridge). The risk is real but its magnitude depends on choices the three
  companion documents have not made. I have not inflated any of these to
  `[CONFIRMED]`.

Two facts about the base frame everything below, and they are *load-bearing*:

- **The chain has already been forked twice by non-determinism**, both cited in
  the migration doc's §2 and in fleet memory: `expected_bits` read from
  node-local mutable state (2026-08-08) and `CF_TIMESTAMPS` indexed by height in
  a DAG. §5.5 answers with a **hard rule**: every consensus-relevant value used
  to validate block *B* must be derivable from `B.parent`'s committed state,
  never from node-local mutable state. **An EVM is the largest new surface on
  which that rule can be broken**, and most of the determinism findings below
  are that rule meeting EVM reality.
- **The base is one hash function.** §6.1 ("One hash function, many uses; every
  use gets a tag") makes SHA-3 / SHAKE-256 the single primitive; the Coherence
  pool, the state SMT, block identity, and the euvm's `state.rs` SMT all use it.
  **EVM is Keccak-256 by definition** (addresses, the `KECCAK256` opcode,
  storage trie, `CREATE2`). These are not the same function. That collision is
  finding E2 and it is structural, not incidental.

The euvm crate (`crates/bloch-euvm`) is the closest thing to prior art: it is a
deterministic, gas-metered eUTXO validator VM, explicitly **not consensus-wired**
(`lib.rs` §Scope), and it has already been bitten by exactly the class of bug an
EVM re-opens at ten times the surface — its `audit_gas.rs` documents an **F2**
where a *flat* gas schedule let a cheap opcode sequence do unbounded CPU work
(the fix: gas scales with operand byte length). Read E1 and E4 as "F2, but for a
Turing-complete account VM nobody has written yet."

---

## Severity index

| # | Severity | Finding | Verdict |
|---|----------|---------|---------|
| E1 | **High** | Gas schedule + EVM-engine dependency version are consensus objects; either read from node-local config or bumped silently reintroduces the `expected_bits` fork class | CONFIRMED (hazard); PLAUSIBLE (which impl) |
| E2 | **High** | EVM forces **Keccak-256** into consensus state, breaking the §6.1 one-hash discipline and adding a second state-derivation path the `single_derivation_path` test exists to forbid | CONFIRMED |
| E3 | **Critical** | eUTXO and account state in one block: cross-model execution order is undefined; if the proposer fixes it, order is consensus **and** MEV; if unfixed, two honest nodes diverge on `state_root` | CONFIRMED (gap); PLAUSIBLE (resolution) |
| E4 | **High** | Asymmetric DoS: a cheap EVM tx that triggers many ~4,589 B PQ verifications (or that shares a block with PQ-signed eUTXO txs) costs validators far more than it pays, unless gas prices PQ verify at its true cost | CONFIRMED |
| E5 | **High** | An EVM path into the Coherence pool re-fixes **leaf positions**, which are consensus and bind the nullifier — a single break is a consensus fork *and* a privacy de-anonymisation at once | CONFIRMED (leaf=consensus); PLAUSIBLE (that a bridge is built) |
| E6 | **High** | MEV at L1 gives the slot proposer a real-money reason to reorg/withhold; the V4 fee **burn** does not capture MEV, so it does not damp the reorg incentive; compounds the PoS sortition-DoS (F7) | CONFIRMED (economics); PLAUSIBLE (magnitude) |
| E7 | **Critical** | If secp256k1 accounts are admitted (brief option A), every account that has ever transacted exposes a recoverable pubkey — a standing, day-one quantum liability that is the exact thing the project exists to avoid | CONFIRMED |
| E8 | **High** | A quantum adversary who drains the secp256k1 side gets **fungible, stakeable** BLCH: the theft contaminates the PQ side through the shared balance space and the staking gate unless explicitly firewalled | CONFIRMED (fungibility); PLAUSIBLE (firewall absent) |
| E9 | **Medium** | Under-priced `SSTORE` grows unbounded account state that every node must fold into the SHA3-256 SMT — state bloat amplified by per-write SMT re-hashing | PLAUSIBLE |
| E10 | **Medium** | Gas fees vs the V4 fee model: two fee regimes (EVM gas, eUTXO fee) must agree on burn-vs-validator split, or emission economics diverge; EIP-1559 base fee must derive from parent, not running local state | PLAUSIBLE |
| E11 | **Medium** | Account **nonces** are mutable per-account state; a reorg across the DAG→linear transition seam cascades nonce-gap invalidations that eUTXO spends do not have | PLAUSIBLE |
| E12 | **Medium** | A Rust EVM (revm-shaped) uses `HashMap` account/storage caches; any iteration-order leak into logs, refunds, self-destruct order, or the state root is a latent fork — the euvm avoided this on purpose with `BTreeMap` | PLAUSIBLE |
| E13 | **Note/Medium** | If `bloch-euvm` survives alongside the EVM, the chain has **two** contract VMs and two state derivations; the migration must say which owns BLCH balance and forbid double-spend across them | CONFIRMED (tension); PLAUSIBLE (resolution) |

**Vectors examined and explicitly *not* raised as findings** (stated, not
padded): the EVM's *own* opcode-level determinism given fixed gas and a fixed
engine (EVM is deterministic by construction — the risk is entirely at the
edges: gas, hash function, ordering, dependency version — E1/E2/E3/E12, not the
interpreter core); u256 arithmetic overflow inside the EVM (wrapping is defined
and part of the spec — not a bug); and MetaMask/tooling *compatibility* as a
security property (it is an adoption property; the security cost of buying it is
E7, and that is where it belongs).

---

## E1 — High: the gas schedule and the EVM engine version are consensus, and both can silently fork the chain

**Attack / failure.** Gas is not an accounting convenience in a consensus VM; it
is part of the state-transition function. Two nodes that price the same
transaction differently reach different `state_root`s and fork. §5.5's hard rule
says every consensus value must derive from `B.parent`'s committed state. An EVM
puts two things in tension with that rule:

1. **The gas schedule as node-local config.** Every production EVM ships gas
   costs as constants, but real deployments make some of them *configurable*
   (EIP activation flags, a chain-spec file, a `--gas-schedule` override). The
   moment any gas cost is read from a node's local chain-spec rather than from
   committed consensus, it is `expected_bits` again: a value that decides block
   validity coming from mutable local state. The euvm already learned the
   narrow version of this — `audit_gas.rs` F2 was a *flat* schedule that
   mispriced CPU work; the EVM version is a *divergent* schedule that misprices
   validity.
2. **The engine dependency version.** "EVM at L1" in Rust means an
   interpreter — realistically `revm`-shaped. A minor version bump that changes
   one opcode's gas, adds an EIP, or alters refund accounting **is a hard fork**,
   whether or not anyone labelled it one. This project's own history has the
   exact shape (the SHA256D endianness flag-day, the `expected_bits` divergence):
   a consensus-relevant constant that changed under nodes that thought they were
   running "the same binary." An EVM makes the *entire gas table and opcode set*
   into that constant, sourced from a third-party crate on its own release
   cadence.

**Code path / spec.** Migration §5.5 (no node-local mutable state), §6.1;
`crates/bloch-euvm/tests/audit_gas.rs` (the F2 precedent); the fee market is
`BLOCH-L1-FEE-MARKET.md`'s object but the *determinism* of gas is a consensus
invariant that must be pinned here.

**Cost.** Zero to trigger accidentally — a routine dependency update or a
chain-spec edit does it. To weaponise: get two fleet cohorts onto engine
versions with one differing gas cost and submit a transaction that straddles the
difference; the fleet forks at that block.

**What closes it.** (a) Freeze the gas schedule as a **consensus constant** in
this repo, not inherited from the engine crate's defaults; pin the engine to an
exact revision with a flag-day process identical to the SHA256D fork's, and add
a CI guard that fails if the vendored gas table changes without a version bump.
(b) A property test in the spirit of `header.rs::single_derivation_path`:
assert no gas value is read from anything but a committed constant. (c) State
explicitly that an engine upgrade is a coordinated hard fork with a height gate,
never a rolling deploy. `[CONFIRMED]` that this is the same hazard class the
chain has already forked on twice; `[PLAUSIBLE]` only on which concrete engine
is chosen.

---

## E2 — High: EVM drags Keccak-256 into consensus and breaks the one-hash discipline

**Attack / failure.** §6.1 is unambiguous: one hash function (SHA-3/SHAKE-256),
many uses, each domain-tagged. The state SMT (§5.5), block identity (§5.4), the
Coherence accumulator, and the euvm's own `state.rs` SMT are all SHAKE-256. **EVM
cannot run on SHAKE-256.** EVM semantics are defined over **Keccak-256** (the
pre-FIPS variant, different padding from FIPS-202 SHA3-256): the `KECCAK256`
opcode, `CREATE`/`CREATE2` address derivation, the storage/account trie, event
topic hashing, and Solidity's entire ABI/mapping-slot layout all assume
Keccak-256. A contract that computes `keccak256(abi.encode(...))` for a mapping
slot and a node that answers with SHA3-256 disagree on every storage location.
So "EVM at L1" **forces a second hash primitive into consensus state**, and it is
specifically the one the §6.1 discipline was written to exclude.

Two consequences follow:

- **The state commitment splits.** Either account/storage state is committed in
  a Keccak-256 MPT (native EVM) and the rest of the chain in the SHA3-256 SMT —
  two trees, two functions, under one `state_root` — or account state is
  re-hashed into the SHAKE-256 SMT, in which case on-chain `keccak256` results no
  longer match the storage layout and Solidity tooling breaks anyway. There is no
  option that is both EVM-compatible and single-hash.
- **A second derivation of "state."** The `single_derivation_path` property test
  (brief §"How to work"; `header.rs`) exists because three agents independently
  wrote a second `BlockId`. Account state committed under a different tree/hash is
  a *second state derivation* by construction — exactly the pattern that test
  forbids for block identity, now re-appearing one level up at the state root.

**Code path / spec.** Migration §6.1 (one-hash table), §5.5 (SMT is SHA3-256);
`crates/bloch-euvm/src/state.rs` (SHAKE-256 SMT, the "hashing discipline" note);
EVM/Solidity Keccak-256 requirement (fixed property of the target VM).

**Cost.** N/A — this is a structural incompatibility, not an attack that costs
something; the "attacker" is the decision to be EVM-compatible.

**What closes it.** A conscious ruling, priced in the state-model doc: either
(a) admit Keccak-256 as a **second, domain-separated consensus primitive**,
documented as an explicit exception to §6.1 with the audit surface that adds
(two hash functions in the trusted base, two sets of KATs, the Coherence-prover
guest now needing both); or (b) run **EVM semantics without EVM storage layout**
— SHAKE-256 storage trie, a non-standard `KECCAK256` that Solidity does not
expect — and accept that this is "EVM bytecode, not EVM tooling," which is the
brief's option B wearing a different hat. This must be decided before any gas or
state work; it is upstream of E1 and E9. `[CONFIRMED]`.

---

## E3 — Critical: eUTXO and accounts in the same block have no defined cross-model execution order

**Attack / failure.** Genesis-4 blocks carry eUTXO transactions (the base model,
§7's `DEPOSIT`/`EXIT`, ordinary transfers, euvm validators) and — under this
instruction — account-model EVM transactions, and the block commits **one**
`state_root` over the whole state (§5.5). That forces a question the design has
not answered: **within a single block, what is the execution order between an
eUTXO transaction and an EVM transaction, and who fixes it?**

The eUTXO model is order-*independent* by design where it can be — the euvm
`batcher.rs` exists precisely because a hot single-state contract needs a
*canonical* total order to be deterministic, and it sorts orders by a canonical
key "independent of submission order." The **account model is order-dependent by
nature**: nonces, balances, and storage are sequential mutable state; tx *k+1*
routinely reads what tx *k* wrote. When the two models share a block and share a
balance space (BLCH in both), there is no canonical key that totally orders a
UTXO spend against an account nonce increment. Two failure modes, and they are
mutually exclusive:

- **Order left implicit.** Two honest nodes, handed the same block body, choose
  different eUTXO-vs-account interleavings, execute an EVM tx that reads a
  balance an eUTXO tx in the same block just moved, and compute **different
  `state_root`s.** This is the 2026-08-08 divergence with a new cause: consensus
  output depending on something not fixed by committed state. It is a
  chain-halting fork, and it fires on honest nodes.
- **Order fixed by the proposer.** The proposer declares the interleaving in the
  block body. Now the order is deterministic — but it is *consensus*, and it is
  worth money: the proposer decides whether the EVM tx sees the pre- or
  post-transfer balance. That is E6 (MEV) arriving through the state model, and
  it means every block's cross-model order is an attackable degree of freedom.

**Code path / spec.** Migration §5.5 (single `state_root` over eUTXO + stake
state), §5.4 (single derivation of block identity); `crates/bloch-euvm/src/
batcher.rs` (the canonical-order requirement for even *one* eUTXO contract);
`BLOCH-L1-EVM-STATE-MODEL.md` owns the resolution.

**Cost.** Implicit-order fork: zero — honest nodes trigger it. Proposer-order
extraction: the value of the reorder, captured every slot the attacker proposes.

**What closes it.** The state-model doc must define a **single, committed,
canonical intra-block order** across both models (e.g. a total order over all
transactions by a canonical key, with cross-model reads resolved against a
snapshot taken at a defined point), and a property test asserting two nodes
compute an identical `state_root` from an identical unordered tx multiset —
mirroring the batcher's determinism test but across models. If BLCH is shared
between the models, the order must additionally be shown free of cross-model
double-spend (E13). This is a Phase-1 blocker: it is the account-model analogue
of F1 (the single most important undefined number), and it cannot be left to the
node integrator. `[CONFIRMED]` that the gap exists; `[PLAUSIBLE]` on the fix
because the state model is unwritten.

---

## E4 — High: a cheap EVM transaction can cost validators a 4,589-byte PQ verification per unit of gas

**Attack / failure.** The base signature is the ML-DSA-65 ‖ Falcon-1024 hybrid,
~4,589 B per signature (migration §5.3), and **both halves must verify** (brief
§Settled #2). Verifying it is milliseconds and kilobytes of work — an order of
magnitude more than a secp256k1 `ecrecover`, which is what EVM gas tables are
calibrated for. Two shapes of asymmetric DoS follow:

- **A precompile that verifies PQ signatures.** For PQ accounts (brief option B)
  to be usable, the EVM needs a precompile that verifies ML-DSA ‖ Falcon — the
  authorization model can't avoid it. If that precompile is priced like
  `ecrecover` (or like a few keccak rounds), a contract that calls it in a loop,
  or a tx with a large PQ-signed call-data batch, makes every validator do
  seconds of verification for a few thousand gas. The euvm's `audit_gas.rs` F2 is
  the exact lesson at smaller scale: gas that does not scale with real operand
  cost is a CPU-DoS. Here the "operand" is a 4.6 KB two-scheme lattice
  verification.
- **The block already carries PQ signatures.** Every eUTXO tx and every
  `DEPOSIT` carries a ~4,589 B hybrid signature the proposer's block forces every
  validator to check. An EVM tx that is *cheap to include* but expands the number
  of PQ verifications the block implies (many inputs, many authorised
  sub-calls) inflates validation cost without paying for it. Whoever sets gas
  must price PQ verification at its measured cost, and must bound the number of
  PQ verifications per block independently of gas, or a block that is within the
  gas limit can still be seconds to validate — a liveness lever that also widens
  the F7 sortition-DoS window (a validator busy verifying is a validator not
  attesting).

**Code path / spec.** Migration §5.3 (hybrid sig size), §7.1 (PoP verified under
both halves); brief §Settled #2; `crates/bloch-euvm/tests/audit_gas.rs`
(operand-length gas as the fix pattern); the concrete numbers belong in
`BLOCH-L1-FEE-MARKET.md`, the *bound* belongs in consensus.

**Cost.** For the precompile-loop variant: the gas for a handful of precompile
calls, chosen to be far below the verification cost they impose. `[CONFIRMED]`
that PQ verify is large and that flat/underscaled gas is a DoS (euvm F2 proves
the pattern in-tree).

**What closes it.** Benchmark ML-DSA-65 ‖ Falcon-1024 verification and price the
precompile (and every PQ-verification-bearing opcode path) at that measured cost
with margin; add a **per-block ceiling on PQ verifications** enforced outside the
gas accounting (a structural limit like the euvm's `check_tx_resource_limits`),
so gas underpricing cannot alone make a block expensive to validate; and add an
adversarial "cheap tx, maximal verification" fuzz case to A2's suite.

---

## E5 — High: an EVM path into the shielded pool re-fixes leaf positions — a consensus fork and a privacy break in one move

**Attack / failure.** The Coherence pool is C1-frozen and **leaf positions are
consensus**: `BLOCH-COHERENCE-UNDER-POS.md` F8 states the nullifier binds the
note's tree position, `nf = SHAKE256(DOM_NF ‖ nk ‖ rho ‖ LE64(position))`, and
§"Leaf positions are consensus and must survive verbatim" forbids re-appending
commitments in any other order. The accept-path ordering is fixed today
(shielded apply → then DAG/fork-choice commit). Introduce an EVM that can *touch*
the pool — a shield/unshield precompile, or an EVM-driven bridge that mints or
burns notes — and the **order in which leaves are appended becomes a function of
EVM execution order**, which E3 already shows is undefined or proposer-chosen.
That single coupling is uniquely bad because it fails on two axes at once:

- **Consensus.** If EVM execution can interleave note appends with eUTXO shield
  txs, two nodes that order the block differently assign the *same note* a
  *different position*, hence a different nullifier, hence a different pool root —
  a hard fork inside the private ledger, which §6.6.2 warns is the "worst possible
  asymmetry."
- **Privacy.** Because the nullifier is a deterministic function of position, an
  adversary who can influence *where* a victim's note lands (by placing EVM txs
  around it, i.e. proposer-side or fee-priority-side ordering control) gains a
  handle on that note's nullifier and on the linkage between deposit and spend —
  partially undoing the unlinkability the pool exists to provide. Ordering
  control over a privacy pool is a de-anonymisation primitive, not just a
  liveness one.

**Code path / spec.** `BLOCH-COHERENCE-UNDER-POS.md` F8, §2.4 ("Ordering inside
the accept path"), §"Leaf positions are consensus"; migration §6.6.1–6.6.2
(continuity, finalized shielded state); the pool is C1-frozen (brief §Settled #3).

**Cost.** If a shield/unshield EVM path exists: the fee to place ordering-relevant
EVM txs around a target — cheap, and free to the proposer. If no such path is
built, the vector is closed at the source.

**What closes it.** The cleanest fix is a **hard consensus boundary**: EVM
execution may not append to, reorder, or read positional data from the Coherence
pool; all pool mutations happen through the existing eUTXO shield/unshield path in
a phase of block application that runs *before or after* — never interleaved with
— EVM execution, with leaf-append order fixed by the eUTXO canonical order alone
(E3's canonical order, restricted so EVM cannot perturb it). If a shield
precompile is genuinely wanted, its note appends must be deferred to a
deterministic post-EVM settlement pass ordered by a canonical key independent of
EVM state, and a KAT must assert leaf positions are identical under any EVM
interleaving. `[CONFIRMED]` that leaf position is consensus and privacy-bearing;
`[PLAUSIBLE]` on severity-realisation because whether the EVM gets a pool path is
an unmade design choice — but it is High precisely because the natural,
convenient design (a shield precompile) walks straight into it.

---

## E6 — High: MEV at L1 gives the proposer a money reason to reorg, and the V4 fee burn does not damp it

**Attack / failure.** With EVM at L1, block *ordering* is worth real money
(sandwiches, liquidations, arbitrage, oracle-update races). That changes the PoS
security argument, not merely fairness:

- **The reorg incentive is now economic.** A slot proposer who sees a fat MEV
  bundle one block back has a reason to *not* build on it and instead re-propose
  to capture it (time-bandit), or to withhold. The PoS base already has the
  levers: F7 shows a per-slot fork-choice subcommittee of only
  `SLOT_SUBCOMMITTEE_SIZE` validators can be DoS'd cheaply, re-opening
  intra-epoch reorgs; MEV supplies the *motive* that F7 assumed was absent. The
  two compose: a well-capitalised proposer with a DoS budget can now profit from
  the reorg F7 said was merely possible.
- **The V4 fee burn does not capture MEV.** Tokenomics V4 burns fees during
  emission, then routes them to validators (brief §Settled #4). Burning *fees*
  is often argued to reduce ordering games — but **MEV is extracted outside the
  fee**: it is the value moved between the victim's trade and the attacker's, and
  none of it flows through the burn. So the mechanism that is supposed to make
  the chain's economics clean leaves the largest ordering-driven incentive
  untouched. Worse, MEV accrues to *whoever proposes*, which rewards exactly the
  stake concentration the PoS gates (G2/G3, the cohort cap) are fighting: MEV is
  a return-on-stake the emission schedule did not model, and it flows
  super-linearly to the operator who proposes most.

**Code path / spec.** brief §Settled #4 (fee burn then validators); PoS
threat-model F7 (sortition DoS / cheap reorg), F8 (concentration timeline);
`crates/bloch-pos-committee` fork-choice and sortition; `BLOCH-L1-FEE-MARKET.md`
owns the fee/MEV accounting.

**Cost.** For the reorg-for-MEV variant: the F7 DoS budget plus the opportunity
cost of the withheld slot, both dominated by a single large MEV bundle. For the
concentration variant: nothing — it is a standing bias in who profits.

**What closes it.** This is not fully closeable — MEV is inherent to a shared
ordered state machine — but the design must (a) *state* that L1 EVM introduces an
MEV-driven reorg incentive the PoW→PoS security analysis did not carry, and
re-run the F7 reorg-cost analysis with MEV as the attacker's revenue; (b) decide
whether any MEV is captured by protocol (e.g. proposer-boost tuning,
enshrined-PBS-style separation, or MEV burn) rather than left entirely to the
proposer; and (c) feed the MEV-as-return-on-stake term into the concentration
gates, which today measure only staked weight. `[CONFIRMED]` on the economics and
the burn gap; `[PLAUSIBLE]` on magnitude, which depends on realised on-chain
activity.

---

## E7 — Critical: admitting secp256k1 accounts puts a recoverable public key on-chain for every account that ever transacts

**Attack / failure.** The brief's option A ("accept secp256k1 accounts at L1 for
EVM transactions") is the cheap adoption path, and its cost is the whole thesis.
EVM authorization is `ecrecover`: the sender address is *recovered from the
signature*, which means the account's secp256k1 **public key is revealed by every
transaction it sends**. secp256k1 is broken by a cryptographically-relevant
quantum computer (Shor). Therefore:

- **Every secp256k1 account that has ever sent one transaction is drainable by a
  future quantum adversary**, retroactively, from data already on the public
  ledger. This is not "harvest-now-decrypt-later" on encrypted traffic; it is a
  standing, permanent liability sitting in plaintext consensus state from the
  first transaction onward. A chain whose entire reason to exist is
  post-quantum authorization would be shipping a quantum-vulnerable
  authorization path as a first-class citizen.
- **The exposure is worse than Bitcoin's.** Bitcoin P2PKH at least hides the
  pubkey behind a hash until spend; the EVM/account model exposes the pubkey on
  *every* send and reuses the address indefinitely, so a long-lived EVM account
  is maximally exposed. There is no "use once" mitigation that survives normal
  EVM usage.

**Code path / spec.** brief §"The hard problem" (option A, verbatim: "it means
the chain has a quantum-vulnerable authorisation path, which is the one thing the
whole project exists to avoid"); the base suite is PQ-only (brief §Settled #2).

**Cost.** To the adversary: a CRQC, once. To the chain: it is paid up front, the
day secp256k1 accounts are enabled — the liability accrues immediately and is
realised whenever the CRQC arrives.

**What closes it.** Only *not* admitting secp256k1 as an authorization method
closes it. If option A is chosen anyway, the security note must be blunt (the
brief already demands this) and the design must at minimum (a) quarantine
secp256k1 accounts so they can hold only a bounded, clearly-labelled class of
value, (b) forbid secp256k1 accounts from staking or authorising any PQ-owned
state (E8), and (c) publish a sunset/forced-migration path to PQ accounts with a
deadline, so the liability window is bounded rather than perpetual. The honest
recommendation, consistent with the project thesis, is brief option B (PQ-only
accounts, EVM semantics without EVM signing) — and to state plainly that this
means MetaMask does not work and tooling must be ported. `[CONFIRMED]`.

---

## E8 — High: stolen secp256k1 value is fungible and stakeable, so the quantum compromise crosses into the PQ side

**Attack / failure.** The brief asks explicitly "what a quantum adversary can
steal from the secp256k1 side and whether that contaminates the PQ side." It
does, unless a firewall is built, for two reasons the base makes true by default:

- **One balance space.** If secp256k1 accounts and PQ accounts denominate the
  same BLCH (the natural design — one coin, one fee market, brief §"one state"),
  then BLCH a quantum adversary drains from secp256k1 accounts is *the same
  fungible BLCH* everyone else holds. It can be sent to PQ accounts, used to pay
  PQ-authorised contract calls, and — most damaging — **staked**. brief §Settled
  #7 makes carried-over liquid balance stakeable; nothing yet distinguishes
  "honestly held BLCH" from "BLCH lifted off a broken secp256k1 key." A quantum
  adversary thus converts a cryptographic break into *validator influence* over
  the PQ consensus, buying its way toward the concentration the gates fight (PoS
  F8), using coins the PQ side considers perfectly valid.
- **Bridges leak authority, not just value.** If any contract lets a
  secp256k1-authorised account move, custody, or trigger PQ-owned assets (a
  wrapped-asset bridge, a shared vault, an approval), then compromising the
  secp256k1 key compromises whatever PQ-side state that contract gates — the
  break crosses the authorization boundary directly, not only through fungible
  coin.

**Code path / spec.** brief §"The hard problem" (option C: "including what a
quantum adversary can steal from the secp256k1 side and whether that contaminates
the PQ side"); brief §Settled #7 (liquid ⇒ stakeable); PoS F8 (concentration via
stakeable float); `BLOCH-L1-EVM-AUTHORIZATION.md` owns the firewall.

**Cost.** The E7 CRQC, then ordinary transactions to move and stake the proceeds
— no additional break needed once the key is recovered.

**What closes it.** If a secp256k1 side exists at all, it must be **firewalled by
consensus, not by convention**: secp256k1-authorised BLCH must be forbidden from
backing a `DEPOSIT` (a staking-eligibility rule analogous to §6.6.3's
"stake must trace to transparent coins," now "stake must trace to PQ
authorization"), and no contract may let secp256k1 authorization move PQ-owned
state. The authorization doc must prove the firewall holds transitively (stolen
BLCH cannot be laundered into stakeable PQ-authorised BLCH through a swap — the
F4 lesson: a market swap defeats coin-tracking, so the rule must bind
*authorization at deposit time*, not coin ancestry). `[CONFIRMED]` on fungibility
and stakeability; `[PLAUSIBLE]` that no firewall exists only because the
authorization model is unwritten — but the default (shared balance, stakeable) is
the contaminating one.

---

## E9 — Medium: under-priced storage growth is amplified by the SHA3-256 state SMT

**Attack.** `SSTORE` into fresh slots grows account state that every node must
carry, and under §5.5 that state is committed in a SHA3-256 sparse Merkle tree.
Each new storage slot is an SMT insertion — a path of SHAKE-256 node hashes
(`state.rs` uses a depth-256 SMT with per-node SHAKE-256, gassed per invocation in
the euvm). So the cost an attacker pays (EVM `SSTORE` gas) and the cost the
network bears (permanent state + SMT re-hashing on every future proof and update
touching that subtree) are decoupled in the classic Ethereum "state rent"
way — but *amplified* here because Bloch commits the whole state in one SMT and
because the Coherence prover / light-client paths must re-derive roots over it.
Ethereum has fought this for a decade (EIP-1559 was not the fix; state expiry and
Verkle are the ongoing ones); Bloch would inherit the unsolved problem on day one
with a heavier hash.

**Code path / spec.** Migration §5.5 (SHA3-256 SMT over state);
`crates/bloch-euvm/src/state.rs` (depth-256 SMT, per-node SHAKE-256, gas per
hash); `BLOCH-L1-FEE-MARKET.md` owns the pricing.

**Cost.** The `SSTORE` gas for N slots, chosen when gas is cheap; the network
pays storage + hashing forever.

**What closes it.** Price state growth at more than its instantaneous compute
(state-rent, a large `SSTORE`-new cost, or an expiry scheme), and account for the
SMT-depth hashing cost in the gas for any op that mutates committed state. State
this is a known-unsolved EVM problem being inherited, not a Bloch invention, so
nobody budgets it as done. `[PLAUSIBLE]` — the magnitude depends on the
(unwritten) gas schedule and whether an expiry scheme is adopted.

---

## E10 — Medium: two fee regimes and a base-fee that must not become local mutable state

**Attack.** The chain would have two fee-bearing transaction classes: eUTXO
transactions (existing fee, §7.4 endowment split) and EVM transactions (gas ×
gas-price). V4 burns fees during emission then routes them to validators (brief
§Settled #4). Two hazards:

- **Divergent split.** If EVM gas fees and eUTXO fees follow different burn-vs-
  validator rules, the emission economics the V4 model pins (`tokenomics_v4.rs`)
  no longer hold — validators earn an unmodelled gas stream, or burn removes an
  unmodelled amount. The two regimes must agree on the split or the supply/reward
  invariants (PoS F12's concern: curve sum vs allocation) drift.
- **EIP-1559 base fee as local state.** An EIP-1559-style base fee adjusts each
  block from the parent's gas usage. Done right, that is *derivable from
  `B.parent`* and consistent with §5.5. Done as a running node-local accumulator
  (the way `expected_bits` was maintained), it is the 2026-08-08 fork again. The
  base fee must be a pure function of committed parent state, proven so, not a
  mutable field a node updates as it goes.

**Code path / spec.** brief §Settled #4; migration §7.4, §5.5;
`tokenomics_v4.rs`; `BLOCH-L1-FEE-MARKET.md` (owner — I defer the mechanism
design there and raise only the determinism and split-consistency constraints).

**Cost.** Split divergence: no attacker needed, it is a modelling error. Base-fee-
as-local-state: the `expected_bits` fork cost, i.e. zero to trigger accidentally.

**What closes it.** One fee-split rule across both tx classes, imported from
`tokenomics_v4.rs` not restated; base fee defined as a pure function of parent
committed state with a determinism property test. `[PLAUSIBLE]` pending the fee
doc.

---

## E11 — Medium: account nonces make reorgs cascade in a way eUTXO spends do not, across the DAG→linear seam

**Attack.** Account nonces are mutable per-account counters; a valid tx requires
`nonce == account.nonce`. On a reorg, every EVM tx after the reorg point must be
re-evaluated against recomputed nonces, and a single dropped tx invalidates every
later tx from the same sender (nonce gap) — a cascade eUTXO does not have (a UTXO
spend is either available or not; there is no sequential counter to desync).
Migration §5.2/§5.4 already flag a delicate **DAG→linear transition seam** (the
historical DAG and the post-transition linear chain coexist in one database, "the
transition block is the unique block whose parent is a DAG selected-tip"). Layering
account-nonce reorg semantics across that seam multiplies the seam's edge cases:
a reorg that crosses near the transition must handle nonce recomputation on the
linear side while the DAG side has no accounts at all.

**Code path / spec.** Migration §5.2 (DAG→linear seam, A5's seam matrix), §5.4;
account-nonce semantics (fixed EVM property); `BLOCH-L1-EVM-STATE-MODEL.md`.

**Cost.** Reorg-dependent; not a cheap standalone attack, but an amplifier of any
reorg (including the E6/F7 MEV reorgs) and a correctness burden on the seam.

**What closes it.** Specify nonce recomputation on reorg as part of the state
model, add it to A5's seam test matrix (reorgs that straddle the transition, with
and without EVM txs), and bound reorg depth interacting with `MAX_REORG_UNDO`
(the Coherence engine already bounds undo at 128 — the account model needs the
same). `[PLAUSIBLE]`.

---

## E12 — Medium: a Rust EVM's HashMap caches are a latent non-determinism the euvm avoided on purpose

**Attack.** The euvm is deterministic *by construction* and says so: "no
`HashMap`, no clock, no hash-map iteration," canonical `BTreeMap` ordering
throughout (`lib.rs`, `batcher.rs`). A production Rust EVM (revm-shaped) is not
built to that discipline — it uses `HashMap` for account and storage caches
because iteration order normally does not affect the result. But it *can* leak
into consensus at several points: the order logs are emitted, the order
self-destructs / account deletions are applied at end-of-transaction, access-list
construction, and — most dangerously — any place the *state root* is computed by
iterating a map rather than a sorted structure. Rust's `HashMap` is randomised
per-process (SipHash with a random seed), so an iteration-order leak is not even
stable across *restarts of the same node*, let alone across nodes: the fork is
non-reproducible, which is the worst kind to debug (cf. the fleet's history of
hard-to-localise consensus stalls).

**Code path / spec.** `crates/bloch-euvm/src/lib.rs`, `src/batcher.rs` (the
explicit no-HashMap discipline as the standard to hold the EVM to); §5.5
determinism rule; whichever engine `BLOCH-L1-EVM-STATE-MODEL.md` selects.

**Cost.** Zero to trigger if the leak exists; it is a latent bug, not a paid
attack — but an adversary who *finds* the leak can craft a tx that reliably
straddles it.

**What closes it.** Hold the EVM engine to the euvm's determinism discipline:
audit every path from EVM execution to `state_root` and to the block body for
map-iteration order, require sorted/canonical structures at every consensus
boundary, seed any unavoidable `HashMap` deterministically, and add a
"same-tx-multiset, shuffled-input-order ⇒ identical state_root, across two
processes" test (the cross-process variant matters because of SipHash
randomisation). `[PLAUSIBLE]` — real for any off-the-shelf engine, but its
presence depends on the engine and the wiring, neither of which exists yet.

---

## E13 — Note/Medium: two VMs, two state derivations — the euvm's fate must be decided, not left ambiguous

**Attack / tension.** The brief asks whether `crates/bloch-euvm` (the eUTXO VM,
consensus-wired at Genesis-3 height 0) "survives, is absorbed, or dies." If it
*survives alongside* the EVM, the chain has **two Turing-ish contract systems**
over one state root, and every question in E3 (cross-model order), E2 (which hash
commits which state), and E8 (which authorization gates which balance) must be
answered for *three* interacting models (eUTXO transfers, euvm validators, EVM
accounts), not two. Concretely: if BLCH can sit in a euvm `ExtOutput`, in a plain
UTXO, *and* in an EVM account balance, the migration must name the **one**
canonical owner of a given coin at a given height and forbid it being spent as two
of the three in one block — a double-spend surface that does not exist while
there is one model. The `single_derivation_path` discipline (brief §"How to
work") is about block identity, but its spirit — *one* way to derive a
consensus object — is exactly what two live VMs violate for *state*.

**Code path / spec.** `crates/bloch-euvm` (consensus-wired at G3 h0 per brief);
migration §5.5; brief §"Second-order questions … whether `crates/bloch-euvm`
survives, is absorbed, or dies."

**Cost.** N/A — a design-coherence risk, realised as double-spend or divergence
surface if left unresolved.

**What closes it.** A ruling in the state-model doc: euvm *dies* (EVM subsumes
contract functionality, euvm's validators re-expressed as EVM contracts — but
then the Ustav/Kirpich tooling built on euvm must be ported, and the shielded-pool
and native-asset semantics euvm carries must survive), or euvm is *absorbed*
(euvm becomes one precompile/execution-context inside the EVM host with a single
shared balance space and a single canonical order), or it *survives* with a
**hard partition** of the state each VM may touch and a consensus rule forbidding
cross-VM double-spend, KAT-pinned. Ambiguity is the risk; any of the three,
stated and tested, is fine. `[CONFIRMED]` that the tension exists; `[PLAUSIBLE]`
on resolution.

---

## Cross-cutting note: Ustav-at-L1 multiplies E2/E3/E4

The other wave direction (Ustav / PSTRN-1 as a consensus object, Kirpich as a
consensus gate) is not my document, but it *composes* with these findings and I
flag the composition so it is not discovered late: promoting charter validation
to consensus means every node runs charter logic as part of block validation.
That charter logic (a) needs a hash — if it reuses Keccak-256 for
EVM-compatibility it inherits E2; if SHAKE-256 it diverges from EVM tooling; (b)
runs *inside or alongside* EVM execution, so it inherits E3's cross-model
ordering question; and (c) is a new per-block validation cost every node pays for
every charter-gated token, an E4-shaped asymmetric-DoS surface where a token
issuer's expensive charter becomes everyone's validation cost (the brief says
this explicitly: "a token issuer's mistake becomes everyone's validation cost").
The Ustav-at-L1 document should treat E2/E3/E4 as constraints it must satisfy,
not re-derive.

---

## Recommended gate additions for sign-off

1. **E3 and E7 are Phase-1 blockers.** Cross-model execution order (E3) is the
   account-model analogue of PoS F1 — the single most important undefined
   behaviour — and must be a committed canonical order with a two-node
   determinism KAT before any EVM code lands. The secp256k1 authorization
   decision (E7) is a founder decision the brief already reserves; the security
   note must be blunt and the recommendation is PQ-only (option B).
2. **E2 is upstream of everything.** Decide the Keccak-256-in-consensus question
   before gas (E1/E9), state (E3), or the fee market (E10) is designed — they all
   depend on how many hash functions and how many state trees the chain commits
   to.
3. **Price PQ verification and bound it structurally (E4)** before any devnet
   benchmarks "EVM throughput," and reuse the euvm's `check_tx_resource_limits`
   pattern.
4. **Firewall secp256k1 from staking and from PQ-owned state by consensus (E8)**,
   binding on authorization at deposit time (not coin ancestry — the F4 swap
   lesson), if any secp256k1 side is admitted at all.
5. **Wall the EVM off from the Coherence pool's leaf ordering (E5)** as a hard
   consensus boundary; a shield precompile, if wanted, appends in a deterministic
   post-EVM pass, KAT-pinned to position-invariance under EVM interleaving.
6. **Re-run the F7 reorg-cost analysis with MEV as attacker revenue (E6)** and
   decide whether any MEV is captured by protocol rather than left to the
   proposer.

---

## What I did NOT do (honest limits)

- **I wrote no code and ran no tests.** Every `[CONFIRMED]` rests on reading
  shipped code/spec/arithmetic or on a fixed property of the EVM/secp256k1/keccak,
  not on execution. The euvm gas F2 I cite is read from `audit_gas.rs`'s prose and
  test names; I did not re-run its suite.
- **The three companion documents did not exist in `integration/pos-modules`
  while I worked** (`BLOCH-L1-EVM-STATE-MODEL.md`, `-AUTHORIZATION.md`,
  `BLOCH-L1-FEE-MARKET.md` were all absent). Every finding that turns on the state
  model, the authorization model, or the fee market is therefore `[PLAUSIBLE]` by
  necessity — I attacked the *premises* and the *base*, not those docs. If they
  land, E3/E8/E10/E13 in particular should be re-checked against what they
  actually decide, and any that they close should be marked closed there.
- **I did not benchmark ML-DSA-65 ‖ Falcon-1024 verification** (E4) or SMT-update
  hashing cost (E9); I assert they are large relative to secp256k1/keccak from the
  ~4,589 B signature size and the scheme, not from measurement. A2 should put real
  numbers on both before gas is set.
- **I did not evaluate a specific EVM engine** (revm/reth/other). E1/E12 are about
  the *class* of Rust EVM; the concrete determinism audit must be redone against
  whichever engine the state-model doc selects.
- **I did not attempt the positive design** — how to *do* PQ accounts with EVM
  semantics, or the exact canonical cross-model order. That is the companion
  docs' job; this document's job was to find where the design breaks, and to
  price the three authorization options the brief reserves for the founder rather
  than pick one silently. My recommendation (option B, PQ-only) is a
  recommendation, not a decision.
- **I did not cover the historical DAG replay of EVM txs** beyond the nonce-seam
  note (E11); pre-transition blocks have no accounts, so there is nothing to
  replay, but A5's seam matrix should confirm no EVM state is expected before the
  transition height.
