# Coherence under PoS — integration plan for the shielded pool (§6.6)

> **PARCIALMENTE SUPERADO — 2026-08-11.** Esta analise foi escrita contra o
> estado do projeto naquele dia e depende de premissas que mudaram DEPOIS:
>
> - **a maquinaria de taint** — dissolvida: o carryover atravessa como um conjunto so, sem lista de exclusao, entao nao ha classe de moeda a marcar.
> - **a fase hibrida de PoW** — apagada: a Genesis-3 para na altura 80.000 e a Genesis-4 nasce de uma snapshot.
>
> O texto NAO foi reescrito, de proposito: o raciocinio que produziu cada
> achado tem valor mesmo quando a premissa mudou, e reescrever apagaria a
> trilha. Leia os achados; confira as premissas contra
> `BLOCH-TOKENOMICS-V4.md` e `BLOCH-POS-SHA3-LATTICE-MIGRATION.md`, que sao
> os normativos.


> **Owner:** A9 (Coherence integration), Genesis-4 / Bell PoS migration.
> **Inputs:** `BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §6.6 (all four requirements),
> `COHERENCE-C1.md` (frozen formats), the live code on `feat/pos-sha3-lattice`
> (`crates/coherence-core/src/lib.rs`, `src/coherence/`, `src/main.rs`), and the
> 11-commit `feat/zk-ledger` branch (`upstream-gitlab/feat/zk-ledger`).
> **Status:** plan + code audit. Findings below are against the tree as of
> `8fca774` (HEAD) and `ed030c3` (zk-ledger tip).

---

## 0. Where the code actually is today

Facts every section below builds on. File:line references are HEAD unless
marked *(zk-ledger)*.

| # | Finding | Where |
|---|---------|-------|
| F1 | The shielded pool is a node-local `Arc<RwLock<ShieldedPool>>` created fresh at startup — pure in-memory, no persistence | `src/main.rs:840` (the spec's `main.rs:844` reference has drifted by 4 lines) |
| F2 | Block acceptance applies shielded txs **before** `dag.add_block`, atomically per block | `src/main.rs:2750-2751` → `ShieldedPool::apply_block_self`, `src/coherence/mod.rs:304` |
| F3 | The proof verifier defaults to `RejectAll`; the SP1 backend is feature-gated and its vkey loader is `unimplemented!()` | `src/coherence/verifier.rs:18`, `:71` |
| F4 | **Consequence of F2+F3: the mainnet shielded pool is provably empty.** Any block carrying a shielded tx fails `ProofInvalid` and is rejected; every block-production path emits `shielded_transactions: Vec::new()` | `src/main.rs:2750`, `:1890`, `:3790` |
| F5 | The engine has a correct, audited reorg-undo primitive (`disconnect_block`, LIFO + block-id check, bounded by `MAX_REORG_UNDO = 128`) — but **nothing in `main.rs` ever calls it**; the accept-path comment admits "the shielded state does not yet track reorgs" | `src/coherence/mod.rs:190`, `:317`, `:50`; `src/main.rs:2747-2748` |
| F6 | The accumulator is genuinely **incremental** (append-only leaf `Vec`, `truncate` used only for reorg undo) and the nullifier set is genuinely **monotone** (`HashSet` insert-only outside undo) | `crates/coherence-core/src/lib.rs:59-79`, `src/coherence/mod.rs:27`, `:106` |
| F7 | `CommitmentTree::root()` on HEAD is O(n) recomputed from all leaves on every call | `crates/coherence-core/src/lib.rs:90-106` |
| F8 | The nullifier derivation **binds the note's tree position**: `nf = SHAKE256(DOM_NF ‖ nk ‖ rho ‖ LE64(position))` — leaf ordering is consensus | `crates/coherence-core/src/lib.rs:46-48`; `COHERENCE-C1.md §1.3` |
| F9 | There is **no nullifier-set root anywhere** in the tree. The set is a bare `HashSet` with no canonical commitment | `src/coherence/mod.rs:27` (both branches) |
| F10 | The `ShieldedTx` wire format has **no transparent value bridge**: `{anchor, nullifiers, outputs, fee, proof, binding_sig}` and `check_spend` enforces `Σin = Σout + fee`. Value can neither enter (shield) nor leave (unshield, beyond the public fee) the pool. **The `shield_tx` of §6.6.3 does not exist yet as a type** | `crates/coherence-core/src/lib.rs:230-237`, `:221`; `COHERENCE-C1.md §6` |
| F11 | No shielded column family exists in storage; `src/storage/` has zero references to the pool. On restart the node rebuilds an empty pool | `src/storage/mod.rs` (grep: no hits) |
| F12 | Anchor window is bounded at `ANCHOR_HISTORY = 100` recent roots | `src/coherence/mod.rs:21` |
| F13 | Doc/code mismatch: C1 §1.4 freezes `EMPTY_LEAF = SHAKE256_32(DOM_MT ‖ 0^0)` but the code (both branches, and therefore the guest) uses `SHAKE256_32(DOM_MT ‖ "empty-leaf")` | `crates/coherence-core/src/lib.rs:83` vs `COHERENCE-C1.md §1.4` |

### What `feat/zk-ledger` already delivers (11 commits on base `d4b9566`)

The branch is on the same lineage as HEAD (`d4b9566` is an ancestor of
`8fca774`) but predates the entire G3/PoS work — adoption is a **port
(cherry-pick + conflict resolution)**, not a merge; `main.rs` alone has
diverged by thousands of lines.

| Commit | What it gives us | §6.6 relevance |
|--------|------------------|----------------|
| `f069610` | **Phase-0 roots-in-coinbase hard fork (ADR-035):** `RootsCommitment{state_root, utxo_root, da_root, proof_root}` as a 151-byte tagged coinbase output folded under the existing merkle root — zero change to the 80-byte MiningHeader/Stratum/ASIC path. Fail-closed Dual-AND validation (`check_roots_commitment_gated`), height-gated inert (`STATE_ROOT_ACTIVATION_HEIGHT = u64::MAX`) | §6.6.2 hybrid-phase bridge. **Gap:** its `state_root` is the **accumulator anchor only** — the nullifier-set root is not committed (*(zk-ledger)* `crates/bloch-crypto/src/core/mod.rs:2229-2340`, `src/main.rs:2213`) |
| `f069610` (same) | `disconnect_block_self` **is actually wired into the accept path** with top-of-undo-stack rollback — the reorg wiring HEAD lacks (F5) | *(zk-ledger)* `src/main.rs:2228` |
| `cd7f62a` | Frontier-based `CommitmentTree`: O(1) cached root, O(log n) append, golden root-equality tests against the old impl | Fixes F7; root semantics preserved |
| `a167203` + `ed030c3` + `49e24a4` | SHAKE-256 Utreexo forest over the transparent UTXO set + stateless witness relay (`accum_witnesses` as a non-committed wire suffix) + canonical UTXO leaf serialization. Two accumulator crates coexist pending a founder dedup ruling | Feeds §5.5's eUTXO commitment in `state_root`, not Coherence directly |
| `7c9fe63` | **ML-KEM-768 + AES-256-GCM per-output `NoteCiphertext`** — fixes a real C1 gap (recipients had no way to discover their notes). Adds `output_ciphertexts` to `ShieldedTx` | Must-adopt; **changes the C1 §6 frozen wire format** → C1 needs a rev (C1.1) |
| `26bd7ae` | DoS bounds (`MAX_TX_NULLIFIERS = 256`), `validate_with_binding` seam with pinned error precedence, reorg-consistent mempool purge (`retain_chain_valid`) | Hardening; adopt |
| `407cffc` | Real SP1 verify path behind `sp1-verify`: explicit `.cpu()` builder (so `SP1_PROVER=mock` cannot inject an accepting mock), Core-proof-only decode, public-values bind check. **Fail-closed: `PINNED_ELF_SHAKE256_HEX = None`** until a reproducible guest ELF is frozen | §6.6.4 verifier discipline; adopt the pinning pattern verbatim |
| `0b64d94` | `ProofCheckpoint` + `PruneGate`: 3-conjunct deterministic AND (recursive proof verifies ∧ DAS available ∧ burial floor), **refuses every prune while any conjunct is unimplemented**; reorg floor at stored checkpoints | This *is* the §6.6.4 "degrade to keep raw signatures" posture, already coded |
| `c5d01f3` | AEAD-at-rest + RS-erasure/DAS scaffold | Phase-2; not on the G4 critical path |

---

## 1. §6.6.1 — Continuity across the transition

**Requirement:** the accumulator is incremental, the nullifier set is monotone,
and neither is reset/re-rooted/rebuilt at `TRANSITION_HEIGHT`. A note shielded
at *h* < T spends at *h* + 1 with its old witness. Failure mode is privacy, not
just correctness: a reset forces universal re-shielding, linking old notes to
new ones and de-anonymising the pool retroactively.

### 1.1 Verdict on the current structure

The data structures **natively support continuity** (F6): the tree only
appends, `truncate` exists solely for bounded reorg undo, and nullifiers only
accumulate. Nothing in either branch keys any Coherence state by height, era,
or genesis id — there is no "reset at height" logic to remove.

What breaks continuity today is not the structure but its **lifecycle** (F1,
F11): the pool lives in RAM and is reborn empty at `ShieldedPool::new()`
(`src/main.rs:840`) on every process start. Continuity across Genesis-4 is
therefore a *state-carriage* problem, and it has two very different cases:

- **Case A (pool still empty at T).** If `ShieldedVerifier` is still
  `RejectAll` at the transition (F3, F4), the pool crossing the seam is the
  empty tree + empty set. Continuity is then trivially satisfied — but the G4
  code must still be written to *carry* state rather than construct
  `ShieldedEngine::new()`, because Case B may hold on any shadow fork or if C2
  activates first.
- **Case B (shielding live before T).** The moment `PINNED_ELF_SHAKE256_HEX`
  is set and `BLOCH_SHIELDED_VERIFY=sp1` activates (per `407cffc`), real notes
  exist and every rule below is load-bearing.

### 1.2 What must be built

1. **Persist the pool (prerequisite for everything).** New RocksDB CFs:
   - `CF_COHERENCE_LEAVES` — leaf index → `cm` (or, with the frontier tree,
     the frontier + leaf count as the primary record and leaves for witness
     service);
   - `CF_COHERENCE_META` — frontier, leaf count, anchor window;
   - `CF_NULLIFIERS` — the spent set (and its commitment structure, §2.3).
   Write-through on `apply_block_self` / `disconnect_block_self`, atomic with
   the block's other CF writes (same batch as the existing
   "DAG store, CF_DAG and applied UTXO state move together or not at all"
   discipline, `src/main.rs:2755-2766`).

2. **The transition block copies, never constructs.** The G4 state machine's
   initial Coherence state = the pool state committed by the last PoW block
   (its Phase-0 `RootsCommitment.state_root` if ADR-035 has activated, §2.5).
   Explicit rule for reviewers: `ShieldedEngine::new()` /
   `CommitmentTree::new()` may appear **only** in genesis construction and
   tests — a lint/property test A9 owns.

3. **Leaf positions are consensus and must survive verbatim** (F8). Because
   `nf` binds `position`, any "compacting" or re-insertion of leaves during
   the migration changes every future nullifier — old notes would either
   become unspendable (wrong nf vs. witness) or, worse, spendable twice under
   two derivations. The seam must carry the exact leaf ordering. This forbids,
   e.g., migrating the tree by re-appending commitments in any other order.

4. **Domains and depth are frozen through the SHA-3 migration.** §6.1
   re-domains the *rest* of the chain; Coherence is already SHAKE-256.
   `DOM_CM` / `DOM_NF` / `DOM_MT` (`crates/coherence-core/src/lib.rs:15-17`)
   and `TREE_DEPTH = 32` (`lib.rs:13`) must not be touched by the migration
   sweep — an explicit exclusion in DEV-2's hash-migration checklist,
   otherwise the sweep itself is the reset §6.6.1 forbids.

5. **The anchor window must not flush at the seam.** A spend built just before
   T references a recent root from `ANCHOR_HISTORY` (F12). The window is part
   of the carried state (it is already snapshotted per-block in `BlockUndo`,
   `src/coherence/mod.rs:62`), so a tx anchored at *h* = T − 1 validates at
   *h* = T + 1. Note the window gives ~100 blocks ≈ 50 min (30 s slots) of
   anchor validity — acceptable, but the seam freeze window (if block
   production pauses at the flag-day) must be shorter than it, or wallets told
   to re-anchor.

6. **Adopt the frontier tree first** (`cd7f62a`). Continuity testing on the
   O(n) HEAD tree is possible but the frontier version is what will ship;
   port it early so the golden root-equality tests double as seam tests.

### 1.3 Test (A3 owns, A9 supplies vectors)

Shadow-fork matrix: shield at *h* < T (Case B forks), assert at *h* + 1…T + k:
(a) old witness + old anchor spends; (b) every pre-T nullifier still rejects
with `DoubleSpend`; (c) `anchor()` at T equals `anchor()` at T − 1 when the
seam block carries no shielded txs; (d) node restart across the seam
reproduces identical roots from the persisted CFs. Gate **G11** in the
migration plan requires this on three shadow forks.

---

## 2. §6.6.2 — Shielded state must be finalized state

**Requirement:** the accumulator root and the nullifier-set root enter
`state_root` and are mirrored in `BlockHeaderV4.coherence_root` (§5.3, §5.5).

### 2.1 The distance from here to there

Today the pool is the **exact pattern that caused the 2026-08-08 consensus
failure** (`expected_bits` from node-local mutable state): consensus-relevant
state (`shielded`, `src/main.rs:840`) living outside the committed state,
mutated on accept, never derivable from a parent's commitment. Three concrete
gaps, in dependency order:

1. **No persistence** (F11) — fixed in §1.2(1).
2. **No nullifier-set commitment** (F9) — a `HashSet` has no canonical root;
   one must be defined (§2.3).
3. **No commitment carried by blocks** on HEAD at all; zk-ledger Phase-0
   commits the anchor only (§2.5).

### 2.2 Exactly what changes

- `ShieldedPool` stops being an `Arc<RwLock<…>>` peer of the state and becomes
  a **component of the state machine** whose post-block digest feeds
  `state_root`. Under §5.5, `state_root` is a SHA3-256 sparse Merkle tree; the
  Coherence contribution is two leaves:
  - `coherence/accumulator_root` — `CommitmentTree::root()` after applying the
    block's shielded txs (semantics identical to zk-ledger Phase-0's
    `state_root`, *(zk-ledger)* `crates/bloch-crypto/src/core/mod.rs:2243-2245`);
  - `coherence/nullifier_root` — §2.3.
- `BlockHeaderV4.coherence_root` (spec §5.3) mirrors both:
  `coherence_root = SHA3-256(DS_COHERENCE_ROOT ‖ accumulator_root ‖ nullifier_root)`.
  Mirroring both matters: a light client verifying a payment proof needs the
  accumulator; an exchange verifying non-double-spend needs the nullifier
  root; neither should have to open the full state SMT.
- **Validation rule (the §5.5 hard rule, applied):** the expected
  `coherence_root` of block *B* is a pure function of *B.parent*'s committed
  Coherence state plus *B*'s shielded txs. No read of the node's live pool.
  The zk-ledger validator already has the right shape — "re-derives from its
  OWN post-apply state and Dual-ANDs, fail-closed"
  (*(zk-ledger)* `src/main.rs:2213`) — port that shape, re-rooted on
  parent-committed state instead of the singleton pool.
- **Reorg handling becomes finality-bounded.** Port the zk-ledger disconnect
  wiring (*(zk-ledger)* `src/main.rs:2228`) — HEAD's missing piece (F5). Under
  PoS, reorgs cannot cross the finalized checkpoint, so `MAX_REORG_UNDO = 128`
  (64 min) comfortably covers the unfinalized suffix (2 epochs ≈ 64 slots);
  keep the existing `ReorgBeyondUndoHorizon` → full-resync escape hatch
  (`src/coherence/mod.rs:39`) for the pathological case, and adopt the
  checkpoint reorg-floor refusal from `0b64d94`.
- **Mempool stays outside the commitment.** `ShieldedMempool`
  (`src/coherence/mod.rs:225`) is policy, not consensus — unchanged, plus
  `retain_chain_valid` from `26bd7ae`.

### 2.3 Defining the nullifier-set root (new consensus object — needs C1 rev)

Nothing in C1, HEAD, or zk-ledger defines this. Proposal:

- A **SHAKE-256 sparse Merkle tree over the 256-bit nullifier keyspace**
  (leaf = 1 at key `nf`), domain `DOM_NFSET = b"bloch:coherence:nfset:v1"`,
  with the standard empty-subtree table so inserts are O(256) hashes worst
  case, O(log |set|) amortised with caching. Consistent with §5.5's choice of
  SMT for `state_root` and gives **non-membership proofs** — which is what a
  spend verifier and a §6.6.4-style pruning proof actually need (prove `nf ∉
  set` at the anchor block). A plain running hash (`H(prev ‖ nf)`) is cheaper
  but proves nothing and forces insertion-order to be consensus; rejected.
- Insert-only (monotone, per §6.6.1); reorg undo = delete of exactly the
  undone block's nullifiers, driven by the existing `BlockUndo.nullifiers`
  record (`src/coherence/mod.rs:61`).

This is a C1 amendment (C1 froze "the global nullifier set" as consensus state
but not its commitment). Bundle with the `NoteCiphertext` wire change
(`7c9fe63`) into a single **C1.1 rev** so the freeze document matches what G4
ships. Fix F13 (empty-leaf constant text) in the same rev — the code constant
is de facto frozen; the document is what must move.

### 2.4 Ordering inside the accept path

Keep the HEAD ordering (shielded apply → then DAG/fork-choice commit,
`src/main.rs:2743-2753`) but make the root check part of the same fail-closed
gate: apply shielded txs to a **staged copy** (the engine already stages —
`apply_block` clones tree+state and commits only on success,
`src/coherence/mod.rs:158-176`), derive both roots, compare against the
header's `coherence_root` and the `state_root` leaves, and only then commit
batch-atomically with the block.

### 2.5 Bridge on the PoW/hybrid phase (recommended)

Adopt zk-ledger Phase-0 (ADR-035) **during the hybrid phase**, extended with
the nullifier-set root (replace one of the Phase-0 zero sentinels or rev the
tag to `roots:v2` with five roots). Rationale: (a) it gets the
derive-and-compare validator code battle-tested before it becomes
finality-critical; (b) it makes the last PoW block carry exactly the
commitment the G4 genesis state must equal (§1.2(2)), turning the seam
handoff into a checkable equality instead of a convention. It is height-gated
inert (`STATE_ROOT_ACTIVATION_HEIGHT = u64::MAX`) until the flag-day — the
same discipline as every recent fork.

---

## 3. §6.6.3 — Shielding is closed to tainted coins

**Required consensus rules:**

```
INVALID  shield_tx   if any input is in the taint set (§4.1)
INVALID  deposit_tx  if any input is a shielded output
```

### 3.1 Finding: there is nothing to retrofit — the shield bridge does not exist

This is the most useful audit result (F10): the C1 wire format and
`check_spend` describe a **closed** pool. `ShieldedTx` has no transparent
input or output fields; the balance equation `Σin = Σout + fee`
(`crates/coherence-core/src/lib.rs:221`) means value cannot enter the pool
(a zero-input tx can only mint zero-value notes) and can only leave as the
public `fee`. The engine test that "shields" (`src/coherence/mod.rs:478`) does
so under a mocked verifier — no real path funds a note from transparent BLCH.

So §6.6.3 is not a restriction bolted onto an existing flow; it is a
**design constraint on two tx types that have yet to be written** (`shield_tx`
here, `unshield` alongside it, `deposit_tx` in §7.1). The rules go in on day
one, with no compatibility burden and no deployed wallets to break.

### 3.2 `shield_tx` design (transparent → shielded)

```text
ShieldTx {
    transparent_inputs:  Vec<OutPoint>       // spends eUTXO outputs; signed hybrid, public
    value_shielded:      u64                 // public: total entering the pool
    outputs:             Vec<[u8;32]>        // note commitments (cm)
    output_ciphertexts:  Vec<NoteCiphertext> // ML-KEM-768 per output (7c9fe63)
    fee:                 u64
    proof:               Vec<u8>             // proves: each cm opens to some (v_i, …)
                                             // with Σ v_i = value_shielded; range checks
    binding_sig:         Vec<u8>
}
```

Validity, checked by every node against parent-committed state:

1. Transparent-side: inputs exist, signatures verify, `Σ inputs =
   value_shielded + fee + change` — ordinary eUTXO validation.
2. **Taint rule:** every `transparent_inputs[i]` must be absent from the taint
   set (§4.1 rules 1-2, taint-set root in `state_root`, spec §5.5 line "the
   taint set root"). Reject otherwise.
3. Pool-side: proof verifies that the committed notes total exactly
   `value_shielded` (so the pool's implicit balance stays backed).

### 3.3 Why the taint check does not hurt privacy

The check runs **entirely on the transparent side, before any private state
exists for this value**:

- `transparent_inputs` are ordinary UTXOs whose full ancestry is already
  public on-chain. Checking membership in a deterministic, consensus-committed
  taint set reads only information every observer already has. Zero bits of
  note content (`v` split across notes, `pk_d`, `rho`, `psi`) are involved —
  the amount entering (`value_shielded`) is public in any shield design
  (Zcash's `t→z` reveals it identically), and *how it is split into notes*
  stays hidden inside the proof.
- Inside the pool, notes minted by a shield are indistinguishable from notes
  created by shielded spends: same `cm` formula, same tree, same ciphertext
  format. The taint rule changes *who may enter*, never *what an entrant looks
  like*.
- No new linkage is created at exit either: unshielded outputs are born
  untainted by construction. That asymmetry (the pool "cleans" whatever was
  allowed in) is exactly why the entry gate is the only place the rule can
  live — and it is the honest cost §6.6.3 already prices: tainted BLCH
  becomes transparent-only and non-staking (the two-class coin, founder
  decision §14.4).

Conclusion: **implementable with no privacy regression.** The one privacy-adjacent
caveat to document for wallets: shield transactions are visible *as* shields
(as in Zcash), so users' shielding amounts and timing are public — a wallet UX
note, not a consensus issue.

### 3.4 `deposit_tx` closed to shielded outputs — structurally free

The second rule is enforced by the type system of the split ledger:
`DepositTx` (spec §7.1) spends **eUTXO outpoints**. Shielded notes are not
eUTXO entries — they are commitments in a disjoint accumulator with no
`OutPoint` representation at all (F10). There is no syntax by which a deposit
could reference a shielded output. The rule therefore needs (a) a stated
invariant in the spec — "the deposit input domain is the transparent UTXO set;
the shielded pool has no addressable outputs" — and (b) a negative test
pinning it (a crafted deposit referencing a fabricated pool-derived outpoint
must fail as *unknown outpoint*, and no future code path may create
pool-backed outpoints without revisiting §6.6.3). The real guard to maintain
forever: **any future `unshield` tx must create fresh transparent outputs
whose provenance is "the pool", never spendable-as-stake shortcuts.** Unshield
outputs are untainted (that is the accepted design), so they *are*
deposit-eligible — the spec should say this out loud rather than leave it to
be discovered.

### 3.5 Ordering constraint with taint activation

The taint set is defined at the Genesis-4 activation block (§4.1 rule 2:
"never re-opened"). `shield_tx` **must not activate before the taint set
exists** — otherwise the 94% concentration shields in the gap and the rule is
decorative forever (the §6.6.3 laundering scenario). Activation order, as
consensus constants: `TAINT_SET_ACTIVATION ≤ SHIELD_TX_ACTIVATION`, both ≤
first shielded-verify activation on mainnet. Given F4 (pool empty, verifier
fail-closed), we control this ordering completely today; it must be pinned in
the fork schedule, not left to ops.

---

## 4. §6.6.4 — Shared prover infrastructure

**Setting:** `crates/coherence-prover` (SP1 guest in `program/`, host in
`script/`, HTTP `/prove`-`/verify`-`/health` service in `service/`;
GPU deploy at `deploy/sp1-prover/` — Fly L40S, scale-to-zero). §6.5.1 would
reuse it to produce one FRI-STARK per epoch proving the quorum verified, after
which raw attestations become prunable. One service, two statements.

### 4.1 How consensus degrades when the prover is down — the ladder

The spec's requirement is that consensus "degrade to keep raw signatures
rather than stall". Concretely, by layer:

| Layer | Prover down ⇒ | Stall risk |
|---|---|---|
| Block proposal / attestation / fork choice / finality | **Unaffected.** Per §6.5.1(1), attestations are carried raw in blocks; nothing on the hot path invokes a prover. FFG justification/finality is computed from raw hybrid signatures | none |
| Epoch aggregation proofs | Not produced. Raw signatures simply accumulate — at the chosen §6.5.2 design, 57.9 GB/year ≈ **1.1 GB per week of outage**: an ops nuisance, not a consensus event | none |
| Pruning | **Fail-closed: no proof ⇒ no prune.** This is already coded as zk-ledger's `PruneGate` 3-conjunct AND (`0b64d94`): recursive proof verifies ∧ availability ∧ burial floor, refusing every prune while any conjunct is unmet. Adopt verbatim as the PoS pruning gate | none (disk grows) |
| Checkpoint sync for new nodes | Fresh proofs stop; new nodes sync from the last proven checkpoint + raw-verify the tail. Degrades sync time, not validity | none |
| Shielded spends (Coherence) | Users who delegate proving to the service cannot create **new** shielded txs; desktop client-side proving (C1 §5) still works. Verification is always local (`verifier.rs`) — accepted blocks are unaffected | none (UX only) |

The load-bearing property: **the prover appears only on prune/compress paths,
never on accept paths.** That must be a stated invariant with a reviewer
checklist item, symmetric to the §5.5 "no node-local mutable state" rule:
*no consensus validity rule may require a proof that a third-party service has
to produce within bounded time.* Proof submission is asynchronous and
permissionless — any node may compute and gossip an epoch proof; the protocol
defines the statement, not the operator.

### 4.2 Coupling risks to pin down (A6 requirements, A9 concurs)

1. **Verifier key discipline.** Both statements' guest ELFs are consensus
   constants: pin by SHAKE-256 hash exactly as `407cffc` does
   (`PINNED_ELF_SHAKE256_HEX`, fail-closed `RejectAll` until frozen), with
   reproducible guest builds (extend `REPRO.md`). An epoch-statement vkey swap
   is a hard fork, and must be treated as one.
2. **No mock injection.** Keep `407cffc`'s explicit `.cpu()` builder rule —
   never `ProverClient::from_env` — so `SP1_PROVER=mock` cannot produce
   accepting proofs on a misconfigured box, now with consensus at stake.
3. **Shared-dependency blast radius.** One `sp1-sdk` regression now touches
   shielded spends *and* pruning. Pin the version (the branch already pins
   `default-features = false` for load-bearing reasons — the alloy/serde
   conflict noted in `407cffc`), vendor or lockfile-freeze it, and cover both
   statements in one KAT suite so an upgrade is tested against both at once.
4. **Raw FRI only** — both statements. The Groth16 wrapper prohibition
   (`COHERENCE-C1.md §3`) applies to the epoch proof identically; one
   `.groth16()` call in the aggregation path silently makes consensus finality
   Shor-breakable.
5. **Availability economics.** Scale-to-zero GPU is fine precisely because of
   the ladder above: the only cost of cold-start latency is delayed
   prunability. No SLA needs to be consensus-critical; A6 should still set an
   ops target (e.g., proofs within 24 h of epoch finality) so disk projections
   hold.

---

## 5. Adoption plan and work items

Ordered; each is a portable unit. "Port" = cherry-pick from
`upstream-gitlab/feat/zk-ledger` onto `feat/pos-sha3-lattice` with conflict
resolution (same lineage, heavy `main.rs` drift).

| # | Item | Source | Phase |
|---|------|--------|-------|
| 1 | Port frontier `CommitmentTree` + golden root-equality tests | `cd7f62a` | now |
| 2 | Port `NoteCiphertext` (ML-KEM-768) + DoS bounds + mempool purge | `7c9fe63`, `26bd7ae` | now |
| 3 | Port SP1 verify path with ELF pinning (stays fail-closed) | `407cffc` | now |
| 4 | Port reorg wiring: call `disconnect_block_self` from the reorg driver (closes F5) | `f069610` wiring, *(zk-ledger)* `src/main.rs:2228` | now |
| 5 | Shielded persistence CFs, batch-atomic with block commit (closes F1/F11) | new | DEV-3 |
| 6 | Nullifier-set SMT root, `DOM_NFSET` (closes F9) | new, §2.3 | DEV-3 |
| 7 | **C1.1 rev**: NoteCiphertext wire, nullifier-root definition, empty-leaf text fix (F13) | doc | with 2+6 |
| 8 | Port + extend Phase-0 coinbase `RootsCommitment` with nullifier root; activate on hybrid phase flag-day | `f069610` | hybrid phase |
| 9 | `shield_tx` / unshield tx types with §3.2 taint rule; activation ordering pinned (§3.5) | new | DEV-3 (with §4.1 taint set) |
| 10 | G4 state machine: Coherence leaves in `state_root` SMT + `coherence_root` header mirror; seam copies from last PoW commitment (§1.2(2), §2.5) | new | DEV-1/DEV-3 |
| 11 | Port `PruneGate`/`ProofCheckpoint` as the §6.6.4 degradation posture; epoch-proof statement added later without touching accept paths | `0b64d94` | DEV-2 |
| 12 | A3 shadow-fork continuity matrix (§1.3); §3.4 negative deposit test; no-`new()`-outside-genesis lint | tests | gate **G11** |

**Out of scope for A9, flagged:** the Utreexo-crate dedup ruling
(`a167203` vs `ed030c3`, founder ADR pending) — it affects `state_root`'s
eUTXO leaf, not Coherence; and the §14.4 two-class-coin founder decision,
which item 9 is gated on.

### The one-paragraph summary

Coherence's cryptography needs nothing from the migration — the code confirms
the spec's claim (already SHAKE-256/FRI end to end, and the pool is provably
empty on mainnet because the verifier fails closed). Everything §6.6 demands
is *state lifecycle*: persist the pool, give the nullifier set a root, commit
both roots to finalized state, and carry them across the seam untouched.
About half of that already exists, tested and fail-closed, on
`feat/zk-ledger` — the coinbase roots commitment, the frontier tree, the
reorg wiring, the pinned SP1 verifier, and the prune gate — and the shield
taint rule costs no privacy because the transparent→shielded bridge it must
guard has not been built yet: we get to build the gate before the door.
