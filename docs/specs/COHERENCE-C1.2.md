<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Coherence C1.2 — note discovery, and the freeze that could not ship

```
Document:   COHERENCE-C1.2
Status:     DRAFT — pending founder ratification. C1.1 is ratified text; an
            extension does not inherit ratification by silence. Every rule in
            this document is proposed, not in force, until ratified.
Amends:     COHERENCE-C1.md §3 and §6; one sentence of COHERENCE-C1.1.md preamble
Registers:  docs/audit/COHERENCE-PROOF-SIZE-2026-08-29.md against C1 §3
Covers:     NoteCiphertext / ML-KEM-1024 (DEV-2); anchor policy (DEV-7) and
            the coherence ratchet (DEV-8), at rule level; shielded DoS bounds
            recorded with values expressly deferred to DEV-13
```

## 0. Why this rev exists, and the sentence it retires

C1.1's preamble ("Why an amendment exists at all") stated, of itself: *"This is an addition, not a change. Nothing C1
froze moves."* For C1.1's own additions that was true. As a doctrine — "C1
amendments never move frozen material" — it does not survive this rev, and
this rev rewrites it rather than stepping around it (the sentence is amended
in place in `COHERENCE-C1.1.md`, with a stamp pointing here).

**C1.2 moves a frozen format.** The C1 §6 `ShieldedTx` wire format gains a
field, and the honest description of why is not "extension" but "defect":

> The frozen format was unshippable. A C1 §6 output is a bare 32-byte `cm`
> (`crates/coherence-core/src/lib.rs:440`, `outputs: Vec<[u8;32]>`). A
> commitment is hiding by construction — that is its job — so the recipient
> of a note had **no way to discover it**. No ciphertext, no memo, no channel:
> the sender would have had to deliver `(v, pk_d, rho, psi)` out of band for
> every payment, which reintroduces a linkable side channel exactly where the
> pool exists to remove one. C1 froze a format in which the pool could hold
> value that no recipient could ever find.

A freeze exists to protect deployed state and deployed wallets. There is
neither: the pool is provably empty (finding F4 of
`BLOCH-COHERENCE-UNDER-POS.md`, reconfirmed in that document's 2026-08-29
reclassification) and no wallet speaks this format. Fixing the freeze now
costs nothing; ratifying the defect into deployed state would have made this
rev impossible later. That asymmetry is the whole argument for moving.

What does **not** move: `DOM_CM`, `DOM_NF`, `DOM_MT`, `DOM_NFSET`,
`TREE_DEPTH = 32`, `NFSET_DEPTH = 256`, the note structure, the commitment
and nullifier derivations, the spend statement (`check_spend`,
`crates/coherence-core/src/lib.rs:391`), the empty-leaf constants, and the
C1.1 nullifier-set commitment. The wire change is additive at the end of the
struct; every existing field keeps its position and meaning.

## 1. `NoteCiphertext` — per-output note discovery (DEV-2)

### 1.1 The wire change

`ShieldedTx` (C1 §6; `crates/coherence-core/src/lib.rs:437`) gains one field:

```
ShieldedTx {
  anchor:              [u8;32],
  nullifiers:          Vec<[u8;32]>,
  outputs:             Vec<[u8;32]>,        // note commitments (cm)
  fee:                 u64,
  proof:               Vec<u8>,             // raw FRI (SP1); see §6
  binding_sig:         Vec<u8>,             // hybrid Falcon‖ML-DSA over sighash
  output_ciphertexts:  Vec<NoteCiphertext>, // NEW — one per output, same order
}
```

**Structural consensus rule:** `output_ciphertexts.len() == outputs.len()`,
checked before any proof verification (it is a length comparison; the proof
is the expensive check and must come last — the same cheapest-first ordering
`staking.rs::validate_deposit` documents). A transaction violating it is
invalid. Positional correspondence is normative: `output_ciphertexts[i]`
is the ciphertext for `outputs[i]`.

### 1.2 The construction

```
NoteCiphertext = { kem_ct, aead_ct }
  kem_ct    ML-KEM-1024 ciphertext (FIPS 203), 1568 bytes, encapsulated to
            the recipient's ML-KEM-1024 encapsulation key (1568 bytes,
            carried in the shielded address — §1.4)
  aead_ct   AEAD (AES-256-GCM) over the note plaintext, key derived from the
            32-byte ML-KEM shared secret
```

The note plaintext must be sufficient for the recipient to **reconstruct the
`Note` and recompute `cm`**: at minimum `(v, rho, psi)` plus a version byte
(`pk_d` is the recipient's own and need not travel). Per-output wire overhead
is ~1.7 KB (1568 B KEM ciphertext + AEAD nonce/tag + ~100 B plaintext),
priced like any other bytes at `GAS_PER_BYTE = 16`
(`crates/bloch-pos-committee/src/fee_market.rs:121`) inside `intrinsic_gas`
(`fee_market.rs:194`) — the sender pays for the discovery channel they emit.

**Frozen by this rev (on ratification):** the algorithms — ML-KEM-1024 per
FIPS 203 for encapsulation, AES-256-GCM for the payload — the one-ciphertext-
per-output structure, and the recommitment obligation of §1.3.

**Not frozen by this rev, pinned at ratification:** the exact byte layout of
`NoteCiphertext`, the KDF from shared secret to AEAD key, and its domain tags.
These exist in DEV-2's implementation, which this document could not read at
writing time (this worktree is isolated from DEV-2's branch — a limit of the
process, stated rather than papered over). Ratification of C1.2 REQUIRES the
sweep that fills this section's `file:line` references from DEV-2's merged
code and verifies the layout against the words. A ratified C1.2 with this
paragraph still in it is a process failure.

### 1.3 What consensus checks, and what it deliberately does not

Consensus checks the **count** (§1.1) and nothing else about a ciphertext.
It does not check that `kem_ct` is a well-formed encapsulation, that `aead_ct`
decrypts, or that the plaintext recommits to `outputs[i]`. It cannot: any
such check either needs the recipient's secret key or drags the ciphertext
into the ZK statement, and the statement (`check_spend`) is frozen.

The consequence, stated as the limit it is: **a sender can emit garbage
ciphertext for a real commitment.** The transaction is valid, the value is in
the pool, and the note is unrecoverable by the recipient (the sender, who
knows the plaintext, can still prove what happened). This is the same
contract Zcash ships. The wallet-side obligation is therefore normative:

> A wallet MUST, on trial-decrypting `output_ciphertexts[i]`, reconstruct the
> note, recompute `cm`, and accept the payment only if `cm == outputs[i]`.
> A decryption that does not recommit is not a payment.

Trial decryption is the discovery mechanism: a wallet scans every
`NoteCiphertext` on chain and attempts decapsulation with its own ML-KEM
secret key. That is linear in chain traffic and private; anything faster
(detection keys, tags) is an optimization with its own leakage budget and is
**out of scope** for C1.2.

### 1.4 The shielded address grows a component

C1 §7 left `pk_d`/`nk` derivation open to the wallet spec (→ C2). This rev
adds to that open item without closing it: the shielded address must now also
carry (or derive) the recipient's **ML-KEM-1024 encapsulation key**. Key
derivation, address encoding, and the relationship between the KEM keypair
and the spending key remain C2 material. What C1.2 fixes is only that the
encapsulation key is per-recipient, 1568 bytes, and FIPS 203 category 5.

## 2. Why ML-KEM-1024 next to ML-DSA-65 — matched threat horizons

The parameter looks inconsistent at first sight: category 5 confidentiality
(ML-KEM-1024) on a chain whose signatures are category 3 (ML-DSA-65, hybrid
with Falcon-1024). It is not an inconsistency; the two primitives face
adversaries with different deadlines.

- **A note ciphertext is a permanent public record.** Every `NoteCiphertext`
  is replicated to every archive node forever. Decrypting it is a
  harvest-now-decrypt-later attack with **no expiry**: an adversary who
  breaks the KEM in 2045 reads the amounts and recipients of 2026
  retroactively, and no migration, re-encryption, or key rotation can undo
  the disclosure — the old bytes are already in everyone's hands. The
  security parameter must cover the longest horizon anyone will ever care
  about the data, which is unbounded. Category 5 is the ceiling FIPS 203
  offers; the pool takes the ceiling.
- **A signature forgery must happen at spend time.** Forging the binding
  signature (or a spend authorization) requires the quantum adversary to
  exist **while the output is still spendable and the suite still accepted**.
  A signature scheme that falls in 2045 threatens transactions signed in
  2045 — not the 2026 record — and the suite-migration machinery
  (`SUITE_MLDSA65_ONLY = 0x0002` and the suite registry, `docs/SPEC.md §10`)
  exists precisely so acceptance can move before that day. Category 3, run
  as an AND-hybrid of two independent lattice families, prices that
  shorter-lived threat honestly.

Different deadlines, different categories. Writing this down matters because
the codebase invited the confusion:

- `docs/SPEC.md:755-756` records the split as a discrepancy: *"Note it is
  **Kyber768** here, versus Postern-courier's ML-KEM-1024"* — the legacy
  node's transport handshake (`legacy/genesis3-node/src/transport/mod.rs:68`)
  encapsulates with Kyber768.
- `docs/whitepaper/ED2-CRYPTO-SECURITY.md:80` (a DRAFT) promises
  *"ML-KEM-1024 where key encapsulation is required"*, restated at line 156.

The documents were split; this decision aligns the **wire with the promise**
for the one KEM surface that is permanent record. The transport case is
genuinely different — session keys are ephemeral, and the harvested-traffic
horizon of a P2P handshake is not the harvested-ledger horizon of a note —
but that argument is not made here: the legacy transport is dead code under
Genesis-4, and the PoS node's transport KEM is its own decision, out of
C1.2's scope. What is in scope is closed: **note confidentiality is
ML-KEM-1024, FIPS 203, category 5.**

## 3. Anchor policy (DEV-7) — rules frozen, value deferred

*Applicability: the Coherence leaves are committed state today —
`crates/bloch-pos-committee/src/state_root.rs:1589-1592` (the two roots as
SMT leaves, inserted at `state_root.rs:1768-1776`), mirrored into
`BlockHeaderV4.coherence_root` by `derive.rs::coherence_binding`
(`crates/bloch-pos-committee/src/derive.rs:297`) and enforced at
`transition.rs:3187`. This section binds the anchor machinery DEV-7 is
building on top of those leaves; if that work does not merge, this section
is inert and must not be ratified as if it described shipped code.*

Three rules, frozen at rule level:

1. **Anchor validity derives from parent-committed state, and from nothing
   else.** The legacy node kept its anchor window as a node-local deque
   (`ANCHOR_HISTORY = 100`, `legacy/genesis3-node/src/coherence/mod.rs:21`)
   — mutable node-local state feeding a validity decision, which is
   `expected_bits` with a different name (the 2026-08-08 consensus failure,
   `bloch-difficulty-validation-order-dependent`). Under PoS the set of
   acceptable anchors for block *B* must be a pure function of *B.parent*'s
   committed state. However DEV-7 represents the window (leaves in the state
   SMT, a committed ring, or a depth rule over ancestor headers), the
   validator must be able to re-derive it; a window read from the node's own
   pool is forbidden.
2. **The window must clear measured proving time, with margin.** The C1-era
   analyses sized anchor validity against "minutes" of proving. The number
   is now measured (`docs/audit/COHERENCE-PROOF-SIZE-2026-08-29.md` §4):
   **83.3 s** core / **214.8–289.3 s** compressed on 8 CPU cores. A wallet
   picks an anchor, proves against it, and broadcasts; the window must
   comfortably exceed the slowest supported proving mode plus propagation,
   or honest transactions expire in flight. With 30 s slots, a 100-deep
   window is ~50 minutes against a ~3.6-minute prove — comfortable — but
   the **value is not frozen here**: it depends on which proof mode survives
   §6 and on DEV-13's repricing, and freezing it now would be freezing a
   number whose inputs are in flight.
3. **No anchor below the ratchet.** An anchor from a branch that finality
   has excluded must not validate a spend (§4). Anchor policy and the
   ratchet are one mechanism seen from two sides: the window bounds how far
   back an anchor may reach; the ratchet bounds how far back the pool may
   ever move.

## 4. The ratchet (DEV-8) — the pool never rewinds below finality

*Same applicability note as §3: rule-level coverage of in-flight work.*

The rule: **the committed Coherence roots never regress below the last
finalized checkpoint.** Concretely:

- Reorg undo of pool state (`CommitmentTree::truncate`,
  `crates/coherence-core/src/lib.rs:286`; `NullifierSet::remove`,
  `lib.rs:169`) is legal only for blocks **above** the finalized checkpoint.
  The undo primitives are C1/C1.1 material and unchanged; what C1.2 fixes is
  the floor under them.
- A node whose fork-choice would require disconnecting a finalized block's
  shielded state must refuse and halt for operator attention, not comply.
  This is deliberately the fail-closed branch: complying silently is how a
  nullifier removal resurrects a spent note (`lib.rs:166-168` documents the
  resurrection hazard), and a resurrected note is a double-spend with a
  delay fuse.

The motivation is not hypothetical. The fleet has already exhibited a
finality-rewind defect class — nodes re-finalizing below their own finalized
checkpoint during the 2026-08 replay incidents — and while that defect lives
in the finality store, not in Coherence, the pool must be written so it
**cannot inherit the class**: even a consensus layer that rewinds must find a
pool that refuses to follow it below the floor. The nullifier set is the
chain's only insert-only-forever structure with money on both sides of the
invariant; it gets its own ratchet rather than trusting the layer above.

Value not frozen: how the floor is carried (the finalized checkpoint is
already committed state; DEV-8 decides whether the pool stores its own copy
or reads the finality engine's) — rule frozen, representation deferred.

## 5. DoS bounds — recorded as shipped, values expressly not frozen

The shielded admission path ships with bounds. C1.2 records their existence
and their names, and **declines to freeze a single value** until DEV-13's
repricing lands. Recording without freezing is deliberate: the audit
(`COHERENCE-PROOF-SIZE-2026-08-29.md` §3) proved that the intuitions these
values were first set under are wrong, so freezing them now would ratify
guesses.

Recorded:

- **`MAX_TX_NULLIFIERS`** (256 at introduction, zk-ledger `26bd7ae` lineage,
  riding DEV-2's port): caps spent notes per transaction; bounds the
  non-membership work and undo-record size per tx.
- **The §1.1 count equality** (`output_ciphertexts.len() == outputs.len()`):
  structural, checked before the proof; also the bound that stops ciphertext
  bytes being attached to a transaction that commits nothing.
- **A per-transaction proof byte cap**: must exist; its value is exactly
  what §6 makes undecidable today (a core proof is 2.66 MiB, a compressed
  one 1.21 MiB, a block 512 KiB — any cap chosen now either forbids all
  proofs or presumes the §6 architecture decision).
- **`SHIELDED_VERIFY_GAS_PROVISIONAL`**
  (`crates/bloch-pos-committee/src/fee_market.rs:155`, `25 ×
  HYBRID_VERIFY_GAS`): the fee market's own comment says the spec forbids
  activation with this number unmeasured (`fee_market.rs:151-154`). The
  audit's §3 finding — proof size is effectively **constant** in the
  statement size (384 bytes of growth for 4× the cycles) — means
  verification is priceable as a constant, which makes DEV-13's job well-
  posed for the first time. That finding also retires a false trade-off:
  `MAX_TX_OUTPUTS` and proof size do not compete for space, so the repricing
  must not couple them.

DEV-13 owns the values. C1.2 owns only the assertion that each bound above
**exists and is enforced before the expensive check it protects** — deleting
one is a consensus change requiring a rev, retuning one is not.

## 6. C1 §3, measured and failed — registered, not resolved

C1 §3 froze the proof system as "SP1, raw FRI **in the block body**" (the
wire format carries `proof: Vec<u8>`) and priced the trade-off as "tens to
hundreds of KB". The premise has now been measured, by
`docs/audit/COHERENCE-PROOF-SIZE-2026-08-29.md` (harness:
`crates/coherence-prover/measure/`, the real guest over `check_spend`):

| | bytes | × the 512 KiB block (`MAX_BLOCK_TX_BYTES_V2 = 524_288`, `fee_market.rs:85`) |
|---|---:|---:|
| Core proof (2-in/2-out) | 2,791,567 (2.66 MiB) | **5.32×** |
| Compressed (FRI recursion) | 1,272,753 (1.21 MiB) | **2.43×** |

For **one** shielded transaction. "Tens to hundreds of KB" was wrong by an
order of magnitude, and the audit's conclusion is adopted verbatim into the
C1 lineage: **the C1 §3 design — raw FRI in the block body — is not viable
under the current limits.** C1 §3 is stamped accordingly (the stamp points
to the audit; the numbers live there).

What C1.2 does with this, and only this:

- It **registers** the measurement against the freeze, so no future reader
  builds on §3's dead premise.
- It keeps the Groth16/PLONK prohibition **fully in force**. Pairing-based
  wrappers would solve the size and are still forbidden; the measurement
  changes the cost of the rule, not the rule.
- It records the audit's §6 observation as an open reopening: the ported
  verifier's `Core`-only decode check (zk-ledger `407cffc`,
  `matches!(proof.proof, SP1Proof::Core(_))`) rejects **compressed** proofs
  — which are FRI recursion, post-quantum, and *not* the forbidden wrap —
  together with the wraps that are. If compressed becomes the path, that
  check must be widened deliberately, as a reviewed change, not discovered
  as a bug.
- It does **not** choose among the audit's three exits (raise the block cap
  ~3×; move proofs out of the block body into a data-availability lane; or
  the forbidden wrap). That is an architecture decision with fleet-cadence
  consequences the audit spells out, it belongs to the founder, and a format
  rev is not where it gets made.

## 7. What this rev does not do

Stated so the next reader does not assume more was settled than was
(the C1.1 §3 discipline, continued):

- It does not build `shield_tx`/unshield. Value still cannot enter or leave
  the pool (finding F10, still open); the balance rule `Σin = Σout + fee`
  (`crates/coherence-core/src/lib.rs:428`) still seals it.
- It does not activate shielded verification. No ELF is pinned; the pool
  remains provably empty; no privacy claim exists before the C4 audit.
- It does not fix F7 (`CommitmentTree::root()` is still O(n) per call,
  `lib.rs:297`) — a performance port, not a format matter.
- It does not decide whether shielding opens to the whole coin set. The
  taint dissolution turned `BLOCH-COHERENCE-UNDER-POS.md` §3.5's guarded
  scenario into the accepted default; that is recorded **as a pending
  founder decision** in that document's 2026-08-29 restamp, and C1.2
  pointedly does not resolve it.
- It flags, without resolving, one live discrepancy found while writing:
  `crates/bloch-pos-node/src/genesis.rs:946` synthesizes a genesis header
  with `coherence_root: [0u8; 32]`, and its `genesis_state` doc comment
  (`genesis.rs:953-956`) says "all three carried roots are zero" — while
  C1.1 §4 (ratified) requires an empty pool to commit the **empty-set
  root, not zeros**, and the ceremony enforces exactly that
  (`tools/genesis4-ceremony/src/lib.rs:1730-1734`, "an empty pool must
  commit the C1.1 empty-set root, not zeros"). Two genesis constructors,
  one of them out of spec. Whoever owns `genesis.rs` owes either a fix or
  a written reason; C1.2's job is only to make the divergence impossible
  to miss.

## 8. Ratification checklist

C1.2 is ratifiable when, and only when:

1. DEV-2's `NoteCiphertext` is merged and §1.2's layout paragraph is
   replaced by pinned `file:line` references verified against the words.
2. §3/§4 either match DEV-7/DEV-8's merged mechanisms or are re-marked
   inert (their rules survive as constraints on future work either way).
3. The founder has seen §6 and the architecture decision it declines to
   make, and §7's shielding-scope decision, even if both remain open —
   ratifying C1.2 does not close them, but it must not hide them.
4. The C1, C1.1, and `BLOCH-COHERENCE-UNDER-POS.md` stamps that cite this
   document are in the same merge, so no ratified text points at a draft
   that failed to land.
