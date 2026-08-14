<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Institutional Dossier — Edition 2

## Cryptography & Security chapters (draft)

```
Document:   ED2-CRYPTO-SECURITY
Status:     DRAFT for Edition 2 assembly — supersedes Edition 1 chapters
            3 (The Post-Quantum Imperative), 10 (Cryptography),
            14 (ZK-Ledger Groundwork), 17 (Security Program),
            18 (Threat Model & Risk Factors)
Prepared:   2026-08-12, against branch integration/pos-modules
Revised:    2026-08-14, against the live Genesis-4 chain
Repository: gitlab.com/blochsispow-group/bloch-pos (private at time of writing)
License:    AGPL-3.0-or-later
```

**Editorial contract, carried from Edition 1 and binding on every section
below: designed ≠ built ≠ booted.** Having a specification, having code that
implements it, and having that code running as the consensus-enforced rule on
a live network are three different states, and every capability in this
document is labeled with which of the three it has reached.

**The label that moved, and it moved the other way from what this document
first said.** An earlier draft opened: *"Genesis-4, the proof-of-stake chain
these chapters describe, has not launched … the node around it is a devnet
skeleton."* **Both halves are now false and are withdrawn.** Genesis-3 stopped
permanently at height 39,918 on 2026-08-13, and **Genesis-4 has been live under
proof of stake since 21:31:19 UTC that day** — 30-second slots, 32-slot epochs,
Casper-style justification and finalisation by epoch. The node is not a
skeleton: it carries a mempool, a JSON-RPC surface (public read endpoint
`https://posternlabs.com/g4rpc`), persistence, executing transfers, and two
transports.

What must be said in the same breath, every time, because "booted" on this
chain is easy to over-read:

- **64 of 64 validators are operated by a single entity.** There is no
  independent validator; one operator can halt the chain.
- **The live transport is `Transport::Devnet`** — a point-to-point TCP full
  mesh with a **fixed peer list, no discovery and no authentication**
  (`crates/bloch-pos-node/src/net.rs`). That is the mechanical reason a third
  party cannot join. A libp2p stack exists in the tree; it is not what the
  fleet runs, and this document does not claim a production network layer
  exists.
- **`Deposit` and `Delegate` are refused at every node's mempool**
  (`crates/bloch-pos-node/src/engine.rs:1900-1907`), because bonding is not
  yet funded from the eUTXO set — so nobody outside can bond stake.
- **Nothing here has been audited by a third party**, and the chain launched
  without the external review its own gates required (§6).

The word "devnet" is accurate about the transport and about nothing else. It is
not the network, the chain, the binary, or the project's stage.

---

## 1. The Post-Quantum Imperative

*This section preserves Edition 1's Chapter 3 nearly whole, because the
argument has not changed and does not need to. What changed is the consensus
mechanism underneath it — and, as Section 2 shows, proof of stake makes the
argument bind harder, not softer.*

### 1.1 Harvest-now-decrypt-later

> **Harvest-now-decrypt-later** — an attack strategy in which an adversary
> records encrypted data, signed messages, or public keys today, with no
> capability to break them yet, in order to decrypt, forge, or otherwise
> exploit them once a sufficiently capable quantum computer becomes
> available.

The strategy is rational for any adversary who believes two things: that a
cryptographically relevant quantum computer will exist within a time horizon
shorter than the useful lifetime of the data or value being targeted, and
that recording the target now is cheap relative to waiting. Both conditions
plausibly hold for a public blockchain. Recording is nearly free — every
public key and every signature on a public chain is, by definition, already
public and archived by anyone who runs a node or an indexer. And the useful
lifetime of value secured by a settlement layer is not bounded by a software
release cycle; it is bounded by how long holders choose not to move their
coins, which for a meaningful fraction of any chain's supply can be a decade
or more.

This produces a threat model distinct from "is quantum computing a threat
today." The correct question for a settlement layer is: by the time a
cryptographically relevant quantum computer exists, will there still be
unspent value secured by a signature scheme that computer can break? For
Bitcoin and for essentially every classical elliptic-curve or RSA-secured
chain, a meaningful fraction of supply sits in outputs whose public key has
already been revealed on-chain — precisely the harvestable set. A protocol
that has not made its signature scheme post-quantum before that computer
exists faces a forced, urgent, contested migration under adversarial time
pressure. Harvest-now-decrypt-later is not a hypothetical confined to some
future chapter of cryptographic history; it is a present-tense collection
activity against any classically-signed public chain today, whether or not
a quantum computer capable of exploiting the harvest yet exists.

### 1.2 NIST PQC standards context

NIST's multi-year public standardization process produced the standards
Bloch's cryptography is built directly on top of rather than around:

| Standard | Algorithm family | Primitive | Role in Bloch |
|---|---|---|---|
| FIPS 203 | ML-KEM (Kyber lineage) | Key encapsulation | ML-KEM-1024 where key encapsulation is required |
| FIPS 204 | ML-DSA (Dilithium lineage) | Signature, module-lattice hardness | ML-DSA-65, one half of the hybrid signature |
| FN-DSA track | Falcon | Signature, NTRU-lattice hardness | Falcon-1024, the second, independent half |

ML-KEM and ML-DSA derive hardness from structured module-lattice problems in
the Kyber/Dilithium lineage; Falcon's hardness derives from NTRU lattices — a
related but structurally distinct construction. That distinction is why the
signature scheme does not simply pick ML-DSA and stop. The implementations
are PQClean-derived, vendored, and frozen under `Cargo.lock`; any update to
the vendored cryptographic lineage passes through a deliberate crypto-review
gate rather than floating in with a routine dependency bump. Edition 2 must
add one hard lesson to that sentence, learned since Edition 1: **a frozen
lockfile pins versions, not feature flags** — see Section 2.

### 1.3 Why a hybrid AND construction

> **Hybrid AND construction** — a composite signature scheme in which a
> message is signed independently under two algorithms, and the composite
> signature is valid only if **both** component signatures verify. This is
> deliberately the conjunctive ("AND"), not the disjunctive ("OR"),
> combinator: an attacker must break both underlying hard problems
> simultaneously to forge a valid Bloch signature, not merely the weaker of
> the two.

Bloch requires ML-DSA-65 and Falcon-1024 to both verify on every spending
authorization. This is live code, not a design note: the suite identifier
`SUITE_MLDSA65_FALCON1024 = 0x0001` and its dispatch are in
`crates/bloch-crypto/src/crypto/mod.rs:40` (sign at `:134`, verify at
`:180-192`), with a documented, already-wired escape hatch
`SUITE_MLDSA65_ONLY = 0x0002` (`:42`) that exists as the priced response to a
failed review of the Falcon path — not as a pending consolidation. The three
compounding reasons from Edition 1 stand unchanged:

1. **Algorithm diversity against an unknown future break.** A cryptanalytic
   advance against one lattice family is not automatically an attack on the
   other; a single-family break does not, by itself, forge a valid spend.
2. **Standardization-track redundancy.** FIPS 204 is final; Falcon sits on
   the FN-DSA track. Requiring both hedges against a future finding specific
   to either track.
3. **No implicit trust in a single implementation lineage.** A defect in one
   vendored implementation does not by itself compromise signature validity.

The cost is real and not hidden: two full post-quantum verifications per
spend cost more compute and more bytes than either scheme alone. Edition 1's
risk statement is retained verbatim in substance: the AND construction
protects against a hard-problem break in one family; **it does not protect
against an implementation bug that makes one verifier permissive.** Both
codebases carry the same scrutiny burden as if each were the chain's only
signature scheme.

The hashing layer follows the same logic at smaller scale: SHAKE-256 and
SHA3-256 with explicit domain separation — distinct tags for key derivation,
Merkle leaves, and Merkle internal nodes — so a hash computed in one
structural role cannot be replayed in another. Every new consensus structure
added since Edition 1 continues this discipline; Section 3's nullifier tree
carries its own domain (`bloch:coherence:nfset:v1`,
`crates/coherence-core/src/lib.rs:68`) precisely so its nodes can never be
reinterpreted as commitment-tree nodes.

### 1.4 Migration risk

The trade stated in Edition 1 is restated without softening: Bloch chooses
cryptography that is more resistant to a future quantum adversary and
correspondingly less battle-tested against classical cryptanalysis than the
incumbent schemes, on the judgment that harvest-now-decrypt-later makes that
trade worth making now rather than later. Choosing post-quantum early does
not remove risk; it changes which risk is carried. Nothing in this chapter
is a claim that Bloch's cryptography is proven secure against all future
attacks — the hybrid AND construction exists as a hedge against exactly that
uncertainty, not as a claim that the uncertainty has been resolved.

---

## 2. What Changed in the Cryptography

The primitives did not change. ML-DSA-65 ‖ Falcon-1024 remains the signature
scheme; SHAKE-256/SHA3-256 remain the hash layer; ML-KEM-1024 remains the
KEM. What changed is the *operating regime* of one of the two signers, and
the discovery that the build system — not the source code — decided which
implementation of it ran.

### 2.1 Proof of stake turns Falcon signing into a different problem

Under proof of work, a wallet signs occasionally, often from a machine that
is offline the rest of the time, and an attacker does not know when. Under
proof of stake, a validator signs **on a publicly known schedule, every
assigned slot, indefinitely, from an internet-facing machine, with its
bonded stake standing behind the key** (`docs/specs/BLOCH-FALCON-ONLINE-SIGNING.md`
§1). A remote attacker knows in advance the exact wall-clock window in which
a given validator will run the Falcon signing algorithm and can observe when
the signed message appears on the network — which includes the signing
latency. Over years of slots that is a high-quality repeated measurement of
the same secret-dependent computation. Falcon is the floating-point-sensitive
half of the hybrid: its Gaussian sampler is the reason NIST's FIPS 206 has
lagged FIPS 204, and the reason "constant-time" is a per-implementation
property, not a family property.

### 2.2 The finding: a transitive Cargo default selected native floating point

The adversarial review of the online-signing question
(`docs/specs/BLOCH-FALCON-ONLINE-SIGNING.md` §3.2, finding F1) found that the
requirement — integer-only, constant-time Falcon signing — was **violated by
a build default, not by an availability gap**. The `pqcrypto-falcon` crate's
default features (`["avx2", "neon", "std"]`) compile and runtime-dispatch
Falcon signing to PQClean's native floating-point variants: AVX2 doubles on
x86_64, `typedef double fpr` on aarch64. Every release binary on both server
architectures was signing Falcon with hardware floating point — silently
selected by a transitive default, on a machine that under PoS would sign on
a public schedule with stake in bond. For the wallet-grade PoW threat model
that configuration was defensible; for a scheduled online signer it is
exactly the forbidden one.

### 2.3 The fix, and the two guards that keep it fixed

Falcon-1024 now signs exclusively through PQClean's `clean` variant —
integer-emulated IEEE-754 binary64, written by the Falcon reference author,
constant-time by construction, bit-exact across platforms. The pin and its
guards, in decreasing order of how easily each could silently regress:

1. **The dependency pin.** `default-features = false, features = ["std"]` at
   both the workspace root (`Cargo.toml:133`) and the crate
   (`crates/bloch-crypto/Cargo.toml:60`).
2. **The dependency-graph guard.** Cargo features are additive: any workspace
   member or future dependency re-enabling the defaults would silently
   restore native-FP dispatch for every binary. `scripts/falcon-clean-guard.sh`
   fails CI if the workspace's *resolved* feature set for `pqcrypto-falcon`
   includes `avx2` or `neon` — and fails if the crate disappears from the
   graph, so a rename cannot turn the guard into a no-op
   (`scripts/falcon-clean-guard.sh:43-48`).
3. **The linked-binary tripwire.** The test
   `falcon_native_fp_variants_are_not_linked`
   (`crates/bloch-crypto/src/crypto/mod.rs:493`) inspects the compiled test
   executable itself for the native variants' symbols
   (`PQCLEAN_FALCON1024_AVX2_*`, `PQCLEAN_FALCON1024_AARCH64_*`), plus KATs
   pinning `clean` outputs so a dependency bump cannot silently re-enable
   dispatch (`crypto/mod.rs:400-406`, `:536-542`).

The measured cost of doing this correctly: 11.6 ms per Falcon-1024 signature
on the integer path versus 0.46 ms native — ~25× slower and ~0.04% of a 30 s
slot (`BLOCH-FALCON-ONLINE-SIGNING.md` §3.3). There is no engineering
pressure to keep the floating-point path; the performance cost of correctness
is a rounding error.

Verification is unaffected — Falcon verification is integer and
deterministic on every path, so this was never a consensus change. Two
protocol-level mitigations recommended alongside the pin — fixed-deadline
publication (pad the one observable a remote attacker has, publication time,
to a constant) and keygen-off-box (single-trace attacks published against
Falcon target keygen) — are spec recommendations, not yet consensus rules
(`BLOCH-FALCON-ONLINE-SIGNING.md` §5). Designed, not built — **and the
scheduled online signing they were written for is now happening on a live
mainnet**, on 64 validators, every slot, so they are open exposures rather
than future work. Gate G7 required external review of exactly this path before
launch; the chain launched without it (§6).

### 2.4 A format boundary worth stating in an institutional document

Bloch's Falcon is and remains **Falcon-as-submitted** (the PQClean profile).
The final FN-DSA standard will not be bit-compatible with it (NTT-form
public keys, sampler changes). If the project ever wants FIPS-validated
FN-DSA, that is a *new suite identifier* migrated through the existing
envelope mechanism — a planned migration, never an in-place swap
(`BLOCH-FALCON-ONLINE-SIGNING.md` §4). The envelope header
(`crypto/mod.rs:37-58`) exists for exactly this class of event.

### 2.5 What did not change

The hybrid AND requirement did not weaken. The escape hatch to
`SUITE_MLDSA65_ONLY` was priced and explicitly **not** pulled — its trigger
is a P0 finding against the `clean` path under external review, not
convenience (`BLOCH-FALCON-ONLINE-SIGNING.md` §6). And Edition 1's carryover
note still applies in updated form: value created on the predecessor chain
crosses into Genesis-4 as a snapshot of transparent balances
(`docs/specs/BLOCH-TOKENOMICS-V4.md` §2), secured by the same hybrid key
material; continuity of old value remains a stated obligation, not an
accident.

---

## 3. Coherence — from "ZK-Ledger Groundwork" to a Frozen Format

Edition 1's Chapter 14 described groundwork: a deterministic execution
substrate that happened to be the precondition succinct proofs need, an SP1
host-side stack, and a firm refusal to imply anything was live. Edition 2
can report that the groundwork acquired a name — **Coherence**, the shielded
pool — and a frozen format, while keeping every one of Edition 1's honesty
constraints intact.

### 3.1 What is now specified and built

The C1 specification froze the pool's formats: note structure, commitment
and nullifier derivation, the commitment accumulator (SHAKE-256 Merkle tree,
depth 32, domain-separated), the spend statement, and the wire format
(`docs/specs/COHERENCE-C1.md`). The proof system is SP1's raw FRI-STARK —
hash-based, **no trusted setup anywhere**, with the Groth16/Plonk wrapper
paths explicitly forbidden (`crates/coherence-prover/README.md:44-53`). A
hash-based proof system is also the choice consistent with this dossier's
post-quantum posture: no pairing or discrete-log assumption is introduced
through the proving back door.

### 3.2 C1.1 — the nullifier-set root (ratified 2026-08-12)

C1 named the global nullifier set as consensus state and never said how the
set is committed; in code it was a bare `HashSet` with no canonical root.
Under proof of work that was survivable, because nothing outside the node
ever had to agree on the set's digest. Under proof of stake it is not:
`state_root` commits every consensus component, so a state-syncing node must
be able to check the set. C1.1 (`docs/specs/COHERENCE-C1.1.md`, the
project's only RATIFIED Coherence spec) closes this:

- **The root is a sparse Merkle tree over the 256-bit nullifier keyspace**,
  SHAKE-256 throughout, keyed by the nullifier itself, under its own domain
  tag `DOM_NFSET = b"bloch:coherence:nfset:v1"` with depth 256
  (`crates/coherence-core/src/lib.rs:68-92`). Empty subtrees short-circuit
  to precomputed roots, so cost is bounded by occupied paths, not the
  keyspace.
- **The root is a function of the set, not of history.** A running hash
  `H(prev ‖ nf)` was rejected because it makes insertion order consensus —
  two honest nodes applying the same blocks in different orders, or one
  redoing a reorg, would commit different roots for identical state
  (COHERENCE-C1.1.md §1.1). That failure shape caused a real incident on
  the predecessor chain, and reorgs are ordinary under PoS.
- **Non-membership is provable.** What a spend verifier needs is "this
  nullifier is not in the set as of this anchor," and a sparse tree can
  prove it where a hash chain cannot: `NullifierSet::non_membership_proof`
  and `verify_non_membership` (`crates/coherence-core/src/lib.rs:123`,
  `:243`), pinned by tests including the adversarial direction — a spent
  key must not verify as absent (`lib.rs:599-702`).
- **One implementation.** `coherence-core` computes the root; the node, the
  SP1 guest, and the genesis ceremony all call the same code. The PoS
  consensus crate carries the 32-byte root as opaque bytes and never
  recomputes it — the interim commitment the PoS layer had been computing on
  the pool's behalf was removed by this rev (COHERENCE-C1.1.md §1.3).
- `insert` returning `false` on a present nullifier **is the double-spend
  check**; `remove` exists solely for reorg undo and restores the exact
  earlier root, pinned by test (COHERENCE-C1.1.md §1.2).

### 3.3 What Edition 1 refused to claim, Edition 2 still refuses to claim

Carried forward deliberately, in the same words the ratified spec uses
(COHERENCE-C1.1.md §3):

- **No privacy claim is made** until the planned external audit of the
  Coherence stack (C4). Read that at full strength on a live mainnet: with
  respect to privacy specifically, Bloch offers **no security guarantee at
  all** — not a weak one — and no user should treat any part of this chain as
  private. (Earlier drafts phrased this as "the chain remains a zero-security
  testnet". The *stance* is unchanged and deliberately not softened; the word
  "testnet" is withdrawn, because Genesis-4 is a mainnet carrying real
  balances, which makes the disclosure more important rather than less.)
- **The value bridge does not exist.** `shield_tx`/unshield is undefined;
  value cannot enter or leave the pool. A shielded pool with no inlet is a
  format and an accumulator, not a privacy feature.
- Shielded-transaction application under PoS is not implemented; the pool is
  inert — headers carry forward the parent's committed roots and no block
  changes them yet. There is no shielded storage; a restarted node rebuilds
  an empty pool.

Designed: the C1/C1.1 formats, frozen and ratified. Built: `coherence-core`
(708 source lines, 12 tests, its only dependency `sha3`), the prover
host-side stack, the genesis-ceremony carry logic. Booted: nothing — no live
proof pipeline, no consensus-wired verifier, no committed timeline. The pool
crossed the genesis seam as an attested **empty** artifact, so no shielded
value moved and none exists. Edition 1's closing caution applies unchanged:
this is a description of direction and precondition, not of a shipped
feature.

---

## 4. The Security Program — and the Findings We Found Ourselves

Edition 1's security chapter named the instruments (cargo-audit, cargo-deny,
cargo-geiger, hardened Clippy, Miri, cargo-fuzz, proptest, OSS-Fuzz, a
blocking supply-chain CI gate) and disclosed what none of them can certify.
All of that stands. What Edition 2 adds is the strongest evidence a security
program can offer: **the defects it found in its own consensus code, before
any auditor did, each fixed with a commit and pinned with a regression
test.** The full record, with reproduction detail, is
`docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md` §3; this section is the
institutional summary. An auditor reads a list like this as maturity.
Hiding it would read as risk.

### 4.1 Seven findings, seven fixes, seven regression tests

**F-1 — Two block identities.** At integration the interfaces crate had a
public tuple `BlockId` mintable from any 32 bytes coexisting with the opaque
header identity; two disagreeing header types and three copies of the
canonical serialization existed — nine construction sites where the design
allows one. Fixed in `62ca5af`. The guard is structural, not a review note:
`single_derivation_path` (`crates/bloch-pos-committee/src/header.rs:626`)
scans the crate source and fails the build on any second construction site,
any manual trait impl, any alias — because this exact class of bug (a DAG
keyed by one hash while storage keyed by another) caused a real outage on
the predecessor chain.

**F-2 — The header did not commit to the body, in the code the node actually
runs.** `compute_post_state` never checked `body_root`, `attestation_root`,
or `coherence_root`; those checks lived only in a parallel validator with no
caller, and 178 green tests said nothing because the test builder stamped
zeros. One `block_id` could name two different bodies. Fixed in `d29e3ad`:
the transition recomputes all three roots. Regression:
`header_must_commit_to_body_attestations_and_coherence`
(`src/transition.rs:2753`), asserting all three mismatch errors in both
directions.

**F-3 — Two state-root derivations.** `transition` and `derive` committed
*different* RANDAO leaf sets for the same block — two roots for one block,
each seam green on its own tests; found independently by two reviewers the
same day. Fixed in `4ca2646`: one function, `state_root::randao_window`
(`src/state_root.rs:924`); the stricter rule won. Regression: the five tests
of `tests/one_state_root.rs` — reverting the old rule fails two of five.

**F-4 — Slashing existed but nothing called it; then its bookkeeping was not
under the root.** `slashing.rs` was implemented, tested, sealed — and had no
call site. Fixed in `8a3e0ea`: evidence became a transaction validated
inside the state transition; invalid evidence rejects the whole block;
forged evidence slashes nobody. Then the anti-replay set, correlation
window, and delegator-loss ledger were found uncommitted under `state_root`
— a state-synced node could double-slash. Fixed in `319c7e6` with three new
committed leaves (`src/state_root.rs:148-150`). Regressions:
`src/transition.rs:2198`, `:2372`, `:2518`
(`every_committed_state_field_is_bound_by_the_root`), `:2815`.

**F-5 — The Ustav supply cap was not a cap (HIGH).** `compile_supply`
compared the cap against a value the *spender* wrote in the redeemer, never
against the amount actually minted: with `cap = 1,000` an issuer minted
1,000,000,000 in one transaction. Since the program hash is the asset's
policy id, promoting Ustav to consensus would have made the chain certify a
false cap. Fixed in `0f67977`: the module reads the mint context and asserts
`prior + delta <= cap`. Regressions:
`supply_cap_cannot_be_bypassed_by_a_redeemer_supplied_amount`
(`crates/bloch-euvm/src/modules.rs:725`) and
`tests/audit_modules_supply.rs:55`, `:135`.

**F-6 — Redeemer padding bypass defeated the freeze control (CRITICAL).**
The VM imposed no redeemer arity; compiled modules read the `frozen` flag at
a fixed top-relative stack offset, so padding the redeemer with one extra
value shifted every read onto attacker-controlled data — a frozen
regulated-token output became spendable with no authority signature. Fixed
in the same `0f67977`: a new `Op::ExpectDepth` opcode
(`crates/bloch-euvm/src/lib.rs:136`, executed at `:379-383`) is emitted as
the first op of every compiled module, making expected arity part of the
program and hence of `validator_hash` — the spender cannot renegotiate it.
Regression: `tests/audit_modules.rs:55`, which deliberately keeps its
bug-era name with the assertion inverted.

**F-7 — The shielded pool did not cross the genesis seam, and its nullifier
set had no canonical root.** The Genesis-3→4 carryover pipeline moved only
transparent balances; the ceremony stamped `coherence_root = [0u8; 32]`
("empty pool") with nothing carrying the tree or the nullifier set — a pool
that does not cross as ordered leaves plus the complete nullifier set either
burns every unspent note or revives every spent one. Worse, the header's
coherence mirror was copied from the parent verbatim, validating nothing.
Fixed in `eacddd9` (merged `c59a175`): the ceremony requires a fail-closed
Coherence artifact, replays leaves in exact position order, carries the
nullifier set whole, and "empty" became an attested artifact, never an
assumption. Follow-up `c6fe0c1` ratified C1.1 (Section 3.2 above).
Regressions: `src/derive.rs:699`, the ceremony tests at
`tools/genesis4-ceremony/src/lib.rs:1675-1735` (including
`dropping_a_nullifier_is_a_different_chain`), and the seven C1.1 set tests.

### 4.2 The pattern, named

F-2, F-3, and the second half of F-4 are one class: **a consensus value with
two derivation paths, or none.** The codebase now carries structural tests
against the class itself, not just the instances — `single_derivation_path`,
`tests/one_state_root.rs`, and
`every_committed_state_field_is_bound_by_the_root`. That is the security
program's actual output: not a clean bill of health, but a machine that
converts each found defect into a permanent guard against its class.

### 4.3 What the program still cannot certify

Unchanged from Edition 1, and restated because it is the most important
paragraph in the chapter: internal adversarial review and automated scanners
reduce risk measurably — the findings above are real defects that would
otherwise have shipped — but they are not a substitute for independent
third-party review. Consensus-logic correctness under adversarial network
conditions, the soundness of the specific cryptographic composition,
bridge-class logic, and economic security all sit outside what static
analysis, fuzzing, and property testing are built to catch. Section 6 states
where third-party review stands.

---

## 5. Threat Model, Updated for Proof of Stake

Edition 1's threat model led with 51%-attackability at low hashrate. **That
risk ended with the PoW chain on 2026-08-13, and what replaced it as the
leading risk is concentration — which is larger, not smaller, and is a
present-tense property of the live network.** Stated once, at the top, in the
position the old caveat held:

> The security question under Genesis-4 is not hashrate, it is concentration:
> all 64 validators are run by one entity, 93.94% of the carryover sits at a
> single address, and 56.05 B of the 57.15 B BLOCH issued at genesis is held
> by the founder and the Foundation. One operator can halt the chain and one
> holder can outvote every other.

Several of the risks below have no PoW analogue at all. The primary sources are the two
adversarial passes `docs/specs/BLOCH-POS-THREAT-MODEL.md` (F1–F13) and
`BLOCH-POS-THREAT-MODEL-2.md` (G1–G4), kept deliberately unrewritten as a
record, with status seals recording what each finding's fate was. The
findings below are stated with their current status; a finding marked
*closed* means closed by wired, tested code, because the second pass's
headline lesson (G1) was precisely that **a correction that is not wired is
not a correction**.

### 5.1 Findings from the adversarial passes, and where they stand

- **F1 (Critical) — the finality quorum had no coherent denominator.** The
  epoch committee was a 128-validator sample; ⅔ of network stake was
  unreachable (permanent finality stall) and ⅔ of committee stake let a
  sub-⅓ adversary stall via sampling variance. Closed by replacing the
  sample with a **partition of the whole active set** — and G1 caught that
  the partition first landed as dead code with no caller while the seal
  claimed the fix. It is now wired at `finality::votes_from_partition`
  (`crates/bloch-pos-committee/src/finality.rs:768`).
- **F2 (High) — honest validators would self-slash**, because per-slot and
  epoch attestations shared one struct and one signing domain, so routine
  multi-slot duty satisfied the `DoubleVote` predicate against itself.
  Closed alongside F1 by the partition and role separation.
- **F6 (Medium) — beacon grinding of the next epoch's committee.** Trailing-
  slot proposers could withhold reveals to grind the mix that seeds the next
  epoch's committees. Closed by a seed look-ahead
  (`MIN_SEED_LOOKAHEAD_EPOCHS`, `src/committees.rs:51-88`): epoch N is
  seeded by the mix fixed at the close of N−2, with the honest residue
  stated — the one-bit-per-withheld-slot bias is displaced an epoch forward,
  not eliminated (the same residue Ethereum accepts).
- **F7 (Medium) — accepted surface, now live:** public sortition hands an
  attacker the per-slot committee schedule one epoch ahead, making targeted
  DoS cheap. Quantified in `BLOCH-POS-SORTITION-DOS.md`; mitigations (sentry
  nodes, late attestation inclusion, proposer boost) are recommendations, not
  yet rules. Accepted and disclosed, not closed — and since 2026-08-13 it is an
  exposure of a running network rather than of a design.
- **F8 / stake-churn — decided and applied:** the warm-up rate was cut from
  900 to 25 bps/epoch with a churn floor (`WARMUP_RATE_BPS = 25`,
  `src/delegation.rs`), turning a zero-to-⅓ stake shift from ~75 minutes
  into ~43 hours — visibility time, not prevention. The per-validator 1%
  cap remains honest about its limit: **Sybil-bypassable by splitting**, per
  its own doc comment. No on-chain rule sees beneficial ownership.
- **G2 (High) — the decentralization rule could halt the chain.** The
  genesis-cohort cap, engaging ~1.3 hours after genesis, would zero the
  entire active set's effective stake if no independent stake had arrived —
  the rule meant to decentralize the founder would stop the network. Closed
  by deferring the cap until independent stake exists
  (`CapStatus::Deferred`, `src/genesis_cohort.rs:100-124`) — with the
  honest cost that the taper is now gated on adoption, and the known drift
  that this consensus behaviour is in code but absent from the spec
  (`BLOCH-POS-GAPS.md`, via CERTIK dossier §4 item 10).
- **F10 — weak subjectivity is an operational dependency, not a window.**
  The 2048-epoch withdrawal delay (22.76 days) is the maximum age of a
  usable checkpoint: a node syncing from anything older can be fooled by a
  long-range fork built with since-withdrawn keys. Fresh checkpoints must be
  published on cadence, and that duty sits with the Foundation — a standing
  operational dependency, stated as such.

### 5.2 Risks proof of stake creates that proof of work did not have

1. **The signer is online, on a schedule, with value bonded behind the
   key.** The entire Section 2 story. Under PoW, consensus keys did not
   exist and wallet keys could live cold; under PoS the validator key is a
   hot key whose compromise is slashable stake, and whose side-channel
   surface is measured in signatures per year (~tens of thousands).
2. **Slashing is a new way to destroy honest value.** A logic error in the
   slashing predicate (F2) or an unauthenticated evidence path punishes
   honest validators. The mitigations are in code — invalid evidence
   rejects the whole block, forged evidence slashes nobody, both
   regression-tested (Section 4.1, F-4) — but the category itself is new:
   PoW had no protocol mechanism that could confiscate a miner's capital.
3. **Long-range forks and weak subjectivity.** PoW finality degraded
   gracefully with hashrate; PoS finality is stronger inside the
   subjectivity horizon and undefined outside it without a trusted
   checkpoint (F10). Syncing from genesis alone is no longer sufficient.
4. **Randomness is now consensus.** PoW needed no beacon; PoS committee
   selection does, and the beacon is grindable at the margin (F6/G3 —
   bounded and displaced by the look-ahead, not eliminated).
5. **The schedule is public.** Targeted DoS against the exact machines that
   carry a slot's fork-choice weight is a PoS-specific, pre-announced
   target list (F7).
6. **Stake concentration is consensus power directly.** Under PoW the
   founder's balance could not vote; hashrate was external and had to be
   bought. Under PoS the founder's carried-over balance is stakeable by
   decision of record: measured at the terminal Genesis-3 snapshot (height
   39,918, 452,726 outputs, 16 addresses) it is **17,046,829,380 of
   18,146,400,000 BLOCH — 93.94% of the carryover** — so if staked while
   others abstain it is ~94% of active stake, **a Nakamoto coefficient of 1**
   (`crates/bloch-pos-committee/src/tokenomics_v4.rs`, measured and pinned,
   not estimated). Including the 10% grant the founder holds **27.04% of the
   cap**; the Foundation holds **29.00%**; together **56,046,829,380 of the
   57,146,400,000 issued at slot 0**, leaving **1.92%** with third parties.
   The consensus-coded bounds (genesis-cohort taper, per-validator cap, churn
   rate) constrain the founder's *validator weight*; they do not and cannot
   constrain the founder's *holdings*. Any framing of those mechanisms as
   fixing concentration would be false, and this dossier does not offer one.
7. **Operator concentration, which on a live chain outranks all of the
   above.** **All 64 Genesis-4 validators are operated by one entity.** This
   is not a scenario conditional on staking behaviour; it is the state of the
   network. One operator can stall finality and one operator can stop the
   chain, and neither requires any mechanism in the protocol. Nor can the set
   become plural by anyone else's choice: the live transport has a fixed peer
   list with no discovery and no authentication, and `Deposit`/`Delegate` are
   refused at every node's mempool, so no outside party can bond stake.
8. **Bootstrap liveness.** A fresh PoS genesis must produce block 1 with
   whatever stake exists at slot 0 — the class of self-inflicted halt G2
   found. PoW chains bootstrap on any nonzero hashrate; PoS chains need a
   staked, attesting set from the first epoch.
9. **Key custody, now with keys.** An earlier draft said "no production
   Genesis-4 key exists". Genesis-4 launched, so a genesis manifest and 64
   validator keys exist and are signing every slot. The custody plan is still
   DRAFT (`docs/specs/BLOCH-GENESIS-KEYS.md`), and **this repository contains
   no evidence about how the live keys were produced or are held** — the live
   genesis manifest is not committed here. That is stated as an open question,
   not resolved in either direction. The Genesis-3 keys guarding the liquid
   carryover were generated long ago under unknown conditions and sit outside
   that plan, inside the risk; those coins crossed the seam and are 93.94% of
   the carryover.

### 5.3 What was retired with proof of work

Stated for completeness, because a threat model that only adds is not being
honest about the trade: rented-hashrate 51% attacks on a low-hashrate
SHA-256d chain — Edition 1's leading risk — ended with the chain on
2026-08-13 and no longer apply. The successor question, "what does it cost to
acquire a stake position that threatens consensus," has a degenerate answer:
nothing needs acquiring, because the founder already holds it (item 6), and
in any case nothing *can* be acquired, because deposits are refused (item 7).

Decentralization is measured by the G1–G11 gates. An earlier draft ended this
section "no gate has an observed value, because the chain has not launched."
**The chain launched.** The gates now have observed values, and they are the
worst possible ones: **G1 (independent stake ≥ 15% of circulating) = 0%**;
**G2 (no entity above 25% of active stake)** fails against a set operated
entirely by one entity; **G3 (Nakamoto coefficient ≥ 7) = 1**; **G4 (≥ 200
validators, ≥ 50 unaffiliated) = 64 validators, 0 unaffiliated**. These were
Go/No-Go conditions on the transition and the transition happened anyway. A
threat model that reported them as "unmeasured" would be understating the
risk, not overstating it.

---

## 6. Audit Status, Stated Honestly

**No independent third-party audit of this codebase has been completed.**
`docs/SECURITY_SELF_ASSESSMENT.md` records zero external audits to date. The
prior internal audits (`docs/audit/AUDIT-2026-04-20_ERA1.md`,
`docs/audit/groundstate_audit.md`) cover a predecessor codebase. What exists
today:

- **A pre-audit dossier prepared for engagement**
  (`docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md`), which answers a
  token-scanner's checklist property-by-property for an L1, defines the
  real audit surface (four crates, ~37k source lines, 814 passing tests,
  measured not asserted), hands over the self-found findings of Section 4
  with commits and regression tests, and lists the open gaps it would not
  want an auditor to discover first. Two of that list's entries have since
  been corrected in the dossier itself and should not be quoted from older
  copies: the PoS node is **not** a devnet skeleton (it runs a live mainnet,
  though its transport is still the unauthenticated fixed-peer mesh and
  deposits are refused at the mempool), and genesis keys **do** exist (they
  are signing every slot; how they were produced and are held is not
  evidenced in this repository).
- **An external-review requirement that was not honoured.** Gate G7 required
  external review of the highest-value target — the online Falcon-1024
  signing path of Section 2
  (`docs/specs/BLOCH-FALCON-ONLINE-SIGNING.md`; CERTIK dossier §2) — **before
  launch. Genesis-4 launched on 2026-08-13 without it.** That path is now
  signing on a public schedule, on 64 internet-facing machines, with value
  bonded behind the keys, unreviewed.
- **Two applicable checks that fail today and are written as FAIL:**
  holder concentration (Nakamoto coefficient 1 — and 1 by operator count
  regardless of staking, since one entity runs all 64 validators) and
  open-source publication (the repository visibility probe in the CertiK
  dossier dates from 2026-08-12 and has not been re-run; the decentralization
  ADR rests on publication before launch). No reframing is offered.

There has been **no external audit, and the chain is live**. Until one
concludes: the consensus crate and the node are unreviewed by third parties,
the hybrid signature composition is unreviewed by third parties, the Coherence
stack makes no privacy claim at all (Section 3.3), activation of the contract
VM remains gated on an audit that has not occurred, and anyone relying on this
protocol for value at risk should weigh those gaps accordingly. Designed ≠
built ≠ booted — and separately from all three: **unaudited, on a mainnet, by
one operator**.
