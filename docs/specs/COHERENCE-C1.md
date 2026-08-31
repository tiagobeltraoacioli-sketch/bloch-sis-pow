# Coherence C1 — shielded-pool format freeze

> Freezes the concrete formats of the Bloch-SIS shielded pool (the tier from
> `COHERENCE-v0.2.md`): note / commitment / nullifier / accumulator, the exact
> statement the ZK circuit proves, the proof system, and the shielded-tx wire
> format. Choices are grounded in a fact-checked survey of post-quantum private
> transactions (2026); each is tagged **production-ready** or **research-grade**.
>
> Non-negotiable (Coherence): every primitive on the security-critical path is
> post-quantum — hash-based (SHAKE-256 / FRI-STARK) or lattice (Module-SIS).
> **No elliptic-curve ZK** (Sapling/Orchard/Halo2/Groth16/Bulletproofs excluded).
> Chain is still a zero-security testnet; no privacy claim until audited (C4).

## 1. Primitives on the critical path — all production-ready, all hash-based

Rationale: the survey found hash-based commitments/nullifiers/Merkle are mature
and already coherent with the chain's SHAKE-256; lattice confidential-amount
constructions (MatRiCT+/Gao) are compelling but **research-grade/unaudited**, so
they are the C1 *research alternative* (§4), not the frozen critical path.

### 1.1 Note
```
Note = { v: u64, pk_d: [u8;32], rho: [u8;32], psi: [u8;32] }
  v     value in satoshis
  pk_d  diversified recipient public key (hash-derived; see wallet spec)
  rho   uniqueness seed (→ nullifier); psi commitment randomness
```

### 1.2 Note commitment (hiding + binding, hash-based)
```
cm = SHAKE256_32( DOM_CM ‖ LE64(v) ‖ pk_d ‖ rho ‖ psi )      # 32 bytes
DOM_CM = b"bloch:coherence:cm:v1"
```

### 1.3 Nullifier (spend uniqueness, hash-derived)
```
nf = SHAKE256_32( DOM_NF ‖ nk ‖ rho ‖ LE64(position) )        # 32 bytes
DOM_NF = b"bloch:coherence:nf:v1"     nk = nullifier key (from spending key)
```
`position` = the note's index in the commitment tree. A repeated `nf` is a
double-spend (checked against the global nullifier set).

### 1.4 Commitment accumulator (membership, hash-based)
Incremental **binary Merkle tree**, depth `D = 32`, nodes = SHAKE-256:
```
node = SHAKE256_32( DOM_MT ‖ left ‖ right )      DOM_MT = b"bloch:coherence:mt:v1"
```
The current root is the **anchor**; a spend proves membership against a recent
anchor. Empty subtrees use a fixed `EMPTY_LEAF = SHAKE256_32(DOM_MT ‖ "empty-leaf")`.

> **Corrected by C1.1 (2026-08-12).** This line read `SHAKE256_32(DOM_MT ‖ 0^0)`
> and was wrong: the code has always computed `SHAKE256_32(DOM_MT ‖ "empty-leaf")`,
> on every branch and inside the SP1 guest (finding F13). The **document** moved,
> not the constant — it is baked into every anchor the pool has produced and into
> the proving circuit, so changing it would invalidate existing anchors and every
> proof against them in order to fix a sentence. See `COHERENCE-C1.1.md` §2.

> **Amended by C1.1 (2026-08-12).** C1 named the global nullifier set as
> consensus state but never defined its commitment (F9). `COHERENCE-C1.1.md`
> defines it: a SHAKE-256 sparse Merkle tree over the nullifier keyspace under
> `DOM_NFSET`, with non-membership proofs. That is an addition — nothing frozen
> here moves.

## 2. The spend statement (what the ZK circuit proves)

Public inputs: `anchor`, spent `nf`s, output `cm`s, a value-balance commitment
`bvk`, the tx sighash. Witness: the spent notes, paths, keys, output notes.

For each spent note the circuit proves, in zero knowledge:
1. **Opening:** `cm = commit(v, pk_d, rho, psi)`.
2. **Membership:** `cm` is in the tree with root `anchor` (Merkle path).
3. **Nullifier:** `nf = nullifier(nk, rho, position)` and `nk` derives from the
   note's spending key (spend authority).
4. **Range:** `0 ≤ v < 2^64` for every input and output.
5. **Balance:** `Σ v_in = Σ v_out + fee` (fee public).

The tx **binding signature** (hybrid Falcon‖ML-DSA over the sighash) ties the
proof to this transaction (non-malleability).

## 3. Proof system — SP1 (hash-STARK / FRI), production-ready

- **SP1** (Succinct, Plonky3 STARK/FRI over BabyBear): the only PQ,
  **multi-audited** (Veridise, Cantina, Zellic, KALOS), permissively-licensed
  general-purpose prover. The spend statement (§2) is a **Rust program** proven
  by SP1 — reuses the same SHAKE-256 used everywhere.
- **PQ-coherence rule:** verify the **raw FRI proof directly**. SP1's default
  on-chain path wraps the STARK in a **Groth16 (non-PQ curve) SNARK** for small
  proofs — that wrapper is **forbidden** here; it would break Coherence.
- Trade-off: raw FRI proofs are larger (tens–hundreds of KB) and proving is
  heavier than curve SNARKs. Acceptable: verification stays cheap and PQ; client
  proving cost is the known burden (§5).

> **Premise measured and failed (2026-08-29).** This section's design — the
> raw FRI proof carried in the block body — was measured against the real
> guest (`crates/coherence-prover/measure/`) and is **not viable under the
> current limits**: one core proof is 2,791,567 B (2.66 MiB), **5.32×** the
> whole 512 KiB block (`MAX_BLOCK_TX_BYTES_V2 = 524_288`,
> `crates/bloch-pos-committee/src/fee_market.rs:85`); one compressed proof
> (FRI recursion — still post-quantum, *not* the forbidden wrap) is
> 1,272,753 B (1.21 MiB), **2.43×**. "Tens–hundreds of KB" above was wrong by
> an order of magnitude. The numbers and the three exits are in
> `docs/audit/COHERENCE-PROOF-SIZE-2026-08-29.md`; the registration against
> this freeze is `COHERENCE-C1.2.md §6` (DRAFT). The Groth16-wrapper
> prohibition stands unchanged — what must move is where the proof lives or
> how large a block is, and that architecture decision is **pending, not
> made**. No constant in this document should be tuned in its place.

## 4. Research alternative (NOT critical-path until audited)

For smaller proofs + ring-signature sender privacy, the **lattice RingCT**
lineage — **MatRiCT+ / Gao et al. (PKC 2025)**, Module-SIS/Module-LWE (the exact
family as Bloch's PoW), 64-bit amounts without wide range proofs, ~23 ms verify,
sub-100 KB — is the natural long-term direction, with **MatRiCT-Au** for optional
auditable disclosure. **Status: research-grade, no independent audit** → tracked
for a post-audit upgrade, never shipped on the security path before C3/C4.

## 5. Client-side proving

FRI/STARK proving of a Sapling-class circuit is feasible on commodity hardware
but heavy; **mobile proving is not yet practical** (consistent with "mobile =
wallet", not a prover). Options: prove on desktop, or a (non-private) delegated
prover for light clients. Recorded as an open cost, not hand-waved.

## 6. Shielded transaction — wire format

> **Amended by C1.2 (2026-08-29, DRAFT — pending ratification).** This
> format was frozen unshippable: an output is a bare 32-byte `cm`, and a
> commitment is hiding by construction, so the recipient of a note had no
> way to discover it — the pool could hold value nobody could find.
> `COHERENCE-C1.2.md §1` adds `output_ciphertexts: Vec<NoteCiphertext>`
> (ML-KEM-1024, FIPS 203; one ciphertext per output, count checked by
> consensus) to this struct. That is the first amendment that moves frozen
> material, and the reason C1.1's preamble sentence "nothing C1 froze moves" was rewritten
> rather than preserved. Until C1.2 is ratified, the struct below remains
> the normative wire.

```
ShieldedTx {
  anchor:        [u8;32],
  nullifiers:    Vec<[u8;32]>,       // one per spent note
  outputs:       Vec<[u8;32]>,       // output note commitments (cm)
  fee:           u64,                // public
  proof:         Vec<u8>,            // raw FRI proof (SP1), NOT a Groth16 wrap
  binding_sig:   Vec<u8>,            // hybrid Falcon‖ML-DSA over the sighash
}
```
Consensus state added: the commitment-tree root history (anchors) and the global
nullifier set. Validity: proof verifies against a known anchor, no `nf` is in the
set, balance holds, binding sig verifies.

## 7. Frozen vs open

- **Frozen (C1):** note/commitment/nullifier/accumulator (SHAKE-256), the spend
  statement (§2), SP1/FRI proof system with raw-FRI verification, wire format.
- **Open → C2:** the SP1 Rust spend program + reference verifier behind a flag;
  parameter tuning (tree depth, FRI params); exact `pk_d`/`nk` derivation in the
  wallet.
- **Open → C3/C4:** external review, the lattice-RingCT upgrade path, audit.
  No privacy claim adopted until C4 (`COHERENCE-v0.2.md §7`).
