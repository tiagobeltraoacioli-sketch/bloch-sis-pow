# Changelog

All notable changes to `bloch-sis-pow` will be documented in this file.

## [Unreleased]

### Changed
- **Security-claim reframing (docs only).** The hardness research
  (`docs/research/POW-CANONICAL-frontier.md` in the protocol repo) established
  that a trapdoorless PoW cannot be both lattice-hard and mineable. The crate
  docs now state the honest model: Bloch-SIS-PoW is a SHAKE-256 hashcash with
  a Module-SIS *structural gate* — security is cumulative hash work, not
  lattice hardness, and no lattice bit-security number attaches to the PoW.
  The 0.1.0 note below ("production mining requires lattice reduction") is
  retained as the historical belief; it is superseded — full-`M` is unmineable
  outright, and the brute-force miner is the correct one for the small-`k`
  design.

## [0.1.0] - 2026-05-02

### Added
- Initial reference implementation of Bloch-SIS-PoW.
- SHAKE-256 unified hash primitive with strict domain separation.
- Centered modular arithmetic over Z_q (q = 8 380 417, FIPS 204).
- Deterministic seed → matrix/vector expansion via rejection sampling.
- Matrix-vector multiplication mod q (reference O(m·n) loop).
- Brute-force reference solver with optional parallel mining helper.
- Verification path with three independent checks (norm, residual, aux).
- ASERT difficulty adjustment with 30-second target block time.
- 43 unit and integration tests covering algorithm correctness.
- Examples: `mine_block`, `mine_easy`, `verify_block`.
- Criterion benchmarks for solver and verifier components.

### Known limitations
- Reference brute-force solver does NOT find solutions at canonical
  parameters (B=2, β=q/16, m=512) due to (1/8)^512 ≈ 0 probability.
  Production mining requires lattice reduction (BKZ + Babai) — out
  of v0.1 scope. See `Bloch_SIS_PoW_Academic_Foundations_v0.1.pdf`.
- Matrix-vector multiplication is unoptimized; production should use
  NTT-accelerated paths (shared with ML-DSA-65 NTT implementation).
- ASERT scaling factor uses byte-shift approximation; production should
  use higher-precision pow2 lookup.
- No constant-time implementation of any operation. Side-channel
  analysis pending.

### Pending
- Formal hardness proof (Phase 1, Q3 2026 – Q1 2027).
- Lattice-estimator concrete-security analysis at canonical parameters.
- IACR ePrint paper draft (target Q1-Q2 2027).
- Trail of Bits / NCC Group audit (Q3 2028).
