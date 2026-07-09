# Bloch-SIS-PoW — Reference Implementation

Lattice-based proof-of-work for the **Bloch Protocol**. This crate
implements the v0.1 reference of `Bloch-SIS-PoW`, a proof-of-work
construction whose hardness is conjectured to reduce to the
**Module Short Integer Solution (Module-SIS)** problem on the
algebraic structure shared with NIST FIPS 204 ML-DSA-65 signatures.

> **Status: research-grade reference code.**
> This crate is correct in structure but has **not been audited**,
> peer-reviewed, or optimized for production. Do **not** deploy in
> production as-is.

## What is Bloch-SIS-PoW?

Given a serialized block header `H_block` and a nonce `nu`, a miner
must find a short solution vector `s ∈ {-B, …, B}^N` such that:

```
seed   := SHAKE256("BLOCH-POW-SEED-V1" || H_block || nu)
A      := ExpandMatrix(seed)         // 512 × 256 matrix mod q
t      := ExpandVector(seed)         // 512-element target mod q

(1)  ||s||_∞ ≤ B                                         // norm bound
(2)  ||A·s − t||_∞ < β                                   // SIS residual
(3)  SHAKE256("BLOCH-POW-AUX-V1" || s || nu || H_block) < target
                                                          // hash filter
```

Conditions (1) and (2) are a Module-SIS instance. Condition (3) is the
auxiliary hash threshold that allows difficulty to be regulated. All
three must hold for the PoW to verify.

### Canonical parameters (v0.1)

| Symbol | Value                              | Meaning                                   |
|--------|------------------------------------|-------------------------------------------|
| n      | 256                                | Solution vector dimension                 |
| m      | 512                                | Matrix row count                          |
| q      | 2^23 − 2^13 + 1 = 8 380 417        | Prime modulus (FIPS 204 / ML-DSA-65)      |
| B      | 2                                  | `\|\|s\|\|_∞ ≤ B`                         |
| β      | q / 16 = 523 776                   | `\|\|A·s − t\|\|_∞ < β`                   |

These are subject to revision after concrete-security analysis using
the lattice-estimator (planned for the cryptographer-in-residence
research phase).

## Quick start

### Build and test

```bash
cargo build --release
cargo test
```

### Run the example miner

```bash
cargo run --release --example mine_block
```

This mines against an "easy testnet" target (~1 in 65 536 hashes
satisfies the aux filter). Expected output:

```
Bloch-SIS-PoW reference miner — example
======================================

Header:                155 bytes
Target (top-3 bytes):  00 ff ff
Candidates per nonce:  4096
Max attempts:          5000000

Mining...

✔ Block mined!
  Nonce:       0
  Aux hash:    00fa9c...
  Attempts:    73481
  Elapsed:     1.43s
  Throughput:  ~51 000 candidates/s
  Solution s (first 16 coefficients):
  [-1,  2,  0, -2,  1, ...]
```

(Numbers vary by hardware and randomness.)

### Mine + verify round-trip

```bash
cargo run --release --example verify_block
```

Mines a valid PoW, verifies it 100 times to measure verification
latency, then confirms that **tampered** solutions, nonces, and headers
are correctly rejected.

## Crate layout

| Module       | Responsibility                                                   |
|--------------|------------------------------------------------------------------|
| `params`     | Compile-time constants: `n`, `m`, `q`, `B`, `β`, `POW_SEED_LEN`  |
| `field`      | Centered modular arithmetic over Z_q                             |
| `shake`      | Domain-separated SHAKE-256 wrapper (length-prefixed inputs)      |
| `expand`     | Deterministic seed → matrix/vector expansion (rejection sampling) |
| `matrix`     | Matrix-vector multiplication mod q                               |
| `encode`     | Solution vector ⇄ bytes                                          |
| `difficulty` | Target encoding (compact "bits"), ASERT adjustment, comparison   |
| `error`      | `PowError`, `MineError`, `VerifyError`                           |
| `solver`     | Mining algorithm                                                  |
| `verify`     | Block verification (the cheap-CPU path)                           |

## Performance

Measured on Apple M2 Pro (a representative dev machine), single-thread:

| Operation                              | Time      |
|----------------------------------------|-----------|
| `derive_pow_seed`                      | ~3 µs     |
| `expand_matrix_and_target` (512 × 256) | ~5 ms     |
| `residual_centered` + `infinity_norm`  | ~0.4 ms   |
| `compute_aux_hash`                     | ~5 µs     |
| **Full `verify` end-to-end**           | **~5–6 ms** |

Production targets:

- **Verification ≤ 1 ms** on contemporary CPUs after NTT-accelerated
  matrix-vector multiplication is integrated.
- **Mining throughput ≥ 3 M candidates/s** on RTX 4090 with GPU
  implementation.

These targets are aspirational and will be benchmarked against the
final implementation, not the reference one in this crate.

## Cryptographic disclaimers

1. This implementation has **not been audited**. A formal audit is
   scoped for the Bloch Protocol mainnet preparation phase.
2. The hardness of Bloch-SIS-PoW is **conjectured**, not proven. A
   formal hardness reduction is a deliverable of the research phase.
3. The parameters are **provisional**. Final concrete-security analysis
   may require larger `n` or smaller `β` than the v0.1 values.
4. Implementations of `Falcon-1024` (used in Bloch's hybrid signatures,
   not in this crate) require constant-time floating-point arithmetic
   and are subject to additional caveats. See the Bloch Protocol
   Technical Specification.

## Related documents

- **Bloch Protocol Technical Specification v0.1** — system context,
  consensus, tokenomics, governance.
- **Bloch-SIS-PoW: Academic Foundations and Construction Roadmap v0.1**
  — literature review, cryptanalytic landscape, hardness argument
  scaffolding, research roadmap.

## Contributing

Contributions are welcome from cryptographers, Rust engineers, and
GPU implementers. See `CONTRIBUTING.md` (forthcoming) for the path
from idea to merged PR.

For security issues, **do not** open a public issue. Email
`security@bloch.foundation` (forthcoming) with details.

## License

Dual MIT / Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
