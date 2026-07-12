# `tests/vectors/` — regression anchors, NOT standards KATs

**Read this before trusting a green run.** Everything in this directory is a
**self-referential regression vector**: a value this repository's own code
produced, pinned so that an *unintended* change to the bytes is caught at test
time. These vectors **detect drift, not correctness**. They are **not** an audit,
**not** a security proof, and **not** the official standards known-answer tests.

Unaudited software. The coin has no value. Nothing here is "secure", "audited",
"attested", "reproduced", or "quantum-safe".

## regression vector ≠ standards KAT

| | regression vector (what lives here) | standards KAT (what we do NOT ship) |
|---|---|---|
| source of the "answer" | this repo's own implementation | an external authority (NIST FIPS-204 `.rsp`, Falcon-1024 NIST KATs) |
| what a match proves | the bytes did not change vs the last blessing | the implementation agrees with the standard |
| RNG for deterministic keygen | ChaCha20 via the `pqcrypto-internals` fork's `with_seeded_rng` | AES-256-CTR NIST DRBG |
| status here | present | **absent** — the official `.rsp` files are not vendored, and a NIST DRBG is not wired (see `crates/bloch-crypto/src/crypto/mod.rs` §"KAT SOURCE / HONESTY") |

Because Bloch's seeded keygen uses a ChaCha20 stream and NIST reproduces keypairs
from an AES-256-CTR DRBG, a signed NIST `.rsp` vector does **not** reproduce a
Bloch seeded keypair. The KATs in `tests/kat_*.rs` therefore assert
**wrapper-equivalence + regression**, never NIST-KAT equivalence.

## the KAT files

| test file | what it pins | fork status |
|---|---|---|
| `kat_mldsa65.rs` | ML-DSA-65 (FIPS-204) sizes; seeded-keygen golden body hashes; sign/verify accept + reject; malformed-parse-no-panic | **A-independent, fork-invariant** (golden hashes are envelope-invariant) |
| `kat_falcon1024.rs` | Falcon-1024 sizes; sign/verify accept + reject; malformed-no-panic. Falcon sig bytes are **never** byte-pinned (float-sampling caveat) | **A-independent** |
| `kat_address.rs` (`vectors/kat_address.json`) | address 20-byte hash + `bloch1q…`/`bloch1t…` strings + parse round-trip for a fixed pubkey | **A-independent** for the fixed-pubkey input |
| `kat_hybrid_equivalence.rs` | asserts-equal to Dev-A's ONE published post-fork canonical tuple (enveloped pk/address/txid/chain-id sighash) | **PENDING DEV-A** — real assertions compiled only under `--features dev_a_frozen`; inert until the consensus bundle lands (PMO R8) |

### pre-fork WIP vectors (will be re-pinned by Dev-A's merge)

`kat_hybrid_signer.rs` / `kat_hybrid_signer.json` and `kat_txid_sighash.rs` /
`kat_txid_sighash.json` pin **pre-fork** values (hybrid pubkey length 3745;
1-argument `sighash(0)`). Dev-A's suite-id envelope (+4 header ⇒ 3749) and
chain-id sighash **deliberately** change these bytes. After Dev-A merges they are
re-pinned **by asserting-equal to Dev-A's published tuple**, never by
auto-accepting whatever the code emits (PMO R8). Do not read a green run of those
two files post-fork as confirmation — they must be rebased first.
