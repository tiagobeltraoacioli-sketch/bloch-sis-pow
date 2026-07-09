# coherence-prover (Coherence C2b-prover) — SP1 scaffold

The zero-knowledge half of the shielded pool: prove the C1 spend statement
(`src/coherence::check_spend`) with **SP1** (hash-STARK / FRI, Plonky3) and verify
the **raw FRI proof** — never SP1's default Groth16 wrapper (that curve SNARK
would break post-quantum coherence, `COHERENCE-C1.md §3`).

> **Not built by the node's `cargo build`.** This crate isn't a path-dependency
> of `bloch`, so the main workspace ignores it. It needs the SP1 toolchain
> (server/GPU-oriented) and is built separately — see below.

## Layout

- `program/` — the **SP1 guest**: reads `SpendPublic` + `SpendWitness`, runs
  `check_spend` (fails the proof if the statement is violated), and commits the
  public inputs. This is exactly the `src/coherence::check_spend` logic.
- `script/` — the **host**: builds the guest ELF, proves, and verifies the FRI
  proof (one-shot, for local testing).
- `service/` — the **HTTP prover service** (`/prove`, `/verify`, `/health`) with
  bearer-token auth, deployed on a GPU server. See
  [`deploy/sp1-prover/`](../../deploy/sp1-prover/) for the Fly.io GPU config
  (L40S, scale-to-zero, artifact-cache volume) and deploy steps.

## Prerequisite — extract `coherence-core`

The guest runs on RISC-V in the zkVM and must be lean/`no_std`-friendly, so it
CANNOT depend on the full `bloch` crate (rocksdb/libp2p). Extract the pure
coherence primitives (`Note`, commitment, nullifier, `CommitmentTree`,
`SpendPublic/Witness`, `check_spend`) from `src/coherence/mod.rs` into a
`crates/coherence-core` crate (deps: `sha3`, `serde`) that BOTH the node
re-exports AND this guest imports — single source of truth. `SpendPublic` and
`SpendWitness` also need `Serialize`/`Deserialize` derives for SP1 io.

## Build + run (where the SP1 toolchain is installed)

```bash
curl -L https://sp1up.succinct.xyz | bash && sp1up      # installs the toolchain
cd crates/coherence-prover/program && cargo prove build  # → guest ELF
cd ../script && cargo run --release                      # prove + FRI-verify
```

## Post-quantum coherence rule

Use the **core STARK/FRI** proof and verification path:

```rust
let proof = client.prove(&pk, stdin).core().run()?;   // FRI, PQ-secure
client.verify(&proof, &vk)?;                            // FRI verification
```

Do **NOT** call `.groth16()` / `.plonk()` — those wrap the STARK in an
elliptic-curve SNARK (Shor-breakable) and are forbidden here. The on-chain
`ShieldedTx.proof` carries the raw FRI bytes; the node verifies them.

## Status

Scaffold only — the guest/host code and the build process are captured so a
machine with the SP1 toolchain can produce and verify a real proof. The proved
statement (`check_spend`) and the consensus checks (`ShieldedState::validate`)
are already implemented and unit-tested in the node.
