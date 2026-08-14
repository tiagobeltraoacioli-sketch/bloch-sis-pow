# coherence-prover (Coherence C2b-prover) — SP1 scaffold

> **Historical — Genesis-3, and never live.** The shielded pool this proves
> for was built for the proof-of-work chain, which stopped permanently at
> height 39,918 on 2026-08-13. The live chain is **Genesis-4, proof of stake**
> (30 s slots, 32-slot epochs, finality by epoch), and it has **no shielded
> pool at all**: `crates/bloch-pos-node` does not depend on `coherence-core`
> and no Genesis-4 transaction type is shielded. This crate is also excluded
> from the root workspace (see the root `Cargo.toml` `exclude` list), so
> `cargo build --workspace` never compiles it. Nothing here has ever secured a
> live transaction. Read "the node" below as the Genesis-3 node.

The zero-knowledge half of the shielded pool: prove the C1 spend statement
(`src/coherence::check_spend`) with **SP1** (hash-STARK / FRI, Plonky3) and verify
the **raw FRI proof** — never SP1's default Groth16 wrapper (that curve SNARK
would break post-quantum coherence, `COHERENCE-C1.md §3`).

> **Not built by any `cargo build`.** This crate is a path-dependency of no
> node and is on the root workspace's `exclude` list, so both `cargo build`
> and `cargo build --workspace` ignore it. It needs the SP1 toolchain
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

## Prerequisite — `coherence-core` (DONE)

The guest runs on RISC-V in the zkVM and must be lean/`no_std`-friendly, so it
CANNOT depend on the full Genesis-3 node crate (rocksdb/libp2p). The pure
coherence primitives (`Note`, commitment, nullifier, `CommitmentTree`,
`SpendPublic/Witness`, `check_spend`) were therefore extracted into
`crates/coherence-core` (deps: `sha3`, `serde`), which the Genesis-3 node
re-exports and this guest imports — single source of truth. `SpendPublic` and
`SpendWitness` carry the `Serialize`/`Deserialize` derives SP1 io needs. This
step is complete; it is described here because it is the constraint the layout
exists to satisfy.

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

Scaffold only, and superseded — the guest/host code and the build process are
captured so a machine with the SP1 toolchain can produce and verify a real
proof. The proved statement (`check_spend`) and the consensus checks
(`ShieldedState::validate`) are implemented and unit-tested in the **Genesis-3**
node (`legacy/genesis3-node`), which no longer runs. This crate itself has
never been part of a shipped node binary — it is excluded from the workspace —
and Genesis-4 has no shielded pool for it to prove for.
