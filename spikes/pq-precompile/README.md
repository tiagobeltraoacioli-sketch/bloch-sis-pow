<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# spike — `pq_verify`, the hybrid-verification precompile

Reference implementation and cost harness for
`docs/specs/BLOCH-L1-EVM-PQ-PRECOMPILE.md`, which decides §6.2 of
`docs/specs/BLOCH-L1-EVM-AUTHORIZATION.md` under the founder's option-2
decision of 2026-08-21.

**This is a standalone spike.** It carries its own `[workspace]` table, exactly
like `spikes/prover-cost/`, so `cargo build --workspace` at the repo root does
not see it and the node binary does not link it. The EVM is not at L1; nothing
here puts it there. Wiring any of this into the state-transition path is a
separate founder decision (ADR-040, SR-2) and would collide with a mainnet that
is, today, not finalising.

```
src/lib.rs                  the precompile: one pure function + its gas function
src/main.rs                 cost harness — prints the spec's §5.4 numbers
tests/precompile.rs         framing, totality, gas, and 4 mutation proofs
tests/permit_pattern.rs     the PQ `permit` existence proof (host model)
contracts/BlochPQ.sol       the library contracts should call
contracts/PQPermitToken.sol EIP-2612 semantics without ecrecover
```

Run:

```
cargo test --release
cargo run --release --bin pq-precompile-cost
```

`--release` is not optional for the harness: a debug-build lattice verification
measures the debug build, not the chain.

There is no `solc` in this repo, so the Solidity is specified and reviewed but
not compiled here, and `tests/permit_pattern.rs` is a faithful host model of
`PQPermitToken.sol` rather than an EVM execution of it. Replacing that model
with real execution against the pinned revm version is an activation gate
(spec §9).
