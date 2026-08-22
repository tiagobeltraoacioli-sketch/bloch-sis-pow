# conformance/ — VM differential-conformance front (C-front)

Implements the executable parts of `docs/specs/BLOCH-VM-DIFFERENTIAL-CONFORMANCE.md`.
Everything here is **software, not consensus**: standalone workspaces, path-deps on
`crates/bloch-euvm` only, nothing reachable from the node's state-transition path
(`bloch-pos-node` / `bloch-pos-committee` do not reference this tree).

## Honest status (2026-08-22)

| Piece | Status |
|---|---|
| `euvm-conformance/` | **RUNS.** NIST CAVP KATs through the VM's real `run()` path: 507 applicable vectors (129 SHA-256d, 378 SHAKE256), each with a control half; 1241 VariableOut rows + Monte files excluded with named reasons (`euvm-conformance/vectors/cavp/MANIFEST.toml`). This is crypto-callback conformance, **not** Ethereum conformance — bloch-euvm is not an EVM and has no external reference implementation (spec §0). |
| `mutation/` | **RUNS.** The C4 mutation campaign over bloch-euvm's own 331 tests + the §4 harness gate for the KAT suite. Measured results in `mutation/results/`; survivors are listed by name, per repo discipline rule 3. |
| `corpora/` | Pins + fetch/verify scripts + filter skeletons for the two FUTURE harnesses. `anza-sbpf` manifest generated and committed; the two multi-GB manifests generate at first fetch. |
| C2 harness (EVM statetest) | **NOT BUILT** — target `crates/bloch-l1-evm` (milestone E2) has zero code. |
| C3 harness (sBPF diff) | **NOT BUILT** — target `crates/bloch-sbpf` (Front 1) has zero code. |

**Real conformance rate reportable today: none for EVM/sBPF** (no target exists);
euvm crypto KATs: 507/507 applicable, with exclusions named above.
