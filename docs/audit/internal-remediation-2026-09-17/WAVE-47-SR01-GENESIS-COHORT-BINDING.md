# Wave 47 SR-01: inactive genesis-cohort binding candidate

Date: 2026-09-18. Branch: `codex/audit-sr01-genesis-binding`. Starting
point: `1711937`. Scope: local source, tests, documentation, and audit evidence
only. No manifest was published, no activation or deployment occurred, and no
live network identity changed.

## Recovered finding and current behavior

The exact source was recovered from repository history at
`a79c88b:docs/audit/deep-audit-2026-09-16/A4-consensus-state-root-ws.md`.
SR-01 records that `CommittedState::genesis_cohort` changes duty weights and
therefore proposer and committee selection, but is absent from
`CommittedState::compute_root`. The root-inventory regression deliberately
pins that omission as "chain identity."

The existing BPOSMAN2 candidate did not complete that chain-identity binding.
Its genesis mix covered the carryover commitment and the two clock fields, and
its state root covered the opening ledger and validator registry. Neither
covered cohort membership. Two otherwise identical V2 manifests with different
cohorts therefore computed the same genesis block id while producing different
duty rosters.

The published `genesis/mainnet.manifest` begins with `BPOSMAN1`. No BPOSMAN2
artifact exists in the repository, and the source already documents V2 as
unpublished and selected only by the explicit `--bind-genesis` creation flag.
The live V1 identity must remain frozen for historical replay.

## Candidate, deliberately inactive

For `ManifestFormat::V2Bound` only, `Manifest::genesis_mix` now computes:

`SHA3-256(DS_RANDAO || GENESIS_MIX || SHA3-256(Manifest::encode()))`

The inner digest covers the magic/version, clock, complete validator records,
cohort vector, four-field carryover commitment, and allocations in one
canonical encoding. This avoids maintaining another hand-copied list of
manifest fields that can drift. Loaded carryover entries remain represented by
their verified commitment in the manifest and by the opening-balance subtree
in the state root.

The V2 opening state is anchored on a header carrying that mix, so changing
cohort membership moves the mix, the derived opening state root, and the final
genesis block id. A focused adversarial regression demonstrates all three.
The same regression changes a V1 cohort and proves that the historical V1
genesis id remains identical. Existing documentation was corrected where it
incorrectly claimed that the state root itself contained the cohort.

SR-01 moves from `OPEN` to `UNARMED CANDIDATE`, not `IMPLEMENTED`. Before any
BPOSMAN2 publication, the ceremony tool and node derivation must be reconciled,
the formula and manifest bytes independently reviewed, launch artifacts
reproduced, and an explicit new-network decision made. Publishing BPOSMAN2
would create a different network from the live BPOSMAN1 chain; this wave does
not authorize or perform that action.

## Validation

- `cargo test --locked -p bloch-pos-node genesis::tests`: 58 passed, zero
  failed. This includes the new cohort A/B regression, the hand-derived
  canonical-manifest formula check, clock/ledger binding regressions, and the
  V1 frozen-identity regression.
- `cargo test --locked -p bloch-pos-node --test published_checksums`: two
  passed, zero failed.
- `git diff --check`: passed.

The build emitted inherited unused-import and dead-code warnings. Repository-
wide `cargo fmt --all -- --check` remains red on extensive pre-existing files;
this wave did not reformat unrelated code.
