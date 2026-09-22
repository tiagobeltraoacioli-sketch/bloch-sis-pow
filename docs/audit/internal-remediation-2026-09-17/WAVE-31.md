# Internal audit remediation, thirty-first wave — 2026-09-18

Base: `a7c7e0f`; implementation commit `7851d80`; branch
`fix/internal-audit-20260917`.

## Retired consensus isolation

LG-12 asked whether the Genesis-3 eUTXO VM and FFG scaffold are reachable from
the live Genesis-4 node. A one-time source search or `cargo tree` inspection is
not a durable answer because a later transitive dependency can silently change
the binary's compiled surface.

The new guard loads locked, offline Cargo metadata, locates the unique
`bloch-pos-node` package and traverses its complete resolved dependency graph.
It fails if that graph reaches the retired Genesis-3 node package (`bloch`),
`bloch-euvm` or `bloch-ffg`. It also fails closed if metadata cannot be loaded,
the live package is absent/ambiguous, or a referenced resolve node is missing.

The built-in adversarial self-test covers a clean graph, a direct retired
dependency, a transitive retired dependency and a missing live root. The live
locked graph reports no forbidden reachability. Both GitHub Actions and GitLab
run the self-test and live check in their blocking test jobs before compiling
the workspace.

This establishes build-graph isolation for the checked-in default live binary;
it does not delete the retired crates from the workspace or claim they are
secure products. LG-12 is implemented. The ledger retains all 200 rows: 66
implemented, 79 partial, 41 open, seven base-changed, four protocol decisions,
one unarmed candidate, one refuted by the original audit and one verified
positive.
