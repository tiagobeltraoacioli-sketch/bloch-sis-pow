# Internal audit remediation, forty-second wave — 2026-09-18

Base: `a453953`; branch `fix/internal-audit-20260917`. This is the local
closeout of the six supplied audit artifacts. It is not a release approval,
deployment record or authorization to choose consensus economics.

## Reconciled result

The ledger contains 200 unique finding IDs and no finding from the supplied
tables was deleted. The final local classification is:

| Status | Count |
| --- | ---: |
| IMPLEMENTED | 66 |
| PARTIAL | 89 |
| OPEN | 30 |
| BASE CHANGED | 7 |
| PROTOCOL DECISION | 4 |
| VERIFIED POSITIVE | 2 |
| UNARMED CANDIDATE | 1 |
| REFUTED IN AUDIT | 1 |

`IMPLEMENTED` means source and regression evidence on this branch. `PARTIAL`
is not closure. None of these labels proves fleet deployment, independent
validator adoption or external review.

## Why the 30 rows remain open

Every remaining row has an explicit boundary. There is no remaining small,
locally safe correction supported by the supplied evidence that can be made
without crossing one of these boundaries.

| Boundary | Findings | Required next authority or evidence |
| --- | --- | --- |
| Coordinated consensus, replay or economic choice (22) | FC-04, FC-05, FC-07, FC-08, FC-10, FC-12; SR-01; ST-03, ST-04, ST-06, ST-07, ST-11, ST-12, ST-13, ST-15, ST-16; TX-04, TX-08, TX-09, TX-10, TX-13, TX-14 | Specify the intended rule and activation epoch; prove historical replay compatibility and mixed-binary behavior; rehearse partitions, recovery and economics as applicable. These rules cannot be silently changed by an audit patch. |
| External operational evidence (3) | INF-02, LG-01, SR-03 | Rotate and separate live credentials with evidence; reconcile the unexplained historical subsidy from authoritative source data; conduct the independent weak-subjectivity signing ceremony. Repository edits cannot establish any of those facts. |
| Architectural work (1) | EN-17 | Move durable reorg publication off the consensus thread while preserving atomic replacement, crash recovery, index invalidation and fail-stop behavior. This is a storage architecture project, not a bounded audit edit. |
| Missing detailed annex text (4) | INF-20, BV-18, NET-21, NET-22 | Supply A10, A9 and A6 (or an itemized equivalent). The six artifacts name only aggregate collections; guessing their constituent claims would create false closure. |

Several protocol candidates and mitigations already exist and are tested, but
remain deliberately inactive where activation would alter consensus. The
protocol-blocker memo records the minimum qualification for recovery, cohort
weight and partition-finality changes. The residual register above is the
handoff for a future decision-bearing release review.

## Completion boundary

Local remediation is complete for the evidence and authority supplied to this
worktree. Completion means that every finding is retained, implemented work is
covered by recorded validation, partial work states its residual, and every
open item identifies what prevents a safe local close. It does **not** mean all
30 open findings are resolved, a release is approved, or production was
changed.

Final repository guards and their exact outcomes are recorded in
`VALIDATION-WAVE-42.txt`.

