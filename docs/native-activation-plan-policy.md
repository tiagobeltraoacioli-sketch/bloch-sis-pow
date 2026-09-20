# Native activation plan review policy

`python3 scripts/check-native-activation-profile.py profile.json` performs offline
consistency checks only. It does not authenticate operator approvals, inspect the
pinned executable, change consensus gates, deploy validators, or open source
custody. `validate(path, now=None)` remains the importable API.

The supported default plan schedules all six gates at the same future epoch.
Staged schedules require a separate review and are rejected by this checker.
`sourceDepositsOpenEpoch` must be no earlier than the latest gate. This field is
an operator plan, not an instruction to automatically resume source deposits.
Deposits must remain closed until withdrawal and source release are qualified.
Each validator readiness artifact must declare both
`withdrawalSimulationPassed` and `sourceReleaseRehearsalPassed`, in addition to
canonical replay, historical root preservation and rollback preparation. These
booleans are claims to substantiate with independently reviewed evidence, not
proofs manufactured by this checker.

Chain observations must include `finalizedSlot` and
`finalityRule: "canonical-checkpoint-slot-v1"`. The finalized checkpoint cannot
be beyond the observed head or its claimed epoch boundary. The plan refuses a
checkpoint more than 96 slots behind the head, a head more than 32 slots behind
the wall clock, and observations or validator readiness older than 600 seconds.
These are conservative review limits, not new consensus parameters.

All six production gate constants in this branch remain `u64::MAX`. A profile
with finite epochs does not make this checkout or an already deployed binary
active. The release commit and executable digest must be corroborated against
the exact reviewed candidate, its build configuration, and a replay against the
actual production base. No broad native-integration branch replacement should
be inferred from the minimal RPC recovery backport. In particular, the latter
changes recovery observations and does not activate native assets.

The release object therefore also references the exact root `Cargo.lock`, build
image attestation, production replay evidence, rollback-package manifest, and
two to eight independent build attestations. It pins the production-base commit,
canonical build-image digest and `/build` path. Every independent builder must
report the exact candidate binary digest and a distinct attestation. The checker
reads and hashes each bounded referenced artifact, detecting missing, substituted
or internally inconsistent evidence. These remain operator inputs:
but it does not establish that a builder is organizationally independent or
that the replay and rollback drill were honestly performed.
It also does not verify the rollback package's detached signature; that remains
the release-integrity runbook's out-of-band trust check.

The native checker validates custody identity and the exact custody artifact
hash, but intentionally does not replace the detailed source custody manifest
validator. Run both over the same artifact with independently supplied source
trust configuration. Retain their reports with the full validator cohort,
replay evidence and approved release pins before any operator decision.
