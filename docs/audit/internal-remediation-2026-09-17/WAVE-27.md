# Internal audit remediation, twenty-seventh wave — 2026-09-18

Base: `d84fad1`; implementation commit `e96f794`; branch
`fix/internal-audit-20260917`. This is local source/CI evidence, not a rollback
drill or a fleet-deployment claim.

## Rollback and release authentication

INF-09 remained open even though two post-audit-base commits had already added
the core rollback mechanism. `make-rollback-package.sh` assembles the known-good
N-1 binary, signs a manifest that covers the binary, stamp, installer, systemd
drop-in and README, and refuses to emit an unsigned package. The generated
installer authenticates that manifest against a public key pinned outside the
package before checking hashes or staging bytes. After restart it compares the
running `/proc/<pid>/exe` hash with the signed package.

The companion self-test generates disposable keys and exercises the good path
plus rewritten manifests, modified installers, stripped signatures, missing or
wrong trust roots and a signature copied from another package. It was already a
blocking GitLab job. This wave adds the same blocking job to GitHub Actions and
extends the common posture guard so either pipeline goes red if the rollback
gate is deleted or made non-blocking.

## Validation and boundary

Both CI YAML files parse. The posture guard's 12-case self-test passes, and the
live files report seven required blocking security jobs in each pipeline. The
test-posture guard, shell syntax and diff-integrity checks pass.

The cryptographic rollback self-test itself was attempted locally and failed
closed before execution because `minisign` is not installed on this workstation;
that is recorded as a limit, not a passing result. Both CI jobs install
`minisign` and then execute the self-test without a failure waiver.

INF-09 moves to partial, not implemented. The repository still cannot prove
that a real release signing key exists, that its public half is pinned on every
host, that an N-1 artifact is staged, or that the systemd/fleet drill succeeded.
Those are the remaining release-time controls. The ledger retains all 200 rows:
63 implemented, 78 partial, 45 open, seven base-changed, four protocol
decisions, one unarmed candidate, one refuted by the original audit and one
verified positive.
