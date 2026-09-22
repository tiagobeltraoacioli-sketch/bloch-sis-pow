# Internal audit remediation, fortieth wave — 2026-09-18

Base: `078b8ad`; branch `fix/internal-audit-20260917`. This wave corrects the
classification of LG-11. It does not authorize or perform a pool redeployment.

## LG-11: positive audit observation, not an open defect

The consolidated audit's exact title is "Pool/pool-proxy: advisor findings
verified closed; residual notes for a redeploy." Keeping that row as generic
`OPEN` inverted the auditor's conclusion. It is now `VERIFIED POSITIVE`.

The current proxy suite independently supports that classification: all 207
unit tests and all three integration pump tests pass. They cover bounded/cancel-
safe framing, authenticated worker usernames, local achieved-difficulty credit,
pending byte limits, per-IP admission, upstream reconnect/reauthorization,
extranonce collision handling, bounded RPC behavior and payout accounting.

This is not a production readiness claim. The inventory marks the PoW pool and
proxy idle after PoW ended. Low/informational observations, obsolete deployment
assumptions and operational configuration must be reviewed if anyone proposes
redeployment; passing tests cannot establish a live deployment posture.

The ledger retains all 200 rows: 66 implemented, 88 partial, 31 open, seven
base-changed, four protocol decisions, one unarmed candidate, one refuted by
the original audit and two verified positives.
