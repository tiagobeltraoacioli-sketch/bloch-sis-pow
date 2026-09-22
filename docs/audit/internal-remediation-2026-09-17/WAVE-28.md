# Internal audit remediation, twenty-eighth wave — 2026-09-18

Base: `b6774d4`; implementation commit `e99f564`; branch
`fix/internal-audit-20260917`. This is repository and CI evidence, not a live
bootnode scan or a fleet-remediation claim.

## Public bootnode RPC refusal

INF-10 reported that published bootnodes exposed the full unauthenticated PoS
JSON-RPC surface on port 8080 even though the documented service intended a
loopback bind. Source configuration alone cannot establish the path visible to
an external caller: a firewall, NAT rule, reverse proxy or deployed unit can
still contradict it.

The existing external bootnode verifier now treats the three known RPC ports
as forbidden on every published entry: the reported 8080 endpoint, the compiled
16310 default and the historical/custom 16400 fleet port. It checks them from
the verifier's network position after proving that the advertised P2P endpoint
is reachable. Any reachable RPC port fails the whole verification; a closed
RPC surface is reported explicitly.

An isolated adversarial self-test supplies a fake network probe. Its positive
case exposes only P2P and must pass; its negative case additionally exposes
8080 and must fail. Both GitLab's blocking `build-and-test` job and GitHub's
blocking live-crate job execute that regression, so later removal or inversion
of the refusal check breaks either pipeline.

## Validation and boundary

Shell syntax, the two-sided verifier self-test, the 37-case blocking-test guard,
the live pipeline posture check, both CI YAML parsers and diff-integrity checks
pass. The test-posture guard still reports all eight live crates in blocking
jobs on both platforms.

No public IP was contacted and no firewall, proxy, service unit or deployed
binary was changed. Consequently INF-10 moves from open to partial, not
implemented. A release operator must run the external verifier from outside the
fleet and remediate any reachable RPC path before this can be closed. NET-01
remains partial as well because consensus-thread RPC isolation is separate.

The ledger retains all 200 rows: 63 implemented, 79 partial, 44 open, seven
base-changed, four protocol decisions, one unarmed candidate, one refuted by
the original audit and one verified positive.
