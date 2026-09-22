# Internal audit remediation, thirty-sixth wave — 2026-09-18

Base: `465cc21`; branch `fix/internal-audit-20260917`. This wave reconciles two
PQ-shield findings against controls already implemented in the remediation
branch. It does not claim that a remote service is a privacy boundary or that
the anchor format supplies a registry.

## BV-03: construction-service disclosure boundary

The original finding correctly observes that vault construction submits the hot
and recovery public keys, the recovery hash and transaction intent to the API.
Those values are public inputs rather than private keys, but their association
is threat-model-sensitive.

The remediated service refuses every non-loopback listener. Its deployment
contract requires a local TLS-terminating proxy with authentication and
per-client rate limits for any network exposure, and its documentation now
recommends local construction and explicitly says not to treat a remote API as
a privacy boundary. Request parsing also minimizes reflection of submitted keys
and values on errors.

This is partial mitigation only. An operator of a deliberately exposed proxy,
or a party that compromises it, can still observe the public inputs and intent.
Eliminating that disclosure requires local/client-side product integration.

## BV-07: anchor ordering and lifecycle

Anchor verification no longer trusts the key carried inside the object: the
caller must supply the independently trusted PQ key, and the signature covers
the committed address, recovery hash, safe destination, delay and opaque policy.
The API and crate also state that syntax/signature validation does not prove
freshness, ownership or correspondence to a particular live vault.

This is partial mitigation, not format-level closure. The anchor has no
canonical sequence, expiry, predecessor link or revocation registry. The opaque
policy field can carry application policy but cannot make two valid anchors
globally ordered by itself. A relying product must define and persist that
lifecycle before activation.

All 17 `pq-shield-api` tests pass offline, including trust-root enforcement,
forgery refusal, listener/request hardening and response minimization. The
ledger retains all 200 rows: 66 implemented, 85 partial, 35 open, seven
base-changed, four protocol decisions, one unarmed candidate, one refuted by
the original audit and one verified positive.
