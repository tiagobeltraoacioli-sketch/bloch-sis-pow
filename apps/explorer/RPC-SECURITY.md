# Public RPC transport — 2026-09-17

Both `apps/explorer/functions/rpc.js` and
`apps/posternpool-site/functions/rpc.js` use `apps/_shared/rpc-proxy.mjs`.
Build Pages functions from the full repository checkout, retaining the shared
sibling directory. The explorer exposes Genesis-4 read method names alongside
historical read names; availability still depends on the upstream node.
This change does not create a transaction index or synthesize unavailable data.

## Deployment prerequisite

Before deploying either project, configure its Pages `BLOCH_RPC_URL` environment
variable with an operator-controlled HTTPS RPC endpoint and a valid certificate.
The former plaintext public-wildcard fallback is removed. Missing, plaintext,
credential-bearing, fragment-bearing or known public wildcard DNS URLs return
503. No endpoint, DNS record, TLS certificate, firewall rule or live Pages
configuration has been provisioned by this source change. Existing deployments
must be reviewed before rollout; copying this configuration alone is insufficient.
Keep the node's direct RPC private and place a read-only gateway with rate limits
in front of it. CORS is intentionally public and provides no authentication.
HTTPS validation alone does not prove DNS ownership or prevent direct-node access.

## Enforced behavior

The proxy accepts individual JSON-RPC 2.0 requests with array parameters and an
explicit read-method allowlist. Batches and write methods are rejected. It strips
unrecognized envelope fields and forwards the parsed method once, preventing
inconsistent duplicate-key interpretation by downstream JSON parsers.
Numeric values must be safe integer literals (no fraction/exponent notation); use supported decimal-string fields
for larger quantities. JSON-RPC identifiers are null, bounded strings or safe
integers. Responses retain their original JSON encoding, so the proxy does not
round legacy integer amounts above JavaScript's safe integer range. Clients
must still parse these amounts without losing precision.

Request bodies are limited to 64 KiB and eight seconds. Upstream calls, including
body consumption, have a twelve-second deadline and a 2 MiB response limit.
Limits apply to streamed bytes, not only Content-Length. Requests abort on timeout,
redirects are refused, response IDs and envelopes are checked, and transport
errors do not expose exception strings. Responses are not cached.
These bounds do not replace per-client rate limits or a node-side resource budget.

Run `node --test apps/_shared/rpc-proxy.test.mjs` from the repository root
(or `npm run test:rpc` in the explorer) using Node 24. Bundle both Pages function
directories with Wrangler before release. Transport tests use mocked upstreams;
they do not qualify live DNS, certificates, gateway policy or chain correctness.
