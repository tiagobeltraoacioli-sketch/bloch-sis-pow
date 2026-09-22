# Wave 56 NET-22: fail-closed RPC Host authority parsing

Date: 2026-09-18. Base: `4747cd6`. Scope: the existing RPC browser-request
gate, one pure policy regression and this evidence note. No endpoint, RPC
method, response shape, network protocol, wire encoding, consensus rule,
persisted format or deployment changed.

## Correction

The RPC listener already rejects a request whose `Host` does not match its
bound-address policy or the operator's explicit allowlist. Its helper extracted
the text before the first closing bracket or colon without validating the rest
of the authority. Consequently malformed values such as `[::1`,
`[::1]suffix` and `localhost:anything` could be reduced to the built-in
allowlisted names `::1` or `localhost`.

The helper now returns no host unless the complete authority has a supported,
well-formed shape:

- a nonempty ASCII hostname or IPv4 spelling, optionally followed by a
  decimal port in the `u16` range; or
- a bracketed, parseable IPv6 literal, optionally followed by the same port
  form, with nothing after the closing bracket except that port.

The policy compares an allowlist entry only after this validation succeeds.
Valid `localhost`, hostname/IPv4 with a numeric port, `[::1]` and
`[::1]:port` clients retain their existing behavior. The change only rejects
malformed HTTP authorities that a compliant client does not emit.

## Regression

`host_policy_rejects_malformed_authorities_instead_of_allowed_prefixes` pins
both sides of the boundary. It accepts case-insensitive localhost and
bracketed IPv6 with or without valid ports, while refusing missing brackets,
trailing bracket garbage, empty/nonnumeric/out-of-range ports, multiple port
separators, embedded whitespace and userinfo-shaped input.

Validation on this checkout:

- malformed-authority Host policy regression: 1 passed;
- existing exact allowlist regression: 1 passed;
- `git diff --check`: passed.

No listener/socket test, workspace-wide formatter or broad suite was run.

## Residual

NET-22 remains **PARTIAL**. `Host`, `Origin` and `Content-Type` form a browser
request gate, not client authentication: a non-browser client can deliberately
send any syntactically valid allowlisted `Host`. Public RPC exposure, the
operator-controlled host allowlist and fleet firewall policy remain separate
risks that were not changed or inspected. Libp2p still allocates its bounded
gossip frame before the application admission callback, and a valid unindexed
block-log tail can still be long.
