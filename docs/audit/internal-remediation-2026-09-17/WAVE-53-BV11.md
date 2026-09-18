# Wave 53 BV-11: network-bound Bitcoin anchor verification

Date: 2026-09-18. Starting point: `405bfb0`. Scope: an additive checked
`bloch-pq-vault` verification API, regressions and ledger wording. No anchor
wire bytes, funded script, key derivation, generic historical verdict,
consensus rule, service deployment or live data changed.

## Local hardening

Earlier remediation made `SignedAnchor::deserialize` reject trailing bytes and
gave callers a syntax/network validator. The generic `verify_anchor` remained
deliberately chain-agnostic: it authenticates the owner key and committed bytes
but cannot decide which address rules or network a Litecoin, Dogecoin,
Bitcoin Cash or Ethereum relying party intends.

Bitcoin consumers now have `verify_bitcoin_anchor`. It requires three trust
inputs that are not taken from the anchor itself:

- the independently trusted owner PQ public key;
- an explicit expected Bitcoin network; and
- the caller's decision to apply Bitcoin semantics.

The checked path preserves version and trusted-key error precedence, refuses a
non-Bitcoin target, parses both `btc_vault_address` and
`designated_safe_dest`, requires both on the expected network, and only then
performs the existing hybrid PQ signature verification. It never guesses a
network from attacker-provided strings. A valid testnet anchor therefore cannot
authorize a mainnet watchtower action through this entry point.

## Regression evidence

Focused tests cover a valid regtest anchor, wrong expected network, mixed
mainnet/regtest addresses, invalid UTF-8, a non-Bitcoin target, an independently
untrusted key and a damaged signature. A compatibility regression confirms the
generic verifier still accepts the historical placeholder-address fixture;
adoption of address semantics remains explicit rather than silently changing
old low-level behavior.

Validation:

- `cargo test --locked -p bloch-pq-vault anchor::tests --offline`: 11 passed;
- the complete vault suite is run before the track handoff;
- `git diff --check` is required for the scoped files.

## Honest residual boundary

BV-11 remains `PARTIAL`. `PqShieldAnchor` fields stay public and `sign_anchor`
plus generic `verify_anchor` remain compatible with arbitrary address bytes.
The standalone API currently checks that both addresses share some Bitcoin
network, but its request format does not carry an independently expected
network. Non-Bitcoin target chains still need their own canonical address
validators. Address validity also does not prove ownership, freshness,
correspondence to the actually funded witness script, registry inclusion or
finality.

Ledger aggregate counts are unchanged. No deployment, consumer adoption or
external audit evidence is claimed.
