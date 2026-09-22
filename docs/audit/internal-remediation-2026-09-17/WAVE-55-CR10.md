# Wave 55 CR-10: strict verification for enveloped vault artifacts

Base: `da2eb46`; branch `agent/wave55-crypto`.

## Scope

The generic `bloch_crypto::crypto::verify` entry point must retain automatic
legacy-raw compatibility for historical transaction verification. That
heuristic is ambiguous when a genuine raw signature starts with the two-byte
envelope magic. Wave 51 added an explicit raw verifier for callers that know
they hold historical raw objects, but modern versioned consumers still had no
corresponding strict-enveloped entry point.

This wave adds `verify_enveloped`. It requires both the public key and
signature to carry parseable suite envelopes before dispatching to the same
suite verifier used by `verify`; raw and mixed raw/enveloped pairs fail closed.
The generic verifier and its historical consensus callers are unchanged.

Two vault formats whose existing contracts already require enveloped keys and
signatures now use the strict entry point:

- `SignedAnchor` / `verify_anchor`
- `SignedRecoveryContextV1::verify`

Their signers already call `crypto::sign`, which emits an envelope. No signed
preimage, serialization, key, signature byte, funded vault format, or
consensus rule changes. Regressions prove strict round trips and raw/mixed
rejection, including a stripped-envelope signature at each migrated vault
boundary.

## Validation

- `cargo test -p bloch-crypto --lib` outside the socket-restricted sandbox:
  186 passed, 2 ignored.
- `cargo test -p bloch-pq-vault`: 45 unit tests and 2 compile-fail doctests
  passed.

The first in-sandbox full crypto run reached 183 passing tests but its three
loopback HTTP tests could not bind sockets (`Operation not permitted`). The
same suite passed completely when rerun with local-socket permission.

## Residual risk

CR-10 remains `PARTIAL`. Historical generic consensus verification still uses
format guessing and retains the 1-in-65,536 raw-signature magic ambiguity;
changing it requires an inventory and coordinated compatibility decision.
Other generic consumers cannot be migrated unless their trusted surrounding
format unambiguously identifies raw versus enveloped bytes. No real
magic-prefixed legacy signature fixture, activation, external review,
deployment, or fleet adoption is claimed.
