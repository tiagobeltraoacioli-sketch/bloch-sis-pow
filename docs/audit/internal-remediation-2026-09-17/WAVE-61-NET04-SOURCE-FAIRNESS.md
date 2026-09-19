# Wave 61 NET-04 / EN-07: per-source verification fairness

Date: 2026-09-18. Base: `8bf7bfc`. Scope: node-local attestation and
transaction admission fairness, three focused regressions and this evidence
note. No wire encoding, protocol identifier, consensus rule, block validity,
persisted format or deployment changed.

## Correction

Wave 60 bounded new block, attestation and transaction admission cryptography
to 1,024 hybrid calls per wall slot. That made sustained unique-input CPU
finite, but a single transport source could still consume the complete shared
allowance before honest traffic arrived.

Attestation and transaction admission now additionally limit one transport
source to 128 new hybrid calls per wall slot. Eight distinct sources are needed
to consume the unchanged 1,024-call aggregate ceiling; exhausting one source's
share leaves the remaining aggregate capacity available to other sources.

No payload field supplies this identity. The engine reads an opaque fingerprint
from the existing RAII source reservation:

- legacy devnet uses its already-normalized remote IP, so IPv4 and mapped IPv6
  for one host share the same allowance across reconnects;
- libp2p uses the authenticated `PeerId` already charged by first-hop
  admission; and
- IP and peer namespaces have distinct domain bytes before hashing.

The fingerprint is carried by `Origin` only inside the process. It is not
serialized, persisted, logged or used as reputation. Exact cached failures are
still answered before either allowance and consume neither cryptography nor
quota. Per-source state is cleared at the next wall slot and cannot have more
successful entries than the 1,024-call aggregate budget.

Exhaustion retains Wave 60 semantics: attestation policy becomes `Ignore`, a
network transaction is not relayed, and an RPC-visible transaction refusal is
retryable. No peer penalty or invalidity claim is manufactured from local load.

## Regressions

`one_source_cannot_spend_another_sources_slot_allowance` uses a two-call source
share inside a four-call aggregate allowance. It proves the noisy source stops
at two cryptographic calls while a different source still executes its call.

`verification_source_fingerprint_reuses_normalization_and_separates_peers`
proves mapped IPv6 and IPv4 share an identity, distinct peers do not, and an IP
cannot collide by construction with peer bytes of the same visible value.

The existing source-lifetime regression and the production
`devnet_predecode_charge_matches_the_engine_release_charge` path now also prove
that a devnet event reaching the engine carries a verification-source
fingerprint in the same guard whose lifetime they already test.

Validation on this checkout:

- `cargo test -p bloch-pos-node one_source_cannot_spend_another_sources_slot_allowance --offline -- --nocapture`:
  1 passed, 546 filtered out in the node unit target;
- `cargo test -p bloch-pos-node verification_source_fingerprint_reuses_normalization_and_separates_peers --offline -- --nocapture`:
  1 passed, 546 filtered out;
- `cargo test -p bloch-pos-node source_admission_lasts_through_processing_and_failed_delivery_releases_it --offline -- --nocapture`:
  1 passed, 546 filtered out;
- `cargo test -p bloch-pos-node devnet_predecode_charge_matches_the_engine_release_charge --offline -- --nocapture`:
  1 passed, 546 filtered out;
- all integration targets selected zero tests and passed;
- `git diff --check`: passed.

The root integration agent will run the broad suite. No workspace-wide
formatter was run because the pre-existing workspace is not formatter-clean.

## Residual

NET-04 and EN-07 remain **PARTIAL**. This per-source share covers transported
attestations and transactions. Block admission and RPC transaction submission
remain under only the aggregate 1,024-call ceiling: block orphan promotion does
not retain original transport provenance, and the current RPC engine request
does not carry a normalized client identity. Eight colluding transport sources
can still consume the aggregate allowance, one NAT intentionally shares a
devnet allowance, and the legacy transport still has no authenticated peer
identity or penalty path. Fair scheduling, Sybil resistance, fleet firewall
evidence and bounded pre-callback libp2p allocation remain open.
