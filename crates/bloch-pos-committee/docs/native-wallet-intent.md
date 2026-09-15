# Native wallet intent decoding

`transition::native_dex::pool_intent::DecodedIntent` is a read-only integration
boundary for a future wallet review. It is available only with the existing,
default-off `native-dex-rehearsal` feature. It does not add a signing method,
WASM export, browser provider method, RPC endpoint or live transaction variant.

The caller supplies a domain from independently authenticated configuration.
`DecodedIntent::decode` delegates to the existing bounded, canonical pool wire
decoder and then to the selected executor's authorization function. This keeps
wallet-side Rust integration from reimplementing the protocol's signing hashes.
Wrong domains, unknown operations, noncanonical encodings, truncated/trailing
bytes and oversized packets are refused. No state is read or mutated.

The result owns the complete original packet and decoded request. It exposes
only immutable references, so a caller's later changes to its input buffer or
to a cloned request cannot change what the object reports. Amounts retain the
existing integer base-unit types; no labels, decimals or token symbols are
inferred from a website's presentation.

## Data consumers must distinguish

| Accessor | Meaning | Not evidence of |
| --- | --- | --- |
| `operation()` | Structurally decoded operation kind | Safe execution or source finality |
| `request()` | Complete typed operation, including both funding legs and witnesses | Input ownership, sufficient funds or valid signatures |
| `domain()` | Domain matched to the caller's expected value | Authenticity of that expected value |
| `authorization()` | The executor's existing domain-separated signing digest | User consent, authenticated witness tables or a valid signature |
| `packet_hash()` | SHA3-256 of every packet byte, including signatures | Consensus transaction ID or message to sign |
| `matches_packet(bytes)` | Exact equality to the retained packet | Freshness, funding, signature verification or executability |

`operation()` distinguishes import, withdraw, create pair, initialize, add,
swap, remove and close pair. It is a dispatch label, not a sufficient approval
screen. A consumer must inspect the full operation: asset/route identity,
recipient and output owners, input outpoints, amounts, slippage/LP limits,
reserve identity, pool root/revision, expiry heights, declared byte/gas/tip
fields, and the applicable signer roles. Fee totals and spendability require
verified current host state; decoding alone cannot report them.

Changing witnesses can preserve `authorization()` while changing `packet_hash()`.
Filling signatures therefore requires decoding the new packet; it cannot pass
an exact-byte comparison to the earlier packet. Neither matching authorization
digests nor successfully decoding forged signatures makes a packet authorized.
The existing executor remains responsible for all cryptography and transition
checks. This module deliberately supplies no `approve`, `sign` or broadcast API.

## Validation

The pool-wire tests exercise all six pool lifecycle variants, retain exact bytes
and every decoded field, check the existing executor digests, reject every
truncated prefix and malformed boundaries, and distinguish witness changes from
slippage changes. A compile-fail doctest prevents mutable request access.

`bloch-ustav`'s swap and sponsored gateway crypto fixtures now derive the message
through this decoder before signing with real ML-DSA-65 + Falcon-1024 keys.
Existing successful execution, invalid-signature, theft, stale state and bridge
round-trip tests run through that path. Gateway fixtures cover both import and
withdraw. External source events remain simulated and no funds are transferred.

Run with Rust 1.94.1:

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --lib native_dex
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --doc
cargo +1.94.1 test --locked --release -p bloch-ustav --features native-dex-host --test blch_swap_crypto --test joint_gateway_crypto
```

The existing GitHub and GitLab native regression jobs include these commands.
Local results do not imply remote CI success. Browser delivery, verified chain
context, account-specific intent review, explicit approval, native DEX signing,
consensus activation and an operational USDT bridge remain separate work.

## Single-payer funding review

`pool_review::FundingReview::prepare(state, packet, payer, height)` adds a local
BLCH funding check to the immutable decoder. The state and height must come from
an authenticated host view, and the selected public key must come from the
wallet's own signer. Website-supplied copies of those values do not establish
trust. This API deliberately supports exactly one BLCH payer; bridge issuer,
committee and multi-payer review flows are outside its scope.

Preparation checks the one encoded BLCH key against that selected key. It checks
input uniqueness, real UTXO existence and script ownership, refuses ordinary
spends of locked reserves, and counts only unlocked payer coins as funding.
A protocol-reserve input is excluded only if it matches the referenced pool or
close operation's known locked reserve. It is never reported as spendable wallet
balance. The inputs must cover at least the full packet's network charge.

The charge comes from the existing fee dispatcher and current local state.
`wallet_outputs_sats()` reports all outputs addressed to the payer, including
swap proceeds if applicable. It must not be labeled "change" or "net cost".
The full typed intent remains available for reviewing all other fields.

The review records the complete state root, exact packet, selected key, review
height and earliest inclusive expiry height across the outer operation, native
transaction and (for imports) source-event certificate. Inconsistent nested
expiry is refused. Heights are not wall-clock timestamps.

After the separate human review, `finish` consumes the object and compares the
current account, exact packet and complete state root, rejects regressing heights
and expiry, and returns the immutable intent only if those checks pass. A failed
attempt also consumes it; the same review cannot be retried. A signed packet has
different bytes, so filling witnesses requires a separate review at submission.

This is an observation of local state, not a state lock, reservation, permission
token or human-approval system. It does not authenticate the selected key's
private-key possession, validate signatures, prove source finality, validate the
complete native leg or establish pool/AMM execution validity. Context must still
be checked at signing and submission, and the real executor must validate the
complete transaction. No transfer is sent by preparation or finishing.

Regression tests cover all six pool operations, exact fees settled by execution,
reserve exclusion, payer mismatch, duplicate/missing/incorrectly indexed coins,
unknown pool references, changed state/account/packet, height regression and
inclusive inner/outer expiry. A compile-fail test prevents reuse after finishing.
Real-PQ integration tests additionally exercise a trader swap and a sponsored
bridge import/withdrawal, including the import certificate's shorter deadline.

## Fully signed submission preflight

`pool_submission::SubmissionReview::prepare` accepts the complete signed packet,
selected BLCH payer, trusted state, execution height and host signature verifiers.
It first performs `FundingReview`, then runs the existing operation executor on a
private clone of the state. The original state is never changed, on either success
or failure. No alternate signature checks, fee rules or AMM formulas are introduced.
All eight decoded operation kinds use the same dispatcher as ordinary execution.

A successful review exposes the immutable funding review, typed simulated receipt
and predicted resulting state root. These are simulation results, not a committed
receipt or proof of inclusion. Filling or changing witnesses requires a new
preflight of the final packet. Unsigned or forged packets must be refused by the
host's real verifiers; supplying permissive test verifiers invalidates that claim.

`finish` consumes the review and requires the exact original execution height,
selected payer, packet bytes and parent state root. Even an advancing height still
inside the expiry interval requires another preflight, since execution effects
can depend on height. A failed attempt also consumes the review. This does not
approve, sign, reserve funds, enqueue, broadcast or install the simulated state.
Submission and inclusion must still use the executor and durable host commit path.
The caller remains responsible for authenticated state, real signature verifiers,
account authorization and human review. External source finality remains dependent
on the configured gateway attestation model.

Preflight clones the complete local state and runs full cryptography. It is intended
for a bounded local host integration; this change adds no public simulation RPC.
A service exposing it would need its own concurrency and resource limits. The
existing single-BLCH-payer restriction remains in force, including on gateway
transactions; this is not an issuer-only or committee-only signing interface.

Real-PQ regression fixtures compare predicted and actually executed roots for swap,
import and withdrawal, verify that successful and failed preparation leave the
source state unchanged, and reject corrupted witnesses, impossible slippage,
stale pool roots and changes of account, bytes, height or parent state. A compile-
fail doctest prevents reuse after finishing. These checks run in the existing
native feature jobs; there is no browser export or live consensus activation.
