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

## Attaching the BLCH payer signature

After a separate human approval and a call to the wallet's trusted signer,
`FundingReview::finish_with_payer_signature` consumes the retained review. It
rechecks payer, state and height, bounds the returned signature, and verifies it
against the reviewed joint authorization digest using the host's signature
verifier. It accepts a signature only, never a replacement packet from a website.

The method clones the retained typed request and replaces exactly the sole BLCH
payer witness signature. All outputs, asset and route identifiers, price limits,
fee declarations, native owner signatures and gateway authority witnesses remain
unchanged. It encodes and decodes the final packet through the canonical transport,
checks that the authorization digest is unchanged, and recalculates the charge.
A changed charge or invalid final size declaration is refused without repricing.
Declared size slack can accommodate different signature lengths only within the
existing protocol limits. The method does not manufacture placeholders or choose
fee declarations for the caller.

The resulting packet has its own full-packet hash. Other witnesses may still be
missing or invalid: this API verifies only the single BLCH payer signature.
`SubmissionReview` must check the complete signed packet before submission, and
inclusion still requires normal execution. A failed attachment consumes the review.
No private keys, browser provider methods, signing grants or broadcasts are added.
The selected payer and verifier must originate from trusted wallet/host state;
this method does not independently establish user consent or key possession before
receiving the signature.

Real-PQ tests reconstruct a swap packet byte-for-byte from its zeroed payer witness,
then run full submission preflight. They reject wrong-key, wrong-message, damaged,
empty and oversized signatures, account changes, height regression, expiry and
changed state. A valid signature that makes the final packet exceed its reviewed
size declaration is also refused. Sponsored import and withdrawal exercise the same attachment path
while preserving every issuer, owner and committee witness byte.

## Account signature across BLCH and native inputs

`FundingReview::finish_with_account_signature` extends the payer-only attachment
with an explicit account-owner path. Both methods share the existing signature,
context, canonical-packet and unchanged-charge checks; payer-only attachment keeps
its original behavior. The account method fills the BLCH payer signature and the
positional native owner witnesses for unlocked inputs owned by that exact payer.

Ownership is resolved from the retained transaction's input outpoints in the
trusted current state, not from website-supplied indexes, output recipients or
owner labels. Native inputs must exist, belong to the declared asset and have a
witness slot. An unlocked input must also be spendable through the combined state's
custody-aware view. A locked input's witness is preserved even if its recorded
owner is the selected account; reserve authorization remains executor-owned.
Other accounts' input witnesses, policy module redeemers, eligibility proofs and
gateway committee approvals are preserved exactly. An initialization operation
has no native transaction and uses only the BLCH payer attachment.

This method verifies one account's signature, not every role in the packet. It
cannot fill issuer/module/committee roles or promise executability. Full signed
submission preflight and normal execution remain required, including all reserve
and AMM checks. Missing or invalid other-party witnesses remain invalid. No key
access, browser export, network submission or consent mechanism is added.

Real-PQ tests clear both payer and native owner signatures, attach the same verified
joint signature, and execute swaps in both directions. They compare the complete
resulting packet with the expected bytes, keep reserve witnesses empty, and compare
preflight roots with actual execution. Sponsored gateway import and withdrawal
preserve other-owner and issuer/committee signatures byte-for-byte. Missing native
inputs are refused without altering the source state.

A separate structural regression covers all six pool lifecycle operations with
the deterministic test verifier, including native reserves whose recorded owner
is the payer. Reattaching the existing account signature preserves the complete
canonical packet and its execution behavior. This structural test is distinct
from the real-PQ integration checks above.
