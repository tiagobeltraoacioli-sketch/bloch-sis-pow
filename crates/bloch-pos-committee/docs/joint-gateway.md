# BLCH-funded gateway operations in the native DEX rehearsal

The default-off `native-dex-rehearsal` feature now accepts gateway imports and
withdrawals inside the complete BLCH/native `State`. This closes the previous
gap where gateway execution existed only before assembling that State.
Registration and route enablement still happen during trusted rehearsal setup;
this change does not add runtime administrative authority over routes.

## Joint authorization and atomic settlement

`gateway::Request` contains a real BLCH `TransferV2` fee leg, a bounded existing
gateway envelope, an outer expiry and a prepaid native-work budget.
`State::quote_gateway` charges the complete signed envelope, including issuer,
owner and committee witnesses. Native work uses the existing conservative
rehearsal multiplier and transaction/block resource limits. This is not a newly
calibrated live-chain fee schedule.

The sponsor, issuer, withdrawal input owners and route committee sign the same
`BLOCH-JOINT-GATEWAY-AUTH-v1` digest, binding the authenticated network domain,
BLCH spend intent, existing route-bound gateway intent, outer expiry and gas
budget. Ordinary standalone gateway certificates are intentionally insufficient.
Changing sponsor inputs, change destinations, fee terms, source-event identity,
withdrawal destination or expiry requires new joint signatures. The scoped
verifier only translates the expected gateway digest to this joint digest;
key admission and hybrid-PQ verification remain the host's responsibility.
The optional durable host uses its fixed production PQ verifiers.

`State::execute_gateway` checks both custody lock layers, fee bounds and expiry,
then validates a private BLCH plan. It executes the gateway against a private
clone of the native pool ledger. Only after both succeed does it consume the
BLCH plan and install the staged native state and fee escrow. On any returned
error, balances, native supply, route liabilities, replay records, reserves and
fee escrow remain unchanged. A gateway withdrawal cannot burn a DEX reserve,
even with signatures from its original owner. All paired/native custody maps
remain inside the complete State.

This implementation clones the native pool ledger for atomic staging. It does
not claim constant memory or eliminate per-operation cloning within a batch.
The host must still enforce resource limits and measure operational capacity.

## Transport, batching and restart

The new canonical `BLCHGWAY` envelope uses version 1:

| Field | Encoding |
| --- | --- |
| Magic / version / domain | 8 bytes / u16 LE / 32 bytes |
| Outer expiry / native gas | u64 LE / u64 LE |
| BLCH section | u64 LE length followed by canonical TransferV2 |
| Gateway section | u64 LE length followed by existing USTVUSDT envelope |

The fixed overhead is 74 bytes. Total length, base witness/item counts and both
section lengths are checked before decoding their tables. Wrong domains,
unknown versions, truncation, trailing data and noncanonical encodings reject.
The parser does not authenticate signatures or external events by itself.

`pool_wire::Request::Gateway` and `Receipt::Gateway` include this operation in
the existing dispatcher, batch budgets, candidate reexecution, admission and
durable journal. Imports can fund a later pair creation in the same candidate.
A failed later operation rolls back the complete batch, including an earlier
import and its BLCH fee. Existing pool frames and state snapshot/root layouts
are unchanged. Older receivers cannot decode the new operation: all rehearsal
participants must update before exchanging candidates or journals containing it.

## Reading locally executed bridge records

`state.native().gateway()` exposes three read-only queries:

- `import_record(&route, nonce)` retrieves the imported deposit and its source
  transaction/block/event identity, or None when absent.
- `release_record(&route, nonce)` retrieves the recorded burn/release, or None
  when absent.
- `releases_after(&route, after, limit)` returns references to releases in
  ascending nonce order for exactly that route. None starts at zero; a supplied
  cursor is exclusive. Limits must be 1 through `MAX_RELEASE_PAGE` (128).

The page API rejects unknown routes and invalid limits. A cursor at `u64::MAX`
returns an empty page for a known route without overflowing. Queries borrow
records directly from the ordered maps, so they do not clone the complete
gateway or expose an executable inner ledger. They do not modify supply,
liabilities, replay protection or the state root.

For the durable host, prefer `journal.release_page(expected_checkpoint, &route,
after, limit)`. It verifies journal health and the complete expected height/root
before returning a bounded borrowed page. The page carries that checkpoint and
route; `next_after()` returns the last nonce, or None for an empty page. Continue
using the same checkpoint. A changed height or root returns `WrongHead`; restart
the traversal deliberately instead of silently switching states. A nonempty final
page may require a final empty query. Queries after a write/sync failure return
`Poisoned` until the host reopens and reconciles the journal.

The borrowed page prevents mutable access to the journal while its records are
still in use. A network service must acquire its host read lock before calling
this API; the library does not install a transport or a global lock. For individual
import lookups, query `journal.state()` and associate results with
`journal.checkpoint()` while holding the same host read lock. Admission previews
do not appear in that journal state. Persisted import/release records remain
queryable after replay and reopening against the trusted checkpoint. Queries
on a separately simulated State describe that simulation, not the journal.

A cursor alone does not bind a chain, state root or finality. A host serving
multiple pages must pin the complete checkpoint or explicitly restart paging
when the state changes; do not silently combine pages across a reorganization.
An import record does not prove source finality, and a release record does not
prove an external payout occurred. These APIs do not assign execution heights
to individual records or establish a payout authorization policy.

## Validation and deployment boundary

### Checkpoint-bound redemption review

The optional local host exposes
`journal.redemption_review(expected_checkpoint, &route, nonce)`. It checks journal
health and the exact expected height/root before looking up a committed release.
Unknown routes or releases are refused. It also reconciles all routes for that
release's native asset against native supply, returning the release and an
`AssetLiabilities` report under the same checkpoint and immutable journal borrow.
Admission previews are never used. A stale height/root or poisoned journal cannot
produce a review. The query changes neither state nor the durable file.

The review's `observer_request_json()` exports exactly the seven fields consumed
by the bridge's `inspect-stablecoin-release.py`: native domain, native asset,
route ID, nonce, recipient, amount and native burn. IDs are fixed-size lowercase
hex and uint64 fields are decimal strings, preserving values above 2**53.
The caller can retain `checkpoint()` alongside this request for its own verified
checkpoint policy. The JSON deliberately contains no settlement authorization.

The exported file alone is not an authenticated proof: another process can alter
it, and the source observer cannot independently establish native finality from
those fields. Authentication of the checkpoint and transport, matching source
payment evidence, source reorg handling and an atomic paid-liability transition
remain separate requirements. A committed local burn does not prove external
payment. The API remains behind `native-dex-host`; no RPC service, consensus
activation, source transaction or settlement mutation is introduced.

### Redemption review integrity commitment

`RedemptionReview::commitment()` returns SHA3-256 of `commitment_preimage()`.
This is a versioned integrity identifier for the entire review, not a signature,
trusted checkpoint certificate, or authorization to pay or settle a redemption.
The source release ID remains its existing SHA-256 ABI digest; these two hash
domains must not be confused.

The preimage concatenates these fields without JSON encoding:

1. ASCII `BLOCH-REDEMPTION-REVIEW-v1` followed by one zero byte.
2. Checkpoint height (8-byte unsigned big-endian), then its 32-byte root.
3. Native domain and native asset ID (32 bytes each).
4. Native supply (8 bytes), cumulative imports and burns (16 bytes each).
5. Source-compatible release ID (32 bytes), binding route, nonce, recipient,
   amount and native burn through `Release::id()`.
6. Route count (4-byte unsigned big-endian).
7. For each route in ascending route-ID order: route ID (32 bytes), source domain
   (32), token (20), vault (20), cumulative imports (16), cumulative burns (16),
   outstanding amount (8), and release count (8).

All integers are unsigned big-endian. The query already limits the review to
32 routes, so the preimage is at most 5,567 bytes. There are no caller-selected
hash algorithms, ambiguous text numbers or host-endian fields. Changing any
bound checkpoint, release or accounting field changes the identifier; replaying
the same persisted journal produces the same identifier.

The commitment can be retained alongside the observer JSON to detect accidental
mixing of reviews. An attacker can replace an unsigned payload and its hash
together. Authentication still requires an independently trusted signer/checkpoint
policy and a verified transport; no such trust is inferred from this commitment.
Neither the journal format nor source contract route IDs change.

### Hybrid PQ review attestations

`RedemptionReview::certificate_message(authority, valid_until)` provides the
domain-separated digest for an independently configured authority to sign.
It uses SHA3-256 of ASCII `BLOCH-REDEMPTION-ATTESTATION-v1` plus one zero byte,
the 32-byte review commitment, SHA3-256 of the complete canonical hybrid public
key envelope, and the 8-byte unsigned big-endian native expiry height.
Keys must pass the concrete `BlochVerifier` suite and canonical-key checks;
expiry cannot precede the review checkpoint. Private keys remain outside the
review and journal APIs. No operational authority is generated or installed.

`verify_certificate(trusted_checkpoint, trusted_authority, current_height,
valid_until, signature)` requires the exact independently trusted checkpoint and
verifies with ML-DSA-65 **and** Falcon-1024 through `BlochVerifier`. The host must
supply trusted authority policy and native height; taking a public key, root or
height from an untrusted certificate is not authentication. Accepted heights run
from checkpoint height through expiry inclusive. A modified expiry, different
key, substituted review, wrong signature domain, malformed signature, or damage
to either hybrid component is refused. Signature size remains bounded by the
native verifier. Callers must define key rotation, revocation, permitted validity
windows and any additional authority quorum outside this primitive.

Success authenticates an authority's attestation to this local review, not
consensus finality, a source payout or a completed settlement. It does not replace
the issuer and bridge quorum required for gateway supply changes. Verification
does not consume a certificate and may be repeated; durable payment/burn replay
guards remain necessary for any future settlement transition. The existing
Python observer still accepts only an unauthenticated release request and does
not yet verify this certificate. No network certificate transport or live
authority registry is introduced by these local host methods.

### Detached review verification

`dex_journal::verify_exported_review` verifies canonical exported review bytes
without opening the originating journal. Callers supply the expected route and
release, an independently authenticated checkpoint and authority, the current
native height, and the certificate. The bounded decoder rejects unknown versions,
truncation, trailing bytes, duplicate or unordered routes, inconsistent accounting,
and a release that does not match the selected route. It checks the selected
route's cap; other routes' configurations remain covered by the trusted attestation.
The existing hybrid PQ verifier authenticates the complete canonical commitment
and enforces the certificate's height validity window.

The returned commitment authenticates an attestation only. It is not consensus
finality, external custody evidence, or permission to settle a redemption. Trust
inputs must never be taken from the untrusted export. The Python source-chain
observer is not yet wired to this Rust API; operational authority provisioning,
transport integration, and durable settlement remain separate work.

### Existing integration coverage

The complete market rehearsal is now covered by
`bridge_import_liquidity_independent_trade_and_redemption_survive_restart` in
`bloch-ustav/tests/joint_gateway_crypto.rs`, with the continuation implemented
in `tests/support/bridge_market_roundtrip.rs`. It performs these signed steps:

1. Import the attested test asset to the liquidity provider, paying BLCH fees.
2. Fund sealed BLCH/native reserves and initialize the LP position.
3. Buy native units with 100,000 base units of BLCH using an independent trader's
   real funding output and hybrid signatures, without the LP owner's signature.
4. Burn exactly the native output received by that trader, funding the bridge
   fee from the trader's swap change and producing one local release record.

The test checks unchanged LP shares, intact post-swap reserves during the burn,
native supply reduced by the purchased amount, route liabilities and fee escrow.
The remaining BLCH reserve and change outputs plus escrowed fees must equal
the provider's and trader's original combined funding, counting each output once.
Executing all five frames through receiver candidate validation produces the
same final state as direct execution. Corrupting the final committee signature
rejects the entire batch, including its earlier import, liquidity and swap.

With `native-dex-host`, each step is separately admitted and committed at a new
height, then the journal is closed and replayed before proceeding. Pending
previews never expose a release through checkpoint-bound journal queries. Only
the committed final burn produces the expected release; replaying any completed
step after restart rejects without changing the checkpoint. Final roots and fees
match the single-candidate execution. This also tests that valid operations can
be confirmed at later heights without altering their intent.

Run the complete workflow locally with:

```sh
cargo +1.94.1 test --locked -p bloch-ustav --features native-dex-host --test joint_gateway_crypto
```

Both repository CI configurations already run this target; their existing
selection now includes the complete workflow without a new optional job.

`bloch-ustav/tests/joint_gateway_crypto.rs` uses real hybrid signatures with
test-only keys and simulated source events. It covers sponsored import/burn,
fees, receiver reexecution, snapshot restore, journal reopen, replay with fresh
fee funding, independent signer failures, wrong destinations, underfunding,
exhausted gas, deadlines, malformed frames, mixed import/pair batches and
attempted reserve burns before and after restoration.
It also checks that pending previews are absent from journal queries and that
record lookups and pages survive committed journal replay. Unit tests cover
page caps, exclusive cursor boundaries and route isolation; compile-fail tests
prevent mutation through the read-only gateway view.

No source vault is deployed, no source finality is proven and no external
payment is made by this implementation. A withdrawal receipt contains a local
release record, not an executed payout or consensus finality. Admission previews
may contain the same record; relayers must never pay from previews. Native block
integration, authenticated finality, external relayers and live fee settlement
remain separate work before a funded BLCH/USDT market can operate.
