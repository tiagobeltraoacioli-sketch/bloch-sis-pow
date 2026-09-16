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
inputs must never be taken from the untrusted export. The `verify-redemption-review` executable exposes this API through a bounded,
versioned stdin protocol for the Python source-chain observer. Build it with
`cargo build -p bloch-ustav --features native-dex-host --bin verify-redemption-review`.
It reads at most 65,537 bytes, rejects input over 65,536 bytes and trailing data,
and returns only the verified lowercase commitment plus newline on success.
The observer supplies operator-controlled trust separately from the certificate;
its release-observer documentation defines the wire format. Operational authority
provisioning, independently authenticated live state, and durable settlement
remain separate work. The executable performs no network calls or state writes.

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

For the optional real Python-to-Rust review integration check, set
`BLOCH_NATIVE_REVIEW_PROBE` to the bridge checkout's absolute
`scripts/tests/native_review_process_probe.py` path when running
`cargo test -p bloch-ustav --features native-dex-host --test joint_gateway_crypto`.
Committed test reviews and public PQ certificates are sent to that probe over
stdin; private keys stay inside the native test process. The probe verifies the
real executable and rejects eight altered inputs per fixture. This check needs
Python 3 and both repositories and does not run unless explicitly configured.

The verifier process now requires `BLOCH-REVIEW-VERIFY-v2` requests. Two u64
big-endian operator policy limits follow expiry: maximum checkpoint age and
maximum certificate lifetime. Rust enforces both limits with checked subtraction
before signature verification; v1 requests are refused. Upgrade the bridge
adapter and native executable together. Review commitments and certificate
signing formats are unchanged. This process policy does not supply authenticated
live native heights or consensus finality. The lower-level library verification
API remains independent of operator-specific freshness limits.

`verify-redemption-review --protocol` returns exactly `BLOCH-REVIEW-VERIFY-v2`
plus newline without reading stdin. Other arguments are refused. This supports
the bridge's explicit `check-native-verifier.py` deployment diagnostic; protocol
compatibility alone is not a cryptographic self-test or operational readiness.

### Binding the BLCH projection during candidate preparation

`pool_candidate::prepare_with_base_roots` adds explicit expected parent and post
BLCH roots to the existing independently reexecuted candidate preparation. A
wrong parent is refused before cryptography; a wrong post drops the staged state.
Only a matching candidate returns the exclusively borrowed `Prepared` handle,
which must still be durably persisted before commitment. Dropping that handle
continues to abort without state mutation. Full candidate domain, height, joint
root, operation and signature checks are retained.

The host must derive `BaseRoots` from its authenticated parent and independently
validated block expectations. This check links the BLCH projection only: it does
not prove that a live header commits the combined native gateway root, authenticate
a header, or supply finality. No live node admission path invokes this API yet.
A block containing other operations must compose them into one defined transition
before comparing roots; an arbitrary intermediate candidate root is not a complete
block state root. Activation and combined-root header encoding remain required.

`bloch_ustav::dex_journal::Journal::append_with_base_roots` now exposes that check
at the durable local host boundary. It accepts independent `BaseRoots`, uses the
concrete BLCH and native PQ verifiers, and writes candidate bytes only after both
projections match. It shares the existing fsync-before-state-install path and
poisons the handle on write/sync failure. Rejected roots leave the file and state
unchanged; callers can retry with correct independently obtained expectations.

The on-disk candidate format and replay behavior are unchanged. Reopening still
reexecutes against the independently authenticated joint tip; historical host
BLCH expectations are not separately stored or reauthenticated. Existing `append`
and pending-batch callers retain their explicit local-rehearsal semantics. A live
block integration must select the bound path and provide authenticated context;
this addition does not wire the node, change block formats or activate consensus.
Real PQ integration tests cover both mismatches, successful persistence and
restart of the bound journal.

`dex_admission::PendingBatch::commit_with_base_roots` connects the same explicit
host expectations to buffered admission. It rebuilds the candidate at the trusted
host height, then uses the journal's bound append path. Rejected roots preserve
queued frames and byte accounting for retry (the existing monotonic height
watermark still applies). Success clears and closes the batch exactly once;
a second commit is rejected without another disk write. Real PQ round trips
exercise both parent/post mismatch retries, identical rebuilt bytes, successful
commit and replay after reopening. This method is opt-in; ordinary local
`commit` retains its prior behavior and no live node is activated by the API.

For a host that has approved a specific canonical candidate,
`PendingBatch::commit_expected_candidate` additionally compares the rebuilt
candidate byte-for-byte with the host's independently supplied bytes before the
bound journal append. This covers native operations, ordering, domain, height,
parent and joint post-state claims; BLCH projection roots alone cannot identify
all gateway changes. Empty or oversized expectations are refused without copying
them. A mismatch preserves queued frames and journal bytes, while the normal
monotonic height watermark still applies after rebuilding. The expected bytes
never bypass reexecution or signature verification. Real PQ tests remove an
admitted suffix, reject the stale candidate, restore the suffix, and commit the
matching candidate; they also reject changed joint-root bytes. Host approval and
live consensus integration remain external requirements, not inferred trust.

Hosts that require exact candidate approval should create queues with
`PendingBatch::new_requiring_expected_candidate`. This immutable per-queue policy
refuses both ordinary `commit` and roots-only `commit_with_base_roots` with
`ExpectedCandidateRequired`, before rebuilding or writing anything. Only
`commit_expected_candidate` can persist that queue. Rejection preserves frames,
height and journal state; the existing closed-batch error takes precedence after
success. Queue edits do not remove the policy. The ordinary constructor remains
available for explicitly local rehearsal, and lower-level journal APIs retain
their documented scope. This is caller-error protection, not a security boundary
against arbitrary host code or an implementation of consensus authentication.
Real PQ integration tests exercise refused downgrade attempts followed by root
mismatch, edited-queue rejection, successful exact commit and restart.

### Persistent local host policy

`Journal::create_requiring_base_roots` creates a new `BLCHDJ02` journal with the
same anchor and record encoding, but a persistent root-expectation requirement.
`open` recognizes this header and preserves that requirement across restart.
Plain `append` is refused; `append_with_base_roots` retains its verified, synced
write path. `PendingBatch::new` automatically requires exact-candidate commits
when attached to such a journal, so callers cannot accidentally revert to the
ordinary queue commit after reopening. Direct journal callers still provide the
candidate itself and independently validated BLCH root expectations.

Existing `BLCHDJ01` journals keep their previous semantics; no automatic migration
or rewriting occurs. Older binaries reject the new header rather than opening it
with weaker semantics. Header policy is local operator configuration, not a
cryptographically authenticated consensus field: changing or rolling back the
file can defeat it. Protect journal files and independently authenticate anchors
and tips. Replay validates the complete joint state but does not reconstruct past
host approvals or store their expected BLCH roots. Real PQ tests verify rejection
before and after restart, inherited queue policy, unchanged disk bytes on refusal,
and successful bound replay. Production consensus activation remains pending.

A host that requires bound persistence should pair creation with
`Journal::open_requiring_base_roots`, rather than relying on `open` to infer
policy from the file alone. The strict opener rejects `BLCHDJ01` before replay,
anchor hashing or incomplete-tail recovery, even when its candidate history could
match the expected joint tip. Rejection leaves file bytes untouched and releases
the lock. Real PQ restart tests replace the bound header with the legacy header
and append an incomplete tail, require refusal with recovery enabled, then restore
the test file and reopen successfully. Existing generic `open` remains available
for intentional legacy compatibility. This prevents silent policy downgrade by
header substitution when the host selects the strict API; it does not authenticate
host configuration, historical approvals or consensus finality.

`Journal::recovered_tail_bytes` reports the number of physically incomplete tail
bytes removed during the current successful open. New and clean opens report
zero; the count is not persisted as consensus state. It is set only after the
truncation and sync succeed. Hosts can log this local recovery event without
mistaking it for a payment or finality indication. Bound-format real PQ tests
cover partial length prefixes and payloads, rejection without modification under
`Reject`, unchanged bytes when the trusted tip mismatches, exact truncation after
authenticated-prefix matching, retained policy, and zero on the next clean open.
A complete invalid length record is refused even with recovery enabled.

Before append, the journal now checks that both its open file length and write
cursor match its tracked durable extent. It repeats this check after candidate
verification and before persistence. A changed extent returns `StorageChanged`
and poisons the handle; metadata/position I/O errors also poison it. No staged
state is installed or additional bytes written after detection. Reopening and
reconciling against independent trust is required rather than silently seeking
past or overwriting unexpected data. Integration tests deliberately bypass the
advisory lock to truncate or extend owned test files and verify unchanged bytes,
unchanged in-memory head and refusal of subsequent writes and release queries.
This detects extent/cursor changes, not same-length edits, renamed files or all
races with a malicious writer; operator-controlled storage remains required.

The append checks also compare the complete 48-byte header with the bytes retained
when the journal was created or successfully opened. This detects same-length
changes to policy/version, anchor height or anchor root without hashing the whole
history on every append. The cursor is restored to the validated append position;
read/seek failures poison the session just like extent mismatches. Tests mutate
each header region while the journal remains open and require refusal without
new disk writes or state installation. Same-length candidate payload edits and
races with an uncooperative writer are still outside this fixed-header check;
full authenticated replay and controlled storage remain necessary.

### Experimental candidate-to-block binding

`pool_candidate::block_binding` proposes a digest for a future authenticated
block extension. Its preimage is `BLOCH-NATIVE-BLOCK-BINDING-v1` plus NUL,
network domain (32 bytes), parent block identifier (32), slot (u64 LE), height
(u64 LE), parent BLCH root (32), post BLCH root (32), candidate length (u64 LE),
and SHA3-256 of the exact candidate bytes (32). SHA3-256 of that preimage is the
binding. The bounded hashing function alone does not parse or approve a candidate.

`prepare_for_block` compares this digest with the independently authenticated
host expectation, using the state's network domain, then performs existing
candidate reexecution and BLCH projection checks. Mismatches do not mutate state;
the returned prepared handle retains the same abort/commit lifetime guarantees.
Slot and parent block validity are still the integrating host's responsibility:
this helper binds their values but does not validate ancestry or the schedule.

No current Genesis4 header carries this field, no live node calls the helper,
and computing a digest from attacker-supplied inputs is not authentication. A
future activation must include the extension in the signed header, validate the
joint state transition, and define its composition with other block operations.
Current block formats, signatures and activation parameters are unchanged.
Tests cover each bound field, a separately computed Python vector, forged
candidate claims under a matching digest, and real PQ gateway preparation.

`Journal::append_for_block` connects the experimental block binding to durable
local persistence with concrete PQ verifiers. Its typed internal admission
context distinguishes local, BLCH-root-bound and block-bound preparation without
optional-field combinations. It derives candidate height from the supplied block
context, checks the expected extension digest, reexecutes, validates BLCH roots,
and shares the existing storage-identity checks and fsync-before-install path.
Real PQ tests reject changed slot and parent block without file/state changes,
then commit the matching context and reopen against the trusted joint tip.

The host must independently authenticate the expected binding and validate block
ancestry/scheduling. Current journal records still contain only candidate bytes;
replay authenticates the joint tip but does not reconstruct the historical block
context or prove inclusion. `BLCHDJ02` requires BLCH roots, not this particular
block admission mode. A production integration must commit and persist the block
extension under consensus rules; no live header format or node path changes here.

`PendingBatch::commit_for_block` connects buffered admission to
`Journal::append_for_block`. It rebuilds and compares the exact expected candidate
bytes at the context's height, then checks the authenticated extension expectation
and BLCH projections through the journal. An explicit internal enum keeps local,
base-root and block-context admission distinct. Context mismatch preserves the
queue and file; successful fsync closes and clears the batch exactly once.
Tests with real PQ operations cover slot/parent changes through both direct and
buffered paths, byte-identical retry, refusal of a second commit, and restart.
The existing monotonic height watermark, storage checks, and no-live-consensus
limitations remain in force. Neither this API nor `BLCHDJ02` proves that a signed
network header included the proposed extension.

### Direct-child host admission

`BlockParent` carries the parent block identifier, slot and height from an
independently authenticated host chain view. `validate_block_parent` requires
matching child parent identity, checked `parent.height + 1 == child.height`, and
strictly increasing slot; skipped slots are allowed, skipped block heights are
not. Overflow is refused. This verifies one supplied edge, not chain ancestry,
validator eligibility, signatures on headers or consensus finality.

`Journal::append_child_block` additionally requires the local journal height to
match the supplied parent height before using the block-binding persistence path.
Tests reject wrong parents, heights and slots without file/state changes, then
persist and reopen a valid real-PQ candidate. The journal still does not store
network block identifiers: callers must authenticate the parent and its mapping
to the journal state independently. This API cannot skip blocks containing no
native operations; a production design must define those state transitions and
header commitments. Existing lower-level rehearsal APIs remain explicit and no
network activation is performed.

### Signed-header binding rehearsal

`prepare_for_signed_header` verifies an existing canonical header signature and
its body commitment over a single candidate, checks the supplied parent/slot
edge, reexecutes the candidate and compares the resulting BLCH projection with
the header's declared state root. It uses the existing `derive::body_root` and
`proposal_signing_root` rather than creating an alternative block identifier.
The host supplies an independently resolved eligible proposer key and signature
verifiers. Real hybrid-PQ tests cover valid binding, altered proposer metadata,
changed body root, and a correctly signed but incorrect post-state claim.

This is NOT a Genesis4 block validator. The candidate is not a currently admitted
`PosTransaction`, the root here is a BLCH projection rather than the full live
transition result, and proposer selection, RANDAO, attestations, rewards, fee
settlement and activation are not checked by this helper. A header accepted here
must not be submitted or treated as consensus-valid. No node path invokes it.
The full integration requires a defined native transaction encoding, consensus
state commitment and activation before delegating these checks to the real
`Transition::apply_block` flow.
