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
