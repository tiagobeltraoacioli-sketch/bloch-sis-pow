# SDK 0.1.14 release candidate

Status: prepared locally, not published. This is a new version of the existing
`@blochprotocol/genesis4-sdk` package, not a replacement for the 0.1.13 bytes at
their existing URL. There are no dependency, export, WASM signer, address,
transaction encoding or default endpoint changes.

## Changes and compatibility

- Included receipt inputs and outputs must use native `u32` output indexes,
  including offline deposit inspection.
- Persisted signed envelopes are decoded as native Transfer/TransferV2 before
  broadcast or tracking. Their actual spend root must agree with the envelope's
  root and consensus txid; the exact raw bytes must agree with `rawHash`.
- Each identity field is captured once before validation and I/O, so caller
  mutation cannot change the returned identity or admission correlation checks.
- Oversized raw envelopes fail before decoding or network callbacks. The raw
  limit is 524,254 bytes, preserving the native 1 MiB JSON-RPC request cap.

Valid 0.1.13 envelopes remain compatible. Malformed envelopes accepted only
because older code checked two unrelated hash assertions now fail before I/O.
Synthetic receipts with out-of-range output indexes also fail. Do not repair a
rejected persisted envelope by overwriting its identifiers; recover its original
record and reconcile the original txid before considering any new transaction.

The transfer codec, spend-root fold, txid derivation, domain constants and RPC
body limit were compared directly with native L1 source commits
`4d4c5075872c622fdd26aa418a9d249ec95fbcea` and
`e7261e6c74194662cdec0fa77e2124c5eda9da21`. These selected rules match across the
two commits. This does not assert that the complete node implementations or
deployed gateways are identical. Cursor mode remains explicit and disabled by
default until the selected node's support is independently confirmed.

## Distribution procedure

1. Review the SDK patch and candidate evidence. Attribute the final SDK source
   to a committed revision before production distribution. The candidate record
   binds the base commit, full patch and artifact hash; when the SDK changes are
   committed, it also records that source commit. A commit is not publication or
   approval of the integration.
2. Run the exact-artifact checks in `scripts/PACKAGE-VERIFY.md`. Keep a downloaded
   copy and hash of the currently served 0.1.13 package separate from the
   candidate. Confirm persisted V1/V2 envelopes remain usable through the
   upgrade without creating replacement transactions.
3. Add the reviewed tarball and `.tgz.sha256` as new files under
   `apps/bloch-ops/wallets/downloads/`. Preserve every existing 0.1.13 file and
   URL. The proposed new URL is
   `https://ops-blochinc.xyz/wallets/downloads/blochprotocol-genesis4-sdk-0.1.14.tgz`;
   this document does not claim that URL is live.
4. Update the SDK link and version in `apps/bloch-ops/wallets/index.html`, the
   Ops README and the explorer's SDK reference together. Keep the previous
   immutable URL available for provenance and controlled recovery. Run the
   affected static-site checks before deploying the reviewed site revision.
5. Use the existing Ops deployment command from `apps/bloch-ops`:
   `wrangler pages deploy . --project-name bloch-ops --branch main`. This retains
   compilation of its existing Pages Function. Publication is a separate
   authorized action; no deployment command is run by the candidate scripts.
6. Fetch the exact new tarball and checksum from the public URL, compare them
   with the reviewed candidate bytes, and run the installed-package verifier on
   that downloaded artifact. A web link or displayed version is insufficient.
7. Obtain the integrator's actual installed version/hash and adapter contract.
   If P2B uses another SDK or its own adapter, apply the equivalent validation
   there. Run the coordinated deposit/withdrawal/reconciliation qualification
   against that actual integration before any approval claim.

## Remaining integration requirements

These fixes address native outpoint validity, transaction identity integrity,
stable reconciliation metadata and bounded transmission. The SDK keeps no
durable outbox, credit ledger, nonce reservation or withdrawal authorization
store. It sends one broadcast request per explicit call, with no automatic
retry. The caller must persist the exact envelope durably and decide whether a
retry is appropriate after ambiguous transport failures.

Structural decoding does not verify hybrid signatures, witness-table ordering,
UTXO ownership, fees, consensus activation, inclusion or finality. HTTP receipt
fields remain source observations, not authenticated consensus evidence.
Gateway agreement, live inclusion/finality, durable duplicate-credit prevention,
custody controls, end-to-end qualification and operational stability remain
separate requirements. No evidence reviewed here establishes that P2B uses this
SDK, installed this candidate or approved the native L1 integration.
