# Internal audit remediation, fifth wave — 2026-09-17

Base: `fb65a38`, branch `fix/internal-audit-20260917`. Four retained roles
(primary plus three specialists) implemented and cross-reviewed this wave.
No deployment, validator restart, production key operation, consensus activation
or funded-address migration is included.

## Proposal selection

Transfer admission is no longer treated as a permanent reservation of inputs
or fees. Proposal selection rechecks committed inputs, ownership, conservation
and the proposal epoch's base fee before packing. Selected inputs are reserved
so conflicting high-tip candidates cannot crowd out independent spends. Funded
deposit eligibility uses one lazily constructed proposal state and active total,
not a full state projection for every candidate. Existing transition probing
remains authoritative; no signature or consensus encoding changes.

Fee/reorg-dependent refusals remain retryable without permanent rejection bars.
This fixes proposal selection, not the entire EN-06 finding: retained stale
entries can still rank highly in capacity eviction. EN-10 also remains open;
a wall-clock lag or untrusted peer-height veto cannot safely distinguish catch-up
from an actual chain halt. No new signing veto or activation epoch was introduced.

See [proposal selection and readiness limits](PROPOSAL-REVALIDATION.md).

## Operator inputs, keys and publication

New `genesis` and `genesis-mainnet` creation rejects duplicate validator indices,
public keys and cohort entries, plus cohort members absent from the validator
set, before writing output. Historical manifest decoding and state construction
are unchanged. TX-22 remains partial for arbitrary programmatic constructors.

Argon2 headers are checked against a default combined memory/pass budget of
1 GiB-pass before allocation. Production parameters are unchanged. A verified
historical file with higher cost can use the explicit
`BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF=1` recovery opt-in, still bounded by the
original memory/pass/lane maxima. This does not authorize expensive new seals.
The default can still allocate 1 GiB at one pass; this is not a universal memory
or wall-clock guarantee. See [keystore operations](../../../deploy/KEYSTORE-AT-REST.md).

An optional shared `--publication-dir` coordinates checkpoint output prefixes
for each network/genesis/epoch. Complete records are fsynced and atomically
installed without replacement; concurrent callers adopt the same issuance time
or refuse conflicting signed fields. The operator-owned private registry needs
durable backups. Omitted options, older tools and independent registries remain
outside its coordination. See [checkpoint operations](CHECKPOINT-AND-LOG-OPERATIONS.md).

## Wallet and API

A fallible wallet import API refuses exhausted indices before mutation, and the
legacy CLI handles that error before saving. Pre-KDF structural checks reject
duplicate indices, unsupported metadata and contradictory derived-address
networks, while preserving historical imported cross-network keys. Historical
V1/V2/V3 derivations and KDF parameters are unchanged. The legacy import method
now returns a Result as well: Rust callers must handle failure rather than rely
on a void method. Broader hostile-file and derived-key authenticity checks remain
open. The hardened gate caught and rejected an intermediate panic wrapper;
no baseline was raised to accommodate it.

The shield API no longer includes arbitrary malformed-field input in parse
errors. Verification responses remove two unnecessary echoed fields:
`verified_against_pq_pubkey` and `commitment_bytes_hex`. Clients using those
response fields need to retain their request artifacts instead. The construction
endpoint still returns the public commitment required for local signing.
This is response minimization, not reliable detection of secrets inside arbitrary
text. CR-07 and BV-20 remain partial.

## Reference indexer

A sync pass stages at most 16 blocks before balance mutation, verifies linkage
and height mappings, and rechecks the fork anchor and batch tip. Concurrent
callers share the pass. Observed RPC shifts and failed replacement fetches leave
the previous published state unchanged. Transaction arrays, identifiers and
indices are validated rather than defaulted/coerced; malformed RPC envelopes
and null hashes cannot masquerade as missing heights. Missing block data is an
error, not proof of completion.

Publication contains no awaits. A store-validation error may persist a shorter
valid prefix; whole-batch rollback is not claimed. Fork search stops after 2,048
comparisons, but there is no total pass deadline: slow RPC calls can still occupy
a pass for hours. Whole-state persistence and pruning remain unresolved.

Crossreview confirmed a deeper upstream limitation: legacy `put_block` writes
`CF_HEIGHT` for every stored block, while fork choice walks `selected_parent`
separately. Stable linked height responses therefore do not prove canonical
selected-chain membership. The reference indexer is not a qualified live balance
authority. An upstream canonical-chain API contract and live qualification remain
required. Existing misindexed data was not rewritten. See
[indexer limitations](../../../tools/indexer/README.md).

## Validation and audit status

The integrated node run passed 430 unit tests and all integration suites.
Nineteen existing unit tests and six performance rehearsals remain ignored.
Targeted proposal and transfer compatibility runs passed five and 21 tests.
The final wallet run passed 173 unit tests plus one integration; the legacy CLI
compiled after migration to the Result-returning API. Shield API tests passed
17 cases. Indexer selftests and all 36 node:test cases passed. Operator checks
passed 33 key tests, 17 WS tooling tests, one genesis unit test and nine CLI tests.

All five hardened Clippy gates passed after the panic wrapper was removed. The
crypto arithmetic baseline was lowered from 77 to 74; no baseline increased.

Exact command scopes and log hashes are recorded in `VALIDATION-WAVE-5.txt`.
Existing ignored tests remain unqualified. Local macOS execution is not hosted
CI, Linux deployment, production recovery SLA or independent-validator inventory.

The ledger records 50 locally implemented, 58 partial and 79 open findings,
plus seven base-changed rows, four protocol decisions, one unarmed candidate and
one finding refuted by the original audit. Rows include duplicates and
informational findings. This wave extends several partial mitigations; it does
not claim audit closure. External EVM, DEX, bridge and aggregator work still
requires separate release consolidation.
