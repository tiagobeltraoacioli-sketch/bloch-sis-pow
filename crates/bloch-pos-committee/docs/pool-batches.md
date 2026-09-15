# Atomic BLCH/native pool batches

`native_dex::pool_batch` adds bounded, ordered multi-operation execution to the
default-off `native-dex-rehearsal` feature. It accepts existing
[`pool_wire`](pool-lifecycle-wire.md) frames and a trusted parent state root and
height. This is a local candidate-execution API, not a live block format or an
RPC endpoint.

## Simulation and application

`simulate` validates every operation and returns receipts, aggregate charges,
the parent/post-state roots and a candidate commitment. The caller's State is
unchanged. The result contains no executable component or state-installation
capability. A preview does not reserve funding or guarantee later acceptance.

`apply` checks the expected parent against the current complete state, repeats
full verification and executes against a private clone. It installs the clone
only after every operation and the final fee accounting check succeed. A failed
later operation discards earlier UTXO spends, both reserve legs, LP changes,
locks and fees. Operations execute in supplied order, so later requests can
consume outputs and updated pool revisions created by earlier requests.

Both entry points require the same host-supplied signature verifiers. A producer
preview with a permissive verifier must never authorize acceptance by another
host: application independently revalidates using its production verifiers.

## Resource and fee accounting

The fixed rehearsal limits are 128 operations, 262,144 payload bytes and
60,000,000 gas. Empty batches are rejected; this API does not represent empty
chain blocks. The complete actual payload size is checked before decoding.
Each bounded frame is then decoded and quoted, and both aggregate declared bytes
and gas are capped before state cloning or signature verification. Declared
bytes include existing signature-size slack; checking only actual frame lengths
would miss that charged capacity. Unknown formats or malformed later frames
reject the entire candidate during this preflight.

Every quote uses the same parent-derived price. Quotes only price the signed
request; they do not require future funding outputs to exist yet. Ordered
execution verifies those outputs when each operation is reached. Each actual
receipt charge must match its preflight charge, and the final escrow delta must
equal the sum of all base and priority fees, using checked arithmetic.

The candidate commitment hashes `BLOCH-POOL-BATCH-v1`, network domain, parent
root, little-endian height and operation count, then each little-endian frame
length and its exact bytes, including witnesses, in execution order. It is a
rehearsal identifier, not a consensus block ID, signature or finality proof.

[`pool_candidate`](pool-candidates.md) adds bounded candidate exchange and
independent comparison of the advertised post-state root before installation.
The receiver always reexecutes with its own verifiers.

## Validation and remaining node work

Tests cover dependent swaps, nonmutating simulation, stale-parent rejection,
expired requests, duplicate spends, reordered requests, later signature failure,
pre-cryptography resource rejection and deterministic reexecution after restoring
the complete parent snapshot. Real hybrid PQ tests execute two deposits followed
by a provider redemption and verify that a forged third operation rolls back
the entire batch.

These operations still accumulate fees in the existing rehearsal escrow. This
API does not advance block height, update the next-block fee record, distribute
producer rewards, burn fees, verify a block header or persist a canonical chain.
Production integration must share budgets with all other block transaction
classes and derive activation-era limits from authenticated chain context. It
must also wire mempool admission, body commitments, reorg persistence and trusted
parent/height selection. No snapshot version, historical root, activation gate
or live default node dependency changes here. External USDT backing and bridge
finality remain separate requirements.
