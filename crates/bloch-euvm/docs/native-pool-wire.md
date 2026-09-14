# Native pool action envelope v1

`ustav::gateway::pools::wire` transports Add, SwapExactInput and Remove through
sealed `PoolLedger::execute`. It does not activate node consensus, create pools,
change authorization rules, submit RPC transactions or supply base BLCH custody.
Pool creation and registration remain explicit authenticated setup operations.

Every integer is unsigned little-endian. Header: ASCII `USTVPOOL` (8 bytes),
version u16=1, opcode u8 (1 Add, 2 SwapExactInput, 3 Remove), domain bytes32. Then
pool ID bytes32, expected revision u64 and inclusive valid-until height u64.
Action-specific payload follows:

| Opcode | Payload |
| --- | --- |
| 1 | maximum0 u64, maximum1 u64, minimumLP u64 |
| 2 | inputIndex u8 (0 or 1), amount u64, minimumOut u64 |
| 3 | LPburn u64, minimum0 u64, minimum1 u64 |

Then encode owner public-key envelope as length u32 + bytes, followed by two
funding lists in canonical sorted-asset order. Each list has count u32 and
outpoints consisting of transaction bytes32 + index u32. Entries must be strictly
ascending and unique within each list; cross-list conflicts and actual ownership
are checked by the sealed ledger. Finish with one owner signature length u32 +
bytes. No trailing bytes are accepted.

The outer domain must match the sealed ledger. The signature is over
`PoolLedger::signing_hash(action)`, binding the pool's authenticated state,
revision, complete action, owner and actual funding outpoint identities. It is
not a signature over arbitrary caller-provided balances or opaque transport
bytes. The configured verifier must validate the full native PQ suite. Parsing
only bounds key/signature encodings; it does not claim cryptographic validity.

The decoder rejects envelopes above 32 KiB before allocation. Keys/signatures
are at most 8,192 bytes each; each funding list is at most 128 outpoints. The
largest valid envelope under these limits is 25,731 bytes. Counts are checked
before loops and complete outpoint byte slices are checked before allocating
entries. Empty keys/signatures, invalid headers/versions/opcodes, noncanonical
lists, truncation and trailing data fail closed.

`apply_encoded` charges `100 + ceil(encodedBytes/32)` gas before decoding, passes
the remaining budget to sealed execution, and includes parsing in the receipt's
reported gas. The host supplies authenticated height and gas. Domain, malformed
input, insufficient gas, invalid signatures and locked reserve spends cannot
mutate state. Persist the complete pool/gateway state and independently trusted
root atomically; never dispatch through an extracted inner ledger.

Tests cover all action roundtrips, every byte-prefix truncation, malformed counts,
header and order, exact direct/encoded state parity, parsing gas, signature/domain
failure, replay and rejection of locked reserve funding. The test verifier is a
deterministic key-bound test double; actual ML-DSA/Falcon custody tests live in
`bloch-ustav/tests/native_pool_crypto.rs`.
