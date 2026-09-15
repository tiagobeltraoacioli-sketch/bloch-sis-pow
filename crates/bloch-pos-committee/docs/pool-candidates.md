# Independently verified pool candidates

The default-off rehearsal exposes `native_dex::pool_candidate::{build, apply}`
to exchange ordered pool batches with an advertised final state. It does not
register a live block variant or RPC, authenticate a proposer, establish finality
or enable native operations on the current node.

`build` fully simulates the supplied frames using the host's signature verifiers,
then encodes the resulting parent, candidate commitment and final state root.
It does not mutate the producer's state. `apply` obtains the network domain and
parent from its own State and the expected height from its host. It checks the
encoded context, reexecutes every operation with its own verifiers, and compares
both the commitment and advertised final state **before** installing any change.
A producer preview, including one using permissive signature checks, supplies
no authority to the receiver.

## Canonical framing

All integers are unsigned little-endian. The header is 148 bytes:

| Field | Bytes |
| --- | --- |
| Magic `BLCHPCAN` | 8 |
| Version, exactly 1 | 2 |
| Network domain | 32 |
| Parent combined state root | 32 |
| Host height | 8 |
| Advertised post-state root | 32 |
| Existing `BLOCH-POOL-BATCH-v1` commitment | 32 |
| Operation count | 2 |

Each operation follows as an eight-byte length and an existing `pool_wire`
frame. There is no padding, optional field or trailing data. Count is 1–128;
the total frame payload is at most 262,144 bytes. The absolute input bound is
263,316 bytes, including the maximum framing overhead. A network adapter must
enforce this bound while receiving data, before buffering an unbounded body.

The decoder retains at most 128 borrowed slices and checks lengths, total
payload, exact end of input, domain, height and the ordered frame commitment
before cryptography. The batch layer additionally validates each operation and
caps aggregate declared bytes and gas before staging. Framing overhead is bounded
separately here; it is not added to existing signed transaction fee declarations.
A future live block format must account for its own complete network overhead.

The existing candidate commitment binds the domain, parent, height, count and
length-delimited ordered frames including signatures. The advertised final root
is independently checked against full execution. No caller-supplied fee totals,
receipts or executable snapshots are accepted from the candidate.

## Validation and integration boundary

Tests reject every truncated prefix, unknown versions, wrong domain/height,
oversized lengths/counts, trailing bytes, altered bodies and false commitments.
They verify rollback after an incorrect final-state claim, independent rejection
of a permissive producer's bad signature, replay rejection and deterministic
execution after restoring the complete parent. Real hybrid PQ tests exercise a
candidate containing two dependent deposits followed by a provider redemption,
including rejection of a forged final root without changing reserves or fees.

The optional [durable host journal](../../bloch-ustav/docs/dex-journal.md) now
persists and replays these candidates against independently trusted checkpoints.
It does not select or activate the canonical chain.

The receiver still needs authenticated chain context and production verifiers.
This API does not select the canonical parent, advance height, implement a
mempool, persist/reorganize blocks, change historical roots or settle block fees.
It remains separate from proposer authentication, consensus activation, wallet
signing and verified external USDT backing. An accepted rehearsal candidate is
not authorization for an external bridge payout.
