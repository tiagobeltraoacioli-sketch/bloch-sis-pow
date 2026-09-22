# NET-20: producer wire budget (partial)

Date: 2026-09-17. Node-local proposal selection only. Incoming block acceptance,
protocol activation epochs, existing wire codecs, and signature domains remain
unchanged.

## The mismatch

Consensus permits up to 4,096 attestations in a block. Current hybrid signatures
make a full such body much larger than libp2p's 4-MiB gossip frame allowance.
The old producer bounded only attestation count and transaction bytes, so it
could sign and adopt a block its own transport could not publish.

The producer now reserves a payload allowance of 4 MiB minus 1 KiB for
libp2p framing. It encodes a base envelope with the selected transaction bodies
and a placeholder sized to `bloch_crypto::crypto::max_signature_len()`. That
helper derives the current suite upper bound from the ML-DSA constant and the
Falcon library's maximum; actual hybrid and ML-DSA-only signing tests pin the
bound. This avoids estimating the signature length from one random signature.

Each already-sorted attestation is measured with `codec::encode_attestation`.
The producer keeps the deterministic prefix that fits, then recomputes its
attestation commitment before probing the post-state. The input pool remains
unchanged by this packing step. An oversized base body is refused before the
proposal slashing watermark or signing closure is touched. Ordinary transaction
selection already fits the smaller consensus transaction-byte allowance.

The policy also applies when producing on devnet or dual transport: a local
block should remain carryable by peers using the smaller supported transport.
It does not add a receiver validity check and does not retroactively reject a
larger block.

## Qualification and limits

Two codec tests exercise the exact byte boundary, one byte above it, deterministic
prefix retention, and full-count candidate lists sized with real current hybrid
signatures. The synthetic validator indices and the synthetic boundary-sized
signature test packing and codec behavior; they are not a claimed valid
4,096-validator consensus rehearsal. A separate actual two-node libp2p exchange
test sends an encoded envelope exactly at the producer budget, validating the
framing reserve against the live transport implementation.

This is a partial remediation. Existing or externally produced consensus-valid
blocks above transport limits still need a separately designed and qualified
sync/gossip compatibility path. Devnet's 8-MiB frame bound and libp2p's 8-MiB sync
page bound are not raised here. Nor does this change prove that the maximum
consensus block is inexpensive to verify. No claim is made that older binaries
adopt the new producer selection policy automatically.

Targeted results: codec packing 2 passed
(`/private/tmp/bloch-wave7-proposal-wire.log`); actual libp2p boundary exchange
1 passed (`/private/tmp/bloch-wave7-gossip-boundary.log`); the full seven-test
proposal/revalidation/reporting module also passed after this production change
(`/private/tmp/bloch-wave7-tx-reporting-final.log`).
