# Native pair wire format v1

`ustav::pairs::wire` provides a bounded binary codec and atomic dispatcher for
native registered-asset pair settlement. It is an integration building block;
it does not expose an RPC endpoint or activate Genesis-4 consensus rules.

`encode_pair(domain, swap, witnesses)` and `decode_pair(bytes)` transport both
complete legs and their owner, module and KYC witnesses. `apply_encoded_pair`
checks the envelope domain against `Ledger::domain`, then calls `settle_pair`
with one shared gas budget. There is no operation for separately executing a
leg from this envelope. All owners and applicable module authorities sign the
existing joint pair digest, not the transport bytes or individual leg digests.
Changing the domain or either transfer invalidates authorization.

## Canonical layout

All integers use fixed-width little-endian encoding. Counts and byte-string
lengths are unsigned 32-bit integers; a byte string is its length then bytes.
There are no variable integers, optional padding, JSON or serializer defaults.

The header is eight ASCII bytes `USTVPAIR`, a `u16` version equal to 1, one
operation byte equal to 1, and the 32-byte network domain. Exactly two records
follow in ascending asset-ID order. Each record contains:

1. Asset ID (32 bytes).
2. Input count and input records: transaction digest (32 bytes), index (`u32`).
3. Output count and output records: owner byte string, amount (`u64`).
4. Delta (`i128`), mint nonce (`u64`), policy revision (`u64`), valid-until (`u64`).
5. Owner-signature count and signature byte strings, in input order.
6. Module count; for each module, redeemer count and redeemer byte strings.
7. Eligibility-proof count; each proof is key (32 bytes), value (8 bytes), and
   exactly 256 sibling hashes of 32 bytes each, in native proof depth order.

Delta and mint nonce must be zero. Inputs and outputs must be nonempty. Inputs
and eligibility keys must be strictly increasing. Unknown versions/operations,
trailing bytes, duplicate assets and the base BLCH zero asset ID are rejected.

Native Ustav admits only `Val::Bytes` module redeemers and membership KYC proofs
with eight-byte expiration values. This format represents all those witness
shapes, including empty signature slots. Integer redeemers and non-membership
proofs are rejected, matching the native witness admission rules. Actual module
arity, public-key admission, proof validity and current policy remain ledger
validation responsibilities; successful decoding is not settlement approval.

## Bounds and atomicity

The envelope limit is 5 MiB, checked before decoding allocates anything. Each
leg allows at most 128 inputs, 128 outputs, 128 owner signatures, 64 modules,
253 redeemers per module and 256 eligibility proofs. Keys and signatures are
at most 8192 bytes. Native aggregate witness and key limits are checked again.
Each byte string must be entirely present before allocation, and each fixed
proof must be entirely present before any proof allocation. Counts are checked
before iterating. Encoding first validates the same native shapes and bounds.

The dispatcher reserves `100 + ceil(envelope_bytes / 32)` reference gas units
before decoding; settlement receives the remaining budget. The receipt reports
both costs. Gas exhaustion, malformed bytes, wrong domain, invalid signatures
or failed policies leave the ledger unchanged. These reference costs are not
live-chain fee parameters.

## Remaining integration work

A live service must use the production PQ verifier and authenticated height,
provide bounded HTTP/RPC ingress before buffering, maintain persistent ledger
state, and authenticate asset registration and issuance through their own
operations. A node integration additionally needs transaction/block commitment
rules, global block gas limits, mempool/miner validation, deterministic state
persistence and rollback, historical replay tests and coordinated activation.
No activation height or consensus flag is supplied by this codec.

Pairs exchange two registered Ustav assets, potentially including a native
stablecoin. Base BLCH accounting is not integrated. Matching, quotes, liquidity
pool custody, LP issuance, reserve continuation, AMM pricing and authenticated
batch orders are separate work. Stablecoin issuance still requires its chosen
reserve, redemption, oracle and governance design; a transport codec creates
neither collateral nor a price peg.

Validation: `cargo test -p bloch-euvm --test native_pairs_wire` covers canonical
roundtrip, full module/KYC witness transport, every truncated prefix, malformed
headers and lengths, size and trailing-byte rejection, actual dispatch and
atomic failures for signatures, domain and gas.
