# Opt-in joint BLCH/native envelope decoder

The `native-dex-rehearsal` feature exposes
`transition::native_dex::wire::decode` and `apply_encoded`. This transport invokes
only the existing sealed rehearsal transition. It is not a Genesis-4 block
operation, network message registration or mainnet activation.

The exact format matches `Request::canonical_bytes`. All integers are unsigned
little-endian:

1. ASCII `BLCHNATV` (8 bytes), version u16=1, domain bytes32.
2. Inclusive valid-until height u64 and prepaid native gas u64.
3. Base section length u64, then canonical `PosTransaction::TransferV2` bytes.
4. Native section length u64, then the canonical `USTVTRAN` envelope.

The decoder validates the total against the existing maximum joint envelope
size before allocation. Each section length is checked against its respective
maximum and the available bytes before invoking its bounded decoder. The base
section must decode to TransferV2; other transaction operations are not admitted.
An allocation-free preflight checks the base section before the generic
transaction decoder runs: at most 128 public keys, inputs and outputs, public
keys of 1–8192 bytes, and signatures of at most 8192 bytes. It also checks the
fixed-width records, fee fields and exact end of the base section. A small
envelope containing a maliciously large inner count cannot trigger an oversized
allocation in the generic decoder.
Both base and complete envelope must reencode byte-for-byte. Unknown versions,
invalid headers, wrong domains, oversized lengths, truncation and trailing data
are rejected. Outer and native domains must match the host's authenticated
network domain.

`apply_encoded` obtains the domain from the sealed state and dispatches through
`State::execute`. Existing full-envelope fee accounting and prepaid native work
remain authoritative; this wrapper adds no second parsing fee. Signatures still
bind the joint authorization digest, not a single constituent transaction.
Atomic base/native planning, locked inputs, owner validation and fee escrow are
unchanged. Height comes from the authenticated host.

Unit tests compare direct and encoded execution, including identical gas/fees,
state roots and receipts. Every strict byte prefix is rejected, alongside bad
header/version/domain, section-length overflow, invalid transaction tags and
trailing bytes. Expiry, forged authorization and replay leave the combined state
unchanged. Tests use a deterministic key-bound verifier; separate `bloch-ustav`
integration tests exercise actual ML-DSA-65 AND Falcon-1024 signatures.
