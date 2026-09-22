# WS arrangement trust and versioning — 2026-09-17

## Implemented operator pin (SR-02 mitigation)

`bloch-pos run --ws-checkpoint checkpoint.bin --ws-signer-set arrangement.bin --ws-signer-set-sha3 HEX` checks SHA3-256 of the **entire raw arrangement file**, including its `BPOSWSS1` magic, set ID, quorum thresholds, adoption epoch, signer count, external flags, and public keys. The hash is the existing fingerprint printed by the ceremony tooling. There is no additional hash-domain prefix and no JSON canonicalization. A byte change fails the configured pin before the arrangement can authorize an incoming checkpoint.

Obtain the expected fingerprint independently from a trusted publication or operator channel. Reading a hash alongside a file downloaded from the same untrusted source does not establish trust. No authoritative production fingerprint has been asserted or installed by this remediation. Wave 50 makes the pin mandatory whenever an external checkpoint and arrangement are supplied; unpinned onboarding is refused instead of warned. Historical checkpoint signatures and cached trusted anchors are unchanged. A pin without both an incoming checkpoint and an arrangement is also refused: it cannot retroactively authenticate an isolated cached checkpoint.

This mitigates arrangement substitution only when the expected fingerprint is trusted. **SR-02 remains partial:** the historical checkpoint digest itself still binds the numeric arrangement ID, not its contents.

## Unimplemented version-2 design; no activation or new accepted format

A future signed checkpoint version must explicitly commit an arrangement digest under a new signing domain. The intended preimage includes the checkpoint version, network/genesis identity, epoch, block/state/validator roots, issuance time, numeric arrangement ID, and a 32-byte digest of a strictly canonical arrangement encoding. Its canonical arrangement encoding must include the version, ordered unique signer keys, external flags restricted to 0/1, quorum thresholds, and review/adoption clock. Encoding counts and key lengths remain bounded. Distinct domain tags must separate checkpoint signing from arrangement hashing and all existing signature domains.

Digest binding is not itself an initial trust anchor: an attacker can sign a self-consistent checkpoint with an attacker-created arrangement. Version 2 must still authenticate its arrangement against an independently pinned release/ceremony root, or a specified transition authorized by the previously trusted arrangement. Key rotation, review-clock changes, and revocation need explicit authorization rules; numeric ID reuse cannot silently select a different policy.

Before implementation/activation:

1. Specify the exact encoding, domain constants, cryptographic validation, trust-source rules, and known-answer vectors in the protocol documents.
2. Define dual-version node and ceremony behavior without reinterpreting any historical signature. Existing version-1 bytes remain version 1.
3. Publish version-2 checkpoints at a strictly later epoch. Reissuing an existing epoch in a different format changes its digest and must not bypass the current equivocation refusal.
4. Specify persisted version/trust metadata and downgrade refusal. A stored version-2 anchor must not silently revert to a version-1 policy; old binaries must fail closed on unknown persistence rather than discard protection.
5. Exercise independent signer verification, malformed encodings, altered keys/quorum/clocks, rotation authorization, cache restart, and cross-version recovery before external validators are asked to upgrade.

No version-2 codec, alternate digest, activation epoch, production ceremony, or trusted arrangement was added in this segment.
