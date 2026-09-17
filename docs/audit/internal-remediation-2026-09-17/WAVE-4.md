# Internal audit remediation, fourth wave — 2026-09-17

Base: `253e26b`, branch `fix/internal-audit-20260917`. Four roles (primary plus
three retained agents) implemented and cross-reviewed this wave. This is local
remediation, not release approval. No binary, validator, website, signing key,
production data directory or activation epoch was changed in production.

## Synchronization

Engine gap requests and the periodic devnet pump now share two finite request
leases. FIFO rotation expires silent holders independently of head progress,
while receive-queue backpressure pauses issuance. A queued request consumes one
matching, unexpired connection authorization, preventing stale writer queues
from bypassing the lease policy after reconnect. Honest slow sockets are not
closed merely because their request lease expires.

Outbound readers now serve reverse-direction get-blocks requests under the
existing rate limits. Page serving runs outside the reader so simultaneous
bidirectional pages cannot deadlock both TCP receive buffers. Serving work has
per-connection and shared bounds, retained until completion across reconnects.
A response write failure closes the socket rather than continuing after a
potential partial frame.

The wire has no response request ID or completion marker. Two request leases
are not a guarantee of only two outstanding response streams. Existing aggregate
receive-byte bounds remain necessary. libp2p identity/claim/Sybil limitations and
protocol-level response accounting are still open. See [sync limits](NODE-SYNC-FOLLOWUP.md).

## Checkpoints and log inspection

Stored and supplied checkpoint state roots are compared with available locally
validated canonical block evidence before adoption. Reserved genesis anchors
and signed genesis-boundary checkpoints retain their distinct historical root
conventions. Missing local evidence warns; it does not become a successful
validation. Validator-set roots and a complete post-sync checking lifecycle
remain incomplete.

Reminting at the same artifact prefix reuses the original timestamp/digest only
when all rederived fields agree. Changed fields and overwrites are refused.
A cross-prefix publication registry and signer coordination are still required.

`block-log-inspect --data-dir ...` provides bounded, read-only framing/decode
diagnostics without opening the mutable store or creating recovery artifacts.
It does not add frame checksums, repair corruption or establish consensus-state
validity. See [checkpoint and log operations](CHECKPOINT-AND-LOG-OPERATIONS.md).

## Cryptographic APIs and provenance

Production seeded key generation uses a scoped RNG API, clears its seed buffer
and handles TLS destruction safely. Historical deterministic streams are
preserved. Forgotten standalone legacy guards and erasure of opaque ChaCha
internal state remain limitations. Fork documentation now describes actual
build/dependency differences; this does not authenticate upstream provenance.

A checked legacy PoW difficulty API rejects regressed heights, overflow and
malformed/zero targets. Existing consensus callers retain historical arithmetic;
this is a migration API, not a silently activated consensus change.

## Scanner installation and public RPC

Scanner installation requires committed platform/version SHA256 pins before
extracting or installing artifacts. It replaces cached binaries atomically and
CI invokes the verified absolute path. The previous Go fallback and PATH trust
are removed. Offline malicious-cache, corrupt-download, pin and symlink
regressions are wired into both existing CI guard jobs. Pins were obtained from
upstream HTTPS release manifests, not independently authenticated signatures.
Both macOS x64 release assets were downloaded and verified locally; Linux/ARM
asset execution is not claimed.

Explorer and pool-site Functions share a bounded read-only transport. It requires
configured HTTPS, rejects known public wildcard DNS (including trailing-dot
forms), refuses redirects, checks RPC envelopes and IDs, limits byte consumption
and applies deadlines. Numeric request tokens are checked before parsing to
avoid rounding; response JSON is returned without numeric reserialization.

The plaintext wildcard fallback is removed. Both projects need a qualified
`BLOCH_RPC_URL`, TLS/DNS and origin access policy before deployment. This source
change deliberately returns 503 for missing/insecure configuration; no live
configuration was modified. CORS remains public, not authentication. Direct
archival-node exposure and rate-limit operations remain open. See
[RPC deployment requirements](../../../apps/explorer/RPC-SECURITY.md).

## Validation and remaining scope

The integrated node run passed 424 unit tests and every integration suite;
19 unit tests and six performance rehearsals remain ignored. A separate final
frozen-source run passed all 23 transport tests. All five hardened Clippy ratchets
passed without increased baselines. Crypto passed 172 unit tests plus one
integration test; RNG passed 17 unit, two vendor-integrity and three documentation
tests. Relevant legacy difficulty checks passed 12 unit and three property tests.
The proxy passed 12 mocked regressions, and both Pages Functions bundles compiled.
Scanner validation passed six installer regressions, nine guard selftests and
the live posture guard. Both real macOS scanner artifacts matched their pins.

The ledger now has 50 implemented, 57 partial and 80 open rows, plus seven
base-changed findings, four protocol decisions, one unarmed candidate and one
finding refuted by the original audit.

Exact final test scopes and log hashes are recorded in `VALIDATION-WAVE-4.txt`.
Mock transport tests and local Functions builds do not qualify hosted Pages
configuration. Rust checks do not establish production restart SLA or validator
version inventory. Full legacy PoW brute-force mining tests were interrupted;
only the relevant difficulty/property suites and no-default-features check are
claimed for that crate.

The finding ledger includes documentation and duplicate rows. Partial mitigations
are not audit closure. Consensus recovery remains unarmed. Protocol decisions,
external signer operations, complete wallet/product migration, deployment
qualification and consolidation with EVM/DEX/bridge/aggregator work remain open.
