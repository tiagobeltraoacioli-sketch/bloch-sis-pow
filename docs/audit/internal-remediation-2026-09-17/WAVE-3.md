# Internal audit remediation, third wave — 2026-09-17

Base: `439a1ca`, branch `fix/internal-audit-20260917`. The integrated node suite
and hardened lint gate have passed. This is not release approval. No binary,
validator, funded wallet or activation epoch has been changed in production.
All new project documentation is in English.

## Keys and restart policy

The ceremony sends its unexported passphrase through a fresh inherited pipe
for each child. Only a descriptor number enters the child's environment.
The node bounds this input by bytes and time, requires a pipe, consumes/closes
the descriptor and uses zeroizing buffers. Existing file/environment interfaces
remain compatible; callers using those old interfaces still bear their risks.
Ceremony tests use disposable mock artifacts and a PTY, not production keys.

Malformed checkpoint/configuration artifacts now use the same typed
operator-action refusal as policy failures, allowing the supplied systemd
configuration to suppress automatic restart. Raw filesystem I/O errors retain
ordinary error handling. These changes require the matching binary/unit pair.
Node terminal restoration after external termination remains a partial finding.

## Node identity and sync

The boot identity check used by production is now the same implementation
covered by its tests. Genesis membership uses actual indices, so sparse
manifest indices cannot enter the unknown-deposited-key path.

Engine gap requests use a bounded rotating peer selection instead of sending
to every connected devnet peer. The separate periodic request mechanism still
has its own budget; this is not a complete shared fair scheduler. libp2p keeps
one request slot for rotation independent of unvalidated claimed height, so a
fixed set of high claims cannot monopolize every request. Sybil resistance,
claim validation and sticky devnet sync leases remain unresolved. See
[node follow-up](NODE-SYNC-FOLLOWUP.md).

## Wallet and vault

Wallet transaction construction refuses another network's recipient before
creating outputs. The historical checksum/encoding is unchanged. Disclosure
creation gains an explicit derivation-family choice, including HD v3 index
zero, without changing previously funded keys or the disclosure wire format.

Checked spend arithmetic, exhausted address indices, bounded recovery work and
malformed AES key errors prevent additional panic/overflow paths. Vault PQ
secret vectors and intermediate seeds use explicit clearing ownership; this
does not prove erasure of classical key copies or third-party internals.
Fallible restoration requires an explicit stored V1/V2/V3 vault version.
See [wallet compatibility and limits](../../../crates/bloch-crypto/WALLET-AUDIT-2026-09-17.md).

## Pool and deployment checks

New authenticated pool sessions canonicalize parsed addresses before recording
shares. Equivalent hex casing no longer creates separate new balances.
Historical journals remain unchanged and require reconciliation before manual
payouts. This is the retired Genesis-3 reference pool, not live PoS accounting.

Image-pin checks inspect the actual scalar, not comments, and require an exact
digest. Broad TODO/user/local-build comment exemptions are removed. Templates
use a deliberately non-pullable sentinel; replacing it requires a real digest.
The one reviewed local compose fixture requires a same-service build and
`pull_policy: never`, and its host RPC ports bind to loopback. The guard is a
structural subset, not a general YAML interpreter or registry-signature verifier.

The PoS Nix module requires a package and transport explicitly, adds mesh-port
wiring and refuses conflicting dual-mode ports. It no longer selects a legacy
binary or an incompatible transport by default. Nix evaluation and Linux
deployment qualification remain pending; see [module notes](../../../os/BLOCH-POS-MODULE-AUDIT-2026-09-17.md).

## State commitment coverage

Three ADR-041 regressions pin the existing leaf encodings and zero/absence
semantics, mutate every key/value including high bytes, and check iteration
order independence. The tag registry now documents existing tags through
`0x1E`, and the state-root module accurately describes its bounded thread-local
memo. These are coverage/documentation corrections; production hashing,
serialization and activation behavior are unchanged.

## Qualification

The integrated node run passed 413 unit tests and all integration suites,
including cold-start synchronization, recovery and credential CLI tests.
Nineteen unit tests and six performance rehearsals remain ignored. Subsequent
buffer preallocation was checked by the targeted pipe regression; all four
mock ceremony PTY tests passed, including inherited allexport and signal cleanup.

Wallet qualification passed 172 crypto unit tests plus one integration test,
seven BTC wallet tests, 28 vault tests and 15 shield API tests. Existing
ignored crypto tests remain ignored. Pool authorization/framing tests passed
five cases, including authenticated aliases sharing one accounting identity.

All five hardened Clippy targets passed without increased baselines. Test-guard
selftests passed 37 cases; the image guard passed seven groups, including 15
scalar/exemption bypass scenarios, and the checked-in deploy files. Changed
deploy YAML parsed successfully using Ruby. Nix evaluation remains unavailable.
Log digests are recorded in `VALIDATION-WAVE-3.txt`.

All three new ADR-041 tests and the existing tag-uniqueness test passed.
The ledger now records 47 implemented, 51 partial and 89 open rows, alongside
seven base-changed findings, four protocol decisions, one unarmed candidate and
one finding refuted by the original audit. Rows include duplicates; a completed
test/documentation finding is not equivalent to eliminating a live vulnerability.

No claim of overall audit closure or production recovery SLA follows from
these local checks. Consensus recovery remains unarmed, and the remaining
protocol, operational and product blockers in the ledger still apply.
