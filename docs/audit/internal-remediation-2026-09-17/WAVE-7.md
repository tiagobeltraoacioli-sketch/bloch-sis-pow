# Internal audit remediation, seventh wave — 2026-09-17

Base: `776804e`, branch `fix/internal-audit-20260917`. This is an intermediate
checkpoint of the four-role session scheduled for 17:55–21:55 São Paulo time.
No binary publication, deployment, validator restart or activation is included.
Code, documentation and reports remain in English.

## Recovery, signing and finality

Native terminal passphrase entry now restores complete terminal settings before
pending terminating/job-control signals are delivered. It preserves existing
signal dispositions/masks and refuses interrupted partial entries. Eleven real
CLI PTY cases exercise the supported pre-thread startup path. SIGKILL/SIGSTOP and
multithreaded use remain outside its guarantee.

A crash after replacing a reorg log could leave a same-sized old slot index that
silently omitted valid blocks on restart. Startup now rebuilds this disposable
index; rewrites durably invalidate it before publishing the log. A per-directory
generation guard keeps local serving threads from combining different log/index
generations. If an index append fails, later appends cannot skip over the missing
entry: serving scans the unindexed tail until a rebuild restores indexing.

Cache/log publication uses unique private create-new staging instead of truncating
predictable `.tmp` paths. Symlink fixtures show unrelated targets are untouched.
Persistence refuses records larger than the reader's existing 8 MiB ceiling
before publishing them; exact-limit records reopen successfully. Startup index
rebuilding adds a linear header/index pass, not a second consensus replay. This
is not a production recovery-time measurement. See [recovery details](LOG-INDEX-CRASH-RECOVERY.md).

Transaction status uses the named canonical finalized checkpoint's slot, avoiding
premature finalization within an epoch. Failed reorg validation cannot publish
candidate transaction entries, and successful reorg cleanup keeps its FIFO index
consistent. Pruning removes descendants disconnected by the existing floor;
reachable above-floor branch growth remains open. Out-of-order finality processing
now emits bounded-frequency diagnostics and increments a saturating counter,
without changing consensus recovery policy or committed state.

## Network admission

Producer packing measures actual codec bytes and reserves the supported signer's
maximum before touching signing watermarks. It keeps a deterministic prefix of
attestations below the existing gossip ceiling. Exact-boundary and real transport
tests pass. Incoming/historical oversized blocks remain a compatibility question;
no consensus cap was silently changed.

Libp2p connect, periodic sync and page chasing share three outstanding request
slots, at most one per PeerId. Exact response/failure IDs and last-disconnect
cleanup release them. A bounded FIFO prevents a responsive page-chasing peer from
continually reacquiring the slot before an already waiting peer. Legacy devnet's
different wire limitations and Sybil/fairness limitations remain explicit.

The bounded exact failed-signature cache now also covers transfer, funded and
lifecycle admission. Corrected signature/key/root inputs are retried; contextual
state/epoch/registry refusals are never cached. Real hybrid tests include the
actual funded activation epoch 2884. Distinct junk still consumes verification
work; this does not replace rate limits or peer policy.

## Wallets and vaults

Current/legacy transaction builders reject duplicate outpoints, malformed txid or
destination lengths, aggregate overflow and unusable remote UTXO rows. Both CLIs
parse original decimal strings into exact satoshis: 2^53+1 and the u64 maximum
round-trip without floating-point rounding. More than eight fractional digits,
signs and exponent notation are explicitly refused; default fees are unchanged.
Optional and legacy paths check recipient network before discarding its envelope.

The optional wallet HTTP client caps actual streamed response reads at 64 MiB,
checks declared length early and preserves its existing request timeout. HTTP/RPC
errors expose status/numeric code rather than arbitrary peer body/message/data.
These input caps are not total memory or CPU guarantees.

Vault CSV maturity uses the input's actual nSequence, not merely the smaller script
operand. A real-signature regression with script delay 144 and input sequence 288
refuses execution before 288. Bitcoin Core differential qualification and the
separate funded vault/Coherence authorization blockers remain unresolved.

## Explorer and SP1

The Rust historical explorer respects snapshot cursors for TXID/block contents,
paginates ambiguous matches and legacy TXID lists, rejects malformed/overflowing
numeric queries, and refuses stale sync on both API families. Provenance no longer
claims a fixed host or consensus verification for structure-only indexes. Absolute
socket deadlines prevent a trickling client from renewing its worker indefinitely.
Subsecond log metadata detects same-size in-place mirror replacements. Diagnostic
RPC comparison bounds responses, validates envelopes and refuses mismatching or
moving chain anchors. See [compatibility and limits](HISTORICAL-INDEXER-QUERIES.md).

The SP1 candidate recipe pins base-image digests and the downloaded toolchain's
SHA256, removes shell-piped installers and whole-repository copies, isolates the
guest workspace and commits its lockfile. Actual guest dependency resolution
passed with unchanged lock bytes. No Linux container, guest ELF or GPU proof was
qualified locally; apt inputs and independent reproducibility remain open.

The service preserves existing authorization for both prove/verify routes but
checks it before JSON parsing. Native worker permits survive HTTP cancellation
until work actually finishes. Fixed-integer proof encoding/decoding now agree,
trailing bytes are refused, and output/input proof budgets agree. Eleven tests
compiled and passed against the real pinned SP1 SDK. The test-only empty ELF was
never used to set up or prove a statement; production still requires a real ELF.
Native work cannot be killed by timeout and can delay shutdown. The shared V1
spend-authorization defect still blocks funded activation.

## Secret scanning and evidence

Both CI definitions now run blocking tracked-source and full-depth reachable Git
history scans using the checksum-verified scanner. Reviewed native redacted
baselines contain public identifiers, not accepted credentials. A real regression
showed that a replacement value at the same source location could inherit a
redacted exception; source exceptions now also require the exact reviewed file
SHA256. Newly tracked inputs, replacements, new-history reintroductions and shallow
checkout refusal are tested. Deleted/unfetched refs and old leak/rotation claims
remain unverified. See [scan scope](HISTORY-SCAN.md).

The ledger retains all 200 findings: 52 implemented, 66 partial, 69 open, seven
base-changed, four protocol decisions, one unarmed candidate and one refuted by
the original audit. These labels describe source work, not fleet deployment or
universal closure. Exact local test commands, logs, failures and final results are
recorded in `VALIDATION-WAVE-7.txt` after integrated checks complete.
