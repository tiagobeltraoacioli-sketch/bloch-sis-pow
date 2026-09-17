# Internal audit remediation, second wave — 2026-09-17

Status: local implementation and scoped qualification complete; the overall audit remains open. This is not release approval. No production validator, published binary, activation epoch or existing vault was changed. The first wave is commit `203b410`; the following work builds on it in `fix/internal-audit-20260917`.

## Engine and network

Held attestations are evaluated using their own epoch and target seed. The registry projection still follows canonical state rather than a complete historical branch view, so EN-12 remains partial. Duplicate parked blocks avoid repeated hybrid verification. Known-parent blocks must advance the slot before insertion. Remembered refused branches shed their parked descendants; unseen or evicted ancestry can still cause gap requests. Unattributed proposal failures no longer permanently remove or bar innocent mempool transactions.

A bounded cache remembers 4,096 exact failed gossip signature checks, binding the public key, signing root and signature. Altering any of these causes a fresh check. It does not cache successful authorization or replace consensus verification. Unique malicious signatures still consume verification work; per-peer fairness and consensus-thread isolation remain open. Pending-attestation release now updates the duty index when removing entries.

## Checkpoints and operator keys

The standalone weak-subjectivity verifier rejects zero or impossible thresholds and duplicate signer keys. Envelope decoding checks untrusted counts against available bytes before allocation. These are defensive checks, not a new checkpoint trust model.

The new offline slashing-protection CLI exports bound records, imports them with a monotone maximum merge, and initializes a conservative minimum-slot floor. Records are bound to the validator public-key hash and the raw genesis-manifest digest. Foreign identity, malformed records and invalid floors are rejected. Export refuses to overwrite an existing file; private writes are atomic and synced. Runbook examples now use actual commands and RPC methods.

These records do not fence a live copy on another host. A lost host must be externally prevented from signing, and an initialization floor must exceed every possible prior signature, including unpublished signatures. RPC status alone cannot establish this. If history cannot be bounded, keep the identity disabled and follow the documented replacement procedure.

Key mutations reject foreign ownership and symlink targets before taking locks or writing. Read-only inspection no longer creates a lock. Interactive passphrases use a private unbuffered terminal reader and zeroizing storage; restoring echo on process-terminating signals remains open. Newly sealed files enforce an Argon2 floor of 64 MiB and three iterations. Authenticated legacy weak files remain readable with a warning; oversized legacy KDF costs remain a separate issue.

Inspection prints the full public-key hash needed by the recovery CLI, preserving it through sealing. The disposable WS drill creates a fresh private directory and removes its four generated secret files on normal, error and trappable signal exits. Public evidence remains. SIGKILL, power loss, backups and secure media erasure remain outside that cleanup guarantee; the drill must never use production keys.

The plaintext-keystore flag is parsed as an option rather than matched anywhere in argv. Typed WS policy refusals exit with code 78, and supplied systemd configurations suppress automatic restart for that code and limit other repeated starts. Some malformed checkpoint inputs still return ordinary errors: this is partial KS-16 remediation, and existing deployments require the matching unit configuration.

## Vault, anchoring and Coherence

An explicit V3 vault derivation uses hardened role paths and a separate PQ derivation domain. V1/V2 addresses and derivations remain compatible. Existing-funds migration and the deposit/branch-A key architecture are unresolved.

The shield API validates delay fields, address syntax/network consistency, transaction bounds and conflicting verification forms. It accepts JSON, rejects browser cross-site requests and bounds bodies. The binary binds to loopback; authentication, TLS and per-client rate limits still require deployment integration. Secret-field screening is documented as a limited schema check, not proof that arbitrary values contain no secrets.

Anchoring HTTP now bounds time and response bytes, refuses credentials over non-HTTPS URLs and redirects, and checks JSON-RPC identity and response shape. Anchor extraction rejects ambiguous carriers and nonzero padding. Signer binding and consensus transaction-codec qualification remain open. The local script evaluator rejects additional malformed programs, but has not been qualified against Bitcoin Core.

Coherence rejects reuse of the same input-tree position inside one spend. Separate executable tests preserve evidence of the unresolved V1 ownership and cross-spend nullifier attacks. These passing characterization tests demonstrate unsafe behavior; they are not security closure. See `crates/coherence-prover/AUTHORIZATION-BLOCKER.md`. No production proof artifacts were regenerated.

## Ledger, CI and operations

Legacy snapshot export and sorted UTXO iteration now fail on malformed keys, undecodable values or trailing bytes instead of silently dropping funds. Historical output-index interpretation remains explicit and compatible; no genesis balance was rewritten.

The reference TypeScript indexer bounds address history/UTXO pages (100 default, 500 maximum), binds cursors to the indexed revision, caps API/RPC bytes and preserves corrupt snapshots instead of presenting empty balances. Snapshot replacement uses exclusive private temporary files, fsync and rename; unchanged polls skip writes. Actual changes still synchronously rewrite the whole state, so LG-07 remains partial. Pagination changes the client contract and needs consumer integration before deployment.

Follow-up regressions also fixed chained spends within a block, repeated consumption, forward references, output collisions and undo restoration of intermediate outputs. Planning fails before committed state mutation, and rollback checks required undo records before starting. Snapshot validation checks structure/counters/tip metadata; null-prototype serialization preserves special address keys, and private revision counters cannot be frozen by persisted statistics. Fetched block height must match the requested position. Consistency across RPC branch switches remains unresolved because arbitrary DAG parents do not establish a selected-parent contract. Previously misindexed snapshots need an explicitly authorized rebuild; this patch does not silently repair historical balances.

The release rehearsal uses a repository-owned Cargo serialization wrapper rather than an executable in world-writable temporary storage. Its lock is cooperative and is not a security boundary or a guarantee that descendants stop when the wrapper is killed.

GitLab's excluded legacy package uses its own manifest. GitLab gains the native Ustav/EUVM checks already expected by the security posture. Hardened arithmetic findings introduced by the remediation are removed, without raising lint baselines. CI guard tests cover more ways to hide or skip test execution; arbitrary workflow semantics are not certified by a text guard.

Monitoring definitions add scrape availability, missing/stale engine heartbeat, store errors, repeated starts and inactive expected-validator alerts. Target labels make role/host matching available during local rule evaluation. These are source definitions, not deployed alert coverage. Exact missed-duty monitoring and runtime Prometheus qualification remain open.

The validator-activity metric now follows current registry membership, activation/exit windows, boot grace and doppelganger gates instead of retaining a startup value. It describes eligibility, not proof of a scheduled or signed duty. Zero startup timestamps no longer produce false finality or unsealed-key alerts. An append-failure counter is best-effort because the fatal exit may precede the next scrape.

## Validation and release limits

Validation completed locally with the pinned Rust toolchain and Node 24:

- Committee: 426 unit tests and all integration suites passed; ignored rehearsals remain ignored.
- Node: 407 unit tests and all integration suites passed, including three-process cold-start synchronization, recovery fencing and the new offline protection CLI. The later validator-activity regression and full-hash key-inspection CLI suite also passed on the final source.
- Vault: 26 tests; shield API: 15; anchoring: 19 plus one doctest; Coherence: 12 unit, one robustness and four authorization/duplicate-input tests. The two unsafe authorization characterization tests are evidence of an open blocker.
- Reference indexer: offline selftests and all 25 security/regression tests passed, with no skipped tests.
- Native Ustav/EUVM suite and native dependency-boundary check passed. Four ignored tests remain unqualified.
- Hardened Clippy passed all five crates with no baseline increase. CI guard: 37 selftests and both checked-in pipelines passed its supported structural checks. Scorer: nine regressions plus its shell selftest passed.
- Monitoring YAML parsed using Ruby; this is not a Prometheus rule-runtime test. Shell syntax and disposable-drill cleanup/refusal checks passed; `git diff --check` passed.

The initial integrated run exposed two old tests that expected duplicate signer-key acceptance. Those assertions now verify rejection, and the rerun passed. The activity regression initially failed because the sandbox blocked its fixture's loopback socket; it passed with local socket access. These failed attempts are not counted as passing evidence. Command outcomes and log digests are recorded in [VALIDATION-WAVE-2.txt](VALIDATION-WAVE-2.txt).

The inherited workspace-wide formatting differences remain outside this patch. GitLab formatting is informational (`allow_failure: true`), so it must not be described as a blocking check. No Linux production recovery SLA, fleet inventory, external signer ceremony, Bitcoin Core differential qualification or coordinated consensus activation is established by these local tests.

Four concurrent roles cover integration/reporting, node/consensus, checkpoints/keys/CI, and vault/indexer. They share this isolated remediation worktree; unrelated EVM, DEX, bridge and aggregator work still needs release integration.
