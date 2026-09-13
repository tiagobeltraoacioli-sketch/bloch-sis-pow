# Validator activation preflight — 2026-09-13 UTC

## Canonical reference approved by the operator

**Do not set a lifecycle activation epoch yet.** The read-only fleet survey
found conflicting live finalized checkpoints. The proposed recovery reference
is the epoch-2713 checkpoint reported by 56 validator RPCs and both public
archivals:

`f8a49015db6c66a0839a69320df7c2705dec4ddd5f249ba7046338d5f127aac1`

The operator explicitly approved this checkpoint in the activation conversation
with “sim” after the recovery question. This authorizes the described sequential
recovery, starting with node 35; it does not select a finite lifecycle epoch.
This is an operator-selected reference, not an automatic authority rule.
RPC counts do not constitute a cryptographic stake quorum. Adopting it on nodes
that finalized a conflicting history requires the operator's explicit decision.
No node was stopped, restarted, reseeded or upgraded during this preflight.
No signing journal, key, unit configuration or mainnet gate was changed.

## Live observations

Inventory: the operator's local SSH manual verified on September 10. Seven
documented hosts were queried serially through their local RPCs. Indices below
are inventory/port labels; signing identity was not independently derived from
private keys. The survey obtained 63 responding RPCs.

| Group | RPCs | Finalized epoch | Finalized root |
|---|---:|---:|---|
| Proposed reference chain | 56 | 2713 | `f8a49015db6c66a0839a69320df7c2705dec4ddd5f249ba7046338d5f127aac1` |
| Conflicting chain: 35, 36, 42, 49, 50, 56 | 6 | 2713 | `d3c7461e76257bf237d43737b8e83e2bd6129010c18835979c5f3526dd4f9ec8` |
| Stalled node: 0 | 1 | 2488 | `0a79524e32f850dc33a4c02340a9d8c60f862700c9d52c81a393654dbd9e0712` |
| Index 63 | Not located | — | No response at its documented/calculated port on the seven hosts |

The two public archival endpoints independently returned the proposed reference
root at finalized epoch 2713. Their responses were read-only observations, not
signed checkpoint envelopes. The public registry's `active: 64` count must not
be confused with 64 reachable, healthy signing processes.

The first host was checked twice: its RPC groups disagreed at epoch 2712 as
well. Socket-to-process checks confirmed that the nine RPC listeners belonged
to processes using the same executable and genesis manifest:

- Executable SHA-256:
  `b37d3b87c3a4fdf75d2954563f47f8f066cdf6b27f50f0384d0ea8bd12f46c10`.
- Public manifest SHA-256:
  `7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd`.

This rules out different manifests as the explanation on that host. It does
not identify the running binary's source commit or prove which gates it carries.
That binary did not recognize `getbuildinfo`; a public archival also did not
recognize `getvalidatoradmission`. The public proxy separately refused the
admission method. A current network epoch alone does not prove a fleet upgrade.

[Sanitized RPC evidence](reproducers/validator-activation-live-2026-09-13.json)
contains opaque host IDs and full checkpoint values. Access addresses, process
paths and the local access inventory remain outside the public report.

## Local qualification completed

`rehearse-validator-activation.py` now constructs a disposable regime with
the four already-finite shipping gates compressed to epoch 1 and the five
ADR-041 gates at epoch 4. All other unarmed features remain unarmed. It refuses
unexpected gate changes and retains parameter diffs and complete logs.

- The finite-boundary test passed: local clock advancement did not bypass the
  committed-epoch gate; funded registration was accepted after L, included,
  replayed consistently, and refused when submitted again.
- A separately compiled unarmed build replayed all 127 exported pre-L blocks
  and agreed with each committed state root. This checks the activation-gate
  delta on this source tree, not arbitrary older deployed binaries.
- The current-regime four-process connected control agreed in all three
  terminal states. Its final state at slot 489 was
  `9dc84124f0314a06ecacb43198641994867f6317ca62883e40d8b4b124ba874e`.
- A 300-slot partition (9.375 epochs) still ended with different terminal
  states after reconnection under the compressed current regime. The one-half
  quorum-floor policy's documented residual remains relevant; this observation
  does not by itself establish the cause of the live six-node divergence.
- Twelve reporting regressions and four source-rewrite guard tests passed.
  The report now compares complete terminal states, avoiding false failure
  caused solely by sequential RPC samples at different moving slots. It still
  refuses missing data and conflicting state roots for the same block.

The earlier full lifecycle, withdrawal mutation and offline signing results
remain recorded in [the opening checklist](../VALIDATOR-OPENING.md).
The [current-regime evidence bundle](reproducers/validator-activation-current-regime-2026-09-13.json)
retains the parameter diff, boundary/compatibility result, network RPC snapshots
and terminal states. These are local working-tree qualifications, not a signed
release or certification of the older live binary.

## Approved recovery sequence

1. Reconfirm the reference checkpoint on both archivals and representative
   nodes. Locate index 63 or record its actual operational status. Recheck the
   six affected signing identities against their intended units before mutation.
2. Preserve the conflicting public histories and current signing-protection
   journals. Check disk capacity and prepare an isolated, keyless replay of the
   selected public history using the intended release. Confirm the approved
   checkpoint is in that history and that replay reaches its expected state.
3. Recover the six conflicting nodes one at a time, starting with node 35 as
   the canary. Fence its old process before any replacement can sign. Preserve
   its existing key and signing journal; never copy a donor's key or journal,
   clear a watermark, or use a broad unreviewed datadir restore.
4. Reconcile chain state only through the explicitly approved recovery path.
   The engine normally refuses a cut below its finalized checkpoint
   (`engine.rs::cut_below_finalized_latch`). Do not silently enable the finality
   rewind override. Hold signing until replay, journal checks and doppelganger
   observation complete; verify the canary follows the selected finalized
   history before proceeding to the next node.
5. Diagnose and recover node 0 separately. Its stale state is not evidence
   that it should receive the same treatment without examination.
6. Re-enumerate the fleet, prove a common finalized history and observe at least
   three additional epoch boundaries. Record running binary hashes, intended
   validator identities and the status of index 63.
7. Complete funded joining over independent processes, release hardening and
   exact deployed-to-candidate compatibility. Then select a future lifecycle
   epoch with enough margin for the audited rollout and observation windows.

Reference approval is recorded above. Recovery must preserve signing protection
and retained evidence of the conflicting public history.
No finite mainnet L or deployable activation release has been selected.


## Approved recovery investigation — 2026-09-13 UTC

The epoch-2713 reference was reconfirmed by node 7 and both public archivals,
including `getblockbyid` reporting that exact block as finalized at height
63,592 (block slot 86,814). Node 35 knew that block but reported it as
`not_canonical`.

Public-header inspection confirmed indices 0, 7, 35, 42, 49 and 56
at their corresponding data directories. All six inspected keystores use the
legacy plaintext format with mode 0600. No `slashing_protection.bin` was found
under the first fleet host's data tree. The running executable identifies
itself as `46133196-varredura`; the source at that revision uses in-memory
last-attested/last-built counters, rather than the newer persistent journal.
The version banner is not a reproducible source-to-binary attestation.
Do not treat absent journals as proof that these established keys never signed.
Node 0's log continues to report attestations against its stale head.

An isolated observer replay was started at 01:49 UTC using the already-built
candidate whose banner names `22b8b7fdbbe0`. Its SHA-256 is
`6221e468343436868e205c33b642c173c362d500be95836d35fca61d12719ccf`.
A stable copy of node 7's three named public files was captured without stopping
it. No key, signing journal or lock file was copied. The observer binds only
to loopback, has no peers or keystore, runs at reduced CPU priority, and has a
two-hour process timeout. Its input log contains 63,683 blocks.

| Public input | Bytes | SHA-256 |
|---|---:|---|
| blocks.log | 895587295 | `fc7d58c5379e3ea6f6ff11e1afcc408dcd82ea3775bb82ae9d88c5314e8290eb` |
| meta.bin | 44 | `da9aec00e71b0d4dd647f20281a97fcffecb3b493159e621a35429043e2e8741` |
| ws_latest.bin | 154 | `fa8d166c7b3ee7a63087ca298a123c6cdc514a8987d1b65fd338d46f99a8b5d5` |

This candidate has not yet qualified for deployment. Production signers have
not been stopped, restarted, reseeded, rekeyed or upgraded during this stage.
A signing restart depends on validated replay and a reviewed migration of the
legacy signing protection; an empty new journal is not that migration.


### Legacy lock compatibility incident

The candidate's `keys inspect` command prints public key metadata but also
probes the data-directory lock by acquiring it. Against the older live binary,
that probe reported a free lock and replaced six legacy PID sentinels with its
own short-lived process PIDs. This was an inspection side effect, not evidence
that the validators were stopped. After verifying each live systemd PID and
its actual data-directory argument, and that each inspection process had exited,
the six original live PID values were restored and fsynced. No signing process
was started or stopped and no key or chain file was changed. Do not use the
new lock probe on a running legacy data directory; verify the actual process
and inspect public headers without lock acquisition instead.

The operator subsequently authorized migration of all 64 validators in batches
of 10 or 11 while retaining the current distribution across seven servers.
The operator also explicitly requested locating and activating validator 63
after recovery. These authorizations do not waive compatibility, signer fencing,
legacy protection migration, duplicate-instance checks, or canary validation.


### Validator 63 located; placement retained

A subsequent scan of all twelve inventoried 8-GB servers and seven 32-GB
servers found the registry-matching public key for index 63 in two inactive
locations: CLASSIC-003 and HOST-006. The public-key hash is
`dc5ea934b7954baa791da4abccc707bbe9fe203323d84bb9dd807a9c12d2e90b`.
The classic host's validator service is masked. HOST-006 already holds the
matching keystore, but has no installed `bloch-n63` service and no process
using its data directory. No private key was copied or displayed during this
search: the scanner reads only the bounded public header, with unbuffered I/O,
and does not acquire or modify locks. The scan covers known data locations
and visible processes, not inaccessible container storage (`/opt/containerd`).

A different key with index label 63 is running with a devnet manifest on
CLASSIC-007. It must not be confused with the mainnet identity.

The planned placement is HOST-006, using its existing key. After activation,
that server would run ten validators and each of the other six would retain
nine, totaling 64. The host reported approximately 13.7 GiB available RAM and
829 GB free disk at inspection. No USB copy or inter-host key transfer is
needed for this placement. The inactive classic copy must remain fenced.

[Proposed batches](reproducers/validator-migration-batches-2026-09-13.json)
contain 11, 11, 11, 11, 10 and 10 validators, with canary 35 validated separately
before the rest of the first batch. They are planning data, not an executable
rollout; current effective-stake availability must be checked before each batch.

The full local `cargo +1.94.1 test --locked -p bloch-pos-committee
-p bloch-pos-node` command completed successfully: 1,001 tests passed and none
failed (28 ignored). This does not replace exact deployed-history replay.


### Legacy signing reservation prepared and checked

`prepare-validator-recovery-fence.py` prepares a new, identity-bound BPOSSLP2
reservation from public network metadata, a verified public-key hash and an
operator-established last-possible signing slot. It reads no secret and refuses
to replace any existing output. Both slot watermarks are set to the fence slot;
both epoch watermarks are set to its epoch. This conservatively reserves old
proposal slots and attestation targets and prevents a new vote with a source
below that epoch. It does not claim to reconstruct the old signature history.

For actual migration, establish the fence only after every process holding the
identity is stopped, include any observed future signing slot in the bound,
and preserve the old public history. Use this path only when the validator has
no existing journal; retain an existing journal unchanged. Verify the binding
and the chosen bound before installing the new reservation. The normal signer
then refuses duties at or below these bounds, including after restart.
Doppelganger observation remains enabled. No fleet reservation has been installed.

The `recovery_fence` integration target ran eleven tests successfully, including
decoding the Python-produced record with the actual Rust journal reader,
restart persistence, old-slot/double-vote/surround-vote refusal, refusal of a
wrong identity or network, and refusal to overwrite an existing record.
`hardened-clippy.sh` also completed successfully on the working tree.

### Additional compatibility experiment

An isolated copy of source `22b8b7f` is being built with the sole parameter
change `LEAK_RECOVERY_ACTIVATION_EPOCH: 2700 -> u64::MAX`, matching the old
revision's gate setting. Its stamp explicitly identifies it as an experiment.
This does not modify the source checkout, current validator executables or
service configuration. It is not yet a deployment candidate. The purpose is
to test the known gate difference against the exact same public history before
selecting recovery release rules or any future activation epoch.


### Exact comparison target and network configuration

The public input contains 63,683 complete frames and includes the approved
checkpoint. Its last block is at slot 86,916, height 63,683:
`c5873bb8e6f322ba3bd75bac868511eb9986c65c107cf6db877d2aa8435ec249`,
with committed state root
`f3d175945681996a94ec7a8390f7bb21d5b55fdde3cb21d43ba595b36673e524`.
The healthy reference RPC agrees with that header and height; at the check it
classified this tip as justified, not finalized. The approved epoch-2713
checkpoint remains finalized. Qualification must compare the exact replay tip
and state, not merely a progress message saying all input frames were visited.

All 64 observed public keys match the registry on the approved chain. At the
recorded epoch-2718 observation, planned batches account for approximately
13.268%, 16.597%, 17.225%, 13.222%, 20.909% and 18.778% of effective stake.
These are scheduling observations; recheck both available and batch weight at
each stop, accounting for already-unavailable validators.

The inspected live unit still dials numerous retired classic endpoints and
points index 63 to the wrong large server. Draft units have been prepared for
all 64 identities, each with exactly 63 current peer addresses and index 63 on
HOST-006. They contain an intentionally nonexistent binary placeholder and
have not been installed. The inspected host's firewall already covers TCP
19063 for several fleet peers; full connectivity checks remain part of rollout.


### Committed joining-validator duties verified

The independent two-process admission rehearsal passed with both nodes ending
at slot 703, height 703 and the same state root. A subsequent targeted
`funded_joining_network_evidence` test used the actual Rust block-store reader
on both retained, stopped stores and verified that each contains proposals
and included attestations from the newly admitted validator (index 1).
This establishes committed duties, in addition to process log messages.
The evidence applies to fresh devnet identities and compressed activation
epochs; it does not qualify replay of deployed mainnet history.


### Seven-host release and connectivity preflight

A sequential read-only check at 02:58–02:59 UTC found identical deployed
binary, manifest and carryover hashes on all seven large hosts. Every host
reported NTP synchronization. All 49 TCP probes (one currently listening
validator endpoint on each destination from each source) connected. This
checks representative reachability, not every validator port or future
service readiness. The binaries remain the legacy release; none was replaced.

### Restart duplicate-instance protection correction

Reviewing the actual restart path exposed two operational problems in the
candidate: its 64-slot observation deadline was established before log replay,
and replayed proposals called the same duplicate-instance hook as gossip.
A long replay could consume the observation window, while a historical own
proposal could permanently halt duties before the live loop began.

The working-tree correction arms the window after replay and weak-subjectivity
validation, excludes disk/local proposals from duplicate sightings, and ignores
an authenticated duty whose slot predates the observation window. Current own
network duties still halt signing permanently. Nine targeted tests passed,
including replay of an actual own committed proposal and delayed versus current
attestations. Hardened clippy passed without increasing any baseline. The first
sandboxed test attempt could not bind local ports; the permitted rerun passed.
The subsequent complete node-suite run passed 407 tests with no failures
(24 ignored across eleven targets). An independent-process rehearsal with
the default observation protection enabled is in progress. No corrected binary has been
installed on a production validator.

The protected independent-process run subsequently passed: both nodes ended
at slot 703, height 640, state root
`a334b8732b18ae71f72090e02fa5f37b1c390fa41bf09f154046de917fac5753`.
The first 64 slots were observation, explaining the lower block count than
the earlier bypassed run. Both stores contain the joining validator's
proposals and attestations; neither process performed a duty before its
observation deadline. See [protected network evidence](reproducers/validator-joining-network-protected-2026-09-13.json).

A warm restart of a separate copy of the stopped devnet founder store also
passed: 640 blocks replayed, no duplicate report, and the first new duty at
slot 1012, exactly its post-replay observation deadline. It used the same
qualified devnet binary digest recorded in the protected network evidence.

### Shipped epoch-2700 candidate fails the approved history

The original candidate (`22b8b7f`, binary SHA256
`6221e468343436868e205c33b642c173c362d500be95836d35fca61d12719ccf`)
finished visiting 63,683 input frames but accepted only 63,234 blocks, ending
at slot 86,431, epoch 2700, justified 2699, finalized 2698. Its state root was
`f7e54ec1639ebd2a30b0da0d8dd3fc5683051b5de6fe696d5ca4065f068262e9`.
The expected end is slot 86,916 and a different state root. RPC also explicitly
reported the approved epoch-2713 checkpoint block as unknown. This is a failed
compatibility test, not a successful replay with a temporarily lagging RPC.

The endpoint was loopback-only, had no peers and no validator key. Production
was unchanged. The epoch boundary matches the known leak-recovery rule
mismatch; the MAX-gated control is still replaying, so attribution to that
single parameter remains conditional on the control reproducing the exact
reference state. Retained [failure evidence](reproducers/validator-mainnet-replay-incompatible-2026-09-13.json)
includes complete RPC roots and the approved checkpoint reference. Do not
install the epoch-2700 candidate on the signing fleet.

### Completed compatibility control and Monday candidate qualification

The MAX-gated control completed successfully: all 63,683 blocks reproduced
slot 86,916 and state root
`f3d175945681996a94ec7a8390f7bb21d5b55fdde3cb21d43ba595b36673e524`.
The approved epoch-2713 checkpoint is finalized. Changing only the recovery
gate accounts for the failed epoch-2700 candidate. Both keyless observers
were stopped. See [compatible replay evidence](reproducers/validator-mainnet-replay-compatible-2026-09-13.json).

The isolated Monday candidate schedules recovery at epoch 2880 and all five
lifecycle gates at epoch 2884, retaining historical rules before the gates.
Finite-boundary, protected independent-process joining, and complete funded
lifecycle rehearsals passed. The lifecycle run passed two full-cycle tests
and the automatic RANDAO recommit test; source integrity checks passed.
Hardened clippy passed. The full committee/node suite had one test-only
boundary assertion failure, corrected to the largest reachable epoch and
verified by a passing targeted rerun. No runtime change was needed for it.

Read-only duplicate checks found 58 masked and 38 absent service names on
11 legacy hosts, all inactive with MainPID zero. This is evidence for the
inspected paths and services, not a claim about inaccessible containers.
Production migration remains zero. Native release qualification, canary 35,
all batches, archival compatibility and fleet readiness are still required.
