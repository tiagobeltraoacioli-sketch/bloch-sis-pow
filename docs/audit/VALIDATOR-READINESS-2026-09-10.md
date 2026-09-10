# Validator readiness audit — 2026-09-10

Reviewed baseline: `911e2ca`. Worktree: `audit/validator-readiness-2026-09-10`.
Scope: funded admission and lifecycle, finality activation, authorization,
accounting, state commitments, mempool policy, restart/replay, duplicate-key
protection and release operations. Independent parallel agent reviews covered
persistence and the funding/finality transitions. This is an implementation
review with executable regressions, not external certification or a proof of
security of the entire blockchain.

## Release verdict

**Do not activate public mainnet admission yet.** The source already implements
funded registration, authenticated exit, withdrawal, slashing and RANDAO renewal,
but this review found operational defects that must be included in any candidate
binary. All five lifecycle epochs remain `u64::MAX`; legacy unfunded deposits
remain permanently disabled. No production node, key or activation epoch was
changed by this review.

A corrected binary with unarmed gates is a **candidate for qualification**, not
an admission activation release. Compile-time lifecycle tests alone do not prove
that the deployed fleet supports these transactions or that transport, disk
recovery, partitions and operator procedures are qualified.

## New findings and repairs

| ID | Severity | Evidence and impact | Disposition |
|---|---|---|---|
| VA10-01 | High, persistence | `Store::read_all` ignored an incomplete trailing frame, but the append handle resumed at physical EOF. The next durable block could become unreadable on restart because its bytes followed the old torn frame. | Fixed: under the exclusive directory lock, truncate and fsync only incomplete trailing framing before append/index initialization. Complete invalid frames remain errors. Regression covers partial length prefixes and payloads, append, second restart and indexed reads. |
| VA10-02 | High, boot integrity | Boot discarded the ingestion result for each decoded logged block and could continue with a rebuilt head shorter than the retained log. | Fixed: canonical replay requires the next parent to equal the rebuilt head and the logged block to become that head; otherwise boot returns `InvalidData`. Test uses a correctly signed, canonically encoded invalid state root, then a valid control and duplicate-frame rejection. |
| VA10-03 | High, validator restart | Historical own proposals were passed to duplicate-key detection while replay used wall slot zero and an already armed window. Replay could permanently halt a legitimate restart. Long replay could also exhaust the observation window before observing live traffic. Delayed old signatures were mistaken for a live duplicate. | Fixed: only gossip proposals reach this detector; the window starts after replay; accepted message slots must be at or after observation start. Tests prove historical replay and stale gossip are harmless while a fresh own-key message still permanently halts duties. |
| VA10-04 | Medium, lifecycle liveness | Automatic RANDAO renewal required `exit_epoch == MAX`, although consensus keeps an exiting validator active for 32 epochs. An exiting key with an exhausted chain stopped proposing during its active interval. | Fixed node policy to renew while `exit_epoch > wall_epoch`, matching consensus. Extended short-chain real-PQ rehearsal includes a signed exit, multiple rotations and replay. The pre-fix test passed the non-exiting control then failed sustained production in the exiting case. |
| VA10-05 | Low, onboarding | Published deposit signing examples omitted the now mandatory trusted `--genesis` argument. | Updated both signing roles in the admission specification. |

The persistence fix does not silently repair complete malformed/invalid frames.
Operators retain the data directory for diagnosis if replay fails. Block-log
compatibility was checked against both writers: `apply_canonical` appends only
adopted canonical blocks, and `do_reorg` rewrites the entire `chain[1..]` sequence.
A historical fork/duplicate-containing file is outside this writer contract;
the new guard explicitly refuses it rather than inventing a migration.

## Earlier findings rechecked

- **VAD-01:** five lifecycle activation constants now have compile-time equality
  assertions; withdrawal and RANDAO node paths and fresh wire tags are present.
- **VAD-02:** funded activation requires `deposit_epoch < finalized.epoch`, the
  eight-epoch inclusion delay and a four-validator churn cap. Stalled finality
  cannot activate funding. Recovery does not backdate activation. The finalized
  checkpoint at E covers the end of E-1, explaining the strict inequality.
- **VAD-03:** lifecycle mempool admission shares financial/state checks with
  consensus, before eviction/broadcast; pending input/key conflicts are refused;
  adopted heads and reorgs revalidate pending lifecycle transactions.
- **VAD-06:** offline signing loads a trusted genesis manifest and refuses a
  mismatching domain before opening the selected keystore.
- **VAD-04 remains:** the admission lifecycle rehearsal drives two real engines
  with actual cryptography and state transitions; it is not a qualification of
  independently supervised processes across partitions and host failures.
- **VAD-05 remains intentional:** funding requires a native 32-byte PQ script.
  Carried padded 20-byte ownership is not silently accepted as native funding.

## Security properties examined

Funding amounts are resolved from committed UTXOs, not client estimates; exact
ownership, input uniqueness, bond/change/fee conservation, fee refunds, expiry,
network domain, both hybrid authorizations and registry uniqueness are checked
before mutation. Registry indices append with overflow checks. Role signatures
bind the intended withdrawal and change scripts.

Withdrawal pays only the registered script, zeros the bond, checks output
collision/narrowing and records unissued principal write-off. Funded provenance,
write-off, slashing low-water marks and RANDAO generations affect the state root.
Slashing extends the withdrawal lock and caps rewards to backed losses. The
indeterminate genesis write-off class fails closed. The eight guard mutations
provide negative evidence for these boundaries, not just happy-path coverage.

Duty identity resolves the public key against the current branch's committed
registry; it does not trust a stale preassigned index. Signing watermarks are
bound to key and genesis, fsynced before signatures and protected by an exclusive
data-directory lock. These protections do not coordinate two separate copies
of the same key on different hosts.

## Residual risks and missing release evidence

1. **Process/network qualification:** run multiple separately supervised nodes
   with distinct data directories, candidate admission and new-key duties,
   restart after reveals, partition longer than activation delay, rejoin,
   competing registration order, finality recovery and full exit/withdrawal.
   Retain roots/logs and compare with replay. Engine-level tests are insufficient
   evidence for transport and operations.
2. **Fleet provenance:** inventory exact executable hashes, manifest digests,
   validator identities, signing overrides and service restart counts on all
   seven validator hosts and both archivals. Establish that each signing key
   has one active process. A 64-slot observation window is a defense, not proof
   of uniqueness under partitions, delayed sync or sparse duties.
3. **Legacy fleet discrepancy:** the parent operational review found eleven old
   `g4-v52..62` services on a nominally idle 8-GB host, including a restart loop
   (`g4-v52` restart count 3165). Its public manifest differs from mainnet in
   genesis time and has zero shared genesis public keys among the two sets of
   64 compared. This does not cover every host or post-genesis registration.
   No old service was stopped as part of this audit.
4. **Cross-network lifecycle authorization:** ExitV2 and RandaoRecommit roots
   do not include the genesis digest. ADR-041 D2 explicitly accepts the exit
   boundary until a coordinated network-binding migration. Avoid key reuse
   across networks; the risk is not removed by funded-deposit domain binding.
5. **Release/canary evidence:** reproducible Linux candidate, checksums, SBOM,
   pinned toolchain and source commit; boot and replay copies of real archival
   data without signing; compare pre-activation head/state roots; rehearse disk
   failure and restart before any coordinated fleet rollout.
6. **Activation ceremony:** select and publish one future epoch only after the
   above evidence, signing/withdrawal custody rehearsal and operator readiness.
   All five gates must move together. An old binary must never resume after the
   flag day; reverting an activated chain is not an ordinary binary rollback.
7. **RPC release surface:** the initial public RPC HTTP 405 was traced by the
   parent operator task to omitted Cloudflare Functions during site packaging,
   not to the blockchain. Redeployment restored `getchaininfo`: observed head
   slot 80,575 against wall slot 80,576, epoch 2,517, finalized epoch 2,515,
   64 active validators and eight corroborating witnesses. The public proxy
   refuses `getvalidatoradmission` with `-32601 method_not_allowed`. A direct
   read-only loopback query on one archival also returned `-32601 method not
   found: getvalidatoradmission`, proving that this consulted binary does not
   implement that endpoint. This finding is limited to that archival, not an
   assertion about every fleet member. Qualify the candidate, then coordinate
   the node upgrade and intended read-only admission/status proxy exposure;
   do not expose privileged signing or mutation methods to solve discovery.


## Reproduction commands

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee --lib
cargo +1.94.1 test --locked -p bloch-pos-node
python3 scripts/check-validator-lifecycle-mutations.py
python3 scripts/rehearse-validator-admission.py
python3 scripts/rehearse-validator-admission.py --randao-only
```

The Python rehearsals create disposable source copies and compile all five gates
at epoch zero; the RANDAO test additionally uses a 16-reveal chain. These builds
are test artifacts only, never production candidates. Network tests require
permission to bind local ephemeral ports. The initial sandbox-only admission
run failed with `EPERM` at bind and is not counted as a protocol failure.

## Validation record

- Committee library: **421 passed, 4 ignored**.
- Shipping node suite: **375 unit tests plus 23 integration tests passed**;
  **20 ignored** across its targets. Ignored tests are not counted as passed.
- Persistence subset: **14 passed**, including torn-tail append/restart.
- Duplicate-key subset: **8 passed**, including historical replay and stale/fresh
  message distinction.
- Signed invalid-state-root replay regression: **1 passed**.
- Withdrawal guard mutation run: control passed; **all eight mutations killed**.
- Corrected short-chain RANDAO rehearsal: **1 passed**, exercising both the
  ordinary case and a validator with a signed scheduled exit, repeated
  rotations and replay (48.06 seconds). The pre-fix run passed the ordinary
  case and failed production in the exiting case.
- Full activated lifecycle phase: **2 passed** (1003.97 seconds), covering
  state-invalid funding rejection before eviction/relay, funded registration,
  finalized activation, real newcomer proposal/attestation, authenticated exit,
  observed equivocation/slashing, the full 2,048-epoch withdrawal delay,
  withdrawal spending, replay root equality and persistent signing protection.
  This disposable snapshot was created before the node repairs; the corrected
  shipping-node regressions and dedicated corrected RANDAO run above provide
  the repair validation. The wrapper's later short-chain phase uses that old
  snapshot and is not evidence for the corrected RANDAO policy; its exit status
  is not presented as an all-green final-tree pipeline.

Code repair commits: `559d8bc` (torn-tail recovery) and `2c292b2` (checked replay,
duplicate-key restart handling, scheduled-exit renewal and signing examples).
The runtime changes are node-local; consensus constants and wire rules are
unchanged. The reported ignored suites, external audit, real-fleet replay and
multi-process qualification remain outstanding. A candidate may now be built
from this audited source with all lifecycle gates unarmed for those next checks.

No release binary has been published or deployed by this review.
