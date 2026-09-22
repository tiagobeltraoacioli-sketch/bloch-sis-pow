# Internal audit remediation, sixth wave — 2026-09-17

Base: `5cf75ed`, branch `fix/internal-audit-20260917`. This is the first
integration checkpoint of the four-role session beginning at 17:55 São Paulo
time, with a maximum end time of 21:55. Work continues after this checkpoint.
No production binary, deployment, validator restart or activation is included.

## Node admission and signing

Capacity eviction now rechecks candidate backing against current state instead
of preserving stale transactions solely through their claimed tips. It plans
evictions and commits them only after validating the incoming transaction, so
a forged replacement cannot delete existing entries. Count, byte and source
capacity regressions and a funded-admission test at the actual activation epoch
2884 pass. Ordinary-transfer replacement and package policy remain separate.

Both transports charge bounded source reservations before their first
engine-facing channel. Reservations survive forwarding and cloning until the
event finishes. One source cannot consume the aggregate queue; inactive source
entries disappear. Devnet IPs share capacity behind NAT, count slots have no
class priority, and multiple identities can still fill the aggregate budget.
This is backlog admission, not a verification-rate limit or Sybil defense.
See [source admission](NODE-SOURCE-ADMISSION.md).

Automatic RANDAO recommit signatures now require a durable, identity-bound intent
before the signing callback runs. Restart, write-failure, conflicting intent,
backup merge and recovery-floor tests pass. The existing doppelganger gate still
applies. An isolated short-chain rehearsal exercises actual automatic rotations
and replay without changing shipping activation constants.

**Local persistence compatibility changes:** the first guarded recommit or
recovery-floor initialization upgrades the slashing record to V3. Older binaries
refuse that format. A pre-upgrade backup is not a safe rollback after new
signatures. Release and rollback packages must preserve the new protection.
See [RANDAO signing recovery](RANDAO-SIGNING-RECOVERY.md).

## Checkpoints

The engine retains the full trusted checkpoint and checks its state root against
canonical evidence on live apply and reorg, before processing finality. Evidence
that is absent or not canonical remains pending; a conflicting canonical anchor
refuses continued operation with exit 78. Historical genesis conventions remain
unchanged. Historical validator-set-root verification is still incomplete.

Operators can provide `--ws-signer-set-sha3` to pin all raw arrangement bytes,
including keys, threshold, external flags and adoption clock. This pin must come
from an independent trusted channel. Omitting it preserves compatibility and
warns; checkpoint signatures themselves still bind only the numeric arrangement
ID. The versioned digest-binding document is a design, not an activated format.

## Wallets, vaults and anchoring

HD entries marked as derived must reproduce both public and private key bytes
from the existing mnemonic/index convention. Imported and historical records
retain their compatibility. Wallet loaders cap actual file reads at 64 MiB;
explicit recovery overrides remain bounded by 512 MiB. This is a file-byte cap,
not a total process-memory or KDF-time guarantee. Owned temporary seed, private
key and derived AES-key buffers now clear on error paths as well as success.
Opaque cryptographic-library state and caller copies remain outside that claim.

An explicit raw hybrid verifier avoids magic-byte dispatch when callers already
know the encoding. Generic verification and historical consensus are unchanged;
the ambiguity remains for consumers that do not adopt trusted encoding metadata.

Checked preimage restoration compares the expected recovery hash before
returning a secret. It preserves the existing HKDF domain. An experimental,
opt-in construction for new vault outputs separates the deposit public key from
the delayed and recovery keys; real signature tests reject the old shared-key
bypass. Existing funded outputs and service construction paths are unchanged.
Key independence/deletion, covenant enforcement and the quantum race remain
unresolved. See [vault construction limits](../../../crates/bloch-pq-vault/CONSTRUCTION-AUDIT.md).

Anchoring's mock codec rejects noncanonical integers, impossible counts and
trailing data. Outputs-only RPC reads refuse consensus-hex guessing. Optional
matching policy checks expected commitment and caller-supplied minimum height
and confirmations; it does not authenticate inclusion, finality or signer
authority. The legacy mock fallback remains explicit compatibility behavior.

## Indexer and build checks

Indexer RPC work has a configurable 30-second default pass deadline, checks
monotonic elapsed time even when timers are delayed, and propagates cancellation
through fetch/body reads. Late responses cannot publish. Responsive slow sources
can publish shorter checked batches; shutdown cancels reads and poll sleeps.
Remote RPC requires HTTPS, startup logs omit URL paths/queries, and malformed
operational configuration fails instead of silently selecting defaults.

Synchronous apply/fsync cannot be preempted by this deadline. The legacy height
mapping still does not prove selected-chain membership. This reference remains
unqualified for live exchange balances; pruning and whole-state writes remain
open. Historical proof-of-work status text was corrected.

Release-integrity checks now compare the root lockfile against HEAD, catching
staged changes as well as unstaged changes. Full build checks refuse ambient
compiler, wrapper, target and profile overrides without printing their values;
the compiler version check requires an exact version token. These changes do not
create the missing canonical Linux build/publishing pipeline or prove fleet
parity.

## Evidence and remaining work

Commands, outcomes and log hashes are recorded in `VALIDATION-WAVE-6.txt`.
The first integrated run encountered sandbox-denied loopback binds and was
repeated with local socket access. The hardened gate caught one new unchecked
sentinel addition; it was replaced with bounded arithmetic and no baseline was
raised. Existing ignored tests remain unqualified.

The ledger retains all 200 rows: 51 implemented locally, 61 partial, 75 open,
seven changed at base, four protocol decisions, one unarmed candidate and one
refuted by the audit. Rows include duplicates and documentation findings.
Partial status is not closure. Protocol economics, historical state binding,
funded shielded authorization, external-validator rollout and independent
Linux/production qualification remain release concerns.
