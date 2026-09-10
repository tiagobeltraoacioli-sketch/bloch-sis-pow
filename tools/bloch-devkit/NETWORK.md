# Genesis-4 network connector — 0.2.0

This release adds a real Bloch RPC source connector to both DevKit project
types. It is a source-data integration, not settlement of EVM/SVM contracts.

```sh
bloch-dev network-sync --project my-evm-app
bloch-dev network-sync --project my-solana-app
# With the local VM running, refresh Bloch data and bind it to an export:
bloch-dev export --project my-evm-app --bloch-source --output observation.json
```

`network-sync` does not need the local runtime to be running. It reads the
public Genesis-4 RPC, verifies a pinned published checkpoint, recomputes the
304-byte canonical SHA3 block identity, checks network time and the RPC's
corroboration report, and fetches the finalized source block. A second view
must agree before the cursor is atomically persisted under a process lock.
On later syncs, the old finalized block must still occupy its canonical slot;
checkpoint regressions or changes at the same finalized epoch fail closed.
An unsuccessful sync leaves the prior record byte-identical. Never treat an
old file as a successful current sync after an error.

Records live in `.bloch-dev/bloch-source.json`. Header identity follows
`crates/bloch-pos-committee/src/header.rs`; the pinned WS block and state root
come from `checkpoints/wscheckpoint-1536.json`. Mainnet genesis time is fixed
by the existing manifest. Native network ID 1228832244 is **not** an EVM chain ID.

## Trust and scope

The source is the operator's HTTPS RPC at `https://posternlabs.com/g4rpc`.
Its corroboration report is a claim from that operator, not independently
verified validator signatures. Hash checking authenticates header content
against its ID; it does not verify the proposer, committee weight, full chain
ancestry or consensus finality. This is not a trustless light client.

The record explicitly reports `execution_settled: false`, `deposits_enabled:
false` and `withdrawals_enabled: false`. Neither this connector nor the optional
export binding broadcasts a transaction, credits bridged BLCH or changes a
validator. No legacy EVM node is replaced. The running legacy service was
identified as `bloch-l2-node/0.0.0-devnet/devnet`, chain ID 8400; it is not this
connector or the modern Bloch L2 execution engine.

## Native EVM connection

The companion `bloch-l2-evm` branch `feature/genesis4-vm-connector` adds
`genesis4::prepare_source_batch` and `verify_source_batch`. They derive the
timestamp and PREVRANDAO from the accepted source and committed L2 parent,
put the Bloch hash in `anchor_root`, and enforce expected source/pre-state/
parent bindings during signed-batch witness replay. Deposits remain disabled.

From the companion EVM repository:

```sh
cargo run --locked --example genesis4_source -- /absolute/project/.bloch-dev/bloch-source.json
```

This reproduces a **zero-value, empty** EVM batch using a real source checkpoint
and verifies the resulting state independently through the existing witness
path. It does not deploy a user contract to Bloch. SVM projects can consume and
export the same source record; a native SVM execution/settlement adapter is
not included in this increment.

## Remaining architecture decision

L2 settlement follows the existing ADR-040 direction. Native L1 execution is a
different protocol change requiring transaction formats, execution commitments,
resource limits, validation rules and coordinated activation. The connector is
useful to either path; it does not silently select or activate one. Reth RPC,
data availability, authenticated escrow and settlement verification remain
implementation work for the L2 path. Production validator state and keys are
untouched.
