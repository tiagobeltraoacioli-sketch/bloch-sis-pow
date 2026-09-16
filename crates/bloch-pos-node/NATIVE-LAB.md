# Isolated native laboratory

`native-lab` is an explicit, nondefault build feature. It does not alter any
production activation constant. `Transition::new` keeps all existing rules,
including when the laboratory feature is compiled. Laboratory activation belongs
to a separate transition instance pinned to one manifest-derived domain.

The node additionally requires `--native-lab` and a `BPOSLAB1` genesis together.
This format has a distinct manifest digest and genesis mix/header; default builds
reject its magic. Official `BPOSMAN1`/`BPOSMAN2` manifests cannot be activated by
the flag. Laboratory startup refuses carryover/cohort and requires loopback RPC,
metrics and devnet transport with numeric loopback peers. The mainnet genesis
command refuses the laboratory flag. Existing official manifest bytes are tested
unchanged with and without the feature.

The laboratory genesis command allocates 100,000,000,000 synthetic satoshis to
each supplied disposable validator key. These outputs have no external backing
or market value. Use a fresh temporary directory and fresh keys. Never point this
workflow at an official data directory or production keystore.

```sh
cargo build --offline -p bloch-pos-node --features native-lab --bin bloch-pos
python3 scripts/native-lab-process-smoke.py --binary target/debug/bloch-pos
```

The process smoke creates and removes its own temporary keys and genesis, binds
only localhost, produces blocks, submits real hybrid-signed bootstrap, import and withdrawal over RPC, checks
supply 0 -> 100 -> 0 and the burn/release record, refuses malformed import,
terminates and restarts the real node, and checks recovered route accounting,
withdrawal replay refusal and native checkpoint persistence. Separate real-crypto node tests exercise
bootstrap admission, production, durable replay and native snapshot restoration:

```sh
cargo test --offline -p bloch-pos-node --features native-lab --bin bloch-pos native_lab_ -- --test-threads=1
cargo test --offline -p bloch-pos-committee --features native-lab native_lab_instance --lib
```

For a manually retained local network, the devnet script accepts the explicit
fifth argument `--native-lab`; it uses workspace build output and assigns each
validator a distinct RPC port starting at 19410. `BLOCH_DEVNET_BIN` can select an
explicit binary. Leave enough slots for the two-epoch doppelganger window.

Native mempool admission dry-runs the same typed executors with the real hybrid
verifier against a private canonical state. Sponsor bytes, fee ranking, source
limits and input conflicts are accounted for. Only one native operation may be
pending at once in this laboratory policy; unconfirmed native dependency chains
are unsupported. State-dependent refusals are retryable, and adopted-head changes
revalidate pending native operations. Block execution and restart replay use the
same domain-pinned transition. This is not a production mempool rollout.

This network is neither official Bloch Genesis-4 nor EVM chain 84001. A wallet
integration needs a distinct network definition, exact laboratory genesis/domain
pins, typed native signing and a deliberately selected localhost endpoint. Do not
reuse the public wallet G4 RPC proxy or the EVM DEX deployment manifest. This
infrastructure does not deploy a source vault or settle an external asset.

## Offline fixture builder and bounded route query

The feature-scoped `native-lab-fixture` command accepts `--kind info`,
`bootstrap`, `import` or `withdraw`, plus `--genesis`, `--sponsor` and `--committee`
paths pointing only to the disposable laboratory. Transaction kinds also take
`--base-fee` from the local node. After bootstrap, supply `--input-txid` and
`--input-value` from the preceding builder's `output_txid`/`output_value` fields.
The output includes typed canonical `hex`, the transaction-status `txid`, sponsor
change identity/value, native domain/asset/route and withdrawal burn identity.
Signing stays offline; the caller explicitly submits `hex` through RPC.

These fixtures use an asset cap of 1,000 and mint/burn 100 units. Defaults describe
synthetic source records, not a deployment. To bind an actual local source-vault
harness, pass `--source-domain`, `--token`, `--vault`, `--vault-code-hash` (SHA-256
runtime), then import evidence using `--source-tx`, `--source-block`, `--event-index`,
`--deposit-nonce` and `--deposit-sender`. Unknown or duplicate options are refused.
The current withdrawal fixture spends the initial mint output; it is not a general
coin selector or pool-operation builder. Its external recipient is 20 bytes of
`0x0f`; no external payment is issued by this command.

`getnativelabstate(asset, route)` is available only in a laboratory build and
refuses official networks. It returns domain, head ID, root, slot and bounded route
accounting: supply, imported, burned, next release nonce, native commitment and the
first release's burn identity. It does not report owner balances, so locked pool
reserves cannot be mistaken for spendable wallet outputs. Values are explicitly
synthetic and `settlement` remains `none` even after a native burn.

## Wallet review projection RPC

`getnativewalletview` takes no parameters and is available only for the selected
BPOSLAB1 laboratory instance. It returns `format`, `domain`, `genesis`, `head`,
`height` (the current consensus slot, as a decimal string), `stateRoot`, `trust`,
and `context`. The context contains `nativeSnapshotHex`,
`nativeCommitmentHex`, the complete `utxos` array (`txid`, `vout`, `value`,
`scriptHash`), `baseFeeMillisatPerGas`, `blockGasUsed`, `blockTxBytes`, and `epoch`.
All integers in the context are decimal strings; hashes have no `0x` prefix.

The endpoint refuses uninitialized native state, more than 4096 base UTXOs, or
a native snapshot larger than 4 MiB. It never truncates state. This trusted-host
projection supports typed wallet review; it is not a finality proof. Its UTXOs
include custody reserves required for snapshot validation and must not be summed
as a spendable wallet balance. The wallet must apply the restored custody locks.
