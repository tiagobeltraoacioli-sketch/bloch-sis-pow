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
only localhost, produces blocks, checks RPC rejection of a malformed native
import, terminates and restarts the real node, and checks recovered chain state
and native checkpoint persistence. Separate real-crypto node tests exercise
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
