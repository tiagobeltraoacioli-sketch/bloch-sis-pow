# Actual local source deposit, native mint/burn, and source release

The recorded run used an actual `USDTSourceVault` deployment and synthetic
`LOCAL6` token on Anvil 31337, then a separate BPOSLAB1 node process with real
hybrid signatures. No public network, real stablecoin, or production custody
configuration participated. Public evidence is in
[audit/native-source-local-cycle](audit/native-source-local-cycle/summary.json).
No private keys or node data directories are committed.

The source locked 100 units. Native bootstrap was included at slot 845, import at
846 (supply 100), withdrawal at 847 (supply zero). The one-validator laboratory
observed finalized epoch 27 at head slot 928, then restarted and replayed 84
blocks with identical native accounting. Repeated withdrawal was refused.
Only after this check did the source harness release 100 units; recipient delta
was 100 and remaining vault reserve and liability were zero. Single-signature
release and duplicate release were refused. The source vault relies on a
federated certificate; it does not verify Bloch consensus through a light client.

The native runner independently checks source chain/genesis, canonical receipt
and block, vault runtime SHA-256, exact selected deposit-event ABI, route/deposit
IDs, amount, nonce, sender, recipient PQ hash and token transfer. Native inclusion
requires transaction status, not a coincidentally matching supply value. It saves
wire packets, submission responses, block/status observations, route state,
finalized block, restart state and replay refusal. Its default source-release
step is deliberately separate, consuming the produced burn JSON.

To repeat with fresh disposable keys and deployments:

1. Build `bloch-pos` with `--features native-lab`, create fresh temporary validator
   and committee keys, and generate a `--native-lab` genesis.
2. Run `native-lab-fixture --kind info` with that genesis and those keys. Supply
   the emitted domain/asset/PQ-recipient identity, cap 1000 and amount 100 to the
   bridge repository's `scripts/local-source-lab/run.mjs deploy` command.
3. Run the native side, selecting unused loopback ports and a new artifact path:

```sh
python3 scripts/native-source-process-lab.py \
  --binary target/debug/bloch-pos \
  --native-directory /tmp/fresh-native-lab \
  --source-manifest /tmp/fresh-source-lab/manifest.local.json \
  --source-compact /tmp/fresh-source-lab/native-source.local.json \
  --output /tmp/fresh-native-evidence
```

4. After successful finality/restart/replay checks, pass
   `native-burn.local.json` to the bridge harness's `release` command. Preserve
   its release report alongside the native evidence.

This does not yet include wallet browser signing or a native pool swap between
import and withdrawal. The current withdrawal builder spends the original mint
output. A pool-integrated run needs typed create/init/swap builders using the
current spendable native outputs, pool revision and reserves, plus a wallet view
that distinguishes custody locks from spendable funds.
