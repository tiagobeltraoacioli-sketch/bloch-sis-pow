# Bloch DevKit

Version 0.2.0 adds the [Genesis-4 source connector](NETWORK.md) and a companion
native EVM replay adapter. Network data is connected; contract settlement is not.

Installable developer tooling for EVM and Solana SVM applications, with a
versioned export interface for future Bloch network adapters.

**Current scope:** local execution using Anvil and Agave, persistent project
state, Solidity/SBF starters, RPC inspection and offline observation integrity
verification. No network deployment or bridge is activated by this software.

## Install on macOS or Linux

Requires Python 3.9+. From the repository root:

```sh
python3 tools/bloch-devkit/install.py
export PATH="$HOME/.local/bin:$PATH"
bloch-dev doctor
bloch-dev init evm my-evm-app
bloch-dev run --project my-evm-app
# In another terminal:
bloch-dev init svm my-solana-app
bloch-dev run --project my-solana-app
```

The CLI runs in the foreground; Ctrl-C stops the runtime. Anvil saves state
every five seconds and on graceful shutdown; Agave keeps its ledger. Each
project has its own `.bloch-dev` directory. To start a clean environment, create
a new project. Existing projects and export files are never overwritten.

Runtimes are installed separately:

| Runtime | Tested release | Official installation / source |
|---|---|---|
| Anvil / Foundry | 1.7.1 | https://getfoundry.sh/introduction/installation/ |
| Agave / Solana CLI | 4.2.2 | https://github.com/anza-xyz/agave/releases/tag/v4.2.2 |

Put runtime executables on PATH. Alternatively extract the official Agave
archive into `~/.local/share/bloch-dev/runtimes/`, keeping its `solana-release`
directory. The kit discovers Foundry at `~/.foundry/bin/anvil` as well.
Verify release asset hashes against the official GitHub release metadata.
The installer does not download or execute remote scripts. Compiler toolchains
are required only when compiling the included starter projects.

EVM uses local chain ID 31337 and Cancun semantics. Its units are Anvil test
ETH, not BLCH. Anvil does not reproduce the custom Bloch L2 deposit accounting,
fee routing, supply invariant or witness verifier. SVM uses a local Agave
ledger and test SOL. No remote fork or mainnet endpoint is configured.

## Inspect and export

```sh
bloch-dev status --project my-evm-app
bloch-dev export --project my-evm-app --output evm-observation.json
bloch-dev verify evm-observation.json
```

Use the same commands for SVM. Wait for a finalized block before exporting SVM.
Exports contain a full RPC block observation, source genesis identity and a
domain-separated SHA-256 file digest. They are **not execution witnesses** and
cannot be submitted as a Bloch validity proof. `verify` checks file integrity,
not whether a dishonest RPC invented its data. See [INTEGRATION.md](INTEGRATION.md).

RPC listens on loopback. SVM also uses port+1 for WebSocket and port+2 for its
local faucet. Pass `--port` to `init` for multiple projects; update clients to
match. Development accounts and keys must never receive real assets.

## Contribute

Start with [COMMUNITY.md](COMMUNITY.md). Run the CLI tests:

```sh
python3 -m unittest discover -s tools/bloch-devkit/tests -v
```

The installer puts files in `~/.local/share/bloch-dev/kit` and a launcher at
`~/.local/bin/bloch-dev`. To uninstall, remove those two paths; project data and
downloaded runtimes are separate and remain under your control.
