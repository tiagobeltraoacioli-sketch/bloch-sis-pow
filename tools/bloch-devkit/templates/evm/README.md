# EVM starter

Run `bloch-dev run` in this directory. In another terminal:

```sh
forge build
cast rpc eth_accounts --rpc-url http://127.0.0.1:8545
# Use one returned LOCAL_ACCOUNT below (Anvil unlocks its development accounts).
forge create src/Counter.sol:Counter --rpc-url http://127.0.0.1:8545 --unlocked --from LOCAL_ACCOUNT --broadcast
cast send CONTRACT_ADDRESS 'increment()' --rpc-url http://127.0.0.1:8545 --unlocked --from LOCAL_ACCOUNT
cast call CONTRACT_ADDRESS 'number()(uint256)' --rpc-url http://127.0.0.1:8545
bloch-dev export --output observation.json
bloch-dev verify observation.json
```

For a custom port, replace the RPC URLs above and in foundry.toml.
Wallet settings: local RPC URL, chain ID 31337, symbol ETH (local test units).
This Anvil profile is not the Bloch L2 execution engine or its fee/supply model.
No real BLCH deposits, bridge transfers, or settlement occur.
