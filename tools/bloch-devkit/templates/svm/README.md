# Solana SVM starter

Run `bloch-dev run` here. The Agave test validator persists its ledger locally.
Use the Solana CLI from the installed runtime's bin directory:

```sh
solana-keygen new --silent --no-bip39-passphrase --outfile .bloch-dev/developer.json
solana --url http://127.0.0.1:8899 --keypair .bloch-dev/developer.json airdrop 2
cargo build-sbf --arch v3 -- --locked
solana --url http://127.0.0.1:8899 --keypair .bloch-dev/developer.json program deploy target/deploy/bloch_svm_counter.so
bloch-dev export --output observation.json
bloch-dev verify observation.json
```

Replace the RPC port if customized. The first build-sbf downloads its platform
toolchain. This is a native SBF program, compatible with Solana clients; Anchor
projects can also deploy to this validator. Local SOL has no bridge to BLCH.
The counter requires a program-owned, writable, rent-exempt 40-byte account:
authority pubkey (32 bytes) and little-endian count (8 bytes). Create the account
with SystemProgram, then use instruction `[0]` with both counter and authority
signing to initialize it. Instruction `[1]` increments with the authority as a
second, signing account. The supplied client exercises this flow:

```sh
npm ci --ignore-scripts
node client.mjs PROGRAM_ID http://127.0.0.1:8899 .bloch-dev/developer.json
```

The client requires Node.js 20+. The lockfile pins the tested dependency tree.
As of 2026-09-10, npm audit reports moderate upstream advisories in the web3.js
dependency tree (jayson, stream-json and uuid). This optional example accepts
only local HTTP RPC URLs; do not reuse it as a production wallet or RPC service.
