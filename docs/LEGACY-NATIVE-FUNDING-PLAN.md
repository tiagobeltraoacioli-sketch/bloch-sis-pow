# Offline legacy-to-native funding conversion

`native-funding-plan` is an offline preparer for one legacy hybrid UTXO.
It emits Genesis-4 TransferV2, never the legacy wallet's Genesis-3 wire format.
It reads a public-key hex file, uses the consensus codec and fee calculator,
and writes a new unsigned transaction file. Preparation does not unlock a wallet. Optional human-operated signing reads
one encrypted legacy JSON wallet locally. Neither mode connects to the network.

Output zero pays the SHA3-256 of the same public key with the suite-1 header
added. Output one returns change to the original legacy hash (first 20 bytes
of SHA3-256 of the raw public key, followed by twelve zeros). Adding the
public-key header changes the script identity but does not generate a new
private key. The three tests cover conservation/encoding, rejected limits,
and a real disposable hybrid signature verified with both representations.
This does not constitute mainnet transaction qualification.

Build and test:

```sh
cargo +1.94.1 test --locked -p bloch-pos-node --example native-funding-plan
cargo +1.94.1 build --locked -p bloch-pos-node --example native-funding-plan
./target/debug/examples/native-funding-plan --help
```

All numeric values are explicit. `--amount` must cover the intended stake
plus the separately calculated deposit fee; `--max-fee` caps only the
conversion transfer. The tool refuses change below the relay minimum.
It does not estimate deposit fees, prove the supplied UTXO exists, validate
public-key cryptography during preparation, or authorize spending.

```sh
./target/debug/examples/native-funding-plan \
  --pubkey legacy-public.hex --txid INPUT_TXID --vout OUTPUT_INDEX \
  --input-value OBSERVED_SAT --amount APPROVED_NATIVE_SAT \
  --base-fee OBSERVED_BASE_FEE --tip APPROVED_TIP --max-fee APPROVED_TRANSFER_FEE_CAP \
  --epoch EXPECTED_INCLUSION_EPOCH --out new-unsigned-transfer.hex
```

The printed signing root uses the selected epoch's consensus rules. That
epoch is not an expiry. Inspect all input/output amounts, scripts, fee and
root before any human signing operation. Fresh UTXO/finality checks remain required before submission. The old
wallet's `send` and domain-separated message `sign` commands are not
substitutes for that Genesis-4 transfer signing step.


## Human offline signing

Repeat every preparation observation with a new `--out` path and add:

```sh
--tx new-unsigned-transfer.hex \
--wallet /absolute/path/encrypted-wallet.json \
--passphrase-file /absolute/path/owner-only-password-file \
--expected-root INDEPENDENTLY_APPROVED_SIGNING_ROOT
```

The custodian runs this locally, offline, outside an agent or recorded session.
The password file must contain the exact password, without a trailing newline,
be a regular file with owner-only permissions, and contain at most 4096 bytes.
Never pass the password itself as an argument. The wallet is not rewritten.

Before reading the password, the tool reconstructs the transaction from the
explicit public observations, requires byte-for-byte equality with the unsigned
draft, checks the approved root, and refuses an existing output path. After
unlocking, it requires the exact legacy public key, creates a hybrid signature,
and verifies it before writing. The resulting signature does not establish
that the input is still unspent or that the observed fee rate remains current.
Recheck both before submitting. No broadcast command is included.

Tests cover a real disposable encrypted legacy wallet, unchanged wallet bytes,
signature verification and stable transaction ID, pre-unlock intent/root
rejection, repeated-signing refusal, wrong password and file permissions.
These local checks are not a mainnet conversion or an independent audit.
