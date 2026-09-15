# Unsigned legacy-to-native funding plan

`native-funding-plan` is an offline preparer for one legacy hybrid UTXO.
It emits Genesis-4 TransferV2, never the legacy wallet's Genesis-3 wire format.
It reads a public-key hex file, uses the consensus codec and fee calculator,
and writes a new unsigned transaction file. No wallet is unlocked and no
network connection is made.

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
root before any human signing operation. The planner alone is not a signed
transaction workflow; an independently checked offline signing step and
fresh UTXO/finality checks remain required before submission. The old
wallet's `send` and domain-separated message `sign` commands are not
substitutes for that Genesis-4 transfer signing step.
