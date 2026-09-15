# Offline validator payout spending

Development command: `bloch-pos validator-payout`. This is a source-build
addition on the `feat/offline-validator-payout` branch. It is **not present
in the published September 14 Linux executable**. Adding this command does
not require changing the fleet or any consensus parameter. It does not
complete the outstanding mainnet lifecycle qualification or production
key-generation review.

The command prepares, inspects and signs one TransferV2 (wire `0x06`). Its
only input is output zero of `Withdraw { validator: INDEX }`; the input ID
is derived using the consensus codec. It transfers the entire observed
payout, minus the exact fee, to one explicitly approved destination.
The remainder must be at least 1,000 satoshis, matching the node's relay
minimum. An output one satoshi below that minimum is refused before signing.
It never generates a key, contacts an RPC, broadcasts a transaction, or
changes the withdrawal credential recorded in the registry.

## Build and test

From this checkout, using the pinned toolchain:

```sh
cargo +1.94.1 build --locked -p bloch-pos-node --bin bloch-pos
cargo +1.94.1 test --locked -p bloch-pos-node --test validator_payout_cli --test validator_deposit_cli
./target/debug/bloch-pos validator-payout --help
```

The integration tests create disposable sealed identities. They verify the
actual command-line output against the consensus decoder, transaction ID,
hybrid verifier and fee calculator. They also exercise changed destination,
withdrawal credential, validator, input value, fee, signing root, malformed
witness tables, wrong keys, existing files, dangling symlinks, excessive
input files, extreme fees, and plaintext opt-in refusal. This is local
engineering evidence, not a mainnet spend or an independent custody audit.

The full node rehearsal builds this CLI from the same isolated source copy
and uses it to prepare, inspect and sign the payout created by the funded
lifecycle. It checks application by both engines, finality past the spend's
inclusion epoch, and replay to the same state. Signed intent mutations must
fail specifically at signature verification. Run it with:

```sh
CARGO_PROFILE_TEST_OPT_LEVEL=2 python3 scripts/rehearse-validator-admission.py
```

The optimization setting only affects the test build. The rehearsal changes
lifecycle activation gates in a disposable source copy, retains the actual
2,048-epoch withdrawal delay, and uses a separate short-chain build for
RANDAO renewal. It emits `PAYOUT_CLI_EVIDENCE` with full transaction/block
IDs and finalized roots, followed by `PAYOUT_CLI_REPLAY_VERIFIED`. Require
the final passing test result as well as those records; partial logs are
not a completed qualification. These are two engines in one test process
and a separate CLI process, not an independent-process partition test.

The September 15 UTC run passed all stages, including finalized payout
spending and replay. Its [retained evidence and log hashes](audit/reproducers/validator-payout-cli-lifecycle-2026-09-15.json)
also record the six CLI tests and the deposit regression. Mainnet settlement
remains a separate outstanding qualification.

## Obtain and verify public observations

After the real withdrawal has settled, use your own synchronized node to
confirm the validator record and its withdrawal credential, the payout
outpoint/value, and that the output remains unspent. Verify the destination
through your trusted recipient channel. Record the block and finality
references. Do not infer payment merely from a successful submission.

The command accepts those observations as explicit arguments. **It cannot
prove that they are true offline.** Do not import production keys into an
agent session, shared terminal or CI job. The withdrawal custodian runs the
signing step privately with their established sealed keystore.

On the preparation machine, replace every placeholder with a reviewed public
value. `VALUE_SAT` is the actual payout, including any applicable rewards or
penalties; it is not assumed to equal the original deposit.

```sh
common=(
  --validator INDEX
  --input-value VALUE_SAT
  --withdrawal-script WITHDRAWAL_HASH32
  --destination DESTINATION_HASH32
  --base-fee CURRENT_NEXT_BASE_FEE
  --epoch EXPECTED_INCLUSION_EPOCH
  --max-fee APPROVED_FEE_CAP_SAT
)
./bloch-pos validator-payout prepare "${common[@]}" \
  --pubkey withdrawal.pub.hex --tip TIP_MILLISAT_PER_GAS --out payout-draft.hex
./bloch-pos validator-payout inspect "${common[@]}" --tx payout-draft.hex
```

`withdrawal.pub.hex` contains the suite-enveloped public key. Its full
SHA3-256 must equal `WITHDRAWAL_HASH32`. The output is a hex transaction,
not a private-key file. File creation refuses existing paths, including
symlinks. The reserved byte count covers the suite's maximum signature size
and is fixed before signing.

## Inspect and sign privately

On the custodian's offline machine, independently verify the common options
against the recorded observations and intended destination. Inspect the
transaction and approve its complete signing root. Do not automatically
extract an unreviewed root from the draft and treat that as approval.

```sh
./bloch-pos validator-payout inspect "${common[@]}" --tx payout-draft.hex
BLOCH_KEYSTORE_PASSPHRASE_FILE=/private/path/withdrawal.pass \
  ./bloch-pos validator-payout sign "${common[@]}" \
  --tx payout-draft.hex --dir /private/path/withdrawal-keystore \
  --expected-root INDEPENDENTLY_APPROVED_ROOT32 --out payout-ready.hex
./bloch-pos validator-payout inspect "${common[@]}" --tx payout-ready.hex
```

Use a mode-0600 passphrase file. The command rejects plaintext signing even
if the general devnet plaintext opt-in is set. It verifies existing
signatures and refuses to re-sign an already signed artifact. It confirms
that the unlocked key is the payout owner and verifies the new hybrid
signature before writing. The source keystore is not modified.

The signing epoch selects the consensus signature rules. It is **not an
expiry**, and is not itself serialized in TransferV2. The currently pinned
network-binding gate is unarmed; the current signature does not protect
against reuse on another network with matching outpoints. Keep withdrawal
keys distinct across networks. No new network-binding rule is introduced
by this tool.

## Submit and retain settlement evidence

Transfer only the reviewed signed transaction to the submission machine.
Recheck the outpoint, the applicable signing rules, and the node's next base
fee. TransferV2 requires exact value conservation: changing the base fee can
invalidate the fee/output split. There is no deposit-style fee refund or
expiry. Prepare and sign a new draft when the quote is no longer valid.

Submit explicitly through your own node's `sendrawtransaction` interface.
The public read proxy and the deposit-only submission helper are not payout
submission tools. Never feed this file to `submit-tx`, which constructs the
older Transfer format.

Retain the consensus transaction ID printed by the tool, the inclusion
block, finalized checkpoint, and independent confirmation that the old
payout is spent and the new output exists. The output's transaction ID is
unchanged by signing. Only settled mainnet evidence completes that stage
of the controlled validator lifecycle.

## Read-only settlement checks

Replace the placeholders below with the consensus transaction IDs printed
by the withdrawal encoder and payout CLI. Query your own node, preferably
also an independently operated node. These requests do not submit anything:

```sh
curl --fail --show-error --max-time 30 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"getvalidator","params":[INDEX]}' \
  http://127.0.0.1:16400/
curl --fail --show-error --max-time 30 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"gettxout","params":["WITHDRAWAL_TXID",0]}' \
  http://127.0.0.1:16400/
curl --fail --show-error --max-time 30 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"gettxout","params":["PAYOUT_SPEND_TXID",0]}' \
  http://127.0.0.1:16400/
curl --fail --show-error --max-time 30 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"gettxstatus","params":["PAYOUT_SPEND_TXID"]}' \
  http://127.0.0.1:16400/
```

`gettxstatus` returns an object with `result.status`; require `finalized`
for settlement. `unknown` is not a rejection verdict. `gettxout` returns
`result.unspent`, `result.utxo` and `result.at_slot`. An absent output alone
does not distinguish a spent output from one that never existed. Retain its
earlier inclusion/value/credential evidence and verify the new output under
the expected spend ID, destination and value. Compare nodes at a common
block before interpreting differing observations as a divergence.


## Read-only settlement observation helper

`scripts/verify-validator-payout.py` compares observations from two nodes.
Expose each node through a different loopback SSH tunnel, then run:

```sh
python3 scripts/verify-validator-payout.py \
  --rpc-a http://127.0.0.1:16400/ \
  --rpc-b http://127.0.0.1:26400/ \
  --withdrawal-txid WITHDRAWAL_TXID \
  --spend-txid PAYOUT_SPEND_TXID \
  --destination DESTINATION_HASH32 --value-sat EXPECTED_OUTPUT_SAT
```

Use the consensus IDs and output amount from the inspected signed payout,
not a submission's local `tx_hash`. The helper requires both transactions
to be reported finalized, the old output absent, and the new output present
with the exact destination and value. It checks the mainnet network domain
and requires both nodes to remain on the same block/state/finalized checkpoint
throughout each observation. Moving or different heads trigger up to three
attempts by default, one second apart. Set `--attempts 1` for a single
observation or choose up to five attempts. Exhaustion exits nonzero; this
is not proof of network failure. Incorrect network, unfinalized transactions,
malformed responses and output mismatches stop immediately. The successful
JSON records `attempts_used`; observations from failed attempts are discarded. An already spent
destination output cannot pass this intentionally narrow check.

The helper prints JSON only on success and never submits transactions or
reads keys. Loopback HTTP only, disabled environment proxies, refused
redirects, response size limits and timeouts bound RPC access. Different
URLs do not establish independent operators: configure the tunnels yourself.
RPC agreement is not a cryptographic proof, and this helper does not decode
the signed spend to establish its linkage to the withdrawal. Retain the
CLI's inspected intent and earlier withdrawal inclusion evidence alongside
the JSON. This helper does not complete mainnet lifecycle qualification.

Run the synthetic, network-free regression tests with:

```sh
python3 scripts/test-verify-validator-payout.py
```


## Bind observations to the signed payout

The source verifier also supports `--signed-tx`. Use the already verified
local offline payout executable; the helper neither downloads nor authenticates
that executable. Only the signed public transaction moves to the observation
machine. No keystore or password is needed.

Add these options to the two-RPC command above, preserving the same approved
observations used during signing:

```sh
  --signed-tx payout-signed.hex --payout-bin ./bloch-pos \
  --validator INDEX --input-value VALUE_SAT \
  --withdrawal-script WITHDRAWAL_HASH32 \
  --base-fee SIGNING_BASE_FEE --epoch SIGNING_EPOCH --max-fee APPROVED_FEE_CAP_SAT
```

Use the signing observations here, rather than replacing them with a later
base fee. Before any RPC request, the helper invokes `validator-payout inspect`
on a bounded, stable copy of the signed file. The offline CLI verifies the
signature and consensus encoding. Its reported withdrawal input, transaction
ID, destination and output amount must equal the explicitly requested RPC
observations, and its signature-present field must be true. Failure stops
without querying either node.

Successful evidence includes `signed_transaction_inspection`, the signed
file's SHA-256 and the signing root. Without `--signed-tx`, that field is null
and the original RPC-only limitations still apply. A trusted CLI inspection
links the signed intent to the observed IDs; RPC answers remain observations,
not independently verified inclusion proofs. Synthetic tests cover this
integration boundary; they do not establish a mainnet payout.
