# Genesis-4 JavaScript SDK for exchange integration

This package creates or restores a Genesis-4 mainnet address locally and builds a complete signed Genesis-4 mainnet transfer using the
same pinned WebAssembly signer shipped with the Postern wallet. The caller does
not select UTXOs, calculate fees, encode a transaction, or sign it. The package
has no runtime npm dependencies and requires Node.js 20 or newer.

The source files `g4.cjs` and `bloch_wallet_wasm.wasm` are copied from the
Genesis-4 Postern wallet. The WASM SHA-256 is pinned in `core.mjs`:
`2f6548cd822d4840e4584b0200467fcb352aaf84a70ea2b3be0e3f099bfa5f49`.
This is a source-distributed package; no npm publication is assumed.

## Install

The versioned package is served at
`https://ops-blochinc.xyz/wallets/downloads/blochprotocol-genesis4-sdk-0.1.8.tgz`.

```sh
npm install https://ops-blochinc.xyz/wallets/downloads/blochprotocol-genesis4-sdk-0.1.8.tgz
```

It can also be installed from a local checkout:

```sh
npm install /path/to/bloch-sis-pow/sdk/genesis4-js
```

## Create or restore a local wallet

`createLocalWallet()` uses the pinned wallet core to generate a fresh 24-word
mnemonic and its checksummed Genesis-4 mainnet address. `deriveLocalAddress()`
recovers the address from a phrase you already control. Both run inside the
calling Node.js process and make **no RPC or HTTP request**.

```js
import { createLocalWallet, deriveLocalAddress } from '@blochprotocol/genesis4-sdk';

const wallet = createLocalWallet();
// Back up wallet.mnemonic through your own secure, offline key ceremony.
// Do not print it in logs or send it to an API.
console.log(wallet.address);

const restored = deriveLocalAddress({ mnemonic: wallet.mnemonic });
if (restored.address !== wallet.address) throw new Error('Address mismatch');
```

The SDK returns the mnemonic to the caller once and does not persist or encrypt
it. The caller is responsible for controlled backup, process isolation and key
custody. For an interactive encrypted wallet, use Postern Wallet instead of
placing secrets in a website or a remote Ops endpoint. Importing an older
wallet may require its original derivation convention; the function above uses
the current core's default convention.

## Sign and submit

`amount` is a decimal **string in BLOCH**, with at most eight decimal places.
Never pass a JavaScript floating-point number. The returned `rawHex` is the
complete signed, serialized transaction accepted as the sole parameter of
`sendrawtransaction`. The `txid` is the consensus transaction ID derived by
the signer. It is different from the node's `tx_hash` correlation value.

```js
import { createSignedTransaction, broadcastSignedTransaction } from '@blochprotocol/genesis4-sdk';

const signed = await createSignedTransaction({
  addressFrom: process.env.BLOCH_ADDRESS_FROM,
  mnemonic: process.env.BLOCH_MNEMONIC,
  addressTo: process.env.BLOCH_ADDRESS_TO,
  amount: '1.25000000',
  rpcUrl: process.env.BLOCH_RPC_URL ?? 'https://posternlabs.com/g4rpc',
});

// Store the complete signed object before a network write. The RPC call is
// equivalent to sendrawtransaction([signed.rawHex]).
const submitted = await broadcastSignedTransaction(signed, {
  rpcUrl: process.env.BLOCH_RPC_URL ?? 'https://posternlabs.com/g4rpc',
});
console.log({ txid: signed.txid, admitted: submitted.admission.accepted });
```

Run the included script with `BLOCH_MNEMONIC` and `BLOCH_RPC_URL` set:

```sh
node examples/sign-and-broadcast.mjs "$BLOCH_ADDRESS_FROM" "$BLOCH_ADDRESS_TO" 1.25
```

It prints signed bytes without broadcasting by default. Set
`BLOCH_BROADCAST=1` to submit them. Use an exchange-controlled Genesis-4 RPC
node for custody operations. Keep the mnemonic out of command-line arguments,
logs, and network requests; this SDK sends only script hashes and signed bytes.

The SDK reads `getutxos` and `getchaininfo`, takes the **next** base fee and
current epoch, invokes the core for UTXO selection and fee calculation, checks
the preview against the signed transaction, and enforces block and RPC size
limits. It requests the node's maximum 1,000 UTXOs and returns
`utxosTruncated: true` if the source owns more than the node can enumerate.
The core can still select from the visible coins; if those cannot cover the
amount, an exchange node or indexer with a complete UTXO view is required.
Transaction creation and broadcast are separate because a transfer's
fee can become stale at the next block; do not rebuild a transfer after a
timeout until the original txid has been checked.

`accepted: true` means mempool admission, not block inclusion or finality.
Persist the exact signed bytes, txid, `signingRootHex` and `rawHash` for
reconciliation and safe transport retries. SDK 0.1.8 requires all four fields
when broadcasting: before network I/O it recomputes the domain-separated txid
from `signingRootHex` and SHA3-256 of `rawHex`; after admission it compares the
node's byte count and `tx_hash` correlation handle. The latter is **not** the
consensus txid. A mismatch after submission is ambiguous because the node may
already have accepted the bytes; check the original txid before retrying.
If submission times out, retry the same bytes or look up the txid; do not infer failure from
the timeout.

`trackSignedTransaction(signed, {previousObservation})` checks the stored
signed envelope before reading its txid from the archival API. If no included
receipt exists, it returns an unresolved single-node observation. With a prior
observation, it also reports a changed block, receipt, finality or head through
`comparison`. It never broadcasts, rebuilds or approves a transaction:

```js
import { trackSignedTransaction } from '@blochprotocol/genesis4-sdk';

const tracked = await trackSignedTransaction(signed, {
  previousObservation: previous?.observation ?? null,
});
console.log(tracked.txid, tracked.observation.kind, tracked.comparison.status);
// Save the observation for the next check; apply your own payout policy.
```

For a previously saved signed JSON object, the included read-only CLI prints
only the txid, current observation and comparison; it does not print the
signed bytes or submit a transaction:

```sh
node examples/track-signed.mjs signed.json > first-observation.json
node examples/track-signed.mjs signed.json first-observation.json > next-observation.json
```

## Transaction lookup

`getTransaction(txid)` returns one exchange-facing object. It calls the
published `GET https://blochl1.com/api/v1/transactions/{txid}` method, which
joins the canonical archival receipt with a fresh corroborated chain head.

```js
import { getTransaction } from '@blochprotocol/genesis4-sdk';

const tx = await getTransaction(
  '2a70f41229d8587f060c308279238662c2aa331f4d9f32a660231716f418c672'
);
console.log({
  inputs: tx.inputs,
  outputs: tx.outputs,
  feeSat: tx.feeSat,
  height: tx.height,
  slot: tx.slot,
  confirmations: tx.confirmations,
  status: tx.status,
  finalized: tx.finalized,
});
```

Run the example against current Genesis-4 mainnet:

```sh
node examples/lookup.mjs 2a70f41229d8587f060c308279238662c2aa331f4d9f32a660231716f418c672
```

Every input and output carries `value_sat` as a decimal string and a
`script_hash`. Other fields include `blockId`, `transactionIndex`, `kind`,
`sizeBytes`, `stakeSat`, `finalizedHeight`, `observedHeadHeight`,
`observedHeadSlot`, `source`, and `verification`. Confirmations are inclusive:
`observedHeadHeight - height + 1`. `finalized` is true only when the fresh,
corroborated finalized height reaches the canonical receipt's height.
The SDK rejects missing or duplicate outpoints, malformed integer amounts or
script hashes, output txids that differ from the queried transaction, and
contradictory height, confirmation or finality fields. These structural checks
do not independently replay consensus or establish source authenticity.

The archival index currently serves **included transactions**. A 404 does
not prove that a recently submitted transaction failed: it may still be
pending or not yet indexed. No deposit should be credited from a mempool
admission result. Pause crediting when the index or corroborated chain head is
unavailable, and persist the block ID so reorgs can be detected on refresh.

`getTransactionObservation(txid)` wraps that boundary for withdrawal tracking.
It returns `{kind: 'included', receipt}` when the complete canonical receipt is
available. Only after an archival 404, it asks one node for `gettxstatus` and
returns `{kind: 'unresolved', nodeStatus}`. The node status can be `pending`,
`included`, `justified`, `finalized` or `unknown`; none supplies the amounts,
block identity and corroborated finality needed for deposit credit. A failed
node query returns `nodeStatus: null` and remains unresolved. Malformed
included receipts and other archival errors are raised rather than hidden.

```js
import { getTransactionObservation } from '@blochprotocol/genesis4-sdk';

const observation = await getTransactionObservation(process.argv[2]);
if (observation.kind === 'included') {
  console.log(observation.receipt);
} else {
  console.log({ status: 'unresolved', nodeStatus: observation.nodeStatus });
}
```

Run `node examples/observe.mjs <txid>` to try this flow. A node's `unknown`
answer does not prove that a transaction never existed; its status index is
bounded, and a public gateway is not an independent settlement authority.

## Compare successive observations

Persist each observation with the exchange's own transaction record. The pure
`compareTransactionObservations(previous, current)` helper highlights a missing
receipt, changed inclusion block, changed transaction contents, reported
finality regression or lower observed head/confirmation count. It never
authorizes a deposit credit or withdrawal payout. Differences demand review of
the source records and independent node/checkpoint evidence.

```js
import { getTransactionObservation, compareTransactionObservations } from '@blochprotocol/genesis4-sdk';

const current = await getTransactionObservation(txid);
const comparison = compareTransactionObservations(previousObservation, current);
console.log({ comparison, current });
```

The included `examples/compare-observations.mjs` reads a prior JSON snapshot
when supplied and writes the new observation and comparison to stdout:

```sh
node examples/compare-observations.mjs <txid> > first.json
node examples/compare-observations.mjs <txid> first.json > second.json
```

The comparison checks the canonical input/output outpoints, satoshi amounts,
script hashes and inclusion metadata. It ignores extra indexer annotation
fields. `consistent` means only that those two API observations agree; verify
chain identity, source authenticity and your own finality policy separately.

## Inspect deposit outputs

`inspectDepositOutputs({transaction, addressTo, amount})` matches the outputs
of a complete included receipt to a checksummed Genesis-4 mainnet address. It
converts the expected decimal BLOCH amount to integer satoshis, lists every
matching `txid:vout`, sums those amounts with `BigInt`, and returns
`matchedAmountSat`, `differenceSat` and `exactTotal`. It rejects duplicate or
malformed outputs instead of silently ignoring them. The result is a
measurement, not a credit decision; the exchange must apply its own ownership,
finality, duplicate-credit and risk policy. In particular, multiple outputs to
one address are listed separately so each outpoint can be accounted for once.

```js
import { getTransaction, inspectDepositOutputs } from '@blochprotocol/genesis4-sdk';

const transaction = await getTransaction(txid);
const match = inspectDepositOutputs({
  transaction,
  addressTo: expectedDepositAddress,
  amount: '1.25000000',
});
console.log(match.matchingOutputs, match.matchedAmountSat, match.finalized);
```

Run `node examples/inspect-deposit.mjs <txid> <addressTo> <amount>` for a
read-only mainnet query. An archival 404, missing or changed receipt must stay
unresolved; use `getTransactionObservation` and
`compareTransactionObservations` to track that state.

## Verification

`npm test` signs a real transaction through the pinned WASM core against a
synthetic UTXO and tests receipt composition. It does not move mainnet funds.
The lookup example was also run against the live mainnet txid above. No
mainnet signing test can be performed without a funded key supplied by the
exchange; do not send a mnemonic for a production account to the authors.
