# Genesis-4 JavaScript SDK for exchange integration

This package builds a complete signed Genesis-4 mainnet transfer using the
same pinned WebAssembly signer shipped with the Postern wallet. The caller does
not select UTXOs, calculate fees, encode a transaction, or sign it. The package
has no runtime npm dependencies and requires Node.js 20 or newer.

The source files `g4.cjs` and `bloch_wallet_wasm.wasm` are copied from the
Genesis-4 Postern wallet. The WASM SHA-256 is pinned in `core.mjs`:
`2f6548cd822d4840e4584b0200467fcb352aaf84a70ea2b3be0e3f099bfa5f49`.
This is a source-distributed package; no npm publication is assumed.

## Install

The versioned package is served at
`https://blochl1.com/releases/genesis4-js/blochprotocol-genesis4-sdk-0.1.1.tgz`.

```sh
npm install https://blochl1.com/releases/genesis4-js/blochprotocol-genesis4-sdk-0.1.1.tgz
```

It can also be installed from a local checkout:

```sh
npm install /path/to/bloch-sis-pow/sdk/genesis4-js
```

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

// Store signed.txid and signed.rawHex before a network write. The RPC call is
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
Persist the exact signed bytes and txid for reconciliation. If submission
times out, retry the same bytes or look up the txid; do not infer failure from
the timeout.

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

The archival index currently serves **included transactions**. A 404 does
not prove that a recently submitted transaction failed: it may still be
pending or not yet indexed. No deposit should be credited from a mempool
admission result. Pause crediting when the index or corroborated chain head is
unavailable, and persist the block ID so reorgs can be detected on refresh.

## Verification

`npm test` signs a real transaction through the pinned WASM core against a
synthetic UTXO and tests receipt composition. It does not move mainnet funds.
The lookup example was also run against the live mainnet txid above. No
mainnet signing test can be performed without a funded key supplied by the
exchange; do not send a mnemonic for a production account to the authors.
