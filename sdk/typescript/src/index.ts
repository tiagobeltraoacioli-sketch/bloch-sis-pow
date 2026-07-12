// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
//
// @bloch/sdk — community TypeScript client for the Bloch JSON-RPC surface.
//
// SCAFFOLD / pre-production / unaudited. See README for the honesty rails:
// Bloch is ownerless and neutral; this SDK is permissively-licensed community
// tooling with no privileged access; the base is unaudited mainnet-beta
// (k=4 trivially forgeable, 51%-attackable); BLCH is neutral protocol gas,
// NOT a value or investment claim.

export { BlochClient, DEFAULT_RPC_URL, DEFAULT_RPC_PORT } from "./client.js";
export type { BlochClientOptions, FetchLike } from "./client.js";

export { BlochRpcError, BlochTransportError } from "./errors.js";

export * from "./types.js";

export {
  SATS_PER_BLOCH,
  BLOCH_DECIMALS,
  blochToSats,
  satsToBloch,
  formatBloch,
} from "./units.js";

export {
  MAINNET_PREFIX,
  TESTNET_PREFIX,
  parseAddress,
  isValidAddress,
  addressNetwork,
  addressToHashHex,
  addressToScriptPubkey,
  encodeAddress,
  checksumHex,
} from "./address.js";
export type { ParsedAddress } from "./address.js";

export {
  selectCoins,
  InsufficientFundsError,
} from "./coinselect.js";
export type {
  SelectableUtxo,
  CoinSelectionResult,
  SelectCoinsOptions,
} from "./coinselect.js";

export { buildTransaction } from "./txbuilder.js";
export type {
  Signer,
  UnsignedTx,
  UnsignedTxInput,
  UnsignedTxOutput,
  BuildTransactionParams,
  BuiltTransaction,
} from "./txbuilder.js";
