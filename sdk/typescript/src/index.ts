// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
//
// @bloch/sdk — community TypeScript client for the Bloch JSON-RPC surface.
//
// HISTORICAL — GENESIS-3. This client targets the Genesis-3 proof-of-work
// JSON-RPC surface; that chain stopped permanently at height 39,918 on
// 2026-08-13. The live chain is Genesis-4, proof of stake, whose RPC exposes a
// different and much smaller method set.
//
// SCAFFOLD / pre-production / unaudited. See README for the honesty rails:
// permissively-licensed community tooling with no privileged access
// ("ownerless" retracted, ADR-036); under Genesis-4 the security question is
// concentration, not hashrate — all 64 validators are run by one entity, 93.94%
// of the carryover sits at a single address, and 56.05 B of the 57.15 B BLOCH
// issued at genesis is held by the founder and the Foundation; BLCH is neutral
// protocol gas, NOT a value or investment claim.

export { BlochClient, DEFAULT_RPC_URL, DEFAULT_RPC_PORT } from "./client.js";
export type { BlochClientOptions, FetchLike } from "./client.js";

export { BlochRpcError, BlochTransportError } from "./errors.js";

export * from "./types.js";

export {
  SATS_PER_BLOCH,
  BLOCH_DECIMALS,
  MAX_SATS,
  parseSats,
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
