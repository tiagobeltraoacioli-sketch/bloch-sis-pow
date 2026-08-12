// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
//
// Transaction-builder SCAFFOLD for Bloch's UTXO / P2PKH model.
//
// WHAT THIS DOES: assemble an UNSIGNED transaction structure (inputs from coin
// selection, a recipient output, and a change output) for the fixed P2PKH form
// Bloch uses. On Bloch there is NO script system — an output's `script_pubkey`
// is simply the 20-byte SHA3-256(pubkey)[..20] hash (roadmap §1.3).
//
// WHAT THIS DOES NOT DO: it does NOT sign, and it does NOT produce the final
// wire bytes for `sendrawtransaction`. Signing on Bloch is a hybrid
// Falcon-1024 ‖ ML-DSA-65 scheme (both lattice families must verify), the
// `txid` excludes `script_sig` (non-malleable), and the node deserializes the
// broadcast payload with `Transaction::from_stratum_bytes` (Bitcoin-format
// bytes as of node Sprint 1.d). Reproducing that byte layout and the PQ
// signatures is the job of **WalletCore** (bloch-crypto / the mobile crate),
// which is byte-compatible with the node and golden-tested. This SDK
// deliberately does NOT reimplement it.
//
// Instead we define a `Signer` interface. You provide an implementation backed
// by WalletCore (or `bloch-wallet`), which takes the UnsignedTx (plus the
// prevout values it is spending) and returns the ready-to-broadcast hex.

import { addressToScriptPubkey } from "./address.js";
import { selectCoins, type SelectableUtxo, type SelectCoinsOptions } from "./coinselect.js";
import type { Address, Satoshis } from "./types.js";
import { parseSats } from "./units.js";

/** An input reference into a previous transaction output. */
export interface UnsignedTxInput {
  /** 64-hex txid of the previous transaction. */
  prevTxid: string;
  /** Output index within the previous transaction. */
  prevIndex: number;
  /**
   * Value of the output being spent, in satoshis (needed for SIGHASH_ALL).
   *
   * `bigint`, not `Satoshis`: this is money math handed to a signer, and the
   * supply cap 10^19 sat is ~1110x Number.MAX_SAFE_INTEGER, so a `number` here
   * would silently round the amount that gets committed to a signature.
   */
  value: bigint;
  /** 40-hex P2PKH script_pubkey of the output being spent. */
  scriptPubkey: string;
  /** Sequence number (defaults to 0xffffffff). */
  sequence?: number;
}

export interface UnsignedTxOutput {
  /** Recipient P2PKH script_pubkey (40-hex, = 20-byte pubkey hash). */
  scriptPubkey: string;
  /** Amount in satoshis. `bigint` — see {@link UnsignedTxInput.value}. */
  value: bigint;
}

/**
 * An unsigned Bloch transaction. This is a neutral structural representation;
 * WalletCore turns it (plus signatures) into the canonical broadcast bytes.
 */
export interface UnsignedTx {
  version: number;
  inputs: UnsignedTxInput[];
  outputs: UnsignedTxOutput[];
  locktime: number;
}

/**
 * Signing interface. Implementations are PROVIDED BY WalletCore (bloch-crypto)
 * — this SDK never handles private keys or reimplements PQ signing.
 *
 * The implementation is expected to:
 *   1. Compute the SIGHASH_ALL preimage for each input.
 *   2. Produce the hybrid Falcon-1024 ‖ ML-DSA-65 signature + pubkey and place
 *      it in each input's `script_sig` (length-prefixed).
 *   3. Serialize to the node's expected wire format (`from_stratum_bytes`).
 *   4. Return the lowercase hex string ready for `client.sendRawTransaction`.
 */
export interface Signer {
  /** Sign `tx` and return broadcast-ready hex for `sendrawtransaction`. */
  signToHex(tx: UnsignedTx): Promise<string>;
  /** Optional: the change/source address this signer controls. */
  readonly address?: Address;
}

export interface BuildTransactionParams {
  /** Confirmed UTXOs to spend from (e.g. from `client.getUtxos`). */
  utxos: readonly SelectableUtxo[];
  /** Destination address (validated). */
  to: Address;
  /** Amount to send, in satoshis. */
  amount: Satoshis | bigint;
  /** Flat fee to reserve, in satoshis. Derive from `client.estimateFee`. */
  fee: Satoshis | bigint;
  /** Where to send change (usually the sender's own address). */
  changeAddress: Address;
  /** Change outputs below this (satoshis) are folded into the fee. Default 0. */
  dustThreshold?: Satoshis | bigint;
  /** Transaction version (default 1). */
  version?: number;
  /** Locktime (default 0). */
  locktime?: number;
}

export interface BuiltTransaction {
  tx: UnsignedTx;
  /** Sum of selected input values (satoshis). */
  inputTotal: bigint;
  /** Amount sent to the recipient (satoshis). */
  sent: bigint;
  /** Change returned to `changeAddress` (satoshis, 0 if none). */
  change: bigint;
  /** Effective fee (satoshis). */
  fee: bigint;
}

const MAX_SEQUENCE = 0xffffffff;

/**
 * Build an UNSIGNED Bloch transaction: run coin selection, add the recipient
 * output and (if any) a change output. Returns the structure to hand to a
 * WalletCore-backed {@link Signer}. Does not sign or broadcast.
 */
export function buildTransaction(params: BuildTransactionParams): BuiltTransaction {
  // parseSats, not BigInt(): it rejects the already-corrupted `number` form
  // (> 2^53) and anything past the supply cap instead of laundering it.
  const amount = parseSats(params.amount);
  const fee = parseSats(params.fee);
  const dust = params.dustThreshold !== undefined ? parseSats(params.dustThreshold) : 0n;

  const selectOpts: SelectCoinsOptions = { target: amount, fee, dustThreshold: dust };
  const selection = selectCoins(params.utxos, selectOpts);

  const toScript = addressToScriptPubkey(params.to);
  const outputs: UnsignedTxOutput[] = [
    { scriptPubkey: toScript, value: amount },
  ];

  if (selection.change > 0n) {
    outputs.push({
      scriptPubkey: addressToScriptPubkey(params.changeAddress),
      value: selection.change,
    });
  }

  const inputs: UnsignedTxInput[] = selection.inputs.map((u: SelectableUtxo) => ({
    prevTxid: u.txid,
    prevIndex: u.index,
    value: parseSats(u.value),
    scriptPubkey: u.script_pubkey,
    sequence: MAX_SEQUENCE,
  }));

  const tx: UnsignedTx = {
    version: params.version ?? 1,
    inputs,
    outputs,
    locktime: params.locktime ?? 0,
  };

  return {
    tx,
    inputTotal: selection.inputTotal,
    sent: amount,
    change: selection.change,
    fee: selection.fee,
  };
}
