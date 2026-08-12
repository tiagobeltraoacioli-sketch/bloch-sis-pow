// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
//
// Coin selection for Bloch's UTXO model.
//
// SCAFFOLD: this is a simple, deterministic accumulative selector (largest
// UTXOs first), adequate for wallets and payment flows but NOT privacy- or
// fee-optimal. Bloch's hybrid Falcon-1024 ‖ ML-DSA-65 signatures are large
// (~10 KB of script_sig per input), so input count dominates transaction size
// and fee — prefer FEWER, larger inputs, which largest-first naturally does.

import type { Satoshis, Utxo } from "./types.js";
import { parseSats } from "./units.js";

export interface SelectableUtxo extends Utxo {
  /** value in satoshis (inherited from Utxo.value) */
  value: Satoshis;
}

export interface CoinSelectionResult {
  /** Chosen inputs. */
  inputs: SelectableUtxo[];
  /** Sum of chosen input values, in satoshis. */
  inputTotal: bigint;
  /** Change to return to sender, in satoshis (0 if none / below dust). */
  change: bigint;
  /** The fee this selection assumes, in satoshis. */
  fee: bigint;
}

export class InsufficientFundsError extends Error {
  readonly required: bigint;
  readonly available: bigint;
  constructor(required: bigint, available: bigint) {
    super(`insufficient funds: need ${required} sat, have ${available} sat`);
    this.name = "InsufficientFundsError";
    this.required = required;
    this.available = available;
    Object.setPrototypeOf(this, InsufficientFundsError.prototype);
  }
}

export interface SelectCoinsOptions {
  /** Target amount to send, in satoshis. */
  target: bigint;
  /** Flat fee to reserve, in satoshis. Use estimatefee to derive this. */
  fee: bigint;
  /** Outputs below this many satoshis are folded into the fee, not returned as change. */
  dustThreshold?: bigint;
}

/**
 * Accumulative (largest-first) coin selection.
 *
 * @throws {InsufficientFundsError} when the UTXO set cannot cover target + fee.
 */
export function selectCoins(
  utxos: readonly SelectableUtxo[],
  opts: SelectCoinsOptions,
): CoinSelectionResult {
  const { target, fee } = opts;
  const dust = opts.dustThreshold ?? 0n;
  if (target < 0n) throw new RangeError("target must be >= 0");
  if (fee < 0n) throw new RangeError("fee must be >= 0");

  const required = target + fee;

  // Parse every wire value ONCE, up front, into exact bigints. `Satoshis` is a
  // `string | number` wire union (types.ts), and parseSats rejects the
  // already-rounded `number` form rather than letting a corrupted amount decide
  // which coins get spent.
  const sorted = [...utxos]
    .map((u) => ({ u, v: parseSats(u.value) }))
    .sort((a, b) => {
      // Largest value first; break ties deterministically by txid:index.
      if (b.v !== a.v) return b.v > a.v ? 1 : -1;
      if (a.u.txid !== b.u.txid) return a.u.txid < b.u.txid ? -1 : 1;
      return a.u.index - b.u.index;
    });

  const chosen: SelectableUtxo[] = [];
  let total = 0n;
  for (const { u, v } of sorted) {
    chosen.push(u);
    total += v;
    if (total >= required) break;
  }

  if (total < required) {
    const available = sorted.reduce((acc, e) => acc + e.v, 0n);
    throw new InsufficientFundsError(required, available);
  }

  let change = total - required;
  let effectiveFee = fee;
  if (change > 0n && change < dust) {
    // Too small to be worth a change output — donate it to the fee.
    effectiveFee += change;
    change = 0n;
  }

  return { inputs: chosen, inputTotal: total, change, fee: effectiveFee };
}
