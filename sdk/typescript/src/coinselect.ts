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
  const sorted = [...utxos].sort((a, b) => {
    // Largest value first; break ties deterministically by txid:index.
    const bv = BigInt(b.value);
    const av = BigInt(a.value);
    if (bv !== av) return bv > av ? 1 : -1;
    if (a.txid !== b.txid) return a.txid < b.txid ? -1 : 1;
    return a.index - b.index;
  });

  const chosen: SelectableUtxo[] = [];
  let total = 0n;
  for (const u of sorted) {
    chosen.push(u);
    total += BigInt(u.value);
    if (total >= required) break;
  }

  if (total < required) {
    const available = sorted.reduce((acc, u) => acc + BigInt(u.value), 0n);
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
