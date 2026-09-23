import { validIncludedReceipt } from './receipt-validator.mjs';

const HASH = /^[0-9a-f]{64}$/i;
const AMOUNT = /^(0|[1-9][0-9]*)$/;
const MAX_U64 = (1n << 64n) - 1n;

export function matchDepositOutputs(receipt, scriptHash, expectedAmountSat) {
  if (!validIncludedReceipt(receipt, receipt?.txid)) {
    throw new Error('A complete included receipt is required');
  }
  if (typeof scriptHash !== 'string' || !HASH.test(scriptHash)) {
    throw new Error('Expected script hash must be 64 hexadecimal characters');
  }
  if (typeof expectedAmountSat !== 'string' || !AMOUNT.test(expectedAmountSat) || expectedAmountSat.length > 20 ||
      BigInt(expectedAmountSat) === 0n || BigInt(expectedAmountSat) > MAX_U64) {
    throw new Error('Expected amount must be a positive unsigned 64-bit satoshi string');
  }
  const target = scriptHash.toLowerCase();
  const outputs = receipt.outputs.filter(output => output.script_hash.toLowerCase() === target)
    .map(output => ({ txid: receipt.txid, vout: output.vout, valueSat: output.value_sat }));
  const matched = outputs.reduce((sum, output) => sum + BigInt(output.valueSat), 0n);
  const expected = BigInt(expectedAmountSat);
  return {
    txid: receipt.txid, scriptHash: target, expectedAmountSat,
    matchedAmountSat: matched.toString(), differenceSat: (matched - expected).toString(),
    exactTotal: outputs.length > 0 && matched === expected, outputs,
    note: 'Output matching is a local receipt measurement, not a deposit credit or finality decision.',
  };
}
