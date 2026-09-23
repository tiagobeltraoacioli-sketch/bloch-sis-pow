const HASH = /^[0-9a-f]{64}$/i;
const UINT = /^(0|[1-9][0-9]*)$/;
const MAX_U64 = (1n << 64n) - 1n;

function money(value) {
  return typeof value === 'string' && UINT.test(value) && BigInt(value) <= MAX_U64;
}

function entriesValid(entries, txid, outputs) {
  if (!Array.isArray(entries)) return false;
  const seen = new Set();
  for (const entry of entries) {
    if (!HASH.test(entry?.txid) || !Number.isSafeInteger(entry.vout) || entry.vout < 0 ||
        !HASH.test(entry.script_hash) || !money(entry.value_sat) ||
        (outputs && entry.txid.toLowerCase() !== txid.toLowerCase())) return false;
    const key = `${entry.txid.toLowerCase()}:${entry.vout}`;
    if (seen.has(key)) return false;
    seen.add(key);
  }
  return true;
}

export function validIncludedReceipt(receipt, txid) {
  return HASH.test(txid) && HASH.test(receipt?.txid) &&
    receipt.txid.toLowerCase() === txid.toLowerCase() && HASH.test(receipt.block_id) &&
    entriesValid(receipt.inputs, txid, false) && entriesValid(receipt.outputs, txid, true) &&
    [receipt.height, receipt.slot, receipt.index, receipt.size_bytes,
      receipt.confirmations, receipt.finalized_height, receipt.observed_head_height,
      receipt.observed_head_slot].every(value => Number.isSafeInteger(value) && value >= 0) &&
    receipt.size_bytes > 0 && receipt.observed_head_height >= receipt.height &&
    receipt.observed_head_slot >= receipt.slot &&
    receipt.finalized_height <= receipt.observed_head_height &&
    receipt.confirmations === receipt.observed_head_height - receipt.height + 1 &&
    money(receipt.fee_sat) && money(receipt.stake_sat) &&
    typeof receipt.kind === 'string' && receipt.kind.length > 0 &&
    typeof receipt.source === 'string' && receipt.source.length > 0 &&
    typeof receipt.verification === 'string' && receipt.verification.length > 0 &&
    ['confirmed', 'finalized'].includes(receipt.status) &&
    receipt.finalized === (receipt.status === 'finalized') &&
    (!receipt.finalized || receipt.finalized_height >= receipt.height) &&
    ['corroborated', 'final'].includes(receipt.corroboration);
}
