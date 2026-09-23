import { validIncludedReceipt } from './receipt-validator.mjs';

const HASH = /^[0-9a-f]{64}$/i;

function validObservation(item) {
  return item && HASH.test(item.txid) && (
    item.kind === 'unresolved' ||
    (item.kind === 'included' && validIncludedReceipt(item.receipt, item.txid))
  );
}

function transfers(receipt) {
  const entries = list => list.map(({ txid, vout, value_sat, script_hash }) =>
    [txid.toLowerCase(), vout, value_sat, script_hash.toLowerCase()]);
  return JSON.stringify([entries(receipt.inputs), entries(receipt.outputs),
    receipt.fee_sat, receipt.stake_sat]);
}

export function compareReceiptObservations(previous, current) {
  if (!validObservation(current) || (previous !== null && !validObservation(previous))) {
    throw new Error('Complete transaction observations are required');
  }
  if (previous && previous.txid.toLowerCase() !== current.txid.toLowerCase()) {
    throw new Error('Cannot compare different transaction IDs');
  }
  const result = (status, requiresReview, detail) => ({ status, requiresReview, detail });
  if (current.kind === 'unresolved') {
    return previous?.kind === 'included'
      ? result('receipt_unavailable', true, 'A previously included receipt is unavailable. Review the index and chain independently; this alone does not prove a reorganization or failure.')
      : result('unresolved', true, 'No included archival receipt is available. Node status alone cannot support a credit decision.');
  }
  if (previous?.kind !== 'included') {
    return result('first_inclusion', true, 'Included receipt observed. Apply your own destination, amount, confirmation and finality policy.');
  }
  const before = previous.receipt, after = current.receipt;
  if (before.block_id.toLowerCase() !== after.block_id.toLowerCase() ||
      before.height !== after.height || before.slot !== after.slot) {
    return result('block_changed', true, 'Inclusion block, height or slot changed. Review earlier reconciliation decisions.');
  }
  if (transfers(before) !== transfers(after)) {
    return result('receipt_changed', true, 'Canonical inputs, outputs or amounts changed for the same inclusion. Review source records.');
  }
  if (before.finalized && !after.finalized) {
    return result('finality_regressed', true, 'Reported finality regressed. Compare independent nodes and checkpoints.');
  }
  if (after.confirmations < before.confirmations ||
      after.observed_head_height < before.observed_head_height) {
    return result('head_regressed', true, 'Reported head or confirmations moved backward. Check for stale data or a reorganization.');
  }
  return result('consistent', false, 'This tab saw the same included transaction and nondecreasing reported progress. This is not independent settlement proof.');
}
