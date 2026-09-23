import { validIncludedReceipt } from './receipt-validator.mjs';
import { compareReceiptObservations } from './receipt-comparison.mjs?v=20260923-5';
import { LookupResponseError, readBoundedJson } from './bounded-json.mjs?v=20260923-6';
import { matchDepositOutputs } from './deposit-match.mjs?v=20260923-7';
import { buildReconciliationEvidence } from './reconciliation-evidence.mjs?v=20260923-9';

const NODE_STATUS = new Set(['pending', 'included', 'justified', 'finalized', 'unknown']);

const form = document.getElementById('lookup-form');
const input = document.getElementById('lookup-txid');
const message = document.getElementById('lookup-message');
const result = document.getElementById('lookup-result');
const summary = document.getElementById('lookup-summary');
const source = document.getElementById('lookup-source');
const lists = [document.getElementById('lookup-inputs'), document.getElementById('lookup-outputs')];
const observation = document.getElementById('lookup-observation');
const observationText = document.getElementById('lookup-observation-text');
const observationEvidence = document.getElementById('lookup-observation-evidence');
const comparison = document.getElementById('lookup-comparison');
const comparisonStatus = document.getElementById('lookup-comparison-status');
const comparisonDetail = document.getElementById('lookup-comparison-detail');
const depositScript = document.getElementById('deposit-script-hash');
const depositAmount = document.getElementById('deposit-amount-sat');
const depositCard = document.getElementById('lookup-deposit');
const depositStatus = document.getElementById('lookup-deposit-status');
const depositDetail = document.getElementById('lookup-deposit-detail');
const depositOutpoints = document.getElementById('lookup-deposit-outpoints');
const exportButton = document.getElementById('lookup-export');
const tabHistory = new Map();
let currentEvidence = null;

exportButton.addEventListener('click', () => {
  if (!currentEvidence || result.hidden) return;
  const blob = new Blob([`${JSON.stringify(currentEvidence, null, 2)}\n`], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `bloch-tx-${currentEvidence.receipt.txid}-evidence.json`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

function recordObservation(current) {
  const previous = tabHistory.get(current.txid);
  const reference = previous?.lastIncluded ?? previous?.latest ?? null;
  const finding = compareReceiptObservations(reference, current);
  comparisonStatus.textContent = finding.status.replaceAll('_', ' ');
  comparisonDetail.textContent = finding.detail;
  comparison.classList.toggle('review', finding.requiresReview);
  comparison.hidden = false;
  tabHistory.delete(current.txid);
  tabHistory.set(current.txid, {
    latest: current,
    lastIncluded: current.kind === 'included' ? current : previous?.lastIncluded ?? null,
  });
  if (tabHistory.size > 50) tabHistory.delete(tabHistory.keys().next().value);
}

async function nodeStatus(txid) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch('https://posternlabs.com/g4rpc', {
      method: 'POST',
      credentials: 'omit',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 'bloch-ops-wallets', method: 'gettxstatus', params: [txid] }),
      signal: controller.signal,
      redirect: 'error',
    });
    if (!response.ok) throw new LookupResponseError('Gateway status unavailable.');
    const body = await readBoundedJson(response, 64 * 1024);
    if (body?.jsonrpc !== '2.0' || body.id !== 'bloch-ops-wallets' ||
        Object.hasOwn(body, 'error') || !NODE_STATUS.has(body.result?.status)) {
      throw new LookupResponseError('No usable node status returned.');
    }
    return {
      status: body.result.status,
      level: ['corroborated', 'degraded', 'uncorroborated', 'final'].includes(body.corroboration?.level)
        ? body.corroboration.level : 'not reported',
    };
  } finally {
    clearTimeout(timer);
  }
}

function addField(label, value) {
  const wrapper = document.createElement('div');
  const term = document.createElement('dt');
  const definition = document.createElement('dd');
  term.textContent = label;
  definition.textContent = value == null ? 'Unavailable' : String(value);
  wrapper.append(term, definition);
  summary.append(wrapper);
}

function addTransfers(target, values) {
  target.replaceChildren();
  if (!Array.isArray(values) || values.length === 0) {
    const item = document.createElement('li');
    item.textContent = 'No entries in this receipt.';
    target.append(item);
    return;
  }
  for (const value of values) {
    const item = document.createElement('li');
    const amount = document.createElement('strong');
    const outpoint = document.createElement('span');
    const script = document.createElement('span');
    amount.textContent = `${String(value.value_sat ?? 'Unavailable')} sat`;
    outpoint.textContent = `Outpoint: ${String(value.txid ?? 'Unavailable')}:${String(value.vout ?? 'Unavailable')}`;
    script.textContent = `Script hash: ${String(value.script_hash ?? 'Unavailable')}`;
    item.append(amount, outpoint, script);
    target.append(item);
  }
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  const txid = input.value.trim().toLowerCase();
  currentEvidence = null;
  if (!/^[0-9a-f]{64}$/.test(txid)) {
    message.textContent = 'Enter a valid 64-character hexadecimal txid.';
    result.hidden = true;
    observation.hidden = true;
    comparison.hidden = true;
    depositCard.hidden = true;
    return;
  }
  const expectedScript = depositScript.value.trim();
  const expectedAmount = depositAmount.value.trim();
  const matchRequested = expectedScript !== '' || expectedAmount !== '';
  if (matchRequested && (!/^[0-9a-f]{64}$/i.test(expectedScript) ||
      !/^[1-9][0-9]*$/.test(expectedAmount) || expectedAmount.length > 20 ||
      BigInt(expectedAmount) > (1n << 64n) - 1n)) {
    message.textContent = 'For deposit matching, enter both a 64-character public script hash and a positive integer satoshi amount.';
    result.hidden = true;
    observation.hidden = true;
    comparison.hidden = true;
    depositCard.hidden = true;
    return;
  }
  const url = `https://blochl1.com/api/v1/transactions/${txid}`;
  const button = form.querySelector('button');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  button.disabled = true;
  result.hidden = true;
  observation.hidden = true;
  comparison.hidden = true;
  depositCard.hidden = true;
  message.textContent = 'Reading the archival receipt and chain-head observation…';
  try {
    const response = await fetch(url, { signal: controller.signal, credentials: 'omit', redirect: 'error' });
    if (response.status === 404) {
      message.textContent = 'No included archival receipt found. Checking one node’s remembered status…';
      try {
        const status = await nodeStatus(txid);
        observationText.textContent = `The gateway node reports “${status.status}” for this txid. This is a node-local observation; it cannot replace an included receipt.`;
        observationEvidence.textContent = `Evidence level: ${status.level}. “Unknown” does not prove absence. Do not credit a deposit without the required included receipt and finality evidence.`;
        observation.hidden = false;
        message.textContent = 'Archival receipt unavailable. Treat this transaction as unresolved for reconciliation.';
      } catch {
        message.textContent = 'Archival receipt unavailable and node status could not be checked. Pending, delayed indexing or an unknown txid are all possible; do not infer failure.';
      }
      recordObservation({ kind: 'unresolved', txid });
      return;
    }
    if (!response.ok) throw new LookupResponseError(`The public API returned HTTP ${response.status}.`);
    const receipt = await readBoundedJson(response, 2 * 1024 * 1024);
    if (!validIncludedReceipt(receipt, txid)) {
      throw new LookupResponseError('The API returned an incomplete or inconsistent included receipt.');
    }
    if (matchRequested) {
      const matched = matchDepositOutputs(receipt, expectedScript, expectedAmount);
      depositStatus.textContent = matched.exactTotal ? 'Exact output total observed' : 'Deposit amount needs review';
      depositDetail.textContent = `${matched.outputs.length} matching outpoint(s); ${matched.matchedAmountSat} sat observed against ${matched.expectedAmountSat} sat expected. Difference: ${matched.differenceSat} sat. This is not a credit or finality decision.`;
      depositOutpoints.replaceChildren();
      for (const output of matched.outputs) {
        const item = document.createElement('li');
        item.textContent = `${output.txid}:${output.vout} · ${output.valueSat} sat`;
        depositOutpoints.append(item);
      }
      depositOutpoints.hidden = matched.outputs.length === 0;
      depositCard.classList.toggle('review', !matched.exactTotal);
      depositCard.hidden = false;
    }
    const previous = tabHistory.get(txid);
    currentEvidence = buildReconciliationEvidence(receipt, {
      observedAt: new Date().toISOString(),
      previousObservation: previous?.lastIncluded ?? previous?.latest ?? null,
      expectedScriptHash: matchRequested ? expectedScript : null,
      expectedAmountSat: matchRequested ? expectedAmount : null,
    });
    recordObservation({ kind: 'included', txid, receipt });
    summary.replaceChildren();
    addField('Transaction ID', receipt.txid);
    addField('Status', receipt.status);
    addField('Finalized', receipt.finalized === true ? 'Yes' : receipt.finalized === false ? 'No' : 'Unavailable');
    addField('Confirmations', receipt.confirmations);
    addField('Height / slot', `${String(receipt.height ?? 'Unavailable')} / ${String(receipt.slot ?? 'Unavailable')}`);
    addField('Block ID', receipt.block_id);
    addField('Fee', receipt.fee_sat == null ? null : `${receipt.fee_sat} sat`);
    addField('Observed head', `${String(receipt.observed_head_height ?? 'Unavailable')} / slot ${String(receipt.observed_head_slot ?? 'Unavailable')}`);
    addField('Finalized height', receipt.finalized_height);
    addField('Corroboration', receipt.corroboration);
    addField('Receipt verification', receipt.verification);
    addTransfers(lists[0], receipt.inputs);
    addTransfers(lists[1], receipt.outputs);
    source.href = url;
    result.hidden = false;
    message.textContent = 'Included receipt loaded. Apply your own credit and finality policy.';
  } catch (error) {
    message.textContent = error.name === 'AbortError' ? 'The lookup timed out. Retry or use the source API directly.' :
      error instanceof LookupResponseError ? error.message : 'Lookup unavailable. Retry or use the source API directly.';
  } finally {
    clearTimeout(timer);
    button.disabled = false;
  }
});
