const gateway = 'https://posternlabs.com/g4rpc';
const defaultTimeoutMs = 12000;
const chainTimeoutMs = 20000;
const methods = {
  getchaininfo: { params: [] },
  getblockcount: { params: [] },
  getbuildinfo: { params: [] },
  getvalidatorcount: { params: [] },
  getvalidatoradmission: { params: [] },
  getmempoolinfo: { params: [] },
  getblockbyslot: { kind: 'slot', label: 'Slot number', help: 'A non-negative canonical slot. An empty slot returns an error.' },
  gettxstatus: { kind: 'hex', label: 'Transaction ID', help: 'Exactly 64 hexadecimal characters. No private data.' },
  gettxout: { kind: 'hex', second: true, label: 'Transaction ID', help: 'Exactly 64 hexadecimal characters; also provide the output index.' }
};

const form = document.getElementById('rpc-form');
const methodField = document.getElementById('rpc-method');
const parameterRow = document.getElementById('parameter-row');
const parameterField = document.getElementById('rpc-parameter');
const parameterLabel = document.getElementById('parameter-label');
const parameterHelp = document.getElementById('parameter-help');
const secondRow = document.getElementById('second-parameter-row');
const secondField = document.getElementById('rpc-parameter-two');
const message = document.getElementById('request-message');
const responseField = document.getElementById('rpc-response');
const curlField = document.getElementById('curl-command');
const copyResponseButton = document.getElementById('copy-response');
const copyCurlButton = document.getElementById('copy-curl');
const runButton = form.querySelector('button[type=submit]');
let lastResponse = '';

function selectedRequest() {
  const method = methodField.value;
  const config = methods[method];
  if (!config) throw new Error('This method is not available in the read-only console.');
  const params = [];
  if (config.kind === 'slot') {
    const value = parameterField.value.trim();
    if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value))) throw new Error('Enter a non-negative slot number.');
    params.push(Number(value));
  }
  if (config.kind === 'hex') {
    const value = parameterField.value.trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(value)) throw new Error('Enter exactly 64 hexadecimal characters.');
    params.push(value);
  }
  if (config.second) {
    const value = secondField.value.trim();
    if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value))) throw new Error('Enter a non-negative output index.');
    params.push(Number(value));
  }
  return { jsonrpc: '2.0', id: 'bloch-ops', method, params };
}

function updateMethod() {
  const config = methods[methodField.value];
  parameterRow.hidden = !config.kind;
  secondRow.hidden = !config.second;
  if (config.kind) {
    parameterLabel.textContent = config.label;
    parameterHelp.textContent = config.help;
    parameterField.inputMode = config.kind === 'slot' ? 'numeric' : 'text';
    parameterField.placeholder = config.kind === 'slot' ? 'e.g. 117873' : '64-character hexadecimal txid';
  }
  updateCurl();
}

function curlFor(request) {
  return `curl -sS '${gateway}' -H 'Content-Type: application/json' --data '${JSON.stringify(request)}'`;
}

function updateCurl() {
  try {
    curlField.textContent = curlFor(selectedRequest());
    copyCurlButton.disabled = false;
  } catch {
    curlField.textContent = 'Enter a valid parameter to generate a runnable curl command.';
    copyCurlButton.disabled = true;
  }
}

async function rpc(request) {
  const controller = new AbortController();
  const timeoutMs = request.method === 'getchaininfo' ? chainTimeoutMs : defaultTimeoutMs;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(gateway, {
      method: 'POST',
      mode: 'cors',
      credentials: 'omit',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
      signal: controller.signal
    });
    const body = await response.text();
    let parsed;
    try { parsed = JSON.parse(body); }
    catch { throw new Error(`Gateway returned HTTP ${response.status} without JSON.`); }
    return { response, parsed };
  } catch (error) {
    if (controller.signal.aborted) {
      const timeout = new Error(`Gateway request timed out after ${timeoutMs / 1000} seconds.`);
      timeout.name = 'GatewayTimeoutError';
      throw timeout;
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function setMessage(value, isError = false) {
  message.textContent = value;
  message.classList.toggle('error', isError);
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  let request;
  try { request = selectedRequest(); }
  catch (error) { setMessage(error.message, true); parameterField.focus(); return; }
  runButton.disabled = true;
  setMessage(`Requesting ${request.method}…`);
  responseField.textContent = 'Waiting for the gateway…';
  copyResponseButton.disabled = true;
  try {
    const { response, parsed } = await rpc(request);
    lastResponse = JSON.stringify(parsed, null, 2);
    responseField.textContent = lastResponse;
    copyResponseButton.disabled = false;
    const level = parsed.corroboration?.level || parsed.result?.corroboration?.level;
    setMessage(parsed.error ? `RPC error ${parsed.error.code ?? ''}: ${parsed.error.message || 'Unknown error'}` :
      `HTTP ${response.status} · ${level ? `evidence: ${level}` : 'read-only response received'}`, Boolean(parsed.error) || !response.ok);
  } catch (error) {
    responseField.textContent = 'No usable response received.';
    setMessage(error.name === 'GatewayTimeoutError' ? error.message : `Gateway request failed: ${error.message}`, true);
  } finally { runButton.disabled = false; }
});

async function copyText(value, button) {
  try {
    await navigator.clipboard.writeText(value);
    const old = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => { button.textContent = old; }, 1800);
  } catch { setMessage('Clipboard unavailable. Select and copy the text manually.', true); }
}

copyResponseButton.addEventListener('click', () => copyText(lastResponse, copyResponseButton));
copyCurlButton.addEventListener('click', () => copyText(curlField.textContent, copyCurlButton));
methodField.addEventListener('change', updateMethod);
parameterField.addEventListener('input', updateCurl);
secondField.addEventListener('input', updateCurl);

const evidenceStatus = document.getElementById('evidence-status');
const refreshEvidenceButton = document.getElementById('refresh-evidence');
const copyEvidenceButton = document.getElementById('copy-evidence');
let evidenceBusy = false;
let evidenceJSON = '';
const historyLimit = 120;
const history = [];
const historyRows = document.getElementById('history-rows');
const historyJSONButton = document.getElementById('download-history-json');
const historyCSVButton = document.getElementById('download-history-csv');
const clearHistoryButton = document.getElementById('clear-history');

function put(id, value) {
  document.getElementById(id).textContent = value ?? '—';
}

function number(value) {
  return Number.isFinite(value) ? value.toLocaleString('en-US') : '—';
}

function age(value) {
  if (!Number.isFinite(value) || value < 0) return 'Not reported';
  if (value < 1000) return `${Math.round(value)} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}

function corroborationOf(parsed) {
  return parsed.corroboration || parsed.result?.corroboration || {};
}

async function evidenceCall(method) {
  const started = performance.now();
  try {
    const { response, parsed } = await rpc({ jsonrpc: '2.0', id: `bloch-ops-${method}`, method, params: [] });
    if (!response.ok || parsed?.error || !parsed?.result || typeof parsed.result !== 'object') {
      throw new Error(parsed?.error?.message || `HTTP ${response.status}`);
    }
    return { parsed, elapsed_ms: Math.round(performance.now() - started) };
  } catch (error) {
    error.elapsed_ms = Math.round(performance.now() - started);
    throw error;
  }
}

function clearChainEvidence(state, detail) {
  for (const id of ['chain-height', 'chain-slot', 'chain-finalized', 'chain-validators', 'chain-lag',
    'evidence-heights', 'evidence-distance', 'evidence-latency', 'witness-count', 'witness-age',
    'plane-agreement', 'plane-age']) put(id, '—');
  put('snapshot-state', state);
  document.getElementById('snapshot-state').classList.add('error');
  put('snapshot-time', detail);
  put('witness-state', 'Current state unavailable');
  put('witness-note', 'See the observation history for earlier replies.');
}

function showChainEvidence({ parsed, elapsed_ms }) {
  const result = parsed.result;
  if (!Number.isSafeInteger(result.height) || result.height < 0 ||
      !Number.isSafeInteger(result.finalized_height) || result.finalized_height < 0 ||
      result.finalized_height > result.height) {
    throw new Error('Gateway returned invalid chain heights');
  }
  const c = corroborationOf(parsed);
  const plane = c.plane || {};
  const witness = c.witness || {};
  const consistent = c.level === 'corroborated' && plane.certified === true &&
    plane.agree_on_head === true && witness.available === true;
  const conflict = plane.agree_on_head === false || plane.certified === false || witness.available === false;

  put('chain-height', number(result.height));
  put('chain-slot', number(result.slot));
  put('chain-finalized', number(result.finalized_height));
  put('chain-validators', number(result.validators?.active));
  put('chain-lag', number(result.behind_by_slots));
  const snapshotState = document.getElementById('snapshot-state');
  snapshotState.textContent = consistent ? 'CORROBORATED REPLY' : 'REVIEW EVIDENCE';
  snapshotState.classList.toggle('error', !consistent);
  put('snapshot-time', `Observed ${new Date().toLocaleTimeString()} · ${elapsed_ms} ms`);

  put('evidence-level', consistent ? 'Corroborated reply' : 'Review corroboration');
  put('evidence-level-note', consistent ?
    'The gateway reports a certified plane, head agreement and an available witness.' :
    conflict ? 'The gateway reports a missing witness or a plane that is not certified or agreeing.' :
      `Reported level: ${c.level || 'unavailable'}. Check the raw reply and another node.`);
  put('evidence-heights', `${number(result.height)} / ${number(result.finalized_height)}`);
  put('evidence-distance', `${number(result.height - result.finalized_height)} blocks`);
  put('evidence-latency', `${elapsed_ms} ms (this browser)`);
  put('witness-state', conflict ? 'Review witness state' : consistent ? 'Witness reported' : 'Evidence incomplete');
  put('witness-note', c.level === 'corroborated' ?
    'The gateway reports these values. Witness freshness is shown below.' :
    'The gateway has not reported a complete corroborated chain view.');
  put('witness-count', Number.isFinite(c.archival_witnesses) && Number.isFinite(c.of) ?
    `${c.archival_witnesses} / ${c.of}` : 'Not reported');
  put('witness-age', age(witness.age_ms));
  put('plane-agreement', plane.agree_on_head === true ? 'Yes, reported' : plane.agree_on_head === false ? 'No, reported' : 'Not reported');
  put('plane-age', age(plane.age_ms));
  return {
    status: 'valid', height: result.height, finalized_height: result.finalized_height,
    finality_distance: result.height - result.finalized_height,
    slot: Number.isSafeInteger(result.slot) ? result.slot : null,
    behind_by_slots: Number.isSafeInteger(result.behind_by_slots) ? result.behind_by_slots : null,
    corroboration_level: typeof c.level === 'string' ? c.level : null,
    reported_plane_certified: plane.certified === true ? true : plane.certified === false ? false : null,
    reported_head_agreement: plane.agree_on_head === true ? true : plane.agree_on_head === false ? false : null,
    reported_witness_available: witness.available === true ? true : witness.available === false ? false : null,
    round_trip_ms: elapsed_ms
  };
}

function historyDocument() {
  return {
    schema: 'bloch-ops-rpc-observations-v1',
    exported_at: new Date().toISOString(),
    gateway,
    method: 'getchaininfo',
    scope: 'Requests made by this browser tab; in-memory only; latest 120 attempts.',
    limitations: 'Gateway observations may be cached. Browser timestamps and round trips are local. Samples do not prove uptime, consensus or a finality SLA.',
    samples: history
  };
}

function formatSigned(value, unit = '') {
  if (!Number.isFinite(value)) return '—';
  return `${value > 0 ? '+' : ''}${number(value)}${unit}`;
}

function renderHistory() {
  const last = history.at(-1);
  const valid = history.filter(sample => sample.status === 'valid');
  const current = valid.at(-1);
  const previous = valid.at(-2);
  put('history-count', number(history.length));
  put('history-head-change', previous ? formatSigned(current.height - previous.height) : '—');
  put('history-distance-change', previous ? formatSigned(current.finality_distance - previous.finality_distance, ' blocks') : '—');
  put('history-last-valid', current ? new Date(current.observed_at).toLocaleTimeString() : '—');
  put('history-summary', !last ? 'Waiting for the first chain request.' :
    `${valid.length} valid of ${history.length} recorded attempts · latest ${last.status} at ${new Date(last.observed_at).toLocaleTimeString()}. A valid reply is not a consensus determination.`);
  historyJSONButton.disabled = history.length === 0;
  historyCSVButton.disabled = history.length === 0;
  clearHistoryButton.disabled = history.length === 0;
  historyRows.replaceChildren();
  if (!last) {
    const row = historyRows.insertRow();
    const cell = row.insertCell();
    cell.colSpan = 7;
    cell.textContent = 'No samples in this tab yet.';
    return;
  }
  for (const sample of history.slice(-8).reverse()) {
    const row = historyRows.insertRow();
    const values = [
      new Date(sample.observed_at).toLocaleTimeString(),
      sample.status === 'valid' ? 'Valid reply' : `${sample.status}: ${sample.error || 'unknown'}`,
      number(sample.height), number(sample.finalized_height),
      sample.finality_distance == null ? '—' : `${number(sample.finality_distance)} blocks`,
      sample.corroboration_level || 'Not reported',
      sample.round_trip_ms == null ? '—' : `${number(sample.round_trip_ms)} ms`
    ];
    values.forEach(value => { const cell = row.insertCell(); cell.textContent = value; });
    if (sample.status !== 'valid') row.classList.add('history-failed');
  }
}

function recordHistory(sample) {
  history.push({ observed_at: new Date().toISOString(), ...sample });
  if (history.length > historyLimit) history.shift();
  renderHistory();
}

function downloadHistory(format) {
  if (!history.length) return;
  let body;
  let mime;
  if (format === 'json') {
    body = JSON.stringify(historyDocument(), null, 2);
    mime = 'application/json';
  } else {
    const fields = ['observed_at', 'status', 'error', 'height', 'finalized_height', 'finality_distance', 'slot', 'behind_by_slots', 'corroboration_level', 'reported_plane_certified', 'reported_head_agreement', 'reported_witness_available', 'round_trip_ms'];
    const csvCell = value => {
      const raw = String(value ?? '');
      const safe = /^[\s]*[=+\-@]/.test(raw) ? `'${raw}` : raw;
      return `"${safe.replaceAll('"', '""')}"`;
    };
    body = [fields.join(','), ...history.map(sample => fields.map(field => csvCell(sample[field])).join(','))].join('\r\n') + '\r\n';
    mime = 'text/csv';
  }
  const url = URL.createObjectURL(new Blob([body], { type: `${mime};charset=utf-8` }));
  const link = document.createElement('a');
  link.href = url;
  link.download = `bloch-ops-getchaininfo-${new Date().toISOString().replaceAll(':', '-')}.${format}`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function showBuildEvidence({ parsed }) {
  const result = parsed.result;
  put('build-version', result.package_version || result.build_version || 'Version not reported');
  put('build-node', corroborationOf(parsed).source_node || 'Not reported');
  put('build-commit', result.commit || 'Not reported');
  put('build-digest', result.source_digest ? `${result.source_digest_alg || 'digest'}: ${result.source_digest}` : 'Not reported');
}

async function loadEvidence() {
  if (evidenceBusy) return;
  evidenceBusy = true;
  refreshEvidenceButton.disabled = true;
  evidenceStatus.textContent = 'Requesting chain and build evidence…';
  const [chain, build] = await Promise.allSettled([evidenceCall('getchaininfo'), evidenceCall('getbuildinfo')]);
  const exportData = { observed_at: new Date().toISOString(), gateway, note: 'Gateway observations; not independent consensus proof.' };
  let failures = 0;
  if (chain.status === 'fulfilled') {
    try {
      recordHistory(showChainEvidence(chain.value));
      exportData.getchaininfo = chain.value.parsed;
      exportData.getchaininfo_round_trip_ms = chain.value.elapsed_ms;
    } catch (error) {
      failures++;
      recordHistory({ status: 'invalid', error: error.message, round_trip_ms: chain.value.elapsed_ms });
      exportData.getchaininfo = chain.value.parsed;
      exportData.getchaininfo_round_trip_ms = chain.value.elapsed_ms;
      exportData.getchaininfo_status = 'invalid';
      put('evidence-level', 'Invalid chain response');
      put('evidence-level-note', error.message);
      clearChainEvidence('INVALID REPLY', 'Latest refresh was invalid; live values cleared.');
    }
  } else {
    failures++;
    const timedOut = chain.reason?.name === 'GatewayTimeoutError';
    recordHistory({ status: timedOut ? 'timeout' : 'failed', error: chain.reason?.message || 'Gateway request failed', round_trip_ms: chain.reason?.elapsed_ms ?? null });
    put('evidence-level', timedOut ? 'Chain request timed out' : 'Chain request unavailable');
    put('evidence-level-note', chain.reason?.message || 'Gateway request failed.');
    clearChainEvidence(timedOut ? 'TIMED OUT' : 'UNAVAILABLE', 'Latest refresh failed; live values cleared.');
  }
  if (build.status === 'fulfilled') {
    showBuildEvidence(build.value);
    exportData.getbuildinfo = build.value.parsed;
    exportData.getbuildinfo_round_trip_ms = build.value.elapsed_ms;
  } else {
    failures++;
    put('build-version', 'Build request unavailable');
    put('build-node', build.reason?.message || 'Gateway request failed.');
    put('build-commit', '—');
    put('build-digest', '—');
  }
  evidenceJSON = JSON.stringify(exportData, null, 2);
  copyEvidenceButton.disabled = !exportData.getchaininfo && !exportData.getbuildinfo;
  evidenceStatus.textContent = `${failures ? `${failures} of 2 requests failed` : 'Both read requests answered'} · observed ${new Date().toLocaleTimeString()}`;
  evidenceStatus.classList.toggle('error', failures > 0);
  evidenceBusy = false;
  refreshEvidenceButton.disabled = false;
}

refreshEvidenceButton.addEventListener('click', loadEvidence);
copyEvidenceButton.addEventListener('click', () => copyText(evidenceJSON, copyEvidenceButton));
historyJSONButton.addEventListener('click', () => downloadHistory('json'));
historyCSVButton.addEventListener('click', () => downloadHistory('csv'));
clearHistoryButton.addEventListener('click', () => { history.length = 0; renderHistory(); });
updateMethod();
renderHistory();
loadEvidence();
setInterval(() => { if (!document.hidden) loadEvidence(); }, 30000);
