const gateway = 'https://posternlabs.com/g4rpc';
const fields = {
  state: document.getElementById('admission-state'),
  active: document.getElementById('admission-active'),
  epochs: document.getElementById('admission-epochs'),
  minimum: document.getElementById('admission-minimum'),
  detail: document.getElementById('admission-detail'),
  time: document.getElementById('admission-time'),
  refresh: document.getElementById('admission-refresh')
};
let lastSuccess = 0;
let pending = false;

function mark(state, activeClass = false) {
  fields.state.textContent = state;
  fields.state.classList.toggle('available', activeClass);
  fields.active.classList.toggle('available', activeClass);
}

function formatStake(sats) {
  if (!/^\d+$/.test(String(sats))) return '—';
  const amount = BigInt(sats);
  const whole = amount / 100000000n;
  const fraction = (amount % 100000000n).toString().padStart(8, '0').replace(/0+$/, '');
  return `${whole.toLocaleString('en-US')}${fraction ? `.${fraction}` : ''} BLCH`;
}

function updateAge() {
  if (!lastSuccess) return;
  const age = Math.floor((Date.now() - lastSuccess) / 1000);
  fields.time.textContent = `Response received ${age < 60 ? `${age}s` : `${Math.floor(age / 60)}m`} ago`;
  if (age >= 90 && !pending) {
    mark('STALE');
    fields.detail.textContent = 'The last response is over 90 seconds old. Recheck the gateway and your own synchronized node before acting.';
  }
}

async function refreshAdmission() {
  if (pending) return;
  pending = true;
  fields.refresh.disabled = true;
  if (!lastSuccess) mark('CHECKING');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(gateway, {
      method: 'POST', mode: 'cors', credentials: 'omit', cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 'bloch-ops-admission', method: 'getvalidatoradmission', params: [] }),
      signal: controller.signal
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    const result = payload?.result;
    if (payload?.error) throw new Error(`RPC ${payload.error.code ?? 'error'}`);
    if (!result || typeof result.active !== 'boolean' || !Number.isSafeInteger(result.epoch) || result.epoch < 0) {
      throw new Error('Incomplete RPC response');
    }
    fields.active.textContent = result.active ? 'Active' : 'Inactive';
    fields.epochs.textContent = `${result.epoch.toLocaleString('en-US')} / ${Number.isSafeInteger(result.activation_epoch) ? result.activation_epoch.toLocaleString('en-US') : 'not set'}`;
    fields.minimum.textContent = formatStake(result.minimum_stake_sat);
    const domain = typeof result.network_domain === 'string' && /^[0-9a-f]{64}$/i.test(result.network_domain)
      ? `${result.network_domain.slice(0, 12)}…${result.network_domain.slice(-8)}` : 'unreported';
    const evidence = payload.corroboration?.level === 'node_local' ? 'Node-local gateway reading' : 'Gateway reading';
    fields.detail.textContent = `${evidence}; network domain: ${domain}. Compare with your own node. This response describes admission only; it does not establish exit, payout or delegation readiness.`;
    fields.time.dateTime = new Date().toISOString();
    lastSuccess = Date.now();
    mark(result.active ? 'NODE REPORTS ACTIVE' : 'NODE REPORTS INACTIVE', result.active);
    updateAge();
  } catch (error) {
    mark(lastSuccess ? 'STALE / CHECK FAILED' : 'UNAVAILABLE');
    fields.active.textContent = lastSuccess ? 'Last response only' : 'Not verified';
    fields.active.classList.remove('available');
    fields.detail.textContent = `${error.name === 'AbortError' ? 'Gateway timed out' : `Gateway check failed (${error.message})`}. Check the endpoint or query your own synchronized node; do not treat a previous admission flag as current.`;
    if (!lastSuccess) fields.time.textContent = 'No response received';
  } finally {
    clearTimeout(timeout);
    pending = false;
    fields.refresh.disabled = false;
  }
}

fields.refresh.addEventListener('click', refreshAdmission);
refreshAdmission();
setInterval(() => { updateAge(); refreshAdmission(); }, 30000);
