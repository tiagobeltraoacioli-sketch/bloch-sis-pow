// Offline contract checks for the loopback-only client. No keys, funds, signing, or broadcast.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createPqShieldClient } from './pq-shield-client.mjs';

const H32 = 'ab'.repeat(32);
const HEX = '00';
const fields = { network: 'regtest', csv_delay: 144, deposit_amount_sat: 100_000,
  trigger_amount_sat: 99_500, fee_sat: 500, safe_destination: 'bcrt1safe',
  vault: { csv_delay: 144 } };
const unsigned = (signer, amount) => ({ unsigned_tx_hex: HEX, txid: H32,
  sighashes: [{ input_index: 0, sighash_hex: H32, sighash_type: 'SIGHASH_ALL',
    sign_with: `${signer} (secp256k1)`, witness_script_hex: HEX,
    prevout_amount_sat: amount }], non_custodial: 'sign locally' });
const responses = {
  '/health': { status: 'ok', service: 'pq-shield-api', non_custodial: true, signs: false },
  '/vault/address': { network: 'regtest', csv_delay: 144,
    deposit: { address: 'bcrt1deposit', witness_script_hex: HEX, script_pubkey_hex: HEX },
    trigger: { address: 'bcrt1trigger', witness_script_hex: HEX, script_pubkey_hex: HEX },
    non_custodial: 'sign locally' },
  '/vault/unvault-tx': { ...unsigned('hot_key', 100_000),
    trigger_output: { address: 'bcrt1trigger', vout: 0, amount_sat: 99_500 } },
  '/vault/branch-a-tx': { ...unsigned('hot_key', 99_500), matures_after_blocks: 144 },
  '/vault/clawback-tx': { ...unsigned('recovery_key', 99_500),
    safe_output: { address: 'bcrt1safe', vout: 0, amount_sat: 99_000 } },
  '/anchor/commitment': { commitment_bytes_hex: HEX, commitment_len: 1,
    bloch_governance_guard_hash: H32, non_custodial: 'sign locally' },
  '/anchor/verify': { valid: false, reason: 'invalid signature',
    verified_against_pq_pubkey: HEX, commitment_bytes_hex: HEX },
};

function withResponse(t, route, value, status = 200, contentType = 'application/json') {
  const original = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    assert.equal(url.origin, 'http://127.0.0.1:8787');
    assert.equal(url.pathname, route);
    assert.equal(options.method, route === '/health' ? 'GET' : 'POST');
    assert.equal(options.redirect, 'manual');
    if (options.body) assert.doesNotThrow(() => JSON.parse(options.body));
    return new Response(contentType === 'application/json' ? JSON.stringify(value) : value,
      { status, headers: { 'content-type': contentType } });
  };
  t.after(() => { globalThis.fetch = original; });
  return createPqShieldClient();
}

test('all seven routes accept the documented public response shapes', async (t) => {
  for (const [route, response] of Object.entries(responses)) {
    await t.test(route, async (sub) => {
      const client = withResponse(sub, route, response);
      const result = route === '/health' ? await client.health()
        : route === '/vault/address' ? await client.vaultAddress(fields)
        : route === '/vault/unvault-tx' ? await client.unsignedUnvault(fields)
        : route === '/vault/branch-a-tx' ? await client.unsignedBranchA(fields)
        : route === '/vault/clawback-tx' ? await client.unsignedClawback(fields)
        : route === '/anchor/commitment' ? await client.anchorCommitment(fields)
        : await client.verifyAnchor(fields, HEX);
      assert.deepEqual(result, response);
    });
  }
});

test('malformed or inconsistent responses fail closed', async (t) => {
  const cases = [
    ['/health', 'health', {}, { signs: true }],
    ['/vault/address', 'vaultAddress', fields, { trigger: { address: 'bcrt1trigger', witness_script_hex: 'zz' } }],
    ['/vault/unvault-tx', 'unsignedUnvault', fields, { trigger_output: { address: 'bcrt1trigger', vout: 0, amount_sat: 99_501 } }],
    ['/vault/branch-a-tx', 'unsignedBranchA', fields, { matures_after_blocks: 145 }],
    ['/vault/clawback-tx', 'unsignedClawback', fields, { safe_output: { address: 'attacker', vout: 0, amount_sat: 99_000 } }],
    ['/anchor/commitment', 'anchorCommitment', fields, { commitment_len: 2 }],
    ['/anchor/verify', 'verifyAnchor', fields, { verified_against_pq_pubkey: 'ff' }],
  ];
  for (const [route, method, input, patch] of cases) {
    await t.test(route, async (sub) => {
      const client = withResponse(sub, route, { ...responses[route], ...patch });
      await assert.rejects(method === 'verifyAnchor' ? client[method](input, HEX) : client[method](input),
        /Unexpected .* response/);
    });
  }
});

test('HTTP errors report route and status without including any server body', async (t) => {
  const client = withResponse(t, '/vault/address', null, 400);
  await assert.rejects(client.vaultAddress(fields), /\/vault\/address returned HTTP 400: server rejected request/);
});

test('plain-text 413 and malformed server errors never echo request or response data', async (t) => {
  const marker = 'do-not-repeat-this-marker';
  const cases = [
    [413, `Payload Too Large: ${marker}`, 'text/plain', 'request body exceeds server limit'],
    [500, `<html>${marker}</html>`, 'text/html', 'server rejected request'],
    [400, { error: `Invalid input ${marker}` }, 'application/json', 'server rejected request'],
  ];
  for (const [status, body, contentType, reason] of cases) {
    await t.test(`HTTP ${status}`, async (sub) => {
      const client = withResponse(sub, '/vault/address', body, status, contentType);
      await assert.rejects(client.vaultAddress({ ...fields, public_marker: marker }), (error) => {
        assert.equal(error.message, `/vault/address returned HTTP ${status}: ${reason}`);
        assert.equal(error.message.includes(marker), false);
        return true;
      });
    });
  }
});

test('malformed and oversized successful responses fail without echoing their bodies', async (t) => {
  const marker = 'do-not-repeat-this-marker';
  await t.test('invalid JSON', async (sub) => {
    const client = withResponse(sub, '/health', `<html>${marker}</html>`, 200, 'text/html');
    await assert.rejects(client.health(), (error) => {
      assert.equal(error.message, 'Unexpected /health response; invalid JSON');
      assert.equal(error.message.includes(marker), false);
      return true;
    });
  });
  await t.test('response above 64 KiB', async (sub) => {
    const client = withResponse(sub, '/health', 'x'.repeat(64 * 1024 + 1), 200, 'text/plain');
    await assert.rejects(client.health(), /Unexpected \/health response; body exceeds 64 KiB/);
  });
});

test('redirects are rejected without forwarding the public payload', async (t) => {
  const marker = 'public-request-marker';
  const prior = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = async (_url, options) => {
    fetches++;
    assert.equal(options.redirect, 'manual');
    assert.match(options.body, /public-request-marker/);
    return new Response(null, { status: 307, headers: {
      location: `https://unexpected.example/${marker}`,
    } });
  };
  t.after(() => { globalThis.fetch = prior; });
  await assert.rejects(createPqShieldClient().vaultAddress({ ...fields, marker }), (error) => {
    assert.equal(error.message, '/vault/address returned a redirect or unexpected origin');
    assert.equal(error.message.includes(marker), false);
    return true;
  });
  assert.equal(fetches, 1);
});

test('unexpected response origins and followed redirects are rejected', async (t) => {
  const prior = globalThis.fetch;
  t.after(() => { globalThis.fetch = prior; });
  for (const responseUrl of ['https://unexpected.example/health', 'http://127.0.0.1:9999/health']) {
    globalThis.fetch = async () => ({ url: responseUrl, status: 200, ok: true, body: null });
    await assert.rejects(createPqShieldClient().health(), /redirect or unexpected origin/);
  }
  globalThis.fetch = async () => ({ redirected: true, status: 200, ok: true, body: null });
  await assert.rejects(createPqShieldClient().health(), /redirect or unexpected origin/);
});

test('network and timeout failures never echo transport details', async (t) => {
  const marker = 'public-request-marker';
  const prior = globalThis.fetch;
  t.after(() => { globalThis.fetch = prior; });
  for (const error of [new Error(`Failed to fetch ${marker}`),
    new DOMException(`Timed out with ${marker}`, 'TimeoutError')]) {
    globalThis.fetch = async () => { throw error; };
    await assert.rejects(createPqShieldClient().vaultAddress({ ...fields, marker }), (caught) => {
      assert.equal(caught.message, 'Unable to reach local /vault/address service');
      assert.equal(caught.message.includes(marker), false);
      assert.equal(caught.cause, undefined);
      return true;
    });
  }
});

test('remote origins and secret-shaped nested request fields are rejected before fetch', async () => {
  for (const base of ['https://127.0.0.1:8787', 'http://localhost:8787',
    'http://127.0.0.2:8787', 'http://127.0.0.1:8787/path', 'http://user@127.0.0.1:8787']) {
    assert.throws(() => createPqShieldClient(base), /127\.0\.0\.1 self-hosted/);
  }
  const previous = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('fetch must not run'); };
  try {
    const client = createPqShieldClient();
    await assert.rejects(client.vaultAddress({ vault: [{ nested: { mnemonic: 'placeholder' } }] }),
      /Refusing secret-shaped field: mnemonic/);
    await assert.rejects(client.verifyAnchor({ signature: '00' }, ''),
      /independently trusted PQ public key/);
  } finally { globalThis.fetch = previous; }
});
