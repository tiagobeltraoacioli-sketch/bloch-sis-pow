import test from 'node:test';
import assert from 'node:assert/strict';
import { createRpcProxy, secureUpstream } from './rpc-proxy.mjs';
const env = { BLOCH_RPC_URL: 'https://rpc.example.org/api' };
const envelope = { jsonrpc: '2.0', id: 7, method: 'getchaininfo', params: [] };
const request = (body = envelope, headers = {}) => new Request('https://explorer.example.org/rpc', {
  method: 'POST', headers: { 'content-type': 'application/json', ...headers },
  body: typeof body === 'string' ? body : JSON.stringify(body),
});
const reply = text => new Response(text ?? '{"jsonrpc":"2.0","id":7,"result":{}}');
const call = (proxy, req = request(), config = env) => proxy.onRequestPost({ request: req, env: config });
const proxy = (fetchImpl, options = {}) => createRpcProxy(['getchaininfo'], { fetchImpl, ...options });

test('requires configured HTTPS and rejects credentials and public wildcard DNS', async () => {
  for (const url of [undefined, 'http://rpc.example.org', 'https://a:b@rpc.example.org', 'https://rpc.example.org/#x', 'https://1.2.3.4.sslip.io', 'https://foo.nip.io', 'https://xip.io', 'https://1.2.3.4.sslip.io.', 'https://foo.nip.io.']) {
    assert.throws(() => secureUpstream(url));
    assert.equal((await call(proxy(() => assert.fail('must not fetch')), request(), { BLOCH_RPC_URL: url })).status, 503);
  }
  assert.equal(secureUpstream(env.BLOCH_RPC_URL), env.BLOCH_RPC_URL);
});

test('forwards only read method envelope, forbids redirects and preserves large numeric amounts', async () => {
  const exact = '{"jsonrpc":"2.0","id":7,"result":{"amount":18446744073709551615}}';
  const p = proxy(async (url, options) => {
    assert.equal(url, env.BLOCH_RPC_URL);
    assert.equal(options.redirect, 'error');
    assert.deepEqual(JSON.parse(options.body), envelope);
    return reply(exact);
  });
  const response = await call(p, request({ ...envelope, extra: 'discard' }));
  assert.equal(response.status, 200);
  assert.equal(await response.text(), exact);
  assert.equal(response.headers.get('cache-control'), 'no-store');
});

test('rejects write methods, batches, malformed IDs and request envelopes before fetching', async () => {
  const p = proxy(() => assert.fail('must not fetch'));
  for (const body of [[envelope], null, { ...envelope, id: {} }, { ...envelope, id: 2 ** 53 }, { ...envelope, params: {} }, { ...envelope, jsonrpc: '1.0' }]) {
    assert.equal((await call(p, request(JSON.stringify(body)))).status, 400);
  }
  assert.equal((await call(p, request({ ...envelope, method: 'sendrawtransaction' }))).status, 403);
  assert.equal((await call(p, request('{'))).status, 400);
  assert.equal((await call(p, request(envelope, { 'content-type': 'text/plain' }))).status, 415);
});

test('bounds actual request bytes even without Content-Length', async () => {
  const p = proxy(() => assert.fail('must not fetch'), { requestLimit: 32 });
  assert.equal((await call(p)).status, 413);
  assert.equal((await call(p, request('{}', { 'content-length': '1000' }))).status, 413);
});

test('bounds streamed and declared upstream responses', async () => {
  for (const response of [reply('x'.repeat(256)), new Response('{}', { headers: { 'content-length': '256' } })]) {
    assert.equal((await call(proxy(async () => response, { responseLimit: 128 }))).status, 502);
  }
});

test('rejects mismatched IDs, ambiguous results, malformed JSON and HTTP failures', async () => {
  for (const response of [reply('{'), reply('{"jsonrpc":"2.0","id":8,"result":0}'), reply('{"jsonrpc":"2.0","id":7,"result":0,"error":{}}'), reply('{"jsonrpc":"2.0","id":7,"error":"bad"}'), new Response('private infrastructure detail', { status: 500 })]) {
    const result = await call(proxy(async () => response));
    assert.equal(result.status, 502);
    assert.doesNotMatch(await result.text(), /private infrastructure/);
  }
});

test('deadline aborts a fetch that never resolves and sanitizes errors', async () => {
  let signal;
  const result = await call(proxy((_url, options) => { signal = options.signal; return new Promise(() => {}); }, { upstreamTimeoutMs: 15 }));
  assert.equal(result.status, 502);
  assert.equal(signal.aborted, true);
  const failed = await call(proxy(async () => { throw new Error('secret-token-and-host'); }));
  assert.doesNotMatch(await failed.text(), /secret-token/);
});

test('deadline cancels stalled request and response bodies', async () => {
  let cancelled = 0;
  const stream = () => new ReadableStream({ cancel() { cancelled++; } });
  const incoming = new Request('https://example.org', { method: 'POST', headers: { 'content-type': 'application/json' }, body: stream(), duplex: 'half' });
  assert.equal((await call(proxy(() => assert.fail('must not fetch'), { requestTimeoutMs: 15 }), incoming)).status, 408);
  assert.equal((await call(proxy(async () => new Response(stream()), { upstreamTimeoutMs: 15 }))).status, 502);
  assert.equal(cancelled, 2);
});

test('preflight performs no upstream call', () => {
  const response = proxy(() => assert.fail('must not fetch')).onRequestOptions();
  assert.equal(response.status, 204);
  assert.equal(response.headers.get('access-control-allow-origin'), '*');
});

test('both frontend wrappers expose read-only transport', async () => {
  const explorer = await import('../explorer/functions/rpc.js');
  const pool = await import('../posternpool-site/functions/rpc.js');
  for (const handler of [explorer, pool]) {
    assert.equal((await handler.onRequestPost({ request: request({ ...envelope, method: 'sendrawtransaction' }), env })).status, 403);
  }
});

test('rejects lossy nested numeric parameters before forwarding', async () => {
  const p = proxy(() => assert.fail('must not fetch'));
  for (const params of ['[9007199254740993]', '[{"height":9007199254740993}]', '[1e400]', '[0.1]', '[1.00000000000000001]', '[9007199254740991.1]']) {
    assert.equal((await call(p, request('{"jsonrpc":"2.0","id":7,"method":"getchaininfo","params":' + params + '}'))).status, 400);
  }
});

test('duplicate method fields cannot bypass the allowlist', async () => {
  const p = proxy(async (_url, options) => {
    assert.equal(JSON.parse(options.body).method, 'getchaininfo');
    assert.doesNotMatch(options.body, /sendrawtransaction/);
    return reply();
  });
  assert.equal((await call(p, request('{"jsonrpc":"2.0","id":7,"method":"sendrawtransaction","method":"getchaininfo"}'))).status, 200);
  assert.equal((await call(p, request('{"jsonrpc":"2.0","id":7,"method":"getchaininfo","method":"sendrawtransaction"}'))).status, 403);
});
