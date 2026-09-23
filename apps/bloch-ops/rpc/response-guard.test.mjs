import assert from 'node:assert/strict';
import test from 'node:test';
import { maxRpcResponseBytes, readRpcResponse } from './response-guard.mjs';

function reply(body, status = 200, headers = {}) {
  return new Response(body, { status, headers });
}

test('accepts a matching JSON-RPC result and a structured RPC error', async () => {
  assert.deepEqual(await readRpcResponse(reply('{"jsonrpc":"2.0","id":"request-1","result":null}'), 'request-1'),
    { jsonrpc: '2.0', id: 'request-1', result: null });
  assert.equal((await readRpcResponse(reply('{"jsonrpc":"2.0","id":"request-1","error":{"code":-32601,"message":"Missing"}}', 400), 'request-1')).error.code, -32601);
});

test('rejects mismatched ids, malformed envelopes and invalid JSON', async () => {
  for (const body of [
    '{"jsonrpc":"2.0","id":"other","result":1}',
    '{"jsonrpc":"2.0","id":"request-1","result":1,"error":null}',
    '{"jsonrpc":"2.0","id":"request-1"}',
    '{"id":"request-1","result":1}',
    '[{"jsonrpc":"2.0","id":"request-1","result":1}]'
  ]) await assert.rejects(readRpcResponse(reply(body), 'request-1'), /invalid JSON-RPC envelope/);
  await assert.rejects(readRpcResponse(reply('<html>error</html>', 502), 'request-1'), /HTTP 502 without valid JSON/);
});

test('rejects declared and streamed responses above the byte limit', async () => {
  await assert.rejects(readRpcResponse(reply('{}', 200, { 'content-length': String(maxRpcResponseBytes + 1) }), 'request-1'), /1 MiB limit/);
  await assert.rejects(readRpcResponse(reply(' '.repeat(maxRpcResponseBytes + 1)), 'request-1'), /1 MiB limit/);
});
