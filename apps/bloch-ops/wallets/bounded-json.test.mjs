import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LookupResponseError, readBoundedJson } from './bounded-json.mjs';

test('reads a bounded UTF-8 JSON receipt', async () => {
  assert.deepEqual(await readBoundedJson(new Response('{"status":"finalized"}'), 100), { status: 'finalized' });
});

test('rejects declared and streamed oversized responses before parsing', async () => {
  await assert.rejects(readBoundedJson(new Response('{}', { headers: { 'content-length': '101' } }), 100), LookupResponseError);
  await assert.rejects(readBoundedJson(new Response('{"value":"' + 'x'.repeat(100) + '"}'), 100), /size limit/);
});

test('malformed JSON and stream errors have controlled messages', async () => {
  await assert.rejects(readBoundedJson(new Response('{private payload'), 100), /not valid JSON/);
  const response = new Response(new ReadableStream({ start(controller) { controller.error(new Error('secret upstream detail')); } }));
  await assert.rejects(readBoundedJson(response, 100), error => {
    assert.equal(error.message, 'Unable to read the lookup response.');
    return true;
  });
});
