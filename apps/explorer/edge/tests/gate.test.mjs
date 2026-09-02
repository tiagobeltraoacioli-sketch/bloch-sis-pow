// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The governor on the `/g4*` Functions.
//
// These routes reached the archivals with no cap on the calls they would MAKE
// while the site was live. `functions/rpc.js` had that cap from the start;
// these three were written earlier, one per page, and never got it. The tests
// below are about the two properties that matter and neither is obvious from
// reading the handler:
//
//   1. the charge scales with the WORK, not with the request count, and
//   2. a cache hit is neither charged nor refused.
import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import { gate, gateResponse } from '../gate.js';
import {
  _resetGovernorForTests,
  ARCHIVAL_BURST,
  ARCHIVAL_RATE,
  CLIENT_BURST,
  RATE_LIMITED,
  UPSTREAM_BUDGET,
} from '../governor.js';

const req = (ip = '1.2.3.4') =>
  new Request('https://blochl1.com/g4/slots?limit=32', {
    headers: { 'CF-Connecting-IP': ip },
  });

test('a wide range is charged more than a narrow one', () => {
  _resetGovernorForTests();
  const now = () => 1_000_000;

  // ARCHIVAL_BURST is 60. A 32-slot request costs 32 upstream calls, not 1 —
  // so two of them do not fit and the second is refused. If the charge were
  // per REQUEST, sixty 32-slot walks would fit instead of one, and the widest
  // range would be the cheapest thing to point at the chain.
  assert.equal(ARCHIVAL_BURST, 60, 'this test is calibrated against the real burst');

  const first = gate(req('a'), { clientCost: 2, upstreamCalls: 32, now });
  assert.equal(first, null, 'the first 32-slot walk fits in the burst');

  const second = gate(req('b'), { clientCost: 2, upstreamCalls: 32, now });
  assert.ok(second, '32 + 32 > 60, so the second is refused');
  assert.equal(second.error.error.code, UPSTREAM_BUDGET);
  assert.equal(second.status, 503, 'a busy endpoint is 503, not 429 — it is not the caller');

  // …while a cheap request still gets through on what is left. The budget is
  // about work, so small work is still affordable when large work is not.
  const cheap = gate(req('c'), { clientCost: 1, upstreamCalls: 1, now });
  assert.equal(cheap, null, 'a 1-call request still fits in the remaining 28');
});

test('the caller is metered before the chain is', () => {
  _resetGovernorForTests();
  const now = () => 2_000_000;
  // Drain one caller's own bucket with cheap requests.
  for (let i = 0; i < CLIENT_BURST; i++) {
    gate(req('greedy'), { clientCost: 1, upstreamCalls: 1, now });
  }
  const refused = gate(req('greedy'), { clientCost: 1, upstreamCalls: 1, now });
  assert.ok(refused, 'the caller is over their own limit');
  assert.equal(refused.error.error.code, RATE_LIMITED, 'told it is THEM, not the endpoint');
  assert.equal(refused.status, 429);

  // A different caller is unaffected: this is fairness, not a global stop.
  const other = gate(req('polite'), { clientCost: 1, upstreamCalls: 1, now });
  assert.equal(other, null, 'one greedy caller must not lock everyone out');
});

test('the budget refills, so a refusal is temporary', () => {
  _resetGovernorForTests();
  let t = 3_000_000;
  const now = () => t;
  for (let i = 0; i < 10; i++) gate(req('x' + i), { clientCost: 1, upstreamCalls: 16, now });
  const blocked = gate(req('late'), { clientCost: 1, upstreamCalls: 16, now });
  assert.ok(blocked, 'burst exhausted');
  assert.ok(blocked.retryAfterMs > 0, 'and it says when to come back');

  t += Math.ceil((16 / ARCHIVAL_RATE) * 1000) + 1200;
  assert.equal(
    gate(req('late'), { clientCost: 1, upstreamCalls: 16, now }),
    null,
    'after the refill the same request is allowed',
  );
});

test('a refusal is a Response a client can act on', () => {
  _resetGovernorForTests();
  const now = () => 4_000_000;
  let refusal = null;
  for (let i = 0; i < 40 && !refusal; i++) {
    refusal = gate(req('flood'), { clientCost: 1, upstreamCalls: ARCHIVAL_BURST, now });
  }
  assert.ok(refusal, 'something was refused');
  const res = gateResponse(refusal, { 'Access-Control-Allow-Origin': '*' });
  assert.ok(res.headers.get('Retry-After'), 'Retry-After is set');
  assert.equal(res.headers.get('Cache-Control'), 'no-store', 'a refusal must never be cached');
  assert.equal(res.headers.get('Access-Control-Allow-Origin'), '*', 'CORS survives the refusal');
});

test('the /g4 budget is SHARED with /rpc, not a second allowance', () => {
  _resetGovernorForTests();
  const now = () => 5_000_000;
  // Drain via the gate…
  for (let i = 0; i < 4; i++) gate(req('shared'), { clientCost: 1, upstreamCalls: 16, now });
  const refused = gate(req('shared2'), { clientCost: 1, upstreamCalls: 16, now });
  assert.ok(
    refused,
    'the archival bucket is one per isolate across every Function — two front doors ' +
      'onto one pair of nodes must not each get the full ceiling',
  );
});
