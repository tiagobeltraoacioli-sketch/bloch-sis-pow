// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The governor, for the Functions that are not `functions/rpc.js`.
//
// # Why this file exists
//
// `functions/rpc.js` goes through `edge/core.js`, which meters callers and —
// the part that actually protects the chain — caps the calls it is willing to
// MAKE regardless of how many it receives. The `/g4*` Functions did not. They
// were written for one page each, before the edge layer existed, and they went
// straight to the archivals:
//
//   `functions/g4.js`            no cache at all (`no-store`), a fan-out to
//                                BOTH archivals on every single request.
//   `functions/g4/slots.js`      cached and concurrency-capped, but nothing
//   `functions/g4/validators.js` bounded the calls per second across clients.
//
// A cache and a concurrency cap are not a rate limit. Concurrency bounds how
// many calls are in flight for ONE request; it says nothing about a thousand
// requests arriving in a second, which is exactly the shape of "someone linked
// the explorer somewhere". The dashboard's slot strip is the most-visited
// route on the site and it is served by `slots.js`.
//
// Two archivals were measured healthy while this was live. That is a fact
// about traffic on a quiet night, not a defence.
//
// # What a caller is charged, and what the chain is charged
//
// Two ledgers, deliberately separate, both from `edge/governor.js` so the
// budget is shared with `/rpc` rather than being a second allowance:
//
//   CLIENT bucket    fairness between callers. Per IP.
//   ARCHIVAL bucket  the ceiling this layer takes responsibility for, ~10% of
//                    one node's consensus thread. Per isolate, ALL callers.
//
// The archival charge must be the number of upstream calls the request will
// actually make — for a 32-slot range that is 32, not 1. Charging per request
// would make the expensive routes the cheapest to abuse.
//
// # Gate AFTER the cache, never before
//
// A cache hit costs the chain nothing, so it must not be charged against the
// archival budget and must not be refused when that budget is empty. Serving
// from cache under load is the entire point of having one.

import {
  clientBucket,
  clientKey,
  archivalGovernor,
  rateLimitedError,
  upstreamBudgetError,
} from './governor.js';

/**
 * Decide whether this request may proceed to the archivals.
 *
 * @param {Request} request
 * @param {object} opts
 * @param {number} opts.clientCost     tokens against the caller's own bucket
 * @param {number} opts.upstreamCalls  RPC calls this request will make upstream
 * @param {string} [opts.method]       for the error payload
 * @param {*}      [opts.id]           JSON-RPC id, when there is one
 * @param {function} [opts.now]
 * @returns {{error: object, status: number, retryAfterMs: number}|null}
 *          null when allowed; otherwise the refusal to serve.
 */
export function gate(request, opts) {
  // `now` is passed to the buckets as a FUNCTION — they hold it and call it on
  // every refill, so a timestamp here would freeze the clock and the bucket
  // would never refill.
  const now = opts.now || Date.now;
  const method = opts.method || null;
  const id = opts.id === undefined ? null : opts.id;

  const cost = Math.max(1, opts.clientCost | 0);
  const bucket = clientBucket(clientKey(request), now);
  if (!bucket.take(cost)) {
    const retry = bucket.retryAfterMs(cost);
    return { error: rateLimitedError(id, method, retry, cost), status: 429, retryAfterMs: retry };
  }

  // The caller has paid. Now: can the CHAIN afford it?
  //
  // Charged after the client check so a caller who is over their own limit is
  // told that, rather than being told the endpoint is busy — two different
  // problems with two different fixes on the caller's side.
  const need = Math.max(1, opts.upstreamCalls | 0);
  const gov = archivalGovernor(now);
  if (!gov.take(need)) {
    const retry = gov.retryAfterMs(need);
    return { error: upstreamBudgetError(id, method, retry), status: 503, retryAfterMs: retry };
  }

  return null;
}

/** The gate's refusal, as a Response, with the headers a client should honour. */
export function gateResponse(refusal, extraHeaders) {
  return new Response(JSON.stringify(refusal.error), {
    status: refusal.status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'Retry-After': String(Math.ceil(refusal.retryAfterMs / 1000)),
      ...(extraHeaders || {}),
    },
  });
}
