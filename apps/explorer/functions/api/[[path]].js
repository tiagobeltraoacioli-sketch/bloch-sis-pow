// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Cloudflare Pages Function: GET /api/v1/*  — the public explorer API.
//
// A catch-all so the routes live in `edge/api.js`, which knows nothing about
// the Workers runtime and is therefore testable without one. Everything this
// file does is translate: URL in, runtime bindings in, JSON out.
//
// GET only. There is no write surface here on purpose — see EDGE_ABSENT in
// `edge/surface.js` for why `sendrawtransaction` is not served from behind a
// cache.

import { handleApi } from '../../edge/api.js';
import { buildOpts, runtimeFor } from '../../edge/core.js';

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, OPTIONS',
  'access-control-allow-headers': 'content-type',
  'access-control-max-age': '86400',
  'access-control-expose-headers': 'x-edge-corroboration, x-edge-cache, retry-after',
};

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS });
}

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const opts = buildOpts(env, request, runtimeFor(context));

  let out;
  try {
    out = await handleApi(url.pathname, url.searchParams, opts);
  } catch (e) {
    // An unhandled fault at the edge is an edge fault. Say so, rather than
    // letting a 500 read as a chain problem — which is exactly the confusion
    // `noUpstreamAnsweredError` in `functions/g4rpc.js` was written to end.
    out = {
      status: 500,
      body: {
        error: {
          reason: 'edge_fault',
          detail: String((e && e.message) || e),
          chainStatusKnown: false,
        },
      },
    };
  }

  const level = (out.body && out.body.corroboration && out.body.corroboration.level) || 'none';
  const headers = {
    'content-type': 'application/json',
    // Never at a shared cache. The corroboration and the cache age in the body
    // are computed per request; a CDN copy of them would be a stale statement
    // about staleness.
    'cache-control': 'no-store',
    'x-edge-corroboration': level,
    'x-edge-cache': (out.body && out.body.cache && out.body.cache.state) || 'bypass',
    ...CORS,
  };
  const retry =
    out.body && out.body.truncated_because && out.body.truncated_because.retry_after_ms;
  if (out.status === 429 && retry) headers['retry-after'] = String(Math.ceil(retry / 1000));

  return new Response(JSON.stringify(out.body, null, 2), { status: out.status, headers });
}

/** Anything but GET. Stated, rather than falling through to a 405 with no reason. */
export async function onRequest(context) {
  if (context.request.method === 'GET') return onRequestGet(context);
  if (context.request.method === 'OPTIONS') return onRequestOptions();
  return new Response(
    JSON.stringify({
      error: {
        reason: 'read_only',
        detail:
          'the explorer API is read-only. Signed transactions are broadcast at ' +
          'posternlabs.com/g4rpc, which fans them out to every node rather than ' +
          'to the two observers this endpoint reads from.',
      },
    }),
    { status: 405, headers: { 'content-type': 'application/json', allow: 'GET, OPTIONS', ...CORS } },
  );
}
