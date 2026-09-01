// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The public explorer API. REST over the same read path as `/rpc`.
//
// ═══════════════════════════════════════════════════════════════════════════
// EVERY RESPONSE STATES HOW WELL CORROBORATED IT IS
// ═══════════════════════════════════════════════════════════════════════════
//
// The requirement this API exists to meet: `getchaininfo` through
// `posternlabs.com/g4rpc` is SOFT — when no two nodes agree it returns one
// node's answer rather than an error, which is the right call for a wallet
// that would otherwise go blank, but it means the caller is handed a number
// with no way to know that it is one node's opinion. g4rpc does attach a
// `corroboration` object, and this API makes that mandatory and uniform: every
// resource, cached or fresh, final or not, carries the same envelope.
//
//     { "data": …,
//       "corroboration": { "level": "final|corroborated|uncorroborated|node_local", … },
//       "cache": { "state": "hit|miss|coalesced|stale|bypass", "age_ms": … },
//       "chain": { "height": …, "finalized_height": …, "salt": … } }
//
// `level` is the field a consumer branches on, and it is never absent. A UI
// that shows a number without showing the level is choosing to hide it; it can
// no longer do so by accident.
//
// ═══════════════════════════════════════════════════════════════════════════
// THE FAN-OUT RULES
// ═══════════════════════════════════════════════════════════════════════════
//
// `/blocks` is the only endpoint that expands into more than one upstream
// call, and it is the shape that caused the incident this whole layer is a
// response to: a test that swept every slot on every poll — roughly 3,000
// round trips — starved the nodes it was measuring and then reported the
// fracture it had caused.
//
// So it is bounded three times over, and each bound is independent:
//   - `limit` is clamped to MAX_RANGE (20), not merely defaulted;
//   - each slot goes through the ordinary cached read, so a finalised slot
//     costs nothing after the first caller anywhere in the world;
//   - the whole fan-out is subject to the isolate's archival governor, which
//     means a cold range simply degrades to fewer blocks rather than to a
//     burst — the response says which slots it could not fill and why.

import { handleRead, Level } from './core.js';
import { witnessView, salt as lineageSalt, events as lineageEvents } from './lineage.js';
import { counters } from './governor.js';
import { toScriptHash, displayAddress } from './address.js';

/** The most blocks one request may ask for. */
export const MAX_RANGE = 20;

/** The most validators one request may ask for. */
export const MAX_VALIDATORS = 16;

function envelope(out, extra) {
  const body = out.body || {};
  return {
    data: body.result ?? null,
    error: body.error ?? null,
    corroboration: out.corroboration ?? { level: Level.Uncorroborated, missing: ['not evaluated'] },
    cache: { state: out.cacheState || 'bypass', age_ms: out.ageMs ?? null },
    ...(extra || {}),
  };
}

function chainStamp(now) {
  const w = witnessView(now);
  return {
    height: w.height,
    slot: w.slot,
    finalized_height: w.finalized_height,
    finalized_epoch: w.finalized_epoch,
    witness_age_ms: w.age_ms,
    cache_salt: lineageSalt(),
    reorg_events: lineageEvents(),
  };
}

async function call(method, params, opts) {
  return handleRead({ jsonrpc: '2.0', id: 1, method, params }, opts);
}

/** HTTP status for one of our envelopes. */
function statusFor(out) {
  if (out.status === 429) return 429;
  if (!out.body || !out.body.error) return 200;
  const code = out.body.error.code;
  if (code === -32601) return 404;
  if (code === -32602) return 400;
  // -32010 divergent and -32011 stale are "we will not answer this right now",
  // which is 503 and not 500: nothing is broken, and a retry is the correct
  // client behaviour.
  if (code === -32010 || code === -32011) return 503;
  return 502;
}

/**
 * Route one API request.
 *
 * Returns `{ status, body, headers }` and touches no runtime API, so the whole
 * surface is testable without a Worker.
 */
export async function handleApi(pathname, searchParams, opts) {
  const now = opts.now;
  const parts = pathname.replace(/^\/+|\/+$/g, '').split('/');
  // /api/v1/<resource>/<arg>
  if (parts[0] !== 'api') return notFound('unknown prefix');
  if (parts[1] !== 'v1') {
    return {
      status: 404,
      body: {
        error: {
          reason: 'unknown_api_version',
          detail: `this endpoint serves /api/v1 only; got '${parts[1] || '(none)'}'`,
        },
      },
    };
  }
  const resource = parts[2] || '';
  const arg = parts.slice(3).join('/');

  switch (resource) {
    case '':
    case 'capabilities':
      return capabilities(opts);
    case 'status':
      return status(opts);
    case 'block':
      return block(arg, opts);
    case 'blocks':
      return blocks(searchParams, opts);
    case 'validators':
      return validators(searchParams, opts);
    case 'validator':
      return validator(arg, opts);
    case 'address':
      return address(arg, searchParams, opts);
    case 'outpoint':
      return outpoint(arg, opts);
    case 'mempool':
      return mempool(opts);
    case 'edge':
      return edgeHealth(now);
    default:
      return notFound(`no resource '${resource}'`);
  }
}

function notFound(detail) {
  return {
    status: 404,
    body: {
      error: { reason: 'not_found', detail },
      routes: [
        'GET /api/v1/capabilities',
        'GET /api/v1/status',
        'GET /api/v1/blocks?from=<slot>&limit=<1..20>',
        'GET /api/v1/block/<block-id | slot number>',
        'GET /api/v1/validators?from=<index>&limit=<1..16>',
        'GET /api/v1/validator/<index>',
        'GET /api/v1/address/<bloch1q… | 40-hex | 64-hex>?utxos=1',
        'GET /api/v1/outpoint/<txid-hex>/<vout>',
        'GET /api/v1/mempool',
        'GET /api/v1/edge',
      ],
    },
  };
}

async function capabilities(opts) {
  const out = await call('getcapabilities', [], opts);
  return { status: 200, body: envelope(out, { chain: chainStamp(opts.now()) }) };
}

async function status(opts) {
  const out = await call('getchaininfo', [], opts);
  return { status: statusFor(out), body: envelope(out, { chain: chainStamp(opts.now()) }) };
}

async function block(arg, opts) {
  if (!arg) return badRequest('give a block id (64 hex) or a slot number');
  const isId = /^[0-9a-f]{64}$/i.test(arg);
  const isSlot = /^\d+$/.test(arg);
  if (!isId && !isSlot) {
    return badRequest(
      `'${arg}' is neither a 64-hex block id nor a slot number. Genesis-4 has no ` +
        `block-by-height call: under proof of stake the addressing unit is the slot.`,
    );
  }
  const out = isId
    ? await call('getblockbyid', [arg.toLowerCase()], opts)
    : await call('getblockbyslot', [Number(arg)], opts);
  return {
    status: statusFor(out),
    body: envelope(out, { addressed_by: isId ? 'block_id' : 'slot', chain: chainStamp(opts.now()) }),
  };
}

async function blocks(searchParams, opts) {
  const fromRaw = searchParams.get('from');
  const limit = clamp(Number(searchParams.get('limit') || 10), 1, MAX_RANGE);

  // Where to start when the caller did not say. The witness knows the head slot
  // and costs nothing to read, but it can be absent — the fleet may be
  // unreachable, and this endpoint is required to keep working when it is. So
  // fall back to asking the archivals, through the ordinary cached read, rather
  // than refusing a request that never needed the fleet in the first place.
  let from = fromRaw !== null ? Number(fromRaw) : witnessView(opts.now()).slot;
  if (fromRaw === null && !Number.isFinite(from)) {
    const head = await call('getchaininfo', [], opts);
    if (head.body.error) {
      return { status: statusFor(head), body: envelope(head, { chain: chainStamp(opts.now()) }) };
    }
    from = Number(head.body.result.slot);
  }
  if (!Number.isFinite(from) || from < 0) {
    return badRequest('`from` must be a slot number; omit it to start at the head');
  }

  const slots = [];
  for (let i = 0; i < limit && from - i >= 0; i++) slots.push(from - i);

  // Sequential, not parallel. This is the fan-out the incident was about: a
  // parallel sweep is precisely what starved the nodes, and the ordering is
  // free because a cached slot returns without a network call at all. The
  // governor stops the walk the moment it refuses, and the response says so.
  const items = [];
  let stopped = null;
  for (const s of slots) {
    const out = await call('getblockbyslot', [s], opts);
    if (out.status === 429) {
      stopped = { at_slot: s, reason: out.body.error.data.reason, retry_after_ms: out.retryAfterMs };
      break;
    }
    if (out.body.error) {
      // A slot with no block is a missed proposal — normal, and absence rather
      // than an error. SLOT_EMPTY is -32007 on this surface.
      items.push({
        slot: s,
        block: null,
        empty: out.body.error.code === -32007,
        error: out.body.error.code === -32007 ? null : out.body.error,
      });
      continue;
    }
    items.push({
      slot: s,
      block: out.body.result,
      empty: false,
      cache: out.cacheState,
      corroboration: out.corroboration && out.corroboration.level,
    });
  }

  return {
    status: stopped && !items.length ? 429 : 200,
    body: {
      data: items,
      requested: { from, limit, max_limit: MAX_RANGE },
      truncated: !!stopped,
      truncated_because: stopped,
      corroboration: weakest(items),
      cache: { state: 'per-item', age_ms: null },
      chain: chainStamp(opts.now()),
    },
  };
}

/**
 * The range's corroboration is the WEAKEST of its items.
 *
 * Reporting the best, or an average, would let one uncorroborated block hide
 * inside nineteen good ones. A range is only as trustworthy as its worst
 * member, and a caller deciding whether to act on it needs that number.
 */
function weakest(items) {
  const rank = { final: 3, corroborated: 2, uncorroborated: 1, node_local: 0 };
  let worst = null;
  for (const i of items) {
    const l = i.corroboration;
    if (!l) continue;
    if (worst === null || rank[l] < rank[worst]) worst = l;
  }
  return { level: worst || 'uncorroborated', of_items: items.length };
}

async function validators(searchParams, opts) {
  const count = await call('getvalidatorcount', [], opts);
  const from = clamp(Number(searchParams.get('from') || 0), 0, 1e9);
  const limit = clamp(Number(searchParams.get('limit') || 0), 0, MAX_VALIDATORS);

  const body = {
    data: { count: count.body.result ?? null, records: [] },
    requested: { from, limit, max_limit: MAX_VALIDATORS },
    truncated: false,
    corroboration: count.corroboration,
    cache: { state: count.cacheState, age_ms: count.ageMs ?? null },
    chain: chainStamp(opts.now()),
  };
  if (!limit) {
    // The default is the COUNT ONLY. `src/lib/g4.ts` `allValidators(64)` fires
    // 64 calls per page view; making that the default of a public API would
    // publish the same pattern to everyone who finds the URL.
    body.note =
      'records are not returned by default: pass ?limit=1..16 (with ?from=) to page ' +
      'through them. Fetching all 64 at once is the call pattern that made a test ' +
      'starve the nodes it was measuring.';
    return { status: statusFor(count), body };
  }

  let stopped = null;
  for (let i = from; i < from + limit; i++) {
    const out = await call('getvalidator', [i], opts);
    if (out.status === 429) {
      stopped = { at_index: i, reason: out.body.error.data.reason, retry_after_ms: out.retryAfterMs };
      break;
    }
    if (out.body.error) {
      body.data.records.push({ index: i, record: null, error: out.body.error });
      continue;
    }
    body.data.records.push({
      index: i,
      record: out.body.result,
      corroboration: out.corroboration && out.corroboration.level,
    });
  }
  body.truncated = !!stopped;
  body.truncated_because = stopped;
  return { status: 200, body };
}

async function validator(arg, opts) {
  if (!/^\d+$/.test(arg)) return badRequest('give a validator index, a non-negative integer');
  const out = await call('getvalidator', [Number(arg)], opts);
  return { status: statusFor(out), body: envelope(out, { chain: chainStamp(opts.now()) }) };
}

async function address(arg, searchParams, opts) {
  const parsed = toScriptHash(decodeURIComponent(arg || ''));
  if (parsed.error) {
    return {
      status: 400,
      body: {
        error: {
          reason: parsed.error,
          detail:
            parsed.detail ||
            'give a bloch1q… address, a 40-hex pubkey hash, or a 64-hex script hash',
        },
      },
    };
  }

  const bal = await call('getbalance', [parsed.scriptHash], opts);
  const wantUtxos = searchParams.get('utxos') === '1' || searchParams.get('utxos') === 'true';
  const body = envelope(bal, {
    identity: {
      script_hash: parsed.scriptHash,
      given_as: parsed.form,
      address: parsed.address || displayAddress(parsed.scriptHash),
    },
    chain: chainStamp(opts.now()),
  });

  if (wantUtxos) {
    const limit = clamp(Number(searchParams.get('limit') || 100), 1, 1000);
    const u = await call('getutxos', [parsed.scriptHash, limit], opts);
    body.utxos = u.body.error
      ? { error: u.body.error }
      : {
          ...u.body.result,
          corroboration: u.corroboration && u.corroboration.level,
          cache: u.cacheState,
        };
    // The weaker of the two decides the whole answer, for the same reason a
    // range takes its weakest item.
    if (u.corroboration && rankOf(u.corroboration.level) < rankOf(body.corroboration.level)) {
      body.corroboration = u.corroboration;
    }
  }

  // The cost is stated because it is unusual and because a caller ought to
  // know why it is metered eight times harder than a head poll.
  body.cost_note =
    'a balance is answered by a linear pass over the whole committed output set ' +
    '(452,726 entries) on the node consensus thread. This endpoint meters it at ' +
    'eight times a head poll for that reason.';
  return { status: statusFor(bal), body };
}

function rankOf(level) {
  return { final: 3, corroborated: 2, uncorroborated: 1, node_local: 0 }[level] ?? 1;
}

async function outpoint(arg, opts) {
  const [txid, voutRaw] = String(arg || '').split('/');
  if (!/^[0-9a-f]{64}$/i.test(txid || '')) return badRequest('give a 64-hex txid');
  const vout = voutRaw === undefined ? 0 : Number(voutRaw);
  if (!Number.isInteger(vout) || vout < 0) return badRequest('`vout` must be a non-negative integer');
  const out = await call('gettxout', [txid.toLowerCase(), vout], opts);
  return { status: statusFor(out), body: envelope(out, { chain: chainStamp(opts.now()) }) };
}

async function mempool(opts) {
  const out = await call('getmempoolinfo', [], opts);
  const body = envelope(out, { chain: chainStamp(opts.now()) });
  body.note =
    'node-local, not a chain fact. The mempool does not converge on this chain — ' +
    'one sweep of the fleet in a single minute returned pending counts of 0, 1, 2, ' +
    '4 and 5 — so this is the count at ONE observer and two observers disagreeing ' +
    'here is normal rather than a fork.';
  return { status: statusFor(out), body };
}

/** What this isolate has actually spent. Not a chain fact; an edge fact. */
function edgeHealth(now) {
  const t = now();
  return {
    status: 200,
    body: {
      data: {
        counters: { ...counters },
        witness: witnessView(t),
        cache_salt: lineageSalt(),
        reorg_events: lineageEvents(),
      },
      note:
        'per-isolate and reset whenever the isolate is recycled, so these are a ' +
        'sample of edge behaviour and not a total. The number that matters is the ' +
        'ratio of cacheHits to archivalCalls.',
      chain: chainStamp(t),
    },
  };
}

function badRequest(detail) {
  return { status: 400, body: { error: { reason: 'invalid_request', detail } } };
}

function clamp(n, lo, hi) {
  if (!Number.isFinite(n)) return lo;
  return Math.min(hi, Math.max(lo, Math.floor(n)));
}
