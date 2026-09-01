// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The explorer edge's method surface, and the cache class of each method.
//
// # Why this file exists separately from the node's RPC_SURFACE
//
// `crates/bloch-pos-node/src/rpc.rs` freezes the namespace the NODE answers
// (`RPC_SURFACE`, asserted in both directions by
// `the_rpc_method_namespace_is_frozen`). This file freezes the namespace the
// PUBLIC EDGE answers, which is deliberately a strict subset, and it records
// for every node method that is NOT exposed the reason it is not.
//
// The two-direction assertion lives in `tests/surface-frozen.test.mjs`, which
// reads `RPC_SURFACE` out of the Rust source — not out of a copy — and fails
// if this file names a method the node does not have, or omits a node method
// without giving a reason. That is the same freeze the node has, extended
// across the language boundary, because the previous edge allowlist
// (`functions/rpc.js`, Genesis-3) drifted for a whole chain generation and its
// own comment was the only thing that noticed.
//
// # The cache classes, which are the real content of this table
//
// The requirement is to cache on IMMUTABILITY, not on time. So each method is
// classified by *what makes its answer stop being able to change*:
//
//   head           the answer is about the tip. It changes every slot and is
//                  never immutable. Short TTL, single-flight, nothing more.
//   node_local     the answer is a property of the node that was asked, not of
//                  the chain (`getmempoolinfo` — the node's own doc comment
//                  says "node-local, not consensus"). It CANNOT be corroborated
//                  and must never be presented as if it were.
//   content        the answer is addressed by a hash of itself (`getblockbyid`).
//                  A block id cannot come to mean a different block. Cacheable
//                  for as long as we like — with one carve-out, below.
//   lineage        the answer is immutable ONLY relative to a chain lineage
//                  (`getblockbyslot`: which block sits at a slot is a fork-choice
//                  answer). Cacheable once the slot is finalised, under a cache
//                  salt that a detected reorg burns. See `lineage.js`.
//   epoch          the answer is constant within an epoch and changes at the
//                  boundary (validator records: activation, exit and effective
//                  stake all move on epoch transitions). Keyed by epoch, so the
//                  boundary invalidates by construction rather than by TTL.
//   mutable        the answer changes with every block that touches it
//                  (balances, utxos, outpoints). Short TTL only.
//
// # The carve-out on `content`
//
// A block fetched by id is immutable EXCEPT for its `finality` and `finalized`
// fields, which are not properties of the block at all — they are the asking
// node's classification of that block against its own checkpoints, and they
// move. Caching them would make a cached block assert a finality it no longer
// has, which is precisely the bug the client-side `finalBlocks` map in
// `src/lib/g4.ts` has today. `core.js` therefore strips both fields before
// storing and re-derives them at serve time from the current witness.

/** How an answer stops being able to change. See the header. */
export const CacheClass = {
  Head: 'head',
  NodeLocal: 'node_local',
  Content: 'content',
  Lineage: 'lineage',
  Epoch: 'epoch',
  Mutable: 'mutable',
};

/**
 * How expensive the call is for the node that answers it.
 *
 * This is not decoration: it selects which upstream budget the call is drawn
 * from (`governor.js`). `getbalance` and `getutxos` are a linear walk of the
 * entire committed eUTXO set — 452,726 outputs today — run on the consensus
 * thread, and the node's own source says so at `balance_json`. One explorer
 * address page can therefore cost the chain more than a thousand head polls.
 */
export const Cost = {
  /** O(1)-ish against state the engine already holds. */
  Cheap: 'cheap',
  /** A linear walk of the committed set on the consensus thread. */
  Walk: 'walk',
};

/**
 * Every method this edge answers.
 *
 * `corroboration` says what the edge is able to promise for the method:
 *   'quorum'      two independent archivals must return the identical answer.
 *   'lineage'     the answer is head-shaped; the witness certifies the lineage.
 *   'none'        the question is node-local and corroboration is meaningless.
 *   'edge'        the edge answers from its own knowledge; no node is asked.
 */
export const EDGE_SURFACE = [
  {
    name: 'getchaininfo',
    cacheClass: CacheClass.Head,
    cost: Cost.Cheap,
    corroboration: 'lineage',
    ttlMs: 3_000,
    summary: 'head, both checkpoints, active stake, and this node lag in slots',
  },
  {
    name: 'getblockcount',
    cacheClass: CacheClass.Head,
    cost: Cost.Cheap,
    corroboration: 'lineage',
    ttlMs: 3_000,
    summary: 'head height, slot, epoch, and the finalized height beside them',
  },
  {
    name: 'getblockbyid',
    cacheClass: CacheClass.Content,
    cost: Cost.Cheap,
    corroboration: 'quorum',
    // Seven days. Not "forever" only because the Workers cache is not a
    // durable store and a long max-age buys nothing past its own eviction.
    ttlMs: 7 * 24 * 3_600_000,
    summary: 'one block by its 32-byte id; the id is the immutability',
  },
  {
    name: 'getblockbyslot',
    cacheClass: CacheClass.Lineage,
    cost: Cost.Cheap,
    corroboration: 'quorum',
    // The unfinalised TTL. A finalised slot gets `finalTtlMs` instead.
    ttlMs: 6_000,
    finalTtlMs: 7 * 24 * 3_600_000,
    summary: 'the canonical block at a slot; which block that is, is fork choice',
  },
  {
    name: 'getvalidator',
    cacheClass: CacheClass.Epoch,
    cost: Cost.Cheap,
    corroboration: 'quorum',
    ttlMs: 120_000,
    summary: 'one registry record by index, with commission and lifecycle',
  },
  {
    name: 'getvalidatorcount',
    cacheClass: CacheClass.Epoch,
    cost: Cost.Cheap,
    corroboration: 'quorum',
    ttlMs: 60_000,
    summary: 'registered total, active count, and total active stake',
  },
  {
    name: 'getbalance',
    cacheClass: CacheClass.Mutable,
    cost: Cost.Walk,
    corroboration: 'quorum',
    ttlMs: 5_000,
    summary: 'summed value of every unspent output locked to a script hash',
  },
  {
    name: 'getutxos',
    cacheClass: CacheClass.Mutable,
    cost: Cost.Walk,
    corroboration: 'quorum',
    ttlMs: 5_000,
    summary: 'the outputs themselves, first page only',
  },
  {
    name: 'listunspent',
    cacheClass: CacheClass.Mutable,
    cost: Cost.Walk,
    corroboration: 'quorum',
    ttlMs: 5_000,
    aliasOf: 'getutxos',
    summary: 'the exchange-facing name for getutxos',
  },
  {
    name: 'gettxout',
    cacheClass: CacheClass.Mutable,
    cost: Cost.Cheap,
    corroboration: 'quorum',
    ttlMs: 5_000,
    summary: 'is this one outpoint still unspent, against committed state',
  },
  {
    name: 'getmempoolinfo',
    cacheClass: CacheClass.NodeLocal,
    cost: Cost.Cheap,
    corroboration: 'none',
    ttlMs: 4_000,
    summary: 'the ASKED NODE pending count and price — not a chain fact',
  },
  {
    name: 'getcapabilities',
    cacheClass: CacheClass.Epoch,
    cost: Cost.Cheap,
    // Answered by the edge itself. Every one of the nine deployed upstreams
    // returns -32601 for this name (measured 2026-09-01): it is in the repo's
    // RPC_SURFACE at surface version 4.1.0 and in no running binary. Forwarding
    // it would hand a caller a method-not-found for a method this edge does in
    // fact implement.
    corroboration: 'edge',
    ttlMs: 60_000,
    summary: 'what this EDGE guarantees; answered here, not forwarded',
  },
];

/** Node methods deliberately not exposed here, each with its reason. */
export const EDGE_ABSENT = [
  [
    'sendrawtransaction',
    'this edge is READ-ONLY. An explorer has no reason to broadcast, and a ' +
      'write path behind a cache is a way to lose a transaction silently. ' +
      'Broadcasting lives at posternlabs.com/g4rpc, which fans a signed ' +
      'transaction out to every node on purpose.',
  ],
  [
    'gettransaction',
    'the node routes this to a permanent NO_TRANSACTION_INDEX refusal: a ' +
      'Genesis-4 transaction has no id at this layer. Forwarding it would ' +
      'spend an upstream call to be told so.',
  ],
  [
    'getnewaddress',
    'the node routes this to a permanent NO_WALLET refusal. Same reasoning.',
  ],
];

const BY_NAME = new Map(EDGE_SURFACE.map((m) => [m.name, m]));

/** The method record, or null if this edge does not answer the name. */
export function methodSpec(name) {
  return BY_NAME.get(name) || null;
}

/** Names, sorted — the golden list the frozen-surface test asserts. */
export function edgeMethodNames() {
  return EDGE_SURFACE.map((m) => m.name).sort();
}

/**
 * Methods whose answer depends on which branch the answering node is on.
 *
 * Everything except the node-local and edge-answered ones. A branch-sensitive
 * answer from a single node is one node's opinion, and serving it is how a
 * balance came to appear and disappear in a wallet (see `functions/g4rpc.js`).
 */
export function isBranchSensitive(name) {
  const m = BY_NAME.get(name);
  return !!m && m.corroboration !== 'none' && m.corroboration !== 'edge';
}
