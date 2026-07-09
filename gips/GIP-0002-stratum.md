# GIP-0002: Stratum mining protocol

```
GIP: 0002
Title: Stratum mining protocol
Author: BLOCH Founder <founder@blochlayer.com>
Status: Draft
Type: Standards Track
Created: 2026-04-21
```

## Abstract

Add a stratum-protocol mining server to the reference Bloch-SIS Protocol node
so that SHA-256d ASICs and existing mining firmware can participate in
block production. Sprint AA.1 (solo mode) lets a miner direct 100% of
a found block's reward to an address of their choosing. Sprint AA.2
(pool mode) extends the same protocol handler with share accounting
and PPLNS payout. Both modes use Stratum V1 — the 2012 JSON-RPC-over-TCP
variant every ASIC speaks natively. Stratum V2 is on the longer-term
roadmap but not in scope for this GIP.

## Motivation

### The problem

Today, Bloch-SIS Protocol mining is CPU-only. The miner loop in `src/main.rs`
builds a block template locally, runs SHA-256d on the node's CPUs until
a target is met, and submits the block. This works for validator nodes
and small operators — and it's what built the first 2,000+ blocks of
mainnet — but it doesn't scale:

- Mainnet block production during the audit fortnight observed
  fork-explosion under mixed-CPU mining (see post-mortem
  [2026-04-21-ibd-reorg.md](../docs/post-mortems/2026-04-21-ibd-reorg.md)
  and the density table: ~20 concurrent blocks per height at one
  observed point).
- SHA-256d at Bloch-SIS Protocol's block time (10s) is dominated by ASICs
  in any mature deployment. Every major SHA-256d chain since 2013
  has normalized around pool mining over stratum.
- ASIC firmware — Braiins OS, Luxor, stock CGMiner, BFGMiner — cannot
  talk to an Bloch-SIS Protocol node at all today. There is no `submitblock`
  path they understand.

### Why stratum V1 specifically

V1 is the baseline. Every SHA-256d ASIC in existence supports it
without config changes. Every hosted mining service speaks it. Every
operator monitoring tool understands its log format. V2 is a better
protocol (encrypted, binary, miner-controlled template) but it's a
rewrite, not a delta, and as of 2026-04 it runs in production at
only a small fraction of the global hashrate.

Starting with V1 gets Bloch-SIS Protocol from zero-ASIC-support to
ASIC-ready in one sprint. V2 can be added later on a separate port
without disrupting V1 operators.

### Why solo mode before pool mode

Solo mode has clean economics: the miner who finds a block gets the
full reward, minus the coinbase fixed 2% community fund allocation
that every block pays. There is no share accounting, no payout
scheme, no pool operator fee dispute, no hashrate-hopping attack
surface. The protocol implementation is a straightforward subset
of pool mining: drop share difficulty, drop share tracking, keep
job delivery and block submission.

Pool mode is a product. It needs PPLNS windows, hashrate estimation,
payout scheduling, operator-fee handling, and honest UX around
variance. Building pool mode well takes multiple sprints.

The sequencing in this GIP reflects that: AA.1 ships solo, AA.2
extends to pool. Each sub-sprint is reviewable, testable, and
deployable independently.

## Specification

### Transport and framing

- TCP server, bound to a configurable address. Default
  `0.0.0.0:3333` — the historical stratum port. Bloch-SIS Protocol's
  internal port convention is `161xx`, but using 3333 means every
  ASIC with default firmware connects without configuration
  changes. Compatibility with ASIC defaults outweighs internal
  consistency.
- Newline-delimited JSON. Each message is a single-line JSON object
  followed by `\n`. Multi-line pretty-printed JSON is not
  supported — matches the de-facto Stratum V1 spec.
- No encryption in V1. This is accepted protocol-level risk; see
  Security Considerations.

### Session lifecycle

A miner connects, subscribes, authorizes, and then receives
`mining.notify` messages as jobs become available. Submissions flow
the other direction.

```
Client → Server: {"id": 1, "method": "mining.subscribe", "params": ["miner-ua/1.0"]}
Server → Client: {"id": 1, "result": [[...subscriptions...], "extranonce1_hex", extranonce2_size], "error": null}

Client → Server: {"id": 2, "method": "mining.authorize", "params": ["bloch1q4fbc...", "x"]}
Server → Client: {"id": 2, "result": true, "error": null}

Server → Client: {"id": null, "method": "mining.set_difficulty", "params": [65536]}
Server → Client: {"id": null, "method": "mining.notify", "params": [job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]}

Client → Server: {"id": 4, "method": "mining.submit", "params": ["bloch1q4fbc...", job_id, extranonce2, ntime, nonce]}
Server → Client: {"id": 4, "result": true, "error": null}
```

### Required methods — server accepts

1. `mining.subscribe(user_agent: str)` → returns `[[("mining.set_difficulty", id), ("mining.notify", id)], extranonce1, extranonce2_size]`.
   The `extranonce1` is per-session, 4 bytes. `extranonce2_size` is
   4 bytes (miner-controllable entropy).

2. `mining.authorize(username: str, password: str)` → returns `true`
   if `username` parses as a valid `bloch1q…` address (Bech32 decode,
   checksum verify, 20-byte hash-length check). Password is ignored.
   Conventional value is `"x"`.

3. `mining.submit(username: str, job_id: str, extranonce2: str, ntime: str, nonce: str)`
   → returns `true` on valid submission, or an error object.

   In solo mode, a "valid submission" is a solution that meets the
   current block target. Submissions below the target are rejected
   with `[21, "Share above target", null]` — miners should never
   submit these, and the target is communicated in `mining.notify`.

   In pool mode, a valid submission is one that meets the share
   target (set by `mining.set_difficulty`). A share that also
   happens to meet the block target is recorded AND the resulting
   block is broadcast to the P2P network.

### Required methods — server sends

1. `mining.set_difficulty(difficulty)` — initial call after subscribe
   sets the per-session difficulty. In solo mode, difficulty equals
   current block difficulty. In pool mode, difficulty is managed
   per-session to target 1 share/second (standard stratum vardiff).

2. `mining.notify(job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs)`
   — sent when a new job is ready. A new job is ready when the
   node's tip changes (new block accepted from gossipsub, or new
   block found locally).

   `clean_jobs: true` means the miner should drop all in-progress
   work and switch to this job — sent when the previous work is
   now stale (e.g., a competing block arrived).

### Coinbase construction

A stratum coinbase has two parts the miner concatenates with
extranonce bytes:

```
coinb1 || extranonce1 (server-assigned) || extranonce2 (miner-chosen) || coinb2
```

In Bloch-SIS Protocol, the base coinbase transaction structure is defined
in `src/core/mod.rs` (fields: prev_txid, prev_index, script_sig,
sequence). For stratum, the coinbase is serialized with `script_sig`
containing:

```
[height (serialized per GSIP-NN)] [extranonce1] [extranonce2] [version tag]
```

where `[extranonce1]` (4 bytes) is filled by the server when it
generated the job, and `[extranonce2]` (4 bytes) is filled by the
miner at submission time. The `script_sig` before extranonce1 and
after extranonce2 is fixed by the server at job-generation time.

The two output-side parts of the coinbase are:

1. **Miner output** — in solo mode, pays 100% of (block_reward + fees - community_fund)
   to the address from `mining.authorize`.
2. **Community Development Fund output** — 2% of block reward, fixed
   address (`bloch1q633ef5f51f2434437a6daada1e984372cca0be7c2c0de299`
   at time of writing). This is a mainnet consensus rule and stratum
   does not override it.

In pool mode, the miner output instead pays the pool operator
treasury address. Individual miner payouts are settled on-chain
from that treasury via a periodic batch transaction (see Sprint AA.2).

### Job generation

A new job is generated and pushed to every connected session on
two triggers:

1. **New tip accepted** — the node's `accept_block` path has just
   moved the selected tip to a new hash. Every job in flight now
   builds on a stale parent. Send `mining.notify` with
   `clean_jobs=true`.

2. **Mempool refresh** — optional. Even without a tip change, the
   set of pending transactions may have grown enough to justify a
   new job. Implementation throttles this to at most once per 30
   seconds to avoid hashrate waste from too-frequent
   template refreshes. `clean_jobs=false`.

### CLI surface

```
--stratum                    enable stratum server (off by default)
--stratum-addr <addr>        bind address (default 0.0.0.0:3333)
--stratum-mode <solo|pool>   operating mode (required if --stratum is set)
--stratum-max-sessions <N>   connection cap (default 256)
--pool-fee <pct>             pool mode only, operator fee (default 1.0)
--pool-treasury <bloch1q…>    pool mode only, operator payout address
```

`--stratum` without `--stratum-mode` is a startup error — operators
should make the mode decision explicitly.

### Implementation location

In-process, inside the reference Rust node. A new module
`src/stratum/` hosting:

```
src/stratum/
├── mod.rs          -- tokio TCP server, session dispatch
├── protocol.rs     -- V1 method handlers
├── session.rs      -- per-connection state (subscribed, authorized, difficulty, outstanding jobs)
├── jobs.rs         -- template generation from current DAG tip + mempool
├── solo.rs         -- solo-mode submission validation + block broadcast
└── pool.rs         -- pool-mode share accounting (Sprint AA.2)
```

Event loop integration: when `accept_block` moves the selected tip,
it emits a tip-changed event on a broadcast channel the stratum
server subscribes to. No polling.

## Rationale

### Why port 3333 and not 16410

Matches ASIC firmware defaults. Every ASIC ships preconfigured for
port 3333. Asking operators to change a firmware port setting just
to connect to an Bloch-SIS Protocol node is an unnecessary adoption tax.
Internal consistency with the `161xx` range is a developer-facing
concern; defaulting to 3333 is an operator-facing concern, and the
operator wins here.

### Why in-process and not a separate daemon

Two-daemon deployments are operationally harder. A separate
`bloch-stratum` binary would need its own RPC client to the node,
its own lifecycle, its own crash-recovery, its own logs, its own
upgrade coordination. The Bitcoin world's `ckpool`-plus-`bitcoind`
model works but it exists because bitcoind historically doesn't
ship stratum — not because two processes are ideal.

In-process has trade-offs: a bug in stratum code can crash the
whole node. Mitigation: the stratum tokio task is spawned with
panic catching; a panic in one session aborts that session only.
Panics in the server-side job pipeline are fatal and logged.

If a future operator needs process separation — e.g., to scale
a single large-chain node feeding multiple stratum frontends — the
same module becomes extractable via the `submitblock` RPC path.
That's a v0.8 concern, not a v0.6 concern.

### Why solo and pool sharing code, selected by flag

Solo mode is a strict subset of pool mode. Pool mode has everything
solo has, plus: share target (lower than block target), share
accounting, PPLNS window, operator fee deduction. If both modes are
separate code paths, we maintain two places where coinbase is built,
two places where submission is validated, two places where `mining.notify`
is crafted. That's the kind of duplication that breeds bugs by
divergence.

Instead: one code path, with branches on `config.mode` at the three
points that actually differ (target check in `submit`, coinbase
output list in `jobs.rs`, whether to record shares after `submit`).
Each branch is small and obvious.

The flag is chosen at node startup. A single node operates in
exactly one mode. A running node that wants to switch modes has to
restart. This is the correct semantics: a "pool" with solo miners
mixed in makes no sense from a payout perspective.

### Why PPLNS and not PPS/FPPS for pool mode

- **PPS (Pay Per Share)**: pool operator takes all the variance, pays
  miners a fixed rate per share regardless of whether a block was
  found. Requires operator to have large treasury reserves; on a
  new chain with no reserves, the operator can go bankrupt on a
  bad-luck streak.
- **FPPS (Full Pay Per Share)**: like PPS but also pays miners
  for expected fee revenue. Same treasury-risk problem, worse.
- **PPLNS (Pay Per Last N Shares)**: payout per block is distributed
  among the last N shares submitted. Miners bear the variance, not
  operator. N is typically set to ~2–5× the expected shares per
  block. Bootstrap-friendly, protects against hash-hopping (miners
  who join during a lucky block and leave, gaming PPS schemes).

PPLNS is the right default for a new chain with a new pool. If a
well-capitalized operator wants PPS later, they can run a fork of
the stratum module. The reference implementation ships PPLNS.

### Rejected alternative: external pool daemon (ckpool-style)

Discussed above. Rejected because two-daemon complexity isn't worth
the separation for Bloch-SIS Protocol's current scale. May be revisited
if/when single-node scaling becomes the bottleneck.

### Rejected alternative: start with Stratum V2

Better protocol, but no miner adoption yet. Would result in a node
that ASIC operators can't actually use. V2 is valuable as a second
step once V1 miners are active and pushing real feedback on the
protocol surface.

## Backward compatibility

- **Wire protocol**: none. Stratum is a client-server protocol on a
  separate port from P2P/RPC/WS. Existing nodes are unaffected.
- **Block content**: coinbase bytes change in structure (now
  includes `extranonce1 + extranonce2` segment), but that's inside
  `script_sig` which is opaque to consensus. Mainnet validation
  rules do not read coinbase `script_sig` format beyond length
  bounds.
- **Storage schema**: pool mode adds a `CF_SHARES` column family
  for share accounting. Solo mode adds nothing.
- **RPC**: unchanged for existing methods. New methods added in a
  future GIP (likely `getminingstatus`, `getpoolstats`) on the
  existing RPC port.

## Security considerations

### Stratum V1 has no encryption

Session hijacking is a real risk: a network-positioned adversary
can read submissions, rewrite them to pay a different address, and
steal the reward. Mitigation paths:

1. **Operator-level**: terminate stratum behind a TLS-terminating
   reverse proxy (stunnel, nginx stream module). Moves the crypto
   to infrastructure, leaves the node simple.
2. **Stratum V2**: ships with Noise handshake by default. The
   long-term answer.

The reference implementation documents option 1 in
`docs/operations/stratum.md` and does not attempt to add TLS to the
V1 handler. Halfway-TLS is worse than no-TLS because it creates
false confidence.

### Denial of service on the job pipeline

A malicious client could:

- Subscribe but never authorize. Mitigated by a 30-second auth
  timeout: unauthorized sessions get disconnected.
- Submit garbage continuously. Mitigated by per-session rate
  limiting (max 30 submissions/minute); persistent violators get
  disconnected and the source IP is soft-banned for 1 hour.
- Open thousands of connections to exhaust sockets. Mitigated by
  the `--stratum-max-sessions` cap (default 256) and by the OS's
  per-IP connection limits on the listening socket.

### Address validation

`mining.authorize` is the one place a miner supplies an address
that will directly affect a future coinbase. Address validation
MUST:

- Parse as Bech32 with prefix `bloch1q`
- Checksum verify
- Decode to exactly 20 bytes of hash payload
- Not be the zero address

Any failure returns `{"result": false, "error": [24, "Invalid address", null]}`
and the session stays in "unauthorized" state.

### Block-withholding by a malicious miner (pool mode)

A miner in pool mode might submit all shares below block target but
withhold shares that meet block target (stealing variance from the
pool). Classical stratum pools cannot detect this perfectly. PPLNS
partially mitigates by averaging across miners. Detection beyond
that is a research problem; not in scope for this GIP. Documented
in the operations guide so pool operators are aware.

### Reorg during share accounting (pool mode)

If a block found by a pool miner is orphaned by a reorg, the pool
operator has paid out on a block that no longer exists. Reference
implementation: pool payouts are settled only after the block passes
a 10-block confirmation depth (100 seconds at target block time).
Any rollback before depth 10 reverts the payout; after depth 10 the
payout is final even if a subsequent reorg somehow extends past it.
Aligns with CHECKPOINT_DEPTH finality logic.

## Test vectors

### V1 subscribe round-trip

```
-- Client sends --
{"id": 1, "method": "mining.subscribe", "params": ["cpuminer/2.5.1"]}

-- Server responds (example) --
{"id": 1, "result":
  [
    [
      ["mining.set_difficulty", "d07c"],
      ["mining.notify", "d07c"]
    ],
    "31353030",  -- 4-byte extranonce1, hex
    4            -- extranonce2 size in bytes
  ],
  "error": null
}
```

### V1 authorize + submit

```
-- Authorize --
{"id": 2, "method": "mining.authorize", "params": ["bloch1q4fbcd3b3fae5de3e2b4015ca132c8744b8af170a79e4eb45", "x"]}
{"id": 2, "result": true, "error": null}

-- Submit a block solution (solo mode, meets block target) --
{"id": 10, "method": "mining.submit", "params":
  ["bloch1q4fbcd3b3fae5de3e2b4015ca132c8744b8af170a79e4eb45",
   "job_42",
   "deadbeef",
   "65456000",
   "1d00ffff"]
}
{"id": 10, "result": true, "error": null}
```

### Error responses

```
-- Submit after stale (clean_jobs was true on later notify) --
{"id": 11, "result": null, "error": [21, "Job not found", null]}

-- Submit with a share above target (shouldn't happen; indicates
   miner misconfiguration or malicious client) --
{"id": 12, "result": null, "error": [21, "Share above target", null]}

-- Unauthorized submit (auth timeout elapsed, or never authorized) --
{"id": 13, "result": null, "error": [24, "Unauthorized worker", null]}

-- Invalid address in authorize --
{"id": 2,  "result": false, "error": [24, "Invalid address: bech32 checksum failed", null]}
```

## Reference implementation

Forthcoming. Sprint AA.1 will implement `src/stratum/{mod,protocol,session,jobs,solo}.rs`
and accompanying tests in `tests/sprint_aa_stratum.rs`. Link to the
PR will be added here when opened.

## Copyright

This GIP is released under CC0 (public domain).
