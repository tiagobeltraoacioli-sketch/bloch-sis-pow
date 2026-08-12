# Sprint AA.1 — Solo Stratum V1 — Implementation plan

**Status:** planning document, no code written yet.
**Target:** ship a working Stratum V1 solo-mining server inside the
reference Bloch-SIS Protocol (BLOCH) node, sufficient for a real SHA-256d ASIC to
connect, receive jobs, and claim 100% of a found block's reward.
**Estimated focused coding time:** 4–5 hours if no surprises.

This document exists because stratum is a protocol implementation
whose bugs are hard to catch in unit tests — the real test is a
miner ASIC connecting and finding a block. Getting the design right
on paper before writing code avoids costly rework.

Based on the design approved in `legacy/gips/GIP-0002-stratum.md` and the
six design decisions confirmed at end-of-session on 2026-04-21:

1. **Address validation:** strict — invalid Bech32 rejects the
   `mining.authorize` call, session stays unauthorized.
2. **Extranonce1:** unique per-session, 4 random bytes.
3. **Solo difficulty:** fixed at current block target. Every share
   that passes is a real block submission.
4. **Job invalidation:** on tip change (`clean_jobs=true`) or every
   60 seconds if no tip change (`clean_jobs=false`, for mempool
   refresh).
5. **Port:** 3333 (ASIC firmware default).
6. **Coinbase message:** hardcoded `bloch-stratum/v0.6`.

## Module layout

All new code lives in a new module `src/stratum/`:

```
src/stratum/
├── mod.rs           -- StratumServer; tokio TCP accept loop; spawns sessions
├── protocol.rs      -- JSON-RPC framing + V1 method dispatcher
├── session.rs       -- per-connection state machine
├── jobs.rs          -- block-template generation from DAG + mempool
└── submit.rs        -- submission validation: target check, block broadcast
```

Plus:

```
src/main.rs                       -- CLI flags, spawn StratumServer task
tests/sprint_aa_stratum.rs        -- integration tests
legacy/operations/stratum.md        -- operator-facing docs
```

No changes to `src/consensus/`, `src/storage/`, `src/network/`,
`src/core/`. The stratum server consumes DAG + mempool state read-only
and submits blocks through the existing `accept_block` path.

## Data flow (one job lifecycle)

```
┌────────────────────┐
│ DAG: tip changed   │  (accept_block finished)
└──────────┬─────────┘
           │  broadcast channel (tip_changed_tx)
           ▼
┌────────────────────┐
│ jobs.rs::Template  │  build new template:
│                    │    - prev_hash = new tip
│                    │    - coinb1 + coinb2 (split for extranonce)
│                    │    - merkle_branch (pre-computed)
│                    │    - version, ntime, nbits
└──────────┬─────────┘
           │  broadcast to all sessions
           ▼
┌────────────────────┐
│ session::send_notify│ each session gets mining.notify
│                    │  with their unique extranonce1
│                    │  and clean_jobs=true
└────────────────────┘

[miner solves]

           │  miner sends mining.submit
           ▼
┌────────────────────┐
│ submit.rs::verify  │  reconstruct full block:
│                    │    coinb1 || en1 || en2 || coinb2 → coinbase
│                    │    merkle_root = merkle_from_branch(...)
│                    │    header = assemble(...)
│                    │    validate PoW: hash ≤ target
└──────────┬─────────┘
           │
           ▼
   call accept_block(...)
   ──→ if Ok: broadcast NewBlock to P2P, reply {"result": true}
   ──→ if Err: reply {"result": null, "error": ["Block rejected"]}
```

## File-by-file breakdown

### `src/stratum/mod.rs` (~250 lines)

**Types:**

```rust
pub struct StratumConfig {
    pub enabled:       bool,
    pub bind_addr:     SocketAddr,   // default 0.0.0.0:3333
    pub mode:          StratumMode,  // Solo for AA.1; Pool is AA.2
    pub max_sessions:  usize,        // default 256
}

pub enum StratumMode { Solo, Pool }
```

**Entry point:**

```rust
pub async fn run_stratum_server(
    config: StratumConfig,
    dag:    Arc<RwLock<GhostDAG>>,
    store:  Arc<Storage>,
    mempool: Arc<Mempool>,
    tip_changed_rx: broadcast::Receiver<TipChanged>,
    p2p_tx:  mpsc::Sender<NetworkMessage>,  // for NewBlock broadcast
) -> Result<()>
```

Binds TCP listener, spawns per-accept session task, keeps a map of
live sessions for broadcast.

**Session broadcast:** when `tip_changed_rx` fires, iterate all
sessions and push a new `mining.notify`. Handles dropped/closed
sessions by removing them from the map.

**Panic isolation:** each session is spawned with `tokio::spawn` and
has its own panic boundary. A panic in one session is logged and
removes that session; server and other sessions continue.

### `src/stratum/protocol.rs` (~200 lines)

JSON-RPC V1 framing:

```rust
#[derive(Deserialize)]
struct Request {
    id:      Option<serde_json::Value>,
    method:  String,
    params:  serde_json::Value,
}

#[derive(Serialize)]
struct Response {
    id:     Option<serde_json::Value>,
    result: Option<serde_json::Value>,
    error:  Option<[serde_json::Value; 3]>,  // [code, msg, traceback]
}
```

**Reading:** `BufReader::read_line` — V1 is strictly newline-delimited.
No nested/multi-line JSON. Line > 8 KiB is a protocol error — close
the session.

**Dispatcher:** match on `method`:
- `"mining.subscribe"`  → `session.handle_subscribe(params)`
- `"mining.authorize"`  → `session.handle_authorize(params)`
- `"mining.submit"`     → `submit::handle_submit(session, params, dag, store, p2p_tx)`
- `"mining.extranonce.subscribe"` → ack only (not used in V1 solo)
- unknown → `error: [20, "Other/Unknown", null]`

**Writing:** `writeln!` line by line, one JSON per line, with `flush()`
after each response. Slow writers are killed after 10s timeout.

### `src/stratum/session.rs` (~300 lines)

Per-connection state machine.

```rust
pub struct Session {
    pub id:              u64,               // internal for logging
    pub peer_addr:       SocketAddr,
    pub state:           SessionState,
    pub extranonce1:     [u8; 4],           // unique per session
    pub subscribed_at:   Option<Instant>,
    pub authorized_addr: Option<MinerAddress>,
    pub outstanding_jobs: HashMap<JobId, Arc<Template>>,
    pub writer:          OwnedWriteHalf,
    pub submissions:     RateLimiter,       // 30/min cap
}

pub enum SessionState {
    Fresh,         // connected but no subscribe yet
    Subscribed,    // subscribe done, waiting for authorize
    Authorized,    // fully ready, receives jobs
    Dead,          // marked for removal
}
```

**Timeouts:**
- Auth timeout 30s: if `Fresh` or `Subscribed` for > 30s,
  close with `[24, "Authorization timeout", null]`.
- Idle timeout 10min: if `Authorized` but no submissions in 10min,
  close (frees socket for other miners).

**handle_subscribe:**
```rust
async fn handle_subscribe(&mut self, req: Request) -> Response {
    if !matches!(self.state, SessionState::Fresh) {
        return error_response(req.id, 25, "Already subscribed");
    }
    let ua = parse_user_agent(&req.params);
    // Generate unique extranonce1
    self.extranonce1 = rand::thread_rng().gen::<[u8; 4]>();
    self.state = SessionState::Subscribed;
    ok_response(req.id, json!([
        [
            ["mining.set_difficulty", hex::encode(self.extranonce1)],
            ["mining.notify",         hex::encode(self.extranonce1)],
        ],
        hex::encode(self.extranonce1),
        4,  // extranonce2_size
    ]))
}
```

**handle_authorize:**
```rust
async fn handle_authorize(&mut self, req: Request) -> Response {
    let (username, _password) = parse_authorize_params(&req.params)?;
    match address::from_bech32(&username) {
        Ok(addr) => {
            self.authorized_addr = Some(addr);
            self.state = SessionState::Authorized;
            ok_response(req.id, json!(true))
        }
        Err(e) => {
            error_response(req.id, 24, &format!("Invalid address: {}", e))
        }
    }
}
```

**send_notify:**
```rust
async fn send_notify(&mut self, template: Arc<Template>, clean: bool) {
    let job_id = self.next_job_id();
    let msg = json!({
        "id": null,
        "method": "mining.notify",
        "params": [
            job_id,
            hex::encode(&template.prev_hash),
            hex::encode(&template.coinb1),
            hex::encode(&template.coinb2),
            template.merkle_branch_hex(),   // Vec<String> of 32-byte hex
            format!("{:08x}", template.version),
            format!("{:08x}", template.nbits),
            format!("{:08x}", template.ntime),
            clean,
        ],
    });
    let line = serde_json::to_string(&msg).unwrap() + "\n";
    if self.writer.write_all(line.as_bytes()).await.is_err() {
        self.state = SessionState::Dead;
    }
    self.outstanding_jobs.insert(job_id, template.clone());
}
```

### `src/stratum/jobs.rs` (~350 lines)

**Template building** — the most mathematically delicate file. Bugs
here mean miners "mine" but never find a real block because the
merkle root reconstruction doesn't match.

```rust
pub struct Template {
    pub prev_hash:       [u8; 32],       // current tip
    pub coinb1:          Vec<u8>,        // coinbase bytes up to extranonce1
    pub coinb2:          Vec<u8>,        // coinbase bytes after extranonce2
    pub merkle_branch:   Vec<[u8; 32]>,  // branch to reconstruct root
    pub version:         u32,
    pub nbits:           u32,            // current target
    pub ntime:           u32,            // server timestamp
    pub height:          u64,
    pub block_reward:    u64,
    pub fees:            u64,
    pub community_out:   TxOutput,       // fixed 2% to fund addr
}
```

**build_template():**

1. Read current tip from DAG (under read lock).
2. Read current_bits from Storage meta.
3. Get up to 2000 txs from mempool (`get_for_block(2000)`).
4. Compute fees from these txs (as `main.rs` already does).
5. Build coinbase **per-miner-later**. In Template, store the
   fixed parts:
    - `coinb1` = version || input_count || prev_txid(zero) || prev_index(0xffff) || script_sig_len || [height_varint] || [stratum_tag]
    - (extranonce1 + extranonce2 insertion point)
    - `coinb2` = [] || sequence || output_count || [miner_output_placeholder] || [community_output] || locktime
6. Miner output in `coinb2` is **address-less at this stage**.
   The actual construction happens when a submission comes in,
   because the miner's address was set per-session.
7. Merkle branch: compute the branch from the coinbase position
   (index 0) up to the root, EXCLUDING the coinbase itself. The
   miner reassembles coinbase with their extranonce and hashes it
   into the branch to get the root.

**CRITICAL DETAIL — how merkle branch reconstruction works:**

The miner does NOT know the full tx list. The miner receives:
- `coinb1`, `coinb2`, `merkle_branch` (list of 32-byte hashes)

The miner's calculation:
```
coinbase = coinb1 || extranonce1 || extranonce2 || coinb2
coinbase_hash = SHA256d(coinbase)
h = coinbase_hash
for branch_hash in merkle_branch:
    h = SHA256d(h || branch_hash)
merkle_root = h
```

For this to work, `merkle_branch` must be the classical Bitcoin-style
sibling-path from leaf 0 to root, EXCLUDING the leaf itself. Standard
algorithm — bug-prone to implement from scratch. Use the reference:
https://en.bitcoin.it/wiki/Merkle_tree

**Test vector:** for a template with 4 txs (cb + 3 others), the branch is:
```
[hash(tx1), hash(hash(tx2), hash(tx3))]
```
(size 2, not 3).

### `src/stratum/submit.rs` (~200 lines)

**handle_submit:**

```rust
pub async fn handle_submit(
    session: &mut Session,
    req: Request,
    dag: &Arc<RwLock<GhostDAG>>,
    store: &Arc<Storage>,
    mempool: &Arc<Mempool>,
    p2p_tx: &mpsc::Sender<NetworkMessage>,
) -> Response {
    // 1. Auth check
    if !matches!(session.state, SessionState::Authorized) {
        return error_response(req.id, 24, "Unauthorized worker");
    }
    let miner_addr = session.authorized_addr.unwrap();

    // 2. Rate limit
    if !session.submissions.try_acquire() {
        return error_response(req.id, 23, "Too many submissions");
    }

    // 3. Parse params: [username, job_id, extranonce2, ntime, nonce]
    let (username, job_id, en2_hex, ntime_hex, nonce_hex) =
        parse_submit_params(&req.params)?;

    // 4. Sanity: username matches session authorized
    if username != miner_addr.bech32() {
        return error_response(req.id, 24, "Username mismatch");
    }

    // 5. Look up template
    let template = match session.outstanding_jobs.get(&job_id) {
        Some(t) => t.clone(),
        None => return error_response(req.id, 21, "Job not found"),
    };

    // 6. Reconstruct coinbase with miner's address
    let coinbase = build_coinbase(
        &template,
        &session.extranonce1,
        &hex::decode(en2_hex)?,
        &miner_addr,
    );
    let coinbase_tx = decode_tx(&coinbase)?;

    // 7. Reconstruct block
    let block = reconstruct_block(
        &template,
        coinbase_tx,
        hex::decode(ntime_hex)?,
        hex::decode(nonce_hex)?,
    );

    // 8. PoW check
    let block_hash = block.block_hash();
    if !meets_target(&block_hash, template.nbits) {
        return error_response(req.id, 21, "Share above target");
    }

    // 9. Submit via accept_block path
    //    accept_block does its own validation (merkle, sigs, utxo, etc.)
    match accept_block_from_stratum(&block, dag, store, mempool) {
        Ok(_) => {
            log::info!("⛏ STRATUM BLOCK ACCEPTED h={} miner={} hash={}",
                block.height,
                miner_addr.bech32(),
                hex::encode(&block_hash[..8]),
            );
            // Broadcast to P2P network
            let _ = p2p_tx.send(NetworkMessage::NewBlock { ... }).await;
            ok_response(req.id, json!(true))
        }
        Err(e) => {
            log::warn!("stratum block rejected by accept_block: {}", e);
            error_response(req.id, 23, &format!("Rejected: {}", e))
        }
    }
}
```

**CRITICAL DETAILS:**

- `build_coinbase` must match EXACTLY the split point where
  `coinb1` ends and `coinb2` starts in the original `Template`.
  Off-by-one is disaster.
- The miner output value in `coinb2` at template-time was a
  placeholder for 20-byte script_pubkey. Replace with miner's
  actual script_pubkey at submit time. This means the bytes
  `coinb2` sent to the miner must have the placeholder positioned
  so the miner doesn't alter it via extranonce. Keep the
  placeholder at byte position >= `coinb1.len() + 4 + 4` (after en2).
- `accept_block_from_stratum` is a thin wrapper that takes the
  shared dag/store/mempool references. Can't call `accept_block`
  in `main.rs` directly because of the closure-based ownership
  there. Factor out a standalone `accept_block` function OR
  reuse `main.rs`'s function by refactoring signature. Prefer
  option 2 — extract `accept_block` to a new file
  `src/accept.rs`, update `main.rs` imports.

### `src/main.rs` — additions

**CLI additions (in `struct Cli`):**

```rust
/// Enable stratum mining server
#[arg(long)]
pub stratum: bool,

/// Stratum server bind address
#[arg(long, default_value = "0.0.0.0:3333")]
pub stratum_addr: SocketAddr,

/// Stratum mode: solo | pool
#[arg(long, value_enum)]
pub stratum_mode: Option<StratumMode>,

/// Max stratum sessions
#[arg(long, default_value_t = 256)]
pub stratum_max_sessions: usize,
```

Validation:
```rust
if cli.stratum && cli.stratum_mode.is_none() {
    error!("--stratum requires --stratum-mode <solo|pool>");
    std::process::exit(1);
}
if cli.stratum_mode == Some(StratumMode::Pool) {
    error!("Pool mode is Sprint AA.2 — not yet implemented. Use --stratum-mode solo");
    std::process::exit(1);
}
```

**Spawn server:**
```rust
if cli.stratum {
    let config = StratumConfig {
        enabled: true,
        bind_addr: cli.stratum_addr,
        mode: cli.stratum_mode.unwrap(),
        max_sessions: cli.stratum_max_sessions,
    };
    let (tip_tx, _tip_rx) = broadcast::channel::<TipChanged>(16);
    // Wire tip_tx into accept_block path — whenever it sets new tip,
    //   let _ = tip_tx.send(TipChanged { hash: new_tip, height: ... });
    tokio::spawn(stratum::run_stratum_server(
        config, dag.clone(), store.clone(), mempool.clone(),
        tip_tx.subscribe(), otx.clone(),
    ));
    info!("✓ stratum {} on {}", cli.stratum_mode.unwrap(), cli.stratum_addr);
}
```

**Wire tip_changed event:** in the accept_block function's
`Disposition::Extension` and `Disposition::Reorg` branches (after
`store.put_meta("tip_hash", ...)`), emit a tip-changed notification
on the broadcast channel. This is the trigger that propagates new
jobs to miners.

## Integration tests — `tests/sprint_aa_stratum.rs` (~400 lines)

Mock miner as a tokio TCP client. Three tests:

1. **`stratum_subscribe_authorize_round_trip`** — connect, subscribe,
   receive config, authorize with valid address, receive ack, verify
   extranonce1 is 4 bytes random hex.

2. **`stratum_authorize_rejects_invalid_address`** — authorize with
   "not-a-bech32", verify error response with code 24.

3. **`stratum_submit_rejected_when_below_target`** — full flow:
   subscribe, authorize, receive notify, submit a fake solution
   that doesn't meet target. Verify error [21, "Share above target"].

A true end-to-end test (mine a block) needs PoW work, which is slow
for a test. Skip for now — covered by real-ASIC testing post-deploy.

## Docs — `legacy/operations/stratum.md` (~200 lines)

Operator-facing doc covering:
- How to enable (`--stratum --stratum-mode solo`)
- How to connect a miner (URL `stratum+tcp://<seed-ip>:3333`,
  username `bloch1q<address>`, password `x`)
- TLS termination (nginx stream example for wrapping V1)
- Troubleshooting (common errors, log locations)

## Implementation order (amanhã)

Priority ordering — each step produces something testable before
next step starts.

1. **Module scaffolding** (30 min) — create files, empty structs,
   wire `mod.rs` into `lib.rs`, compile clean. No behavior yet.

2. **Protocol framing** (45 min) — `protocol.rs`, JSON parse,
   response formatting. Unit tests for parse/serialize.

3. **Session state machine** (60 min) — `session.rs`, state
   transitions, timeouts. Unit tests for state machine.

4. **Job template builder** (90 min) — `jobs.rs`, merkle branch,
   coinb1/coinb2 split. Unit tests with hand-computed test vector.
   **Most bug-prone** — take care.

5. **Submission handler** (60 min) — `submit.rs`, block
   reconstruction, PoW check, wire to accept_block.

6. **CLI + main.rs wiring** (30 min) — flags, server spawn,
   tip_changed broadcast wire-up.

7. **Integration tests** (45 min) — `tests/sprint_aa_stratum.rs`,
   the 3 scenarios.

8. **Manual ASIC test** (separate, post-deploy) — connect real
   miner, verify first stratum block found on mainnet.

**Total focused coding: ~4.5h.** Plus ~1h build/test cycles on the
Mac. Plan for 5–6h total session.

## Known risks and pre-emptive mitigations

### Merkle branch reconstruction

**Risk:** off-by-one or wrong-hash-order in branch produces
template that no miner can ever solve. ASIC sees target but can't
hit it because root mismatch.

**Mitigation:** test vector with 4 txs computed by hand, asserted
in unit test. If unit test passes, reference implementation matches
real clients.

### Coinbase split point

**Risk:** `coinb1 || en1 || en2 || coinb2` when concatenated must
produce a VALID coinbase tx when `en1` + `en2` are any 8 bytes.
A misplaced split breaks this.

**Mitigation:** split after the stratum-tag bytes in `script_sig`,
before placing `en1`. Ensure `coinb1 + [0u8;4] + [0u8;4] + coinb2`
deserializes as a valid Transaction in a unit test.

### Race between tip_changed and submit

**Risk:** miner submits for a job that was valid when sent, but
tip has since changed. The block reconstructs and passes PoW, but
`accept_block` rejects because parent is no longer a valid tip.

**Mitigation:** `accept_block` already handles this correctly via
the Disposition::ForkLoser branch — block gets stored in the DAG
but doesn't advance selected tip. This is acceptable behavior.

The miner receives `{"result": true}` (block accepted in some form)
but in solo mode this is arguably a loss — we mined but didn't
become the selected tip. **Document this edge case** in
`legacy/operations/stratum.md`. Pool mode (AA.2) will handle it
differently via shares.

### extranonce1 collision

**Risk:** two sessions get the same 4-byte extranonce1. Both mine
identical templates with identical coinbase bytes. Hashrate wasted.

**Mitigation:** 4-byte extranonce1 = 2^32 space. With 256 max
sessions, collision probability per pair is ~6×10^-8. At steady
state with 256 sessions, probability of ANY collision is
~(256^2)/2 × 6×10^-8 ≈ 0.2%. Acceptable. Track extranonce1 uniqueness
in a HashSet and regenerate if collision — 1 line of code.

### Solo mode block orphaned by reorg

**Risk:** stratum-mined block enters DAG. Miner's ASIC firmware
logs "block accepted!". Then another peer's block wins reorg.
The coinbase reward in an orphaned block is unrecoverable.

**Mitigation:** this is a fundamental property of all PoW chains
and is NOT a stratum bug. Document in ops guide. Recommend miners
wait for 10-confirmation depth before treating a block as "paid".

## What AA.2 (pool mode) will add later

Not in scope for this sprint, but shapes design decisions:

- `--pool-fee` and `--pool-treasury` flags (stub now, error if used)
- Share target < block target, `mining.set_difficulty` adjustments
- `CF_SHARES` column family for accounting
- PPLNS window tracking
- Payout transaction builder

The solo → pool migration should be additive: everything in AA.1
still works after AA.2 lands. `--stratum-mode solo` stays available.

## Non-goals for AA.1

Explicit list of what we are NOT doing this sprint, to avoid scope
creep:

- TLS encryption (document nginx reverse proxy instead)
- Stratum V2 (separate sprint, post-AA.2)
- Vardiff in solo mode (fixed block target is correct)
- Multi-worker per session (miner can open multiple sessions)
- WebSocket transport (TCP only; V2 will add)
- Prometheus metrics for stratum (post-AA.2, in Sprint FF)
- `mining.suggest_difficulty` support (accept but ignore)

## When this sprint is "done"

Exit criteria:

1. `cargo build --release` completes without warning regressions.
2. `cargo test --test sprint_aa_stratum` shows 3/3 passing.
3. Node starts with `--stratum --stratum-mode solo` without panic.
4. A real ASIC (or cgminer on another machine) can:
   a. `telnet` → see the port open
   b. Subscribe and authorize successfully
   c. Receive `mining.notify`
   d. Submit shares (even if below target — they get rejected
      cleanly, no panics, no state corruption)
5. Operator docs published to `legacy/operations/stratum.md`.
6. README updated: "Mining" section mentions stratum support.

**Not required for sprint close but desirable next day:**

7. A real ASIC finds and submits a block that is accepted by the
   network. (This is the **functional** validation but is blocked
   by real-hardware availability.)
