# ERA 1 — Pre-rebrand Integration Plan (Sprint AA.1 pt 3)

> **Note (April 2026 rebrand).** This document is the **integration
> plan for Sprint AA.1 pt 3**, written at the end of pt 2b on the
> Era 1 (GroundState) codebase. It captures the design decisions
> for wiring the Stratum V1 scaffolding (already shipped in pt 1,
> pt 2a, pt 2b — 3,291 lines of Rust + 68 tests) to the running
> node so that `--stratum` produces a live mining server.
>
> **This is an Era 1 integration plan referencing partially-
> implemented Era 1 code.** The plan describes:
>   - Files in `src/main.rs`, `src/stratum/` of the Era 1 codebase
>     (paths preserved verbatim under BLOCH but with renamed crate
>     `bloch-layer` and binary `bloch`).
>   - The coinbase tag literal `b"groundstate-stratum/v0.6"` at L152
>     — this is the BYTE SEQUENCE shipped in the Era 1 stratum
>     code (pt 2b). Under BLOCH Phase 6 the genesis is regenerated
>     and any new mining will use a new coinbase tag (TBD; the
>     companion plan `sprint-aa1-plan.md` was rebranded surgically
>     to `bloch-stratum/v0.6` because that document is
>     forward-looking design, not implementation reference).
>   - References to upcoming Era 1 sprints (AA.1 pt 4 mempool
>     selection, AA.2 pool mode) which were planned but not
>     numbered under BLOCH.
>   - References to Era 1 release docs (`docs/releases/v0.6.0.md`,
>     `docs/operations/stratum.md`) which are themselves preserved
>     as Era 1 historical records elsewhere in this rebrand.
>
> **Under the Bloch-SIS Protocol (BLOCH) rebrand (April 2026)** this
> integration plan is **frozen as Era 1 historical record**:
>   1. The pt 1/2a/2b code already shipped is in the BLOCH codebase
>      with renamed identifiers (3.c.5 series rebranded the source).
>   2. The pt 3 integration work described here was NOT completed
>      before the rebrand began.
>   3. Under BLOCH the stratum integration WILL still happen (the
>      design decisions remain valid) but as a renamed work item
>      with BLOCH nomenclature; this Era 1 plan is reference, not
>      execution path.
>   4. The forward-looking sister document
>      `docs/implementation/sprint-aa1-plan.md` was rebranded
>      surgically (Phase 3.e.12.a) precisely BECAUSE it is a pure
>      planning document with no shipped-code references; this
>      pt3-plan keeps Era 1 continuity because it cross-references
>      shipped code with literal Era 1 byte sequences.
>
> Original document follows verbatim.

---

# Sprint AA.1 pt 3 — Integration plan

**Status:** Not yet implemented. This document captures the
design decisions for the remaining wiring so the next work
session can proceed without re-deriving them.

## Goal

Take the stratum scaffolding shipped in AA.1 pt 1/2a/2b and
connect it to the running node so that `--stratum` on the CLI
produces a live, usable mining server.

## What already works (pt 1/2a/2b)

- TCP accept loop, session state machine, subscribe/authorize
- Bitcoin-format transaction serialization + merkle branch
- Full submit pipeline: params → dedup → template lookup →
  coinbase rebuild → merkle walk → PoW check → Block assembly →
  `AcceptBlockFn` callback
- 68 tests covering every error path and the end-to-end
  miner-reconstructs-merkle-root invariant

## What's missing

### 1. CLI flags (~50 lines in `src/main.rs`)

Add to the `Cli` struct (Clap derive):

```rust
/// Enable the stratum V1 mining server
#[arg(long)]
stratum: bool,

/// Bind address for stratum server
#[arg(long, default_value = "0.0.0.0:3333")]
stratum_addr: SocketAddr,

/// Stratum operating mode
#[arg(long, default_value = "solo", value_parser = parse_stratum_mode)]
stratum_mode: stratum::StratumMode,

/// Max concurrent stratum sessions
#[arg(long, default_value_t = stratum::DEFAULT_MAX_SESSIONS)]
stratum_max_sessions: usize,
```

`parse_stratum_mode` shim because `StratumMode::FromStr` returns
String error. Clap wants a clean closure or helper.

### 2. accept_block callback construction (~80 lines)

Place in `run()` in main.rs, AFTER all the Arc clones of dag,
store, mempool, node_state are established:

```rust
let accept_block_for_stratum: Option<Arc<stratum::AcceptBlockFn>> = if cli.stratum {
    let dag        = dag.clone();
    let store      = store.clone();
    let mempool    = mempool.clone();
    let node_state = node_state.clone();
    let otx        = otx.clone();

    Some(Arc::new(move |block: core::Block| -> Result<String, String> {
        let block_hash = block.header.pow_hash();
        let height     = block.height;

        // Delegate to the existing accept_block() for all consensus
        // validation + DAG mutation + retarget + UTXO updates.
        accept_block(&block, block_hash, height, &dag, &store, &mempool, &node_state)?;

        // Mirror the miner-loop's post-accept state refresh.
        {
            let mut s = node_state.write();
            s.tip_blue_score = dag.read().tip_blue_score();
            s.block_count    = dag.read().block_count() as u64;
            s.mempool_size   = mempool.size();
        }

        // Broadcast to gossipsub.
        if let Ok(data) = bincode::serde::encode_to_vec(&block, bincode::config::standard()) {
            let otx_clone = otx.clone();
            let msg = network::NetworkMessage::NewBlock {
                block_hash,
                blue_score: block.blue_score,
                height,
                block_data: data,
            };
            // otx is async; spawn a tiny task to send.
            tokio::spawn(async move {
                let _ = otx_clone.send(msg).await;
            });
        }

        Ok(hex::encode(block_hash))
    }))
} else {
    None
};
```

**Risk:** `accept_block()` acquires write locks on the DAG. Called
from the stratum submit path (which is already on a per-session
tokio task), this is fine — serialization is the same as the miner
loop's. Double-check that no other path holds a read lock across
the callback boundary.

### 3. Per-session template generation (~150 lines)

This is the tricky bit. Each session needs a Template whose
coinbase pays to *that session's* authorized address. So templates
are per-session, not server-wide.

Add to `src/stratum/session.rs`:

```rust
/// Generate a template for this session's authorized address and
/// push it in. Returns the job_id so the caller can send
/// mining.notify immediately.
pub fn install_fresh_template(
    &self,
    dag:          &Arc<RwLock<GhostDAG>>,
    mempool:      &Arc<Mempool>,
    store:        &Arc<Storage>,
    clean_jobs:   bool,
) -> Result<String, String> {
    let authorized = self.authorized_addr.lock().clone()
        .ok_or_else(|| "session not authorized".to_string())?;

    let address = Address::parse(&authorized)
        .map_err(|e| format!("stored address no longer parses: {}", e))?;
    let miner_spk = address.hash().to_vec();

    // Snapshot tip state atomically
    let (parents, height, blue_score) = {
        let d = dag.read();
        let tips = d.tips();
        let h    = d.block_count() as u64;
        let bs   = d.tip_blue_score() + 1;
        (tips, h, bs)
    };

    let current_bits = store.get_meta("current_bits").ok().flatten()
        .and_then(|b| b.as_slice().try_into().ok().map(u32::from_le_bytes))
        .unwrap_or(0x1d00ffff);

    // Select mempool txs (simplest cut: skip txs for now,
    // coinbase-only templates. Add mempool selection in AA.1 pt 4).
    let other_txs = Vec::new();
    let total_fees = 0;

    let job_id = format!("{}-{}", self.id, self.next_job_counter());
    let coinbase_tag = b"groundstate-stratum/v0.6";

    let template = Template::build(
        parents, height, blue_score, current_bits,
        &miner_spk, total_fees, other_txs, coinbase_tag, job_id.clone(),
    );

    if clean_jobs {
        self.replace_templates(template.clone());
    } else {
        self.push_template(template.clone());
    }

    // Send mining.notify
    self.notify(methods::NOTIFY, template.to_notify_params(clean_jobs))
        .map_err(|e| format!("notify send: {}", e))?;

    Ok(job_id)
}
```

Wire into `handle_authorize` so that immediately after a successful
authorize, the first template is generated and notified. This is
what starts the miner mining.

**Open design question:** the handler closures are currently `fn`
not `async fn`, and the template install path needs to do I/O-ish
things (RwLock.read is sync, but nightly `notify` could block on
the writer task's mpsc channel). Probably fine to keep sync; the
mpsc is unbounded.

### 4. Tip change detection (~100 lines)

Two approaches, pick one:

**A. Polling in stratum::run**

Add a 1-second timer that checks `dag.read().selected_tip()` and
compares to a cached value. On change, iterate all authorized
sessions and call `install_fresh_template(clean_jobs=true)`.

Pros: isolated, no changes to main.rs's accept_block path.
Cons: 1-second tip-detection latency (miner works on stale
template for up to 1s).

**B. Broadcast channel**

Add `tip_tx: broadcast::Sender<TipChanged>` to shared state. Hook
into both places in main.rs where `accept_block` Disposition
becomes Extension or Reorg:

```rust
// In main.rs, inside the accept_block success path:
if matches!(disposition, Disposition::Extension | Disposition::Reorg) {
    let _ = tip_tx.send(TipChanged { hash, height, blue_score, parents, bits });
}
```

`stratum::run` already has the scaffolding for `broadcast::Receiver<TipChanged>`.

Pros: zero-latency tip propagation.
Cons: touches accept_block in main.rs (already complex).

**Recommendation: start with A (polling)**. Lower coupling, good
enough for solo mining where tip changes are infrequent.

### 5. Integration test (~300 lines)

Create `tests/sprint_aa1_integration.rs`. Mock:

- `Arc<RwLock<GhostDAG>>` with a controlled tip
- `Arc<Storage>` with a `current_bits` meta
- `Arc<Mempool>` (empty)
- A tokio task that binds a real TCP listener on an ephemeral port
- A test miner that connects, subscribes, authorizes, and polls
  for mining.notify

Test scenarios:
- Full happy path: subscribe → authorize → receive notify →
  mine → submit → accept_block mock called with correct Block
- Invalid address on authorize → error-24 response
- Submit against wrong job_id → error-21
- Multiple sessions get distinct extranonce1 values
- Session cap enforcement (connection 257 rejected)

### 6. Documentation

Already drafted:
- `docs/releases/v0.6.0.md` — release notes
- `docs/operations/stratum.md` — operator guide (marks v0.6.0-alpha2
  limitations, describes v0.6.0-final expected behavior)

Update required on v0.6.0-final: remove "Known limitations" section
items that get addressed, add ASIC connection examples with real
port and address.

### 7. Chain reset (after pt 3 ships)

Separate work: see `docs/releases/v0.6.0.md` section "Chain reset plan".

Critical: `GENESIS_BITS` needs calibration based on expected initial
hashrate. A target too easy (like current `0x1d00ffff`) produces
fork explosion with low actual hashrate. A target too hard produces
no blocks and the network looks dead.

A reasonable starting point: expect ~30-50 Mhash/s from the seed +
2-3 Akash workers during bootstrap. Target 60-second blocks (not
10s — 10s needs more hashrate than we'll have on day 1). Calibrate
GENESIS_BITS so that `target ≈ 2^256 / (30_000_000 × 60)`.

Work it out:
- 30 Mhash × 60s = 1.8e9 hashes per block
- target = 2^256 / 1.8e9 ≈ 2^256 × 5.6e-10 ≈ 2^225
- That's a target leading byte around 2^225/2^248 = 0x80 in top
  4-byte slot → bits with exponent 29 something

Will re-derive precisely at reset time with actual seed hashrate
measured in isolation. Don't hardcode this estimate yet.

## Estimated effort

| Item | Lines | Time |
|---|---:|---:|
| CLI flags                  |  50 | 30 min |
| accept_block callback      |  80 | 45 min |
| Per-session template gen   | 150 |  1.5h |
| Tip detection (polling)    | 100 | 45 min |
| Integration test           | 300 |  2h   |
| Doc updates                | ~50 | 15 min |
| **Total**                  | 730 |  5.5h |

Chain reset is separate: ~1h + 40min Docker build + 30min deploy
+ 30min-1h announcement. Total for "go live" from pt 3 start:
about 8 hours of focused work.

## Why this was deferred from the overnight session

This sprint took the 80-byte MiningHeader refactor (AA.0) plus
three pieces of AA.1 (protocol scaffolding, tx format + merkle
branch, share validation pipeline) from zero to green in a single
night. 3,291 lines of consensus-critical Rust with 68 new passing
tests.

The remaining pt 3 integration involves:
- Tight coupling between stratum module and main.rs state
- Design decisions (polling vs broadcast, template per-session) that
  benefit from deliberation rather than tired execution
- accept_block wiring that touches consensus state under lock — bugs
  here can corrupt chain

Doing pt 3 fresh produces noticeably better architecture and lower
bug risk. The consensus and protocol code is already the hard part
and it's done.
