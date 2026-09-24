# A6 — Node network, RPC and metrics surface audit (Bloch Genesis-4, `bloch-pos-node`)

Auditor: A6. Date: 2026-09-16. Repository: `/home/user/bloch-sis-pow` (read-only; no cargo build/test run).

## 1. Scope & method

**Files read in full:** `crates/bloch-pos-node/src/net.rs` (1590 lines), `p2p.rs` (2533), `codec.rs` (311), `rpc.rs` (2553), `rpc/method_registry.rs` (274), `metrics.rs` (1000), `tests/rpc_method_registry.rs` (skimmed by test name), `rpc/tests.rs` (skimmed by test name), `crates/libp2p-yamux/{Cargo.toml,src/lib.rs,tests/lockfile_guard.rs}` plus a full `diff -u` against the upstream `libp2p-yamux-0.47.0` crate downloaded from crates.io into the scratchpad; the yamux 0.13.10 registry source (`src/lib.rs:126-151`) to verify the assert claim.

**Engine paths read (the receive/send boundary):** `engine.rs` `ingest_one` 2251-2484, `park_orphan` 2486-2504, `prune_below_finalized` 2519-2548, `on_transaction` 3022-3144, `select_transactions` 3166-3216, `on_attestation`/`judge`/`apply_decision`/`release_held` 3719-3903, `serve_rpc` 4024-4240, `envelope_by_id` 4006, `start_devnet`/`start_libp2p` 4427-4485, `run` 4487-4810, the slot loop 5150-5376, `admissible` 5561-5760, `tx_source_hash` 514-528, `propose` 1810-2060, constants at 204/224/275/294/306/337/377/415; `bloch-pos-committee/src/gossip.rs` `process` 309-455; `store.rs` `blocks_after`/`scan_page` 843-960; `main.rs` flag defaults (1218, 1281-1440, 1509-1570); `transition.rs` `from_canonical_bytes` 1010-1070 and `compute_post_state` 5440-5470.

**Deploy configs read for port exposure:** `fly.toml`, `blochv-node-{2..10}.fly.toml` (diffed), `deploy/docker-compose.yml`, `deploy/hardening/{README.md,docker-compose.hardened.yml}`, `os/bloch-pos-node.nix`, `deploy/bootnodes/{bootnodes.txt,verify-bootnodes.sh}`, `docs/THIRD-PARTY-QUICKSTART.md` §0 and §"Same height is not agreement", `deploy/FLAG-DAY-EPOCH-2700.md` and `FLAG-DAY-LIFECYCLE.md` port lines, `deploy/FLEET-INVENTORY.md`.

**Prior art read for KNOWN labelling:** `docs/audit/groundstate_audit.md` (Era-1, PoW — not applicable to this crate), `docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md` (§4 item 1 describes the node as "127.0.0.1 skeleton, no RPC" — obsolete), `docs/specs/BLOCH-POS-NETWORK-CAPACITY.md`, `BLOCH-POS-SORTITION-DOS.md`, `BLOCH-ATTESTATION-GOSSIP.md`, `docs/API.md` (Genesis-3 era, sealed), `deploy/RPC-SURVIVAL-RUNBOOK.md` (Genesis-3), `SECURITY.md`, `audit/CONSOLIDATED-SECURITY-REPORT.md`. The Round-1/2/3/6/7 remediation audits and the 2026-09-07 external audit that code comments cite (`R1 A3-M2..M5`, `R3 M-1/M-4/M-5/M-7/NEW-1`, `R6 HIGH-8/MED-14`, `R7 M6`, `O04/O06`, `SC3-yamux-dedupe`, `C-R6-2`) are **not in the repository**; where a finding is covered by one of those I cite the code comment that names it.

**Method:** adversarial reading as (a) an unauthenticated Internet client of the bootnodes' public ports, (b) a malicious devnet peer that a validator's firewall admits (i.e. a compromised bootnode/observer or fleet host), (c) a malicious libp2p peer for the not-yet-live transport, (d) an RPC client. Every finding below cites the lines that establish it; where I could not confirm a number by execution I say so and give confidence.

**Two facts that frame everything:** (1) the live fleet runs `--transport devnet` (README table row "Transport"; `bootnodes.txt`; quickstart §"The transport is devnet"), a plain TCP full mesh with no authentication, no handshake, no peer scoring and no consequence for a `Reject` (`net.rs:62-71, 175-177`); (2) both published bootnodes answered the **full unauthenticated JSON-RPC, including `sendrawtransaction`, on `:8080` from the open Internet** as measured on 2026-09-01/02, and "two modest concurrent read loops have already made one of them stop answering for over a minute" (`docs/THIRD-PARTY-QUICKSTART.md:118-135, 636-649`; recorded there as R6 MED-14; "whether those ports stay open is an operational decision that has not been taken").

---

## 2. Findings (ordered by severity)

### NET-01 — Public bootnodes expose the full unauthenticated RPC (incl. `sendrawtransaction`) on `:8080`, and RPC executes on the consensus thread
- **Severity:** High. **Status:** KNOWN — `docs/THIRD-PARTY-QUICKSTART.md:118-135` ("Correction, 2026-09-02"), `:636-649` (R6 MED-14). Still recorded as open ("decision not taken").
- **Refs:** `rpc.rs:55-64` (no auth by design), `rpc.rs:1284-1317` (`serve`), `rpc.rs:1017-1043` (`EngineBackend::call` → engine channel), `engine.rs:5358-5363` (`EngineEvent::Rpc` handled inline on the consensus thread), `engine.rs:4136-4205` (`sendrawtransaction` → `on_transaction` → broadcast at 3142).
- **Description:** The RPC has no authentication, no rate limit and no per-IP cap (`MAX_CONNECTIONS = 64`, `rpc.rs:92`). Every method except `getbalance`/`getutxos` (served off-thread from `SharedHead`, `rpc.rs:988-1014`) is answered by the consensus thread between duties. On the two hosts that are the network's only public entry points the RPC is reachable from the Internet on `:8080` (the node's own `--rpc-port 16400` is loopback; something forwards `:8080`). The quickstart's own measurement shows the consensus-thread stall is real, not theoretical.
- **Attack scenario:** (a) Availability: 64 concurrent clients each issuing `getvalidators`/`getblockbyslot`/`gettxout` in a loop keep the loop busy; each request is individually cheap after the 2026-09-05 fixes (`serve_rpc` is O(1)–O(chain) per call), but 64 × 10 s engine timeouts of queued work still stall the observer. (b) Write: `sendrawtransaction` reaches `on_transaction` and relays to all 63 validators (see NET-02 for what that buys). (c) Slowloris on the 64 slots (NET-11).
- **Evidence:** `rpc.rs:57-59` "No API key, no rate limit, no per-method authorisation"; quickstart `:118-123`: "both published bootnodes answer JSON-RPC on `:8080` from the open internet, and `sendrawtransaction` is reachable there".
- **Recommendation:** Close `:8080` (or front it with an authenticating proxy that strips `sendrawtransaction`); add a per-IP connection/rate limit to `rpc::serve`; move the remaining engine-thread reads to the `SharedHead` snapshot (only `sendrawtransaction`, `getmempoolinfo`, `gettxstatus` genuinely need the loop).
- **Confidence:** High (documented measurement + code path).

### NET-02 — Mempool admission is O(N × SHA3) per transaction and admits/relays transactions whose inputs do not exist; one public submission point can saturate every validator's consensus thread
- **Severity:** High (possibly Critical if the estimate below is confirmed by measurement: network-wide liveness degradation with no precondition beyond the public `:8080`/`:19100` ports). **Status:** NEW (the per-source scan was introduced by R7 M6; the "inputs need not exist" gap is acknowledged in `engine.rs:3100-3105` but its amplification is not).
- **Refs:** `engine.rs:3041-3047` (per-source cap scan), `engine.rs:514-528` (`tx_source_hash` = SHA3-256 over the first input's hybrid pubkey, ~3.7 KB), `engine.rs:204` (`MEMPOOL_MAX = 4096`), `:224` (`MEMPOOL_MAX_PER_SOURCE = 64`), `engine.rs:3058-3083` (eviction on strictly-higher tip), `engine.rs:3121`/`5621-5688` (`admissible`: structure, price, then one hybrid verify per input; no UTXO existence check — "What this does NOT catch is a transfer whose inputs do not exist", `:3102`), `engine.rs:3142` (relay after admission), `engine.rs:1932-2000` (proposer probe loop: one `compute_post_state` — which clones the BTreeMap-backed `CommittedState` — per refused transaction, up to `MAX_TXS_PER_BLOCK = 256`), `bootnodes.txt:46-50` ("Your TRANSACTIONS DO relay ... the observer passes it to the 63 validators").
- **Description:** For every incoming transaction, before the cheap structural checks and before any signature check, `on_transaction` computes `tx_source_hash` for **every entry in the mempool** to count same-source entries. Each such hash is SHA3-256 over ~3,745 bytes. At a full mempool that is ~15 MB hashed per incoming transaction (≈30–60 ms on a typical core; not measured). Admission requires valid signatures but not existing inputs, so an attacker with its own keys can (1) fill the mempool with 4,096 syntactically valid, unincludable transfers (≥64 distinct first-input keys defeats the per-source cap; max tip sorts them first and evicts honest transactions with lower tips), and (2) keep every validator's consensus thread busy: each further *admitted* transaction (strictly higher tip than the current minimum) costs every validator the full scan plus one hybrid verify, because admitted transactions are relayed to all peers. At ~20–30 admitted tx/s network-wide the consensus thread is saturated; duties are performed only between event batches (`engine.rs:5309-5364`). Independently, each proposer whose top-256 by tip is attacker transactions runs up to 256 probe iterations, each cloning the committed state (452K eUTXO entries on the live chain per `rpc.rs:2262-2264`), before it can propose. Cost to the attacker: ~30 hybrid signatures per second (Falcon-1024 sign ≈ 5–10 ms) — a fraction of one core.
- **Attack scenario:** From any Internet host: POST `sendrawtransaction` to `139.180.166.5:8080` (or push `FRAME_TX` frames to `139.180.166.5:19100`), 4,096 transfers with fresh keys, nonexistent outpoints, 1 output ≥ 1,000 sat, `tip_millisat_per_gas` ramping upward. Then sustain 20–30 tx/s with monotonically increasing tips. Expected effect: consensus-thread CPU saturation on all 63 validators, proposals delayed by up to 256 state clones per slot, honest transactions evicted; recovery only after the attacker stops (entries expire after `MEMPOOL_TTL_SLOTS = 100`, `engine.rs:275`; each proposer bars only the ones it probed, `REJECTION_TTL_SLOTS = 128`).
- **Evidence:**
  ```rust
  // engine.rs:3041-3047 — runs BEFORE admissible() and BEFORE any signature check
  if let Some(source) = tx_source_hash(&tx) {
      let from_source =
          self.mempool.values().filter(|t| tx_source_hash(t) == Some(source)).count();
  // engine.rs:514-519
  PosTransaction::Transfer { inputs, .. } => { let pk = &inputs.first()?.pubkey; Some(Sha3_256::digest(pk).into()) }
  ```
- **Recommendation:** Keep a `HashMap<[u8;32], usize>` of per-source counts maintained on insert/remove (or cache the source hash alongside each entry) — O(1) per admission. Check at admission that every input outpoint exists in the head's eUTXO set and that its `script_hash` matches the input pubkey (the head is already published as `SharedHead` and `gettxout` reads it); this removes the "valid signature, nonexistent input" class from the mempool and from relay entirely. Rate-limit `sendrawtransaction` per source IP. Cap the proposer's probe loop by wall-clock budget as well as by count.
- **Confidence:** Medium-high on the mechanism (every line is in the code path); medium on the throughput numbers (hash cost and clone cost are estimates; no benchmark run). Cross-reference: the mempool/consensus auditor should own the fix; this is the network-reachable delivery path.

### NET-03 — Devnet inbound connection cap is global with no per-IP limit; 128 idle connections from one attacker lock every other peer out of a bootnode indefinitely
- **Severity:** High (unauthenticated DoS of the only public onboarding path; the accepting node itself keeps running). **Status:** NEW (R3 M-4 / R1 A3-M2 added the cap and the 120 s deadline, per `net.rs:498-523`; neither added a per-IP bound or an idle-heartbeat cost).
- **Refs:** `net.rs:509` (`MAX_INBOUND_CONNECTIONS = 128`), `net.rs:963-965` (global count check, no source-address check), `net.rs:523` (`DEVNET_IO_TIMEOUT = 120 s`), `net.rs:753-769` (per-frame deadline), `net.rs:1012-1030` (reader loop continues on any decoded-or-not frame), `net.rs:791-813` (unknown type byte → `None`, no penalty), `bootnodes.txt:67-68` (public `:19100`).
- **Description:** The accept loop refuses connections once 128 inbound are live, counting per process not per IP. A connection stays alive as long as one frame arrives per 120 s; a 5-byte frame (`len=1 ‖ type 0xFF`) is decoded to `None` and ignored, costing the attacker 5 bytes per ~119 s per connection. Nothing disconnects, scores or bans a peer.
- **Attack scenario:** One host opens 128 TCP connections to `139.180.166.5:19100` and to `139.180.173.231:19100`, sends a 5-byte junk frame every 100 s on each. Every third-party node following `docs/THIRD-PARTY-QUICKSTART.md` is now refused by both bootnodes (`continue` → immediate close, `net.rs:963-965`). The bootnodes' outbound dials to validators are unaffected, so validators do not notice.
- **Evidence:** `net.rs:963`: `if inbound_live.load(Ordering::Acquire) >= MAX_INBOUND_CONNECTIONS { continue; }` — the only admission decision on an inbound socket.
- **Recommendation:** Per-source-IP cap (e.g. 4) in the accept loop; require the first frame within a short deadline and require it to be a *meaningful* frame; charge unknown-type frames (close after N); expose the inbound count in metrics (it is — `peer_count_devnet` — but not split inbound/outbound).
- **Confidence:** High.

### NET-04 — Unauthenticated devnet frames buy bounded but sustained consensus-thread CPU (hybrid verifies) and unbounded log spam; `Reject` has no consequence on this transport
- **Severity:** Medium (reachable from the Internet only on bootnodes; on validators only from firewall-allowlisted hosts — a privileged position). **Status:** KNOWN in principle (`net.rs:62-71`, `bootnodes.txt:12-16`: "a published validator address is an unauthenticated frame-push surface directly into consensus"); the per-turn cost bound and the attestation-variant detail are NEW quantification.
- **Refs:** Blocks: `engine.rs:2251-2448` (order: dedup → parked-refused → 2×SHA3 over body → tx decode → slot horizon → **hybrid verify** at 2422-2427 → `Verdict::Reject` + `eprintln!` at 2443). Attestations: `engine.rs:3719-3740`, `gossip.rs:355-366` (dedup only consults `seen`, which is populated only by *verified* attestations at `:451`), `:377` (committee membership, binary search), `:420` (verify). Budget: `net.rs:249, 271` (4096 events / 64 MiB), `engine.rs:5309-5314` (a turn drains everything queued). Devnet no-op verdict: `net.rs:175-177`. Cost figure: `engine.rs:5738` ("~145 µs each, measured 2026-08-21").
- **Description:** A block with a registered `proposer_index`, matching body/attestation roots and a garbage signature costs one hybrid verify and one `eprintln!` per frame and is then forgotten (not stored, not cached as rejected — only finality-latch refusals are cached, `engine.rs:2268`). An attestation for a *future* slot in the current/next epoch, naming a real committee member (schedule is public — `BLOCH-POS-SORTITION-DOS.md`) with a garbage signature, costs one verify each; since only verified attestations enter `seen`, the equivocation cap never engages for forged variants, so the cost is unbounded per duty until the honest attestation lands. The queue budget bounds this to ≤ 4096 events per engine turn (≈ 0.6 s of verifies), after which duties run; a sustained flood therefore yields ~100% consensus-thread utilisation and one stderr line per rejected frame (journald/disk), but not a hard stall. On devnet the peer pays nothing and is never disconnected.
- **Attack scenario:** From a bootnode's public `:19100`: stream ~5 KB forged block frames at ~7,000/s (≈ 280 Mbit/s). Observer's consensus thread runs at 100%, `getchaininfo` latency rises to the per-turn budget, logs grow at ~7,000 lines/s.
- **Recommendation:** On devnet, count rejects per connection and close after a small threshold; rate-limit `eprintln!` per reason; add a small negative cache of `(proposer_index, slot, sig-hash)` rejects; for attestations, add a per-`(validator, slot)` forged-variant counter with a low cap before the verify.
- **Confidence:** High on ordering (read the code); medium on absolute CPU numbers.

### NET-05 — Devnet `get-blocks` serving is rate-limited per *connection* only (no per-IP/global cap), pages are 4× larger than libp2p's and carry no byte cap
- **Severity:** Medium (bandwidth/disk exhaustion of the public bootnodes; no consensus impact). **Status:** NEW (the per-connection limiter is R3 M-4 / R1 A3-M2, `net.rs:816-851`; the missing aggregate bound is not covered).
- **Refs:** `net.rs:532-533` (8 answers/s, burst 32, **per connection**), `net.rs:240` (`SYNC_PAGE_BLOCKS = 512` vs `p2p::MAX_SYNC_BLOCKS = 128`), `net.rs:894-906` (`Store::blocks_after(.., SYNC_PAGE_BLOCKS)` → `Vec<Vec<u8>>` fully materialised, then written frame by frame; no byte cap — compare `p2p.rs:1740-1743` which caps a page at `MAX_SYNC_FRAME − 1 KiB`), NET-03 for the 128-connection multiplier.
- **Description:** A 9-byte request buys up to 512 blocks. With 128 connections from one host the serving budget is 128 × 8 × 512 ≈ 524K blocks/s (at today's ~10 KB blocks ≈ 5 GB/s of disk reads and egress demand), bounded only by the attacker's ability to receive. The page is materialised in memory before writing: 512 × block size (≤ 8 MiB by `MAX_FIELD_LEN`) per connection — harmless at today's block sizes, but there is no cap.
- **Attack scenario:** Attacker with a fat downlink saturates the bootnode's uplink with its own chain history; validators that depend on the observer for transaction relay and third parties trying to sync are starved.
- **Recommendation:** Per-IP and global token buckets on `serve_get_blocks`; stream the page from the log instead of collecting it; add a byte cap mirroring `read_sync_page`.
- **Confidence:** High.

### NET-06 — libp2p sync codec buffers up to 8 MiB per inbound *request* substream for a 13-byte message
- **Severity:** Medium today (libp2p is not the live transport); would be High if `--transport libp2p`/`dual` were rolled out. **Status:** NEW.
- **Refs:** `p2p.rs:681-687` (`read_request` → `read_capped`), `p2p.rs:722-732` (`take(MAX_SYNC_FRAME + 1).read_to_end`), `p2p.rs:300` (`MAX_SYNC_FRAME = 8 MiB`), `p2p.rs:271`/`1046` (2048 concurrent request-response streams per connection), `p2p.rs:1045` (30 s request timeout), `p2p.rs:1033-1037` (64 inbound connections, no per-IP limit).
- **Description:** The same 8 MiB cap is applied to requests and responses. A `GetBlocks` request is 13 bytes, but the codec will happily buffer 8 MiB of junk per substream before the strict decoder refuses it. One peer may open 2,048 substreams per connection and hold 64 inbound connections; within the 30 s timeout a 1 Gbit/s sender can force ~3.7 GB of `Vec<u8>` growth on the receiving node.
- **Recommendation:** Separate caps: requests ≤ 64 bytes; keep 8 MiB for responses only. Consider lowering `MAX_CONCURRENT_SYNC_STREAMS` for the *inbound* direction.
- **Confidence:** High on the code; the libp2p request-response behaviour reads each inbound stream concurrently (standard).

### NET-07 — libp2p sync steering: `peer_head` is set from the unvalidated header slot before the engine judges, and the top-`SYNC_FANOUT` claimants are always chosen
- **Severity:** Medium (libp2p not live; would be High: three Sybil peers can monopolise a catching-up node's sync requests). **Status:** NEW.
- **Refs:** `p2p.rs:1613-1615` (gossip block: `peer_head` updated from `env.header.slot` before `st.emit`, i.e. before any verdict), `p2p.rs:1529-1530` (same in the sync-response path, where `Origin::none()` means a `Reject` is never scored), `p2p.rs:1384-1398` (`request_blocks` sorts by claimed head, takes `SYNC_FANOUT = 3`), `p2p.rs:304`, `engine.rs:5221-5231` (the periodic sync pump goes through this path).
- **Description:** One gossip block with `slot = u64::MAX` (rejected by the engine as past the horizon, costing the sender −50 score against a −400 graylist threshold — and graylisting does not affect request-response anyway) permanently pins that peer at the top of the head ranking; `peer_head` is never lowered. Three such peers answering with empty pages starve the node's sync pump of honest peers. `MAX_PAGES_WITHOUT_PROGRESS` bounds page-chasing, not the periodic re-selection.
- **Recommendation:** Update `peer_head` only on `Verdict::Accept` (route it through the engine's report), cap the recorded head at `wall_slot + MAX_FUTURE_SLOTS`, and randomise part of the fanout.
- **Confidence:** High.

### NET-08 — libp2p: identify-advertised addresses overwrite the `dialed` map, letting a connected peer suppress redials to honest configured peers (eclipse assist)
- **Severity:** Medium (libp2p not live; requires `--p2p-peer` entries without a `/p2p/<id>` suffix, which the code explicitly expects: "an operator pasting a listen address has no reason to know the id yet", `p2p.rs:1277-1283`). **Status:** NEW.
- **Refs:** `p2p.rs:1171-1180` (`note_dialed`: `self.dialed.insert(addr, peer)` — `HashMap::insert` *replaces* the value on an existing key), `p2p.rs:1496-1504` (identify `listen_addrs` → `note_dialed` for every advertised address), `p2p.rs:1274-1289` (redial tick: `id = peer_id_of(addr).or_else(|| st.dialed.get(addr))`; skip dial if that id is connected).
- **Description:** A connected malicious peer advertises the configured bootstrap addresses as its own `listen_addrs`. The map now says "addr A ↔ attacker". Whenever the honest node at A is not connected (restart, blip), the redial tick sees the attacker connected and never dials A again — for as long as the attacker stays connected (`forget_peer` only clears the mapping on the attacker's disconnect). Combined with the 64-inbound limit having no per-IP cap, this is the assist an eclipse needs.
- **Recommendation:** Never let identify overwrite a mapping learned from a successful *dial*; keep identify addresses in a separate map consulted only for dedup, never for skipping a configured peer; or require `/p2p/` suffixes on configured peers.
- **Confidence:** High.

### NET-09 — Devnet idle-close at 120 s silently drops the first broadcast after an idle period; the honest cadence on non-sync connections is ~16 minutes
- **Severity:** Medium (robustness/liveness of attestation delivery on the live transport; the chain does finalize today, so some path suffices — see caveat). **Status:** NEW (the timeout is R3 M-4 / R1 A3-M2; its interaction with broadcast cadence is not discussed anywhere; the comment at `net.rs:518-522` asserts "an honest peer's connection is never idle anywhere near this long", which is false for 61 of a validator's 63 connections).
- **Refs:** `net.rs:1008-1030` (inbound reader: `read_frame` fails after 120 s idle → `return` → `InboundHalf::drop` → `shutdown(Both)`, `net.rs:621-626`), `net.rs:1071-1085` (dialer-side reader also exits on idle; nothing tells the writer loop), `net.rs:1117-1123` (dialer writes; only a *failed* write triggers reconnect), `net.rs:1103-1109, 1157-1163` (only slot-holding dialers send the 5 s get-blocks ping; `SYNC_FANOUT = 2`), `engine.rs:1802, 2082` (a validator broadcasts its own attestation once per epoch and its proposals), `engine.rs:5221-5231` (sync pump fires only when ≥ 2 slots behind).
- **Description:** On a connection that holds no sync slot, the only frames are the dialer's own broadcasts and relayed transactions. Absent transaction traffic, both directions of a validator pair go idle for ~16 min, so the accepting side closes the socket after 120 s. By TCP semantics the dialer's *first* write after the peer's close succeeds locally (data enters the send buffer, the peer answers RST) and only the *second* write fails — so the frame that was written into a dead socket is lost, and the dialer reconnects only afterwards (`break // reconnect` at 1122). The frame most likely to be lost is the node's own attestation or proposal.
- **Attack scenario:** None needed — this is ambient behaviour. It also explains why the fleet's health appears to depend on background traffic (the founder's consolidation sweep) and the sync pump.
- **Recommendation:** Send a keepalive/ping frame on every connection at < 120 s intervals (a new type byte), or make the inbound side's idle timeout ≫ one epoch; have the dialer's reader thread signal the writer loop to reconnect when it exits; measure per-connection attestation delivery ratio on the fleet before and after.
- **Confidence:** Medium-high on the mechanism (TCP semantics + code); the *observed* impact is unmeasured.

### NET-10 — RPC JSON parser memory amplification and id echo
- **Severity:** Medium where the RPC is public (bootnodes `:8080`), Low at the loopback default. **Status:** NEW.
- **Refs:** `rpc.rs:84` (`MAX_BODY_BYTES = 1 MiB`), `rpc.rs:375-383` (`Json` enum: every element ≥ 32 bytes), `rpc.rs:640-661` (array parse: `Vec<Json>` grows with the input; depth cap 64 does not bound width), `rpc.rs:1256` (`id` cloned and echoed verbatim, even when it is an object/array), `rpc.rs:92` (64 concurrent connections).
- **Description:** A 1 MiB body of `[1,1,1,...]` (~524K elements) becomes ~17 MB of `Json` nodes; 64 concurrent requests ≈ 1.1 GB transient. An `id` of that shape is cloned and serialised back (1 MiB response). No panic, no persistence, but a cheap 16× memory amplifier on an unauthenticated port.
- **Recommendation:** Cap element count (a JSON-RPC call needs < 1,000 nodes); refuse non-scalar `id`s; lower `MAX_BODY_BYTES` to what `sendrawtransaction` needs (a 512 KiB tx is 1 MiB of hex — keep 1 MiB but count nodes).
- **Confidence:** High.

### NET-11 — RPC connection exhaustion/slowloris: 64 slots, 30 s deadline, no per-IP limit
- **Severity:** Medium where public, Low at loopback. **Status:** NEW (the per-request deadline is R1 A3-M4-era hardening; the aggregate is not bounded per client).
- **Refs:** `rpc.rs:92, 96, 1300-1305` (over cap → 503), `rpc.rs:1447-1449, 1454-1479` (one 30 s deadline per request), `rpc.rs:1614-1641` (response written under a 30 s write timeout).
- **Description:** 64 connections each renewed every 30 s (send half a request head, let the deadline expire, reconnect) keep every other client at 503. Cost: 64 sockets.
- **Recommendation:** Per-IP cap (2–4), shorter head deadline (5 s), 503 with `Retry-After`.
- **Confidence:** High.

### NET-12 — Bootnode/observer hosts are a privileged frame-push position into all 63 validators
- **Severity:** Medium (privileged position needed: compromise of a bootnode/observer host). **Status:** KNOWN partially — `bootnodes.txt:12-16, 36-50` documents that validators accept only from firewalled known peers and that the observers dial all 63; the consequence (an observer is exactly such a known peer) is not spelled out.
- **Refs:** `net.rs:1008-1031` (inbound reader on a validator accepts blocks/attestations/txs from any connection it accepted), `net.rs:1071-1085` (the dialer's reader also accepts any frame the dialed peer sends), `engine.rs:3142` (tx relay), NET-02/NET-04 for what frames buy.
- **Description:** Because the transport has no identity, the firewall allowlist is the whole trust model, and the two public observers are on every validator's allowlist. An attacker who gets code execution on `139.180.166.5` (public `:19100` + public `:8080` RPC + SSH) can push forged blocks/attestations (NET-04 cost) and admitted transactions (NET-02) into every validator simultaneously, and can serve a withheld/filtered history to third parties. The observers hold no keys, so safety is not directly at stake; liveness is.
- **Recommendation:** Keep observers off validators' inbound allowlists (validators need nothing from them but transactions, which could come through a separate relay-only path), or move to the authenticated transport.
- **Confidence:** High.

### NET-13 — libp2p `with_peer_score` failure is warn-not-fatal; a scoring-less node is a flood amplifier
- **Severity:** Low (the call practically cannot fail with static params; libp2p not live). **Status:** KNOWN — `BLOCH-POS-NETWORK-CAPACITY.md` §4.2 item 2 and §6 change #5 asked for fatal; still `eprintln!` at `p2p.rs:1012-1016`.
- **Recommendation:** Make it `return Err(...)`.
- **Confidence:** High.

### NET-14 — Devnet sync slots are sticky for the connection lifetime; a silent slot-holder throttles catch-up
- **Severity:** Low. **Status:** NEW.
- **Refs:** `net.rs:229` (`SYNC_FANOUT = 2`), `net.rs:1091-1116, 1157-1168` (slot claimed on connect, released only on write failure/disconnect), `net.rs:865-879` (a refused or empty answer writes nothing — indistinguishable from "caught up").
- **Description:** The first two dialers to connect hold both sync slots as long as their sockets accept writes. A peer that is itself behind, or a malicious allowlisted peer that answers nothing, throttles this node's pull path to its pace; the node only catches up via broadcasts and the 2-slot-behind sync pump (which does broadcast to all peers, NET-15). For a third party whose only peers are the two bootnodes this is the whole sync path.
- **Recommendation:** Rotate slots when a slot-holder returns no progress for N ticks; prefer peers with a higher observed head.
- **Confidence:** High.

### NET-15 — The engine's sync pump broadcasts `get-blocks` to every devnet peer; each answers a 512-block page
- **Severity:** Low (bounded by the O06 byte budget; bandwidth waste and shed churn). **Status:** NEW.
- **Refs:** `engine.rs:5225-5231` (`net.broadcast(get_blocks_frame(..))`), `net.rs:653-671` (broadcast to all outbound and inbound connections), `net.rs:240`.
- **Description:** A validator ≥ 2 slots behind asks all ~63 peers at once; each returns up to 512 blocks (~5 MB today), i.e. ~300 MB inbound per pump, of which the budget admits 64 MiB and the reader threads still parse and discard the rest. This is the 2026-08-21 shape with a lid on it.
- **Recommendation:** Direct the pump at the slot-holding peers only (the devnet equivalent of `p2p::request_blocks`).
- **Confidence:** High.

### NET-16 — Metrics server has no whole-request deadline (per-read timeout renews)
- **Severity:** Low (off by default, loopback by default; a local unprivileged process could blind `/health` for monitoring/systemd). **Status:** NEW (the RPC fixed exactly this: `rpc.rs:1452-1453`).
- **Refs:** `metrics.rs:90, 656, 663-675` (loop: `sock.read` under a 10 s *socket* timeout, no deadline; head cap 8 KiB), `metrics.rs:97` (16 connections).
- **Description:** 1 byte every 9 s keeps a connection for up to 8192 × 9 s ≈ 20 h; 16 of them make `/health` answer 503 "too many connections" to the real probe.
- **Recommendation:** Reuse the RPC's `read_before_deadline` pattern.
- **Confidence:** High.

### NET-17 — Devnet page has a block-count cap but no byte cap (unlike libp2p)
- **Severity:** Low (latent; grows with block size). **Status:** NEW. See NET-05. `net.rs:894` vs `p2p.rs:1740-1743`.

### NET-18 — Deploy/config drift: NixOS PoS module defaults to `--transport libp2p`, which does not interoperate with the live fleet; its comment about the binary's default is stale
- **Severity:** Low/Info. **Status:** NEW (the stale text refers to Round-3 H-2, which `main.rs:1211-1218` and `transport_tests::no_transport_flag_means_devnet` show as fixed: default is devnet, `--p2p-listen` default is loopback).
- **Refs:** `os/bloch-pos-node.nix` `transport` option (default `"libp2p"`, comment: "compiled behaviour is `Dual` on 0.0.0.0:16400"), `package` option TODO ("do not enable this module in a real deploy"), `docs/THIRD-PARTY-QUICKSTART.md:87-90, 796-805` ("`--transport libp2p` against these hosts exchanges zero frames and leaves you alone on your own fork").
- **Description:** An operator who wires the module today gets a node alone on its own fork that reports a plausible height and finality. The module also fixes RPC/metrics to loopback (good) and sets `TasksMax = 512` — note the devnet transport spawns 2 threads per inbound connection (≤ 256) plus 2 per configured peer (~128 → 256) plus RPC (≤ 64) plus metrics (≤ 16) plus the swarm/engine/forwarder threads: a fully loaded validator can approach 512 tasks.
- **Recommendation:** Default the module to `devnet` (or `dual`) until the fleet migrates; delete the stale comment; raise `TasksMax` or document the thread budget.
- **Confidence:** High.

### NET-19 — libp2p identity file is written non-atomically with the default umask before `chmod 0600`, and the chmod result is ignored
- **Severity:** Low (transport identity only; not a validator key). **Status:** NEW.
- **Refs:** `p2p.rs:937-956` (`std::fs::write` then `let _ = set_permissions(0o600)`).
- **Recommendation:** Create with `OpenOptions::mode(0o600)`; write to a temp file and rename; propagate the chmod error.

### NET-20 — Frame-cliff vs consensus caps on the production transport
- **Severity:** Low (latent). **Status:** KNOWN — `BLOCH-POS-NETWORK-CAPACITY.md` §3.3 asked for a consensus `MAX_BLOCK_BYTES` (change #3); only `MAX_BLOCK_TX_BYTES(_V2)` (`fee_market.rs:73, 93`) and `MAX_ATTESTATIONS_PER_BLOCK = 4096` (`params.rs:78`) exist. 4096 × ~4.8 KB ≈ 19.6 MB exceeds `MAX_GOSSIP_BYTES` (4 MiB, `p2p.rs:248`) and even `MAX_FIELD_LEN` (8 MiB, `codec.rs:24`); at today's 64 validators a block cannot approach this, but nothing rules it out by consensus.

### NET-21 — Information exposure by design (Info)
- `getbuildinfo` (`rpc.rs:2471-2507`) reveals rustc version, target triple, commit and source digest — a fingerprint; deliberate and tested (`getbuildinfo_leaks_nothing_operational`).
- `/health` and `/metrics` (`metrics.rs:549-560, 459-463`) expose `validator_active` (this host performs duties) and `keystore_sealed` (0 = plaintext key on disk). If metrics were ever bound routable, these map validator hosts and plaintext-key hosts for the sortition-DoS adversary (`BLOCH-POS-SORTITION-DOS.md`). Loopback default and no-default-port mitigate.
- `identify` (`p2p.rs:1026-1029`) sends the default agent version (`rust-libp2p/<ver>`) and listen addresses. Standard.
- `getchaininfo` exposes only peer *counts* and the transport name; there is no `getpeers` (positive — no peer IPs leak).

### NET-22 — Minor code-level notes (Info)
- `net.rs:766` `vec![0u8; len]` allocates up to 8 MiB before the payload arrives; `calloc` makes it lazily committed, so RSS is bounded by bytes actually sent. Not exploitable beyond bandwidth.
- `net.rs:1022` decodes the full frame before the budget check (`send_to_engine`), so a stalled engine still pays decode CPU per frame per connection; `codec.rs:190,198` pre-allocate `Vec::with_capacity(natt)`/`(ntx)` from untrusted counts (≤ 4096 / ≤ 65,536 entries ≈ 0.6 MB / 1.5 MB) before reading them — bounded.
- `rpc.rs:1303` and `metrics.rs:642` write the 503 on the *accept* thread without a write timeout; the ~60-byte body always fits the kernel send buffer, so this is not reachable in practice.
- `HostPolicy` (`rpc.rs:1391-1421`): when bound to `0.0.0.0`, only loopback names are accepted unless `BLOCH_RPC_HOST_ALLOWLIST` is set, so public clients get 403 by default — good for browsers, but it is a header check, not authentication (`curl -H 'Host: 127.0.0.1'` passes). If the bootnodes' `:8080` forwarder preserves the client's `Host`, the gate may now be refusing naive clients there; it does not close NET-01.
- `store.rs:857-864`: an index/log disagreement falls back to a full-log scan per request — only on corruption, but it silently re-opens the H5 amplifier the index exists to close; consider rebuilding the index once and refusing to serve until then.

---

## 3. RPC method table (`rpc.rs:1114-1188` `route`, `method_registry.rs:80-107`, `engine.rs:4024-4240`)

Authentication: **none, for every method** (`rpc.rs:55-64`). Transport: HTTP/1.1 POST only, `Content-Type: application/json` required, `Origin` header refused, `Host` must match bind/allowlist (`rpc.rs:1496, 1545-1561`). Batch requests refused (`rpc.rs:1236-1243`). Body ≤ 1 MiB, head ≤ 16 KiB, depth ≤ 64, 30 s request deadline, 10 s engine timeout, 64 concurrent connections. Default bind `127.0.0.1:16310` (`main.rs:1564`, help `:383`).

| Method | Auth | Mutating? | Where it runs | Risk note |
|---|---|---|---|---|
| `getchaininfo` | none | no | consensus thread | Cheap now (`head_state_root` cached). Reveals transport name + peer counts. |
| `getbuildinfo` | none | no | consensus thread (constant) | Fingerprint (rustc/target/commit/digest). |
| `getblockcount` | none | no | consensus thread | Cheap. |
| `getblockbyslot` | none | no | consensus thread | Linear scan of `chain` Vec (`engine.rs:4055`, ~35K entries) + envelope clone; cheap. |
| `getblockbyid` | none | no | consensus thread | HashMap lookup + clone. |
| `getvalidator` | none | no | consensus thread | `active_validators()` walk; 64 entries. |
| `getvalidatorcount` | none | no | consensus thread | Cheap. |
| `getvalidatorbykey` | none | no | consensus thread | Index lookup then `getvalidator`. |
| `getvalidatoradmission` | none | no | consensus thread | Cheap; exposes activation constants. |
| `getvalidators` | none | no | consensus thread | Whole registry, uncapped (64 today; documented). |
| `getbalance` | none | no | **off-thread** (`SharedHead`) | Script index; bounded. |
| `getutxos` / `listunspent` | none | no | **off-thread** | Page ≤ 1,000, lazy iterator; bounded. |
| `gettxout` | none | no | consensus thread | Map lookup. |
| `gettxstatus` | none | no | consensus thread | Index lookup. |
| `getmempoolinfo` | none | no | consensus thread | `keys().map(len).sum()` O(mempool); leaks rejection-cache stats. |
| `sendrawtransaction` | **none** | **YES** (mempool + network broadcast) | consensus thread | Up to ~60 hybrid verifies per call (1 MiB body); O(mempool) source scan (NET-02); relays network-wide. |
| `gettransaction` | none | no | dispatcher | Always refused `-32005`. |
| `getnewaddress` | none | no | dispatcher | Always refused `-32006` (no key minting — positive). |
| any other name | — | — | dispatcher | `-32601`. **No admin/debug/shutdown/log-level/peer-add/remove/keystore methods exist** (positive). |

The method set is frozen by an exhaustive match (`method_registry.rs`) and a source-text guard (`tests/rpc_method_registry.rs` `ROUTED`), both verified consistent with `route`.

---

## 4. Listening ports / bind addresses

| Surface | Code default | Live fleet (as documented in-repo) | Deploy configs in repo |
|---|---|---|---|
| Devnet mesh (`--listen <port>`, `--listen-addr`) | port required; addr `127.0.0.1` (`main.rs:1548`); no auth | **Bootnodes: `0.0.0.0:19100` public** (`bootnodes.txt:67-68`); validators: routable ports behind per-IP host firewalls (`bootnodes.txt:12-16`; unverifiable from repo, `FLEET-INVENTORY.md` unfilled); Fly-hosted validators accept no inbound (`net.rs:546-549`) | NixOS PoS module: no devnet flags (module defaults to libp2p) |
| libp2p swarm (`--p2p-listen`) | `/ip4/127.0.0.1/tcp/16400` (`main.rs:1218`); Noise + yamux; identify; no kad/mdns | **Not live** (`bootnodes.txt:26-29`; quickstart). `FLAG-DAY-EPOCH-2700.md:90-93, 166-176`: `dual` on `0.0.0.0:16400` may be rolled host-by-host "with the firewall allowlist"; operators told to check `ss -tlnp` for unexpected `0.0.0.0:16400` | NixOS PoS module opens `p2pListenPort` (16400) in the firewall, `IPAddressAllow` from `allowedPeerCIDRs` |
| JSON-RPC (`--rpc-bind/--rpc-port`) | `127.0.0.1:16310` (`main.rs:1564`); `off` supported | Validators `127.0.0.1:16310` (`FLAG-DAY-LIFECYCLE.md:355`); bootnodes `--rpc-port 16400` loopback **but `:8080` publicly forwarded to it** (quickstart `:118-135, 641-649`, R6 MED-14, "decision not taken") | NixOS PoS module: `127.0.0.1` fixed, not configurable (good). G3 `fly.toml`/`blochv-node-*.fly.toml`: `--rpc-bind 127.0.0.1`, `[[services]]` for RPC removed (MED-6); G3 `deploy/docker-compose.yml`: `--rpc-bind 0.0.0.0` published on 16210-16212 (local testnet only); hardened compose: loopback |
| Metrics (`--metrics-bind/--metrics-port`) | off; bind `127.0.0.1` when enabled (`main.rs:1569`); GET-only | Not documented as enabled fleet-wide (`deploy/monitoring/README.md:48`: no default port) | NixOS PoS module: `127.0.0.1` fixed |
| G3 P2P 16110 | — | retired chain | `fly.toml` publishes 16110; compose publishes 16110-16112; hardened compose publishes 16110 only |

All `*.fly.toml` and `deploy/docker-compose*.yml` files describe the retired Genesis-3 PoW node and say so in their banners ("the live chain ... is not deployed from Fly or from this repository's Dockerfile", `fly.toml:2-11`); they do **not** describe the live PoS fleet's exposure. The only in-repo evidence of live exposure is `bootnodes.txt` and the quickstart's measurements.

---

## 5. Positive observations (verified)

- **`codec.rs`** is panic-free by construction: `Reader::take` uses `checked_add` (`:54-57`), all fixed-width reads go through `take`, `bytes()` caps at 8 MiB and slices before copying, decoders reject trailing bytes; fuzz targets exist for envelope/attestation/header decoders (`fuzz/fuzz_targets/pos_*`). `PosTransaction::from_canonical_bytes` reads counts without preallocation (`transition.rs:1016-1030`).
- **Devnet framing** (`net.rs:759-787`): length cap before allocation, one deadline per frame covering prefix and payload (tests `audit_devnet_frame_deadline_covers_prefix_and_payload`), `Ok(0)` → EOF, `Interrupted` handled.
- **`QueueBudget`** (`net.rs:350-467`): compare-and-swap count and byte reservation, per-class quotas (blocks 100%, attestations 75%, transactions 50%), saturating releases; applied to *both* transports via the forwarder (`engine.rs:4680-4727`). The 2026-08-21 OOM shape is closed.
- **Block ingest ordering** (`engine.rs:2245-2250, 2257-2448`): dedup, finality-latch cache, body/attestation-root recomputation, tx decodability and slot horizon all run before the hybrid verify; unknown proposer/parent → parked, never stored; orphan pool bounded (`ORPHAN_MAX = 256`), pruned below finality. Replaying public chain history into a node costs a hash lookup per block.
- **Attestation pipeline** (`gossip.rs:309-455`): window → checkpoint sanity → dedup/equivocation cap → committee membership → key → signature → Hold, with Ignore/Reject as distinct types; forged attestations cannot frame a validator (only verified ones are recorded).
- **libp2p** (`p2p.rs`): `ValidationMode::Strict` + `validate_messages()`, SHA3 message ids, 4 MiB `max_transmit_size`, P3/P3b explicitly zeroed with an exhaustive struct literal and a pinned test, Genesis-4-only protocol prefixes and topics (`/bloch-g4/...`, `bloch-g4/...`, tested), no `add_explicit_peer`, no kad/mdns/PEX, connection limits (64 inbound / 128 total / pending caps), per-peer sync token bucket + in-flight cap with a permit type that makes unadmitted serving uncompilable, per-peer page-chase budget, bounded FIFO `dialed` map, 300 s idle timeout, transport identity separated from validator keys.
- **libp2p-yamux fork** (verified against upstream 0.47.0 by diff): the vendored `src/lib.rs` is upstream with the `Either<yamux012, yamux013>` backend removed and the five deprecated 0.12-only setters/`WindowUpdateMode` dropped; `Config::default()` keeps `set_read_after_close(false)`; `set_max_num_streams` now configures 0.13 directly; `MAX_BUFFERED_INBOUND_STREAMS = 256` and the muxer polling logic are unchanged. `Cargo.toml` pins `yamux >= 0.13.10, < 0.14`; `Cargo.lock` contains exactly one `yamux 0.13.10` and a path-sourced `libp2p-yamux 0.47.0`; `tests/lockfile_guard.rs` fails if either changes. The claim that yamux 0.13 asserts `max_connection_receive_window >= 256 KiB × max_num_streams` is correct (`yamux-0.13.10/src/lib.rs:140-148`), so `MAX_YAMUX_STREAMS = 4096` is exactly at the 1 GiB default boundary and 4097 would panic at startup — pinned by the fork's two tests. The wire protocol id `/yamux/1.0.0` is unchanged. GHSA-vxx9-2994-q338 is not reachable through this build.
- **RPC** (`rpc.rs`): hand-written HTTP with strict request-line/header validation (no header folding, no duplicate `Content-Length`/`Host`, decimal-only length, chunked refused), single deadline per request, browser-request gate (Content-Type + no-Origin + Host allowlist) closing CSRF and DNS-rebinding, batch refused, depth-limited recursive parser (tested), numbers kept as text, errors as top-level objects, no key-minting or admin methods, frozen method registry with two independent guards, `getbalance`/`getutxos` moved off the consensus thread with index-backed O(page) cost.
- **Metrics** (`metrics.rs`): GET-only, no labels (no cardinality attack), the `unsafe` at `:615-624` is a sound `statvfs` into a zeroed struct with a NUL-terminated `CString`, health verdict corroborated by live wall-clock slot progress (R3 M-5), off by default and loopback by default.
- **Operational honesty**: `bootnodes.txt`, the quickstart and `SECURITY.md` state the devnet transport's lack of authentication and the `:8080` exposure plainly rather than hiding them.

---

## 6. Test-coverage gaps

- **net.rs:** no test for a per-IP inbound bound (none exists — NET-03); no test that an idle inbound connection is closed at 120 s *and* that the dialer recovers without losing the first frame (NET-09); no test for `serve_get_blocks` aggregate load across connections (NET-05) or for page byte size (NET-17); no test that garbage/unknown-type frames have any consequence (NET-03/04); no end-to-end devnet test feeding forged blocks/attestations/txs through `start()` into an engine (the engine tests use `net::start` only as a plumbing stub).
- **p2p.rs:** `read_capped` is tested only on responses (`audit_sync_cap_requires_actual_eof`), not on requests (NET-06); no test for `peer_head` steering (NET-07) or for identify overwriting `dialed` (NET-08 — `dialed_is_bounded_fifo` exercises one peer only); no test that a `Reject` actually lowers a peer's score/graylists it (scoring is configured but never observed); no test of the `with_peer_score` failure path; the two-node live tests cover mesh formation and pagination but no adversarial peer.
- **rpc.rs:** no test for `MAX_CONNECTIONS` (503 path), for memory/element-count amplification (NET-10), for very large `id` echo, or for per-client fairness (NET-11); `malformed_input_never_panics_and_always_answers_json_rpc` is a fixed corpus, and there is **no fuzz target for `parse_json`** or for `read_request_until`.
- **metrics.rs:** `a_slow_connection_does_not_stall_other_connections` proves the accept thread is not blocked but not that the slow connection is ever *closed* (NET-16).
- **codec / transition:** no fuzz target for `PosTransaction::from_canonical_bytes`, `decode_sync_request/response` or the devnet frame reader (`grep` of `fuzz/fuzz_targets` finds only `decode_envelope`/`decode_attestation`/header).
- **libp2p-yamux fork:** upstream's `tests/compliance.rs` was not vendored; the fork carries only two config tests. Nothing exercises the muxer over a socket in this crate (the p2p two-node tests do so indirectly).
- **engine mempool:** no test of admission cost at a full mempool or of the proposer probe loop with an attacker-filled top-256 (NET-02).

---

## 7. Residual risk / not covered

- I did not execute anything: no build, no tests, no benchmark. NET-02's throughput figures (SHA3 over ~3.7 KB per mempool entry; `CommittedState` clone cost per probe iteration) and NET-04's per-verify cost are estimates or quoted from code comments, not measured here.
- I could not verify the live validators' actual bind addresses or firewall rules (`FLEET-INVENTORY.md` is a template; host details are deliberately redacted). Every statement about validator exposure is what `bootnodes.txt` and the quickstart assert.
- I did not audit the consensus crate beyond the entry points the network calls (`gossip.rs::process`, `from_canonical_bytes`, `compute_post_state`'s early checks). The mempool's semantics, fee market and the finality latch belong to other auditors; NET-02 is filed here because its reachability is the network/RPC surface and should be de-duplicated against their findings.
- The Round-1/2/3/6/7 remediation audits and the 2026-09-07 external audit are not in the repository; "KNOWN" labels rely on the code comments and the quickstart that cite them. If those documents already contain NET-03/05/09, the lead should relabel.
- Not covered: `ws_boot.rs`/weak-subjectivity sync trust, `keys.rs`, `store.rs` beyond `blocks_after`, `main.rs` beyond flag defaults, the explorer/Cloudflare RPC front-ends under `apps/`, and whatever process forwards `:8080` on the bootnodes (not in the repo).
- The libp2p findings (NET-06/07/08/13) are latent while the fleet stays on devnet, but `FLAG-DAY-EPOCH-2700.md:90-93` describes rolling `--transport dual` on `0.0.0.0:16400`; they become live the day that happens and should be fixed before it.
