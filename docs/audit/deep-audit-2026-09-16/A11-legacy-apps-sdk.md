# A11 — Legacy (Genesis-3) ledger provenance, web apps, SDKs, pool, euvm/ffg, prover, fuzz

Auditor: A11. Repository: `/home/user/bloch-sis-pow` (read-only). Date: 2026-09-16.

## 1. Scope & method

Scope, in the priority order given: (1) integrity of the carried-over ledger `carryover.tsv.gz`
(exporter `legacy/genesis3-node/src/bin/bloch-snapshot-utxo.rs`, `Storage::iter_utxos_sorted`,
the retired Python tool `tools/genesis4-carryover/`, the Genesis-4 loader
`crates/bloch-pos-node/src/genesis.rs`, split arithmetic in
`crates/bloch-pos-committee/src/tokenomics_v4.rs`, Genesis-3 block/tx validation in
`legacy/genesis3-node/src/{main.rs,reorg.rs,storage/mod.rs}` and `crates/bloch-crypto/src/core/`);
(2) `tools/faucet`, `tools/indexer`, `apps/explorer/functions`, `apps/posternpool-site/functions`,
`apps/site`, `sdk/{typescript,go,python}`; (3) `pool/`, `pool-proxy/`; (4) reachability of
`crates/bloch-euvm` / `crates/bloch-ffg` from the live node; (5) `crates/coherence-prover`,
`spikes/`, `fuzz/`.

Method: code reading and caller grepping only (no cargo/npm runs). Where a claim was checkable
against shipped artifacts I checked it with Python over the real files:

- `carryover.tsv.gz` decompressed: 452,726 rows, SHA-256 `84ddbbac…` (matches the sidecar),
  exact-integer sum, per-address totals, vout distribution, per-row split remainders, sorting.
- `genesis/mainnet.manifest` parsed per `Manifest::encode` (`genesis.rs:835-877`): the shipped
  manifest commits to carryover digest `3d67246e…` (= SHA3-256 of the decompressed file, verified),
  set root `7c756ee8…` (= SHAKE-256 of the file bytes, verified), entry count 452,726 and
  `total_sat` 1,814,640,000,000,000,000 (= 381,074,400,000,000,000 × 100 / 21 exactly, verified).
  So the file in git is the file the fleet booted from.

Confidence levels are stated per finding. "KNOWN" means the project already documents the issue;
what I add in those cases is stated explicitly.

## 2. Findings (ordered by severity)

### LG-01 — The carried ledger holds exactly 39,917 Genesis-3 subsidies, not 39,918; the missing coinbase is unexplained and two concrete mechanisms exist in the exporter/node that produce exactly this signature
- Severity: **High** (KNOWN as an open question in `CARRYOVER-SNAPSHOT.md` and `legacy/README.md`; refined here). By the lead's scale this is Critical-by-definition *if* height 39,918 was a real selected-chain block (a balance was destroyed), and Info if the label "39,918" is simply one above the applied chain. It stays High because the project's own artifact says "terminal height 39,918" everywhere (site, spec, constants) while the ledger demonstrably corresponds to 39,917 applied coinbases, and nothing in the repository can settle which.
- Status: KNOWN (open question) — refined; new mechanisms identified.
- Refs: `carryover.tsv.gz`; `crates/bloch-crypto/src/core/mod.rs:370-372` (G1 carry-over 413,743 UTXOs, 347,544,120,000,000,000 sat), `:385-391` (emission_height offset), `:2318-2320`/`:2491-2495` (zero-value anchor coinbase at local height 0); `crates/bloch-crypto/src/core/tokenomics_v2.rs:80-84,139` (8,400 BLCH per block, V3 fork at local 40,000 never reached); `legacy/genesis3-node/src/storage/mod.rs:204` (`put_block` writes height→hash for every stored block), `:1024-1034` (`get_tip_height` = max stored height); `legacy/genesis3-node/src/main.rs:2960-2976` (body persisted before disposition; fork-losers and refused blocks keep their body), `:3060-3095` (Extension arm: `apply_block_utxo_mutations` failure is only `error!`-logged, the tip still advances), `legacy/genesis3-node/src/bin/bloch-snapshot-utxo.rs:166` (prints a meta key `tip_height` that is never written — so the tool cannot state the applied height of its own output), `:230` (undecodable UTXO value silently skipped — see LG-03); `docs/integration/BLOCH-EXCHANGE-INTEGRATION.md:361-363`; `crates/bloch-pos-committee/src/tokenomics_v4.rs:176-180` (measurement table).
- Description / evidence (exact integers):
  - File total = 381,074,400,000,000,000 sat = 3,810,744,000 BLCH.
  - Genesis-3 opened from the Genesis-1 set: 413,743 UTXOs × 8,400 BLCH = 347,544,120,000,000,000 sat (`CARRYOVER_TOTAL_SAT`).
  - Difference = 33,530,280,000,000,000 sat = 39,917 × 840,000,000,000 sat, remainder 0. Every Genesis-3 block from local height 1 pays a flat 8,400 BLCH (V2 curve, epoch 0; the V3 cut at local 40,000 was never reached), and the local-0 anchor coinbase pays 0. So the set contains the coinbases of exactly 39,917 applied blocks.
  - The single zero-value row (`dc7be805…291d`, vout 0, to `e986db51…`) is the Genesis-3 genesis anchor coinbase: the exchange-integration doc shows this txid at `block_height: 0` with `timestamp: 1785365935` = `GENESIS3_TIMESTAMP`. It therefore does NOT account for the gap.
  - No coinbase under-claim is visible: every row below 8,400 BLCH is either that anchor or a change output (37 of the 38 "vout 16777216" rows plus the vout-0 rows of two-output spends). A miner that claimed less than the subsidy would leave a small-valued single-output coinbase; none exists (unless it was later spent, which cannot be excluded from the file alone).
  - The earlier measurement in the tokenomics table ("2026-08-13, height 39,328, 3,805,746,000 BLCH") sums to 39,322 subsidies — six short of its own label. The label-vs-applied drift is therefore real and varied between measurements; a permanent cause (an under-claim, a never-reapplied block) cannot shrink from 6 to 1, which points at the height *label* not being the applied selected-chain height.
- Mechanisms that produce exactly one missing coinbase, all present in the code as shipped:
  1. Height label from the stored-block map. `Storage::put_block` writes `height→hash` for every block it stores, and `accept_block` stores the body *before* the disposition match; a fork-loser or a refused-after-persist block at height 39,918 therefore raises `get_tip_height()` to 39,918 while the applied selected chain stays at 39,917. `bloch-snapshot-utxo` has no access to the applied height at all (it reads a meta key `tip_height` that nothing writes, so it prints "unknown"); whoever recorded "39,918" took it from elsewhere.
  2. Legacy L-1/M-7 non-atomic apply: in the Extension arm a failed `apply_block_utxo_mutations` is logged with `error!` and the node continues (`tip_hash` is still written). One such failure anywhere in 39,918 blocks leaves the UTXO set short by exactly that block's coinbase and leaves that block's spends unapplied. The migration record's claim that two independent nodes produced byte-identical roots (`apps/site/migration.html`) makes this less likely than (1), but it is not excluded (both nodes ran the same binary against the same block stream).
  3. Exporter silently skips an undecodable UTXO row (LG-03). A single skipped 8,400-BLCH coinbase row gives the same signature.
- Attack / failure scenario: not an attack; a provenance defect. If 39,918 was a genuine selected-chain block, its coinbase (8,400 BLCH → 40,000 BLOCH post-split, owed to whichever address mined it — overwhelmingly likely `e986db51…` or `be7c81e1…`, which hold 426,125 and 21,079 coinbase-sized outputs respectively) was destroyed by the migration, and if that block carried any non-coinbase transaction (unlikely — the whole chain shows only ~113 non-coinbase-shaped outputs and 16 addresses) the carried ledger would contain already-spent outputs (double credit to the spender, loss to the payee).
- Recommendation: publish, from the two snapshot nodes, `meta.tip_hash`, `selected_tip_height` (RPC `getdaginfo.tip_height`), `get_tip_height()` (max stored height), and the block at height 39,918 (hash, disposition, coinbase value, tx count); state in `CARRYOVER-SNAPSHOT.md` whether the ledger is "the state after applying block 39,917" or "…39,918" and correct the terminal-height wording accordingly; run `bloch --verify-carryover`/`derive_carryover_root` on the archival node and compare against the file. If the block was real, the founder decision that the snapshot is canonical should say so explicitly (the owed 40,000 BLOCH is a documented, accepted loss rather than an unexplained one).
- Confidence: high that the gap is exactly one full subsidy and that the zero-value row is the anchor; medium on which mechanism produced it (cannot be resolved from the repository: no block data, no node logs).

### LG-02 — vout endianness (Legacy M-3): the bug is in the exporter/`iter_utxos_sorted`, the Genesis-4 loader carries the corrupted index verbatim into committed state
- Severity: **Low** (KNOWN — `legacy/README.md`, `CARRYOVER-SNAPSHOT.md`; refined here). Balances are unaffected; the consequence lives on the (not yet built) carried-output spend path, which is another auditor's scope.
- Status: KNOWN, refined.
- Refs: `legacy/genesis3-node/src/storage/mod.rs:1285-1287` (`utxo_key` writes vout `to_le_bytes`), `:348-349` (`iter_utxos_sorted` decodes `from_be_bytes`); `legacy/genesis3-node/src/bin/bloch-snapshot-utxo.rs:41-48` (`decode_vout`, default `canonical=false` → BE), `:229-233`; `tools/genesis4-carryover/build_carryover.py:45-55` (`int(vout)` only — no endianness handling, and the tool is retired and never produced fleet bytes); `crates/bloch-pos-node/src/genesis.rs:666-671` (accepts any canonical u32), `:750-756` ("the Genesis-3 outpoint crosses unchanged").
- Answer to (1)(a): the bug is in the **exporter** (and the node's own `iter_utxos_sorted`, which `derive_carryover_root` uses, so node-side verification reproduces it identically). Neither the Python tool nor the Genesis-4 loader introduced it; the loader faithfully commits `(txid, 16777216)`.
- Evidence (measured): exactly 38 rows have vout 16777216 = `1u32.to_le_bytes()` read BE; 35 of them share a txid with a vout-0 row (two-output spends), all 38 are change outputs (37 to `e986db51…`, 1 to `8f674944…`), summing to 13,206,989,419,559 sat (132,069.89 BLCH; ≈628,904 BLOCH post-split). No row has any vout other than 0 or 16777216, so no other index is affected and the loader's strict-ascending check still holds (the mapping is a bijection).
- Consequence: the committed Genesis-4 `EutxoEntry.vout` for those 38 outputs is an index that never existed on Genesis-3. Any spend/proof path that identifies carried outputs by their Genesis-3 outpoint (`(txid, 1)`) — the stated reason for carrying outpoints unchanged — will miss these 38; the correction cannot be applied to the file (it would change the committed digest/root) and must be made on the spend path or by a one-off consensus mapping.
- Recommendation: enumerate the 38 outpoints with their canonical index in `CARRYOVER-SNAPSHOT.md`; make the migration-spend path accept `vout == 16777216` as `1` for exactly these txids (or canonicalise at ingestion in a future manifest version); add a regression test on the real file.
- Confidence: high.

### LG-03 — Snapshot exporter and `iter_utxos_sorted` silently drop undecodable UTXO rows (fail-open on the ledger-producing path)
- Severity: **Medium** (NEW).
- Refs: `legacy/genesis3-node/src/bin/bloch-snapshot-utxo.rs:226-233` (`if key.len() < 36 { continue; }` … `Err(_) => continue`); `legacy/genesis3-node/src/storage/mod.rs:326,351-355` (same two skips); `:1067-1083` (`derive_carryover_root` built on the same iterator).
- Description: a UTXO whose stored value fails `decode::<TxOutput>` (or whose key is shorter than 36 bytes) is omitted from the export without any error, counter or log. The exported count and total are then self-consistent, and every downstream check (Genesis-3 `verify_carryover_snapshot`, Genesis-4 `check_against`, the constants in `tokenomics_v4.rs`) was pinned to numbers measured with the same tool, so none of them can detect an omission. There is no independent cross-check (e.g. against `CF_ADDR_UTXO` cardinality or a block-derived expected total) anywhere in the pipeline.
- Failure scenario: one corrupted RocksDB value → one holder's output vanishes from the opening ledger with a clean "N UTXOs written" log line. This is also mechanism (3) for LG-01.
- Recommendation: fail closed on decode error and on short keys; print and publish a reconciliation triple (UTXO count vs address-index count vs Σ expected subsidies) with every export; re-run against the archival data-dir with the fixed tool and confirm 452,726.
- Confidence: high on behaviour; unknown whether it ever fired.

### LG-04 — Faucet per-address cooldown is bypassable by hex case variation
- Severity: **Low** (NEW; testnet-only service, no value at stake).
- Refs: `tools/faucet/src/address.ts:56-62` (accepts `[0-9a-fA-F]`, lowercases only for hashing), `tools/faucet/src/server.ts:78-88` (`address = parsed.address.trim()` passed raw to `limiter.reserve`), `tools/faucet/src/ratelimit.ts:36-38,71-78` (maps keyed on the raw string); node side `legacy/genesis3-node/src/rpc/mod.rs:1005-1032` and `crates/bloch-crypto/src/address.rs:65-95` both accept mixed-case hex, so the "authoritative" `validateaddress` check does not close it.
- Scenario: the same 48 hex characters have 2^(number of a–f digits) case variants; each is a distinct `lastByAddress`/`inFlight` key, so the 24 h per-address limit collapses to the per-IP limit (5/h), which itself is defeated by IP rotation, and by X-Forwarded-For spoofing when `FAUCET_TRUST_PROXY=1` sits behind a proxy that does not overwrite the header. `FAUCET_TRUST_PROXY` is also undocumented (`.env.example`, README).
- Recommendation: key the limiter on `parsed.hashHex` (or lowercase the address) before `reserve`; document `FAUCET_TRUST_PROXY`.
- Confidence: high.

### LG-05 — Faucet accepts cross-site form POSTs (CSRF-driven drips)
- Severity: **Low** (NEW; testnet).
- Refs: `tools/faucet/src/server.ts:76-86` (no Content-Type check, `JSON.parse` of any body, no origin/CSRF check).
- Scenario: a `<form method=POST enctype="text/plain">` on a third-party page can deliver a body that parses as `{"address":"bloch1t…","x":"="}`; the victim's browser submits it with the victim's IP, consuming that IP's quota for the attacker's address. No CORS header is set, which is correct for `fetch`, but simple form posts bypass CORS.
- Recommendation: require `content-type: application/json` and/or `Origin`/`Sec-Fetch-Site` = same-origin on `/api/faucet`.
- Confidence: high.

### LG-06 — Explorer/pool-site RPC path: plaintext upstream via a third-party wildcard DNS, and the archival node's full unauthenticated RPC (write methods included) is internet-exposed beside the allowlisting Function
- Severity: **Low** (documented as an accepted interim state; restated because the interim has become the steady state).
- Refs: `apps/explorer/wrangler.toml:26-59` (`BLOCH_RPC_URL = "http://136-244-82-226.sslip.io/"`), `apps/explorer/functions/rpc.js:110-152`; `deploy/RPC-SURVIVAL-RUNBOOK.md:50-51,271-278` (socat `:80 → 127.0.0.1:16210`, "the full unauthenticated node RPC, not the Function's read-only allowlist"); `legacy/genesis3-node/src/rpc/auth.rs:86-89` (writes: `sendrawtransaction`, `submitblock`, `submitauxblock`, `createauxblock`, `getblocktemplate`…), `legacy/genesis3-node/src/main.rs:133-140` (write auth is opt-in via `--rpc-require-auth-for-writes`).
- Description: (a) the Function → origin hop is plain HTTP to `sslip.io`, so a third party is in the resolution path and an on-path attacker can feed the explorer false chain data (no keys or consensus affected); (b) the Function's allowlist is decorative for anyone who reads the IP out of git and talks to `:80` directly — heavy methods (`getblocktemplate`, `createauxblock`) and mempool writes are reachable from the internet; on a halted chain these are inert for consensus but remain a CPU/memory DoS surface for the one archival node the explorer depends on. (c) `apps/explorer` ships no `_headers` (no CSP/HSTS), unlike `apps/site`.
- Recommendation: DNS-only `rpc.blochl1.com` record + cloudflared/TLS as the runbook already plans; firewall `:80` to Cloudflare egress or move the allowlist onto the origin (reverse proxy); add `_headers` to the explorer.
- Confidence: high (configuration is in git; the live firewall state is not verifiable from here).

### LG-07 — Reference indexer: unbounded responses and whole-state rewrite
- Severity: **Low** (NEW; reference tool, default bind 127.0.0.1).
- Refs: `tools/indexer/src/api.ts:113-143` (`/address/:addr/history` and `/utxos` return every entry, no pagination), `tools/indexer/src/store.ts:520-533` (`persist` serialises the entire state on every sync tick), `tools/indexer/src/indexer.ts:100`.
- Scenario: against the real ledger the founder address has 426k UTXOs and history entries; one unauthenticated GET forces serialisation of all of them (CPU + memory), and every 3 s tick rewrites a JSON file of the whole index.
- Note: no SQL anywhere (JSON store), path segments validated by `parseAddress` before store access, prototype-pollution guarded (`Object.create(null)` + `Object.hasOwn`), RPC amounts parsed exactly (`parseJsonExactIntegers`), 10 s RPC timeout — the earlier T-1…T-8 findings are fixed as described.
- Recommendation: `?limit/?offset` with a cap; incremental persistence.
- Confidence: high.

### LG-08 — Python SDK amount parsing accepts non-ASCII digits and has an uncaught-exception path
- Severity: **Low** (NEW).
- Refs: `sdk/python/blochclient/units.py:47-60` (`str.isdigit()` is Unicode-aware: Arabic-Indic digits pass `isdigit()` and `int()` parses them; superscripts pass `isdigit()` but `int()` raises a bare `ValueError` with a different message than the module promises), `:75-91` (`bloch_to_sats("")` and `"."` return 0; no `MAX_SATS` bound; `"1٢"` accepted).
- Cross-SDK comparison (answers (2) "signing correctness"): none of the three SDKs implement hybrid ML-DSA-65 ‖ Falcon-1024 signing — TS (`txbuilder.ts`) builds an unsigned structure and defines a `Signer` seam, Go (`signer.go`) and Python (`signer.py`) are type seams only, and the only write is `sendrawtransaction` of caller-supplied hex. That is correct and honestly documented. Units: TS `parseSats` (bigint, rejects unsafe `number`, bounds to 10^19) and Go `Satoshis` (uint64, string on the wire, `MaxSats` bound, `BlochToSats` overflow-safe) are sound; TS `blochToSats` accepts negatives by design and `satsToBloch(number)` truncates silently (documented as display-only). Clients: TS 30 s timeout via AbortController, Go `http.Client{Timeout: 30s}`, Python `urlopen(timeout=30)`; all default to `http://127.0.0.1:16210`; TLS is whatever the URL says (no pinning, no insecure overrides). Dependencies: TS and Python have zero runtime deps, Go module has none (`go 1.21`).
- Recommendation: `re.fullmatch(r"0|[1-9][0-9]*", text)` instead of `isdigit()`; bound `bloch_to_sats`.
- Confidence: high.

### LG-09 — Pool: shares and ledger keyed by the raw `mining.authorize` username, not the parsed address
- Severity: **Info** (NEW; pool idle post-PoW, relevant only if redeployed).
- Refs: `pool/src/stratum.rs:277-330` (`Address::parse(username)` succeeds for mixed case; `session.address = username.to_string()`), `pool/src/shares.rs` (ledger `HashMap<String, …>` by that string), `pool/src/dashboard.rs:35-39` (pseudonym over the raw string).
- Effect: the same on-chain address in two casings is two ledger entries and two dashboard pseudonyms; with the ownership proof on (default) both still require the key, so this fragments accounting rather than enabling theft. Journal replay (`shares.rs:195-240`) trusts the operator-owned JSONL file (not an attack surface).
- Recommendation: canonicalise to `Address::to_string()` before keying.
- Confidence: high.

### LG-10 — Documentation drift on the ledger-critical code (dust recipient, snapshot vintage, zero-value rows, dead "tip height" print)
- Severity: **Info** (NEW).
- Refs and facts:
  - `crates/bloch-pos-node/src/genesis.rs:527-548` says 452,133 rows, "112 rows leave a remainder … 59 satoshis" and "lands the 59 satoshis on the founder's address". On the shipped file: 452,726 rows, **111** rows leave a remainder, dust is **57 sat**, and the largest output is `b9a528a5…:0` (400,000 BLCH, address `cb339d2e…`), tie with `f71fc9ab…:0` broken to the earlier line by the strict `>` — so the 57 sat go to **`cb339d2e…`, not the founder**. The rule itself is deterministic and consensus-consistent; only the prose is wrong. `docs/CARRYOVER.md:41-43` already states 57/111.
  - `legacy/genesis3-node/src/storage/mod.rs:1269-1273`: "a zero-value output … never appears in a snapshot this node produced" — false: the Genesis-3 anchor coinbase is a live 0-value UTXO (row 390,179). The Genesis-3 loader would refuse the Genesis-3 terminal file; the Genesis-4 loader has no zero check and now carries one 0-value `EutxoEntry`. Harmless (H-R7-3 dust rules govern new outputs only), but the invariant claimed by `tests/carryover_loader.rs` ("zero-value row → rejected") is a property of the loader, not of real snapshots.
  - `bloch-snapshot-utxo.rs:166` reads meta `tip_height`, which no code path writes (`grep` shows only `tip_hash`), so the tool always prints "tip height: unknown" — the artifact never carried its own height.
  - `genesis.rs:274-278` still describes the 2026-08-13 measurement as "the real file".
- Recommendation: one pass over `genesis.rs`, `storage/mod.rs`, the snapshot tool and `tokenomics_v4.rs` doc comments against the shipped file; have the tool print `tip_hash` and the applied height.
- Confidence: high.

### LG-11 — Pool/pool-proxy: advisor findings verified closed; residual notes for a redeploy
- Severity: **Info**.
- `pool-proxy/ADVISOR-FINDINGS.md` HIGH/MED items are addressed in code: handshake timeout (`router.rs:341`), `mining.authorize` replay on reconnect (`router.rs:392-460,703-745`), process-wide extranonce1 registry + bounded re-dial (`extranonce.rs`, `claim_unique`), metrics/ledger only on id-matched submits (`router.rs:637-647,1047`), metrics read timeout (`metrics.rs:319-330`), per-IP connection cap (`server.rs:31-39`, M-9), PPLNS credits only locally verified difficulty (`pplns.rs`, S-H4 test), bounded line framing everywhere (`MAX_LINE_BYTES` 8 KiB proxy / 24 KiB pool, enforced during accumulation). `SPRINT2.md` claims 130 unit + 2 integration tests; not run here.
- `pool/src/keyshard.rs`: Shamir 2-of-3 over GF(256) via `blahaj` (post RUSTSEC-2024-0398, with a statistical regression test), honestly labelled "recovery, not threshold signing"; CLI reads secrets from stdin/0600 files, zeroizes, warns on argv use (M-8). Payout math (`payout.rs`) is conservation-tested (`Σ miners + pool_take == reward`), u128 weights, fee capped at 10 %. Ownership proof at authorize is on by default and domain-separated. Upstream trust: `check_reward_consensus` re-derives subsidy/vesting from the emission height before cutting a job.
- Residual if redeployed: dashboard `/api/stats` unauthenticated (pseudonymised, default bind 127.0.0.1); `--no-auth-proof` removes the only defence against credit-squatting; pool-proxy metrics `/pplns` exposes worker ids and fractions (default bind local); the pool's share verifier is the Module-SIS `verify_regime` path (Genesis-3 testnet dialect), while the proxy's `validator.rs` is SHA-256d — both are dead code on Genesis-4.

### LG-12 — euvm / ffg reachability from the live node
- Severity: **Info** — claim confirmed.
- `crates/bloch-pos-node/Cargo.toml`, `crates/bloch-pos-committee/Cargo.toml`, `crates/bloch-crypto/Cargo.toml`: no `bloch-euvm`/`bloch-ffg` dependency (bloch-crypto depends on `coherence-core` only). No `use`/path reference to either crate in `crates/bloch-pos-node/src` or `crates/bloch-pos-committee/src`. The only consumer is `legacy/genesis3-node/Cargo.toml:69-73,213` behind the optional feature `euvm` (off by default; `accept_block` is byte-identical without it, `main.rs:2877-2903`). Not reachable from the live node.

### LG-13 — coherence-prover / SP1, spikes, fuzz
- Severity: **Info**.
- `crates/coherence-prover` is not a workspace member (README: "not built by the node's cargo build"); no `sp1` dependency in any live crate; no proof-verification call path in `bloch-pos-node`/`bloch-pos-committee` (the only "shielded" references are state-root commitments to accumulator/nullifier roots and type definitions in `interfaces.rs`). There is no verify path to be reject-all — the pool simply has no spend path in the live node. The prover `service/` has bearer-token auth (not reviewed in depth; not deployed on the consensus path).
- `spikes/prover-cost`: offline benchmark with KAT vectors; no network surface.
- `fuzz/`: harness re-pointed at `legacy/genesis3-node` plus four `pos_*` targets that `#[path]`-include `bloch-pos-node`'s `codec.rs`/`genesis.rs` (so `pos_carryover_snapshot` fuzzes the real loader). `fuzz/README.md` states no campaign has been run since Genesis-4 and the `pos_*` targets have "no campaign behind them at all"; shipped corpora exist only for `sig_verify` and `merkle_path` (Genesis-3). CI now fails closed if the harness stops building. Assurance from fuzzing for the live loader is therefore nil so far.

## 3. Carried-ledger integrity assessment (a)–(e)

- (a) **Where the vout bug lives:** exporter (`bloch-snapshot-utxo` default BE decode) and `Storage::iter_utxos_sorted`; not the Python tool (retired, never produced fleet bytes; `int(vout)` only), not the Genesis-4 loader (which faithfully commits the corrupted index). 38 rows, all real vout=1 change outputs, values intact. See LG-02.
- (b) **Immature / unconfirmed / orphaned outputs:** immature coinbases are in the UTXO set by design (maturity is enforced at spend time, `check_coinbase_maturity`) and are legitimately carried — they would have matured. The mempool never writes `CF_UTXO` (only `accept_block` → `reorg::apply_block_utxo_mutations` and `execute_reorg` do; the inline reindex at `main.rs:1670-1698` is commented out). Fork-losers are explicit UTXO no-ops (`main.rs:3060-3068`); reorgs roll back through `UndoData` in one atomic `WriteBatch`. So no orphaned-block output can leak *by design*. Two caveats: Legacy H-2 (maturity by `block_count()`) could make honest nodes disagree on one block's validity — a transfer, never inflation, so the total is unaffected, and the two-node identical-root claim covers it; and the Legacy L-1/M-7 continue-on-failure path (LG-01 mechanism 2). No evidence of leakage: the aggregate is *short* by one subsidy, not long.
- (c) **The one-subsidy gap:** exactly 39,917 applied coinbases vs. a declared 39,918; not double counting, not the anchor coinbase, no visible under-claim; most consistent with a height label taken from the stored-block map (or another node) rather than the applied selected chain, with a single failed apply or a silently skipped row as alternatives. See LG-01/LG-03.
- (d) **Split arithmetic:** verified on the shipped file. Aggregate 381,074,400,000,000,000 × 100 / 21 = 1,814,640,000,000,000,000 exactly (divisible by 21). Σ per-row floors = 1,814,639,999,999,999,943; 111 rows have a remainder; dust 57 sat is added to the first maximum output (`b9a528a5…:0`, address `cb339d2e…`), so the committed total equals the exact split and equals `CarryoverCommitment.total_sat` in the shipped manifest. No satoshi is created or destroyed; the per-row truncation cannot exceed 20/21 sat each and the loader's u128 accumulators/`checked_add` cannot overflow at this size. Only the prose about who receives the dust is wrong (LG-10).
- (e) **Genesis-3 validation bugs affecting balances before the halt:** the relevant fixes are in the shipped legacy code — intra-tx duplicate outpoint (C-R3-2, `validate_tx_inputs` unconditional `local_spent`), same-block forward-reference spend (Legacy C-2, `validate_tx_in_block_with_maturity` cutoff), coinbase ceiling overflow (Legacy L-2, `checked_add`), template fee double count (N-7), VULN-03/05. The Era-1 audit (`AUDIT-2026-04-20_ERA1.md`) and the IBD post-mortem concern the pre-rebrand chain (fresh genesis afterwards) and the reorg/undo machinery, not balances on Genesis-3. Whether any of these was exploited before its fix cannot be proven from the repository, but the ledger arithmetic is inconsistent with an exploited mint: any surplus would show as total > G1 + 39,918 × 8,400, and the total is instead one subsidy *below* it.

## 4. Positive observations

- The shipped `genesis/mainnet.manifest` commits to exactly the shipped `carryover.tsv.gz` (SHA3-256, SHAKE-256 set root, 452,726 entries, post-split total) — independently re-derived here.
- The Genesis-4 loader is strict and fail-closed: canonical decimals only, lowercase hex only, exact 20-byte addresses, strictly ascending outpoints (catches duplicates), bounded line and entry counts, four independent commitment checks, u128 accounting with explicit overflow reasoning, a fuzz target on the real source.
- Split constants are pinned by compile-time assertions bucket by bucket; the u64 headroom hazard is asserted in both directions.
- SDK amount handling is uniformly exact (bigint / uint64 / int, decimal strings, supply-cap bound) and none of the SDKs pretends to sign.
- `apps/site`: strict CSP (`default-src 'none'`, `script-src 'self'`), no inline scripts, no third-party scripts (so no SRI needed), fixed-target `_redirects` (no open redirect), third-party notices present.
- Cloudflare Functions: explicit read-only allowlists, envelope rebuilt (no extra fields forwarded), upstream timeout, explicit 503 when unconfigured.
- Faucet: reserve-then-confirm rate limiting (TOCTOU closed), key custody fully outside the process, dry-run default, exact-integer JSON parsing; indexer: prototype-pollution and crash-on-GET fixed, atomic persist, reorg-safe undo journal.
- pool-proxy: every advisor HIGH/MED verified addressed in code; pool keyshard honestly scoped and de-biased.

## 5. Residual risk / not covered

- No block data or node logs exist in the repository, so LG-01 cannot be closed here; it needs the archival node (`tip_hash`, block 39,918, `--verify-carryover`).
- Nothing was built or run (`cargo`, `npm`, `go`, fuzz); test claims in `SPRINT2.md`, faucet/indexer `security.test.ts` and the pool crates are taken from the files.
- Live infrastructure state (firewall on the archival node, Pages env vars vs. `wrangler.toml`, whether the faucet/indexer/pool are deployed anywhere) is not verifiable from the tree; `pool.fly.toml`/`fly.toml` say the miners/pool are decommissioned.
- The Genesis-4 spend path for carried outputs (where LG-02's 38 corrupted outpoints and the single 0-value entry will matter) is another auditor's scope and, per `genesis.rs:512-519`, does not exist yet.
- `pool-proxy/src/{router,merged_engine,merged_serve,btc_rpc,btc_block}.rs` (~3,900 lines) were read only around the advisor findings; the merged-mining path is dead on Genesis-4 and was not audited line by line.
- `crates/coherence-prover/service` (bearer auth, GPU deployment) was not reviewed beyond confirming it is off the consensus path.
