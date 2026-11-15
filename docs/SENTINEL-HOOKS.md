# Bloch Sentinel hooks (node-local)

Interface between a `bloch-pos` node and the external Bloch Sentinel probe
(Postern Cyber). The probe and any analyst run **outside** the node; the node
only exposes local signals and accepts three bounded local commands.

- **Node-local.** No consensus rule, block/state validity, state root, gossip
  validity or fork-choice input changes. Replay of canonical history is
  byte-identical (test `engine::sentinel_hooks::tests::replay_is_byte_identical_with_and_without_the_sentinel`).
- **Off by default.** Without any of the flags below nothing is started,
  nothing is created, and `getsecuritystatus` answers JSON-RPC `-32601 method
  not found`, exactly like a node without this code.
- **No AI, no outbound network calls, no API keys** in the node.

Source: `crates/bloch-pos-node/src/sentinel.rs` (+ `sentinel/`),
`engine/sentinel_hooks.rs`, `net/sentinel_view.rs`.

## Flags

| Flag | Effect |
|---|---|
| `--security-status` | Enables collection and the `getsecuritystatus` RPC method. |
| `--security-events <path>` | Also writes the JSON-lines event log (implies status). |
| `--admin-socket <path>` | Also opens the admin socket (implies status). |
| `--security-status-remote` | Lets non-loopback callers read `getsecuritystatus` and allows a non-loopback `--rpc-bind` with the Sentinel on. Off by default; needs one of the flags above. |

`--security-events` and `--admin-socket` accept `--flag <path>` and
`--flag=<path>`. A Sentinel flag that is present but malformed (no value,
empty value, given twice, a value on a switch) stops the boot.

**Exposure.** The status names inbound peer addresses, bans and reasons, the
validator index, the KES state and the doppelganger window. Therefore:

- the node refuses to start with any Sentinel flag and a non-loopback
  `--rpc-bind`, unless `--security-status-remote` is given;
- at call time only DIRECT loopback callers are answered: the TCP peer is
  loopback, is not a declared `--rpc-trusted-proxy`, and the request carries
  no forwarding header at all (`X-Forwarded-For`, `Forwarded`, `X-Real-IP`,
  `Via`, `X-Forwarded-Host`/`-Proto`/`-Port`/`-Server`, `X-Client-IP`,
  `X-Cluster-Client-IP`, `True-Client-IP`, `CF-Connecting-IP`,
  `Fastly-Client-IP`). Anyone else gets `-32601 method not found`, the same
  answer as a node without the Sentinel (review RC-05). A request that came
  through any proxy, declared or not, is therefore refused unless
  `--security-status-remote` is given: a reverse proxy on the same host
  makes every caller look like loopback, and a proxy that does not append
  to `X-Forwarded-For` lets the caller choose the address the RPC would
  believe. A proxy that strips every forwarding header is indistinguishable
  from a local client: do not put such a proxy in front of a Sentinel node.

## 1. `getsecuritystatus` (JSON-RPC, existing RPC port, default bind 127.0.0.1)

Read-only, no params, answered without entering the consensus queue. Every
list is bounded; the whole answer stays well under 64 KiB.

```
{"jsonrpc":"2.0","id":1,"method":"getsecuritystatus","params":[]}
```

Result (schema `bloch-sentinel-status/1`). Roots are 64-hex strings, times
are unix milliseconds, sources are the 16-hex prefix of the node's opaque
per-address verification source (`addr` is filled when the node knows the
address behind it).

| Key | Content |
|---|---|
| `schema` | `"bloch-sentinel-status/1"` |
| `node_local` | always `true` |
| `generated_ms` | answer time |
| `enabled` | `{status, events, admin_socket}` booleans |
| `chain` | `{published, updated_ms, live, wall_slot, wall_epoch, head{slot,epoch,height,root}, justified{epoch,root}, finalized{epoch,root,height}, finalized_latch{height,root}\|null, finality_lag_epochs, lag_thresholds_epochs[]}`. Published once per wall slot; `published:false` until the first slot. `finalized` is the head state's; `finalized_latch` is the highest finality this process has held (can be above it after a reorg). |
| `peer_finalized_ahead` | `{count, strong_count, conflicting_strong_count, unverified_count, unverified_observations_total, corroboration_sources:3, max_entries:32, entry_ttl_secs:1800, evicted, entries[]}`; entry: `{source, addr, kind, evidence, verified, advertised_finalized_root, advertised_justified_root, root_slot, epoch_hint, our_finalized_epoch, block_root, block_slot, verdict, count, first_seen_ms, last_seen_ms}`. `kind`: `ahead` (root is our canonical block above our finalized checkpoint), `conflicting` (root is a block we hold that is not canonical — a different finalized branch; compare `epoch_hint` with `our_finalized_epoch` for "same epoch"), `unknown_root` (we do not hold the block). Read from the `finalized_root` of blocks the peer sends; `verdict` is the engine's verdict on that block (`accept`/`ignore`; rejected blocks are not recorded). **Evidence:** `verified` is true only when the engine accepted the carrying block (proposer signature, ancestry and transition checked); `evidence` ∈ `verified`, `corroborated` (not verified, but ≥3 sources in different /24 or /64 networks, or one verified source, advertise the same root), `unverified` (a single unauthenticated claim: any connected peer can produce one). **Alert only on `strong_count` / `conflicting_strong_count` or on entries whose `evidence` is not `unverified`; `count` includes unverified claims.** One entry per source; an unverified claim never replaces a verified entry; cleared when an accepted block from the source advertises our root again. |
| `gossip_verdicts` | `{window_secs:600, tracked_sources, max_sources:1024, total_rejected, total_ignored, overflow{rejected,ignored}, top[≤16]{source, addr, rejected, ignored}}` — engine verdicts on blocks, attestations and transactions per source, tumbling 10-minute window. |
| `handshakes` | `{window_secs:600, tracked_sources, keyed_by, total_attempts, total_failures, overflow{attempts,failures}, top[≤16]{addr, attempts, failures}}` — inbound mesh connections (counted at TCP accept, before any cap) and failed mesh handshakes, per IPv4 address or IPv6 /64 (`addr` is that key). The node's own self-dial is not counted as a failure. |
| `peers` | `{transport, devnet_connections, libp2p_peers, mesh_inbound, configured_peers, inbound_by_v4_24{buckets,max_in_one,top[≤16]{prefix,count}}, inbound_by_v6_64{…}}` |
| `doppelganger` | `{state, halted, observe_until_slot}`; `state` ∈ `observing`, `window_passed`, `halted`, `inactive` |
| `kes` | `{validator, keystore_loaded, kes_key_loaded, mode, mode_epoch, period, bind_epoch, bound, state_epoch, state_rolled_to_wall_epoch, last_error}`; `mode` ∈ `static`, `kes`, `fail_closed`, `no_validator` (the verifiers' `kes::signing_mode` rule for the wall epoch, on the head state **rolled into the wall epoch** — the state the signer decides on); `bind_epoch` is `kes_enforced_from` of that state (`null` = not bound). `state_rolled_to_wall_epoch` is false only when the node is not live or is more than 64 epochs behind; the values then come from the unrolled head (`state_epoch`) and must not be alerted on. The roll is the signer's own fold, taken beside the duty memo rather than through it (review RC-04), so reading the status never changes which rolls the attestation door finds already paid for. `last_error`: `{duty, class, validator, wall_slot, at_ms, consecutive}`. |
| `bans` | `{active, max:256, refused_connections, entries[]{range, reason, ttl_secs, expires_in_secs, created_ms}}` |
| `events` | `{enabled:false}` or `{enabled:true, emitted, written, dropped_rate_limited, dropped_queue_full, write_errors, rotations, max_file_bytes, per_type_per_minute}` |
| `admin_commands` | commands received on the admin socket since start |

## 2. Event log (`--security-events <path>`)

One JSON object per line, file mode 0600 (an existing file is narrowed to
0600; a symlink at the path is refused). At 8 MiB the file is renamed to
`<path>.1` (replacing it) and a new one starts, so at most 16 MiB on disk. At
most 60 events per type per minute; drops are counted in `events`. The writer
never blocks the node. Events carry no key material, no key paths and no raw
error text.

Common fields: `schema:"bloch-sentinel-event/1"`, `seq`, `ts_ms`, `type`.

| `type` | Extra fields |
|---|---|
| `finality_lag` | `lag_epochs, wall_epoch, finalized_epoch, finalized_root, threshold_epochs, direction` — the lag crossed one of 4/8/16/32/64 epochs (live node only) |
| `finality_recovered` | same; the lag fell back below 4 |
| `peer_finalized_ahead` | `source, addr, kind (ahead\|unknown_root), advertised_finalized_root, epoch_hint, our_finalized_epoch, our_finalized_root, block_root, block_slot, verdict, verified, evidence (verified\|corroborated)` — emitted only at evidence `verified` or `corroborated`, on first sighting, change or a higher level, at most once per source per 60 s. Unverified claims never produce an event. |
| `conflicting_finalized_checkpoint` | same fields, `kind:"conflicting"` |
| `kes_signing_error` | `duty (attest\|propose\|kes_rotation), class, validator, wall_slot, consecutive`; `class` ∈ `enforcement_unknown, no_kes_key_loaded, not_registered, wrong_validator, wrong_tree, expired_or_not_started, leaf_erased, evolution_refused_clock_jump, evolution_failed, other` |
| `kes_mode_changed` | `from, to, validator, wall_epoch` |
| `doppelganger_detected` | `validator, wall_slot, duties:"stopped"` |
| `ban_applied` | `range, ttl_secs, reason, disconnected` |
| `ban_removed` | `range, by:"admin"` |
| `ban_expired` | `range, ttl_secs` |
| `admin_command` | `cmd (peer.ban\|peer.unban\|peer.bans\|unknown), ok, range?, error?` |

## 3. Admin socket (`--admin-socket <path>`)

Unix stream socket, mode 0600, owned by the node user. The node refuses to
start if the parent directory is world- or group-writable or not owned by the node user
or root, or if the path exists and is not a socket (a stale socket of ours is
replaced). A client whose uid is neither the node's nor root is closed
unanswered. Line-delimited JSON, one answer line per command; max 4096 bytes
per line, 64 commands and 30 s per connection (absolute), 5 s I/O timeout.

```
{"cmd":"peer.ban","addr":"192.0.2.7","ttl_secs":600,"reason":"handshake flood","id":1}
{"cmd":"peer.ban","cidr":"192.0.2.0/24","ttl_secs":600,"reason":"…"}
{"cmd":"peer.unban","cidr":"192.0.2.0/24"}
{"cmd":"peer.bans"}
```

Answers: `{"ok":true,"result":…,"id":…}` or `{"ok":false,"error":"…","id":…}`.
`peer.ban` result: `{range, ttl_secs, reason, disconnected}`; `peer.unban`:
`{range, removed}`; `peer.bans`: the `bans` object above.

Bounds (enforced in `sentinel/bans.rs`): `ttl_secs` 1..3600; at most 256
active bans (renewing an existing range always works); IPv4 no wider than
/16, IPv6 no wider than /48; `reason` ≤160 printable characters. A range that
covers a `--peers`/`--p2p-peer` address (IPv6 peers protected per /64, as the
mesh keys them) or loopback is refused with an error.

Effect: a banned non-configured address is closed at mesh accept, before any
slot, thread or handshake; on libp2p its inbound connection is closed on
establishment. Existing inbound mesh sessions from the range are shut down
when the ban is applied. Dials need no check: every dial goes to a configured
peer, and configured peers cannot be banned. Bans live in memory only and end
at TTL or restart.

Nothing else is reachable through the socket: no restart, no reject-root, no
key or signing operation, no configuration change.

## Changes since c676beec

Schema names are unchanged (`bloch-sentinel-status/1`, `bloch-sentinel-event/1`);
every change below is an added field or a tightened behaviour. No field was
renamed or removed.

- **`peer_finalized_ahead` (status):** new counters `strong_count`,
  `conflicting_strong_count`, `unverified_count`,
  `unverified_observations_total`, `corroboration_sources`; each entry gains
  `evidence` and `verified`. `count` still counts every entry, including
  unverified ones: consumers must alert on the strong counters.
- **Events `peer_finalized_ahead` and `conflicting_finalized_checkpoint`:**
  gain `verified` and `evidence`; they are no longer emitted for unverified
  observations, and are limited to one per source per 60 s.
- **An entry is cleared** only by an accepted block advertising our root
  (before: by any non-rejected block).
- **`getsecuritystatus` caller restriction:** non-loopback callers get
  `-32601`; boot is refused on a non-loopback `--rpc-bind` unless the new
  `--security-status-remote` switch is given.
- **`kes`:** `mode`, `period`, `bind_epoch`, `bound`, `validator` are now
  computed on the state rolled into the wall epoch; `state_epoch` is that
  state's epoch. Same field names.
- **`handshakes`:** new `keyed_by`; the key (and `top[].addr`) is the IPv4
  address or the IPv6 /64; attempts are counted at TCP accept, before the
  connection cap; the node's own self-dial / shared-identity refusals are
  not counted as failures.
- **Flags:** `--flag=<path>` accepted for `--security-events` and
  `--admin-socket`; malformed Sentinel flags stop the boot.
- **Admin socket:** group-writable parent directory refused; the 30 s
  connection lifetime is absolute. Protocol unchanged.
- **Event log:** symlink at the path refused; existing file narrowed to 0600.
