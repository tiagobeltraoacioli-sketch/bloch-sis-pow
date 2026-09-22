<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Monitoring — what the node exports, what it does not, and what to scrape

This directory supplies scrape and alert configuration for the exported node
metrics. Deploying and wiring Alertmanager remain operator actions; checked-in
rules alone do not establish monitoring coverage on any live host.

## Where the metric names come from

Every series name below is read directly from
`crates/bloch-pos-node/src/metrics.rs` as shipped — re-read that file before
trusting this document if the two have drifted. Do not restate a metric's
semantics here without also citing the source; a metrics doc that disagrees
with the exporter is worse than none.

## What the node exports today

| Series | Kind | Meaning |
|---|---|---|
| `bloch_pos_process_starts_total` | counter | Incremented once at boot; use changes of `process_start_unix` to observe restarts (a constant counter reset to 1 cannot expose them reliably) |
| `bloch_pos_store_append_failures_total` | counter | Block-log/index writes that failed (disk-full precursor) |
| `bloch_pos_validator_not_started_total` | counter | Keystore present but validator could not arm |
| `bloch_pos_finality_stalls_total` | counter | Edges into a finality stall (not currently alerted on directly — see `rules.yml`'s use of `last_finality_advance_unix` instead, which needs no rate window) |
| `bloch_pos_blocks_applied_total` | counter | Blocks applied to canonical chain, replay included |
| `bloch_pos_blocks_rejected_total` | counter | Blocks rejected by validation |
| `bloch_pos_head_slot` | gauge | Committed head slot |
| `bloch_pos_wall_slot` | gauge | Wall-clock slot |
| `bloch_pos_behind_by_slots` | gauge | `wall_slot - head_slot`, saturating; 0-1 healthy |
| `bloch_pos_finalized_epoch` | gauge | Committed finalized epoch |
| `bloch_pos_justified_epoch` | gauge | Committed justified epoch |
| `bloch_pos_peer_count` | gauge | Peers across live transports |
| `bloch_pos_mempool_size` | gauge | Mempool entries |
| `bloch_pos_is_syncing` | gauge | 1 while behind and requesting blocks |
| `bloch_pos_validator_active` | gauge | 1 when its registered key is epoch-eligible and startup/doppelganger gates are open; not proof of a signed duty |
| `bloch_pos_last_finality_advance_unix` | gauge | Zero during startup; initialized after replay/WS checks, then updated when finality advances |
| `bloch_pos_heartbeat_unix` | gauge | Unix seconds of the slot loop's latest turn; 0 during boot/replay — what `/health` checks |
| `bloch_pos_data_dir_fs_free_bytes` | gauge | Free bytes on the data dir's filesystem (no matching `*_size_bytes`, so no percentage from this alone) |
| `bloch_pos_process_start_unix` | gauge | Process start time, Prometheus convention |

`GET /health` (same server, different path) answers `200 {"status":"ok"}`,
`200 {"status":"syncing"}`, `503 {"status":"stalled"}`, or
`503 {"status":"starting"}` — see the doc comment at the top of `metrics.rs`
for the exact contract. Both endpoints are loopback-bound and off unless
`--metrics-port` is explicitly passed; there is no default port (`main.rs`)
— **the operator must set an actual port in `prometheus.yml` and confirm it
matches the running unit file**. A failed scrape triggers the availability
alert; the remaining rules cannot observe an unreachable endpoint.

The node refuses an enabled non-loopback `--metrics-bind` unless the command
also carries `--allow-public-metrics`. That flag is an exposure acknowledgement,
not authentication: a deliberately routable endpoint still needs a firewall
and must not be treated as safe for the public internet.

## Additional exported signals and alert coverage

The current exporter includes `bloch_pos_finality_rewinds_refused_total`,
`bloch_pos_equivocations_observed_total` and `bloch_pos_keystore_sealed`.
Their rules are active; previous claims that these metrics did not exist were
stale. Rules also cover exposed write-failure counters, unavailable scrapes, missing
or stale heartbeat, inactive expected validators and observed restart loops.

Set the node scrape target's `role` label to `validator` or `archival`.
Prometheus external labels are not part of local expression evaluation.
Validator activity and sealed-key alerts must not fire for observer-only nodes.
The inactive-validator rule grants 20 minutes of startup grace plus five minutes
pending. These are starting thresholds to qualify against the fleet, not an SLA.
`validator_active` now refreshes each engine turn: the loaded key must match
an active registry record at the current wall epoch and boot/doppelganger gates
must allow participation. A value of one does not establish that a duty was
selected, signed, included, or allowed by durable signing watermarks. The
finality-stall rule excludes the zero timestamp exported before replay ends.
The sealed-key rule also waits for the first engine heartbeat, which is
published only after the keystore gauge has been initialized.

The store-append failure counter is **best-effort**: the node exits immediately
after incrementing it, and a 15-second scrape may never observe that increment.
Keep filesystem-capacity, scrape-unavailability and restart alerts, and preserve
process logs; a zero or absent append-failure series does not prove successful
persistence.

Exact missed-duty accounting remains open: neither `validator_active` nor head
lag proves whether a particular duty was scheduled and signed. Do not label
those metrics as missed attestations. Validate rules with
`promtool check rules rules.yml` and test paging delivery before relying on them.

## What to scrape alongside the node: `node_exporter`

Two of the required alerts need OS-level facts the node has no business
measuring itself:

- **Disk capacity as a percentage.** The node exports free bytes
  (`bloch_pos_data_dir_fs_free_bytes`) but not the filesystem's total size,
  so a "<10% free" alert needs `node_exporter`'s `node_filesystem_avail_bytes`
  / `node_filesystem_size_bytes` for the mountpoint holding the data
  directory.
- **Clock drift.** `node_exporter`'s NTP collector exports
  `node_timex_offset_seconds`. Slot assignment is wall-clock-relative, so
  drift here degrades every slot-based metric the node itself reports
  without the node being able to tell.

`prometheus.yml` in this directory scrapes both `127.0.0.1:9600` (the node,
placeholder port — set to match `--metrics-port`) and `127.0.0.1:9100`
(`node_exporter`, its conventional port), both loopback-only, matching the
node's own loopback-by-default posture.

## Why scraping is local, not central

See the header comment in `prometheus.yml`. In short: the node's metrics
port binds loopback by design, and the perimeter the `os/*.nix` hardening
establishes (`IPAddressDeny=any` plus an operator-filled allowlist) should
not be punched open just so a remote Prometheus can scrape a validator host.
Prometheus and `node_exporter` run on the host; alerts evaluate locally;
getting an alert off the host to a paging system is an Alertmanager peering
question left to the operator (`prometheus.yml`'s `alerting:` block is a
placeholder for exactly that).

## Interim liveness watchdog: the systemd timer

Until an orchestrator is wired to `/health` properly, `os/` ships a
`bloch-health-watchdog` systemd timer + service pair that curls `/health`
every minute and restarts the validator/archival service on **sustained**
503s (not a single blip — see the unit for the exact threshold and why a
one-shot restart-on-503 would itself be a hazard, per Round-3 audit M-5:
"`/health` reports `stalled` on a node that is merely busy"). This is
explicitly an interim measure, not a replacement for `rules.yml`'s
`BlochFinalityStalled` alert, which fires on the more meaningful signal
(finality not advancing) rather than the coarser one (`/health`'s 503).
