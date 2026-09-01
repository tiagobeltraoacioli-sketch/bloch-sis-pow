# Bloch Genesis-4 — Operator Observability

**Status: shipped with the node. Scope: NODE-LOCAL, read-only.** Nothing on
this surface is read by any consensus rule, gossiped to any peer, or written
to any store; two nodes reporting differently cannot fork over anything here.
The one adjacent feature that IS consensus-affecting when armed — the
`--max-propose-lag` proposal-lag gate — is documented in `engine.rs` and is
OFF by default; this document only reports its refusals.

## Who this is for

A third-party validator operator who **cannot SSH into the box and cannot
read the source**. Until this surface existed, the fleet's only reliable
stall diagnosis was watching `node.log` not grow for 75 seconds — on a node
that was answering RPC, holding 57 peers, and reporting a plausible height
the whole time. Every signal below exists because some incident needed it.

## The surfaces

| Surface | Transport | What it answers |
|---|---|---|
| `getchaininfo` → `health` object | JSON-RPC (POST) | "is this node making progress?" |
| `getvalidatorstatus` | JSON-RPC (POST) | "is my validator working?" |
| `GET /metrics` (also `getmetrics` over JSON-RPC) | HTTP on the RPC port | everything, for a scraper (Prometheus text 0.0.4) |
| `GET /health` | HTTP on the RPC port | 200 healthy/syncing, 503 stalled — for load balancers and deposit gates |
| `[health]` log lines | node log | the same verdict, for a human tailing the log |
| `bloch-pos doctor` | CLI | preflight and environment diagnosis |

All HTTP surfaces share the RPC port (default 16310) and therefore the RPC
bind. **Keep the bind on loopback** and scrape through a tunnel or a reverse
proxy — `sendrawtransaction` makes this port a write surface (see
`rpc-exposure` below).

---

## 1. Sync health (`health` in `getchaininfo`; `bloch_pos_syncing` / `bloch_pos_stalled`)

| Signal | Meaning | Operator action |
|---|---|---|
| `behind_by_slots` | wall-clock slot minus head slot | Alone, nothing: this chain fills ~13% of its slots, so healthy nodes routinely sit many slots behind. Judge only together with the two flags. |
| `secs_since_last_block` | seconds since this node last **applied** a canonical block | The number that was previously only visible as log-file growth. |
| `syncing` | ≥64 slots behind, but applied a block in the last 8 slots' worth of time | Leave it alone; it is catching up. |
| `stalled` | ≥64 slots behind AND applied nothing for 8 slots' worth of time | **Alert on this.** RPC answering and peers connected do NOT clear it — that combination is exactly the failed state. Capture the data dir, restart the node. An exchange observer should stop crediting deposits while it is set. |

Honest limitation: a node cannot locally distinguish "I am deaf" from "the
whole chain went quiet". If no block exists anywhere for two epochs, every
healthy node reports `stalled`. That is accepted — a chain-wide two-epoch
outage deserves the same page — and it is why this verdict must never gate
consensus behaviour.

`GET /health` returns the same object with status **200** (not stalled) or
**503** (stalled), so a load balancer needs no JSON parsing.

## 2. Validator status (`getvalidatorstatus`)

On an observer (no `validator.key`) the method returns error `-32009` — "no
validator here" is an answer, not an omission.

| Field | Meaning | Operator action |
|---|---|---|
| `registry.state` | `active` / `queued` / `exiting` / `exited` / `slashed`; `registry: null` means the chain does not know this index at all | Anything but `active` on a node you expect to be validating is the finding. `null` = wrong key or wrong network. |
| `registry.leaked_sat` | inactivity leak accrued (satoshis) | Nonzero: finality has been failing while your votes were absent from the counted set. If the rest of the network is fine, YOUR node is the one not participating — check `stalled`, peers, and the guard. |
| `in_duty_roster` | member of the current epoch's duty roster | `false` while `registry.state=active` means the roster filtered you (e.g. not yet effective); duties will not happen. |
| `next_attestation_slot` / `next_proposal_slot` | next duty, scanned from the wall clock to the end of the NEXT epoch (`projection_end_slot`) | `null` for proposal is normal (small validators are often not chosen in a 2-epoch window). `null` for attestation while in the roster is not — every roster member attests once per epoch. The projection is computed by the same code that performs duties, from THIS node's head; a reorg can shift next epoch's committees. |
| `attested_in_current_epoch` / `..previous_epoch` | is an attestation by this validator **included on the canonical chain** in the head's current/previous epoch (`null` = not tracked that epoch) | The ground truth of "did my duty land". These read the CHAIN's epoch, which lags the wall epoch on a node that is behind — compare with `current_epoch` in the same response. |
| `attestations_signed_since_boot` / `proposals_signed_since_boot` | signatures this process released (reset on restart) | Signed climbing while `attested_in_current_epoch` stays `false`: your votes leave but never land — mesh/gossip problem. Signed NOT climbing while in the roster: duty problem on this node. |
| `duties_refused_since_boot` | duties refused by a protective gate: signing guard, doppelganger silence, proposal-lag gate | Occasional refusals right after a restart are the doppelganger watch doing its job. A steadily climbing value: read the node log — each refusal prints its reason. |
| `signing_guard.present` | slashing-protection store open | `false` on a keyed node = the node performs NO duties (by design; see BLOCH-SLASHING-PROTECTION.md). |
| `signing_guard.highest_proposed_slot`, `.attestation_target_epoch` | the durable watermarks | `current_epoch − attestation_target_epoch` = epochs since this key last voted. Persistent across restarts (unlike the counters). |
| `doppelganger.state` | `disabled` / `watching` (duties deliberately silent until `silent_until_slot`) / `clear` / `alarmed` | `watching` after a restart is normal — do not "fix" the silence. `alarmed` you will rarely see over RPC: the process exits, with the DOPPELGANGER message in the log. Find and stop the other signer before restarting. |

## 3. Metrics (`GET /metrics`, Prometheus text 0.0.4, prefix `bloch_pos_`)

Chain/node series: `head_slot`, `head_height`, `wall_slot`, `behind_slots`,
`secs_since_last_block`, `syncing`, `stalled`, `has_finality`,
`finalized_height`, `justified_epoch`, `finalized_epoch`,
`finality_distance_epochs`, `peers_connected`, `peers_configured`,
`mempool_transactions`, `mempool_capacity`, `mempool_bytes`, `blocks_known`,
`validators_total`, `validators_active`, `uptime_seconds`.

Validator series (present only when the node holds a key):
`validator_index`, `validator_in_registry`, `validator_in_duty_roster`,
`validator_slashed`, `validator_exiting`, `validator_leaked_sat`,
`validator_attested_current_epoch`, `validator_attested_previous_epoch`
(absent when not tracked that epoch — absent ≠ 0), the three
`validator_*_total` counters, `signing_guard_present`,
`signing_guard_highest_proposed_slot`,
`signing_guard_attestation_target_epoch`, `doppelganger_state`
(0 disabled, 1 watching, 2 clear, 3 alarmed).

Suggested alerts:

```yaml
# The one page that matters — the 2026-08 stall shape.
- alert: BlochNodeStalled
  expr: bloch_pos_stalled == 1
  for: 2m

# Finality failing chain-wide or this node partitioned.
- alert: BlochFinalityLagging
  expr: bloch_pos_finality_distance_epochs > 4
  for: 10m

# Validator present but not doing its job.
- alert: BlochValidatorNotAttesting
  expr: bloch_pos_validator_in_duty_roster == 1
        and bloch_pos_validator_attested_previous_epoch == 0
  for: 32m   # one full epoch at 30s slots

# My stake is leaking.
- alert: BlochValidatorLeaking
  expr: increase(bloch_pos_validator_leaked_sat[1h]) > 0

# Isolated node (egress firewall, dead peer list).
- alert: BlochNoPeers
  expr: bloch_pos_peers_connected == 0 and bloch_pos_peers_configured > 0
  for: 5m
```

The scrape itself is a liveness probe of the consensus loop: `/metrics` is
answered by the engine thread, so a scrape timeout means the loop itself is
wedged (a *worse* state than `stalled=1`, which the loop still reports).

## 4. Preflight / diagnosis: `bloch-pos doctor`

Pass the same flags you pass (or intend to pass) to `run`. Read-only;
exit 0 = no failures, 1 = at least one `[FAIL]`.

| Check | What it catches | Incident it answers |
|---|---|---|
| `genesis` | manifest unreadable/corrupt | refuses before the node does |
| `data-dir` | key without signing history (node will refuse to start), blocks.log size | slashing-protection onboarding |
| `disk` | free space under the data dir (warn <20 GiB, fail <5 GiB) | unpruned block log |
| `memory` | available RAM vs the measured >7.5 GiB full-sync peak | the fresh-resync OOM |
| `clock` | median skew vs the configured peers, judged by the same `time_check::gate` the boot uses | rolled-back VM clock defeating weak subjectivity |
| `p2p-listen` | listen port free vs already bound; states plainly that internet-side reachability cannot be proven from inside | — |
| `p2p-egress` | TCP-dials every configured peer; if ALL are unreachable, points at leftover egress firewall rules (`iptables -S OUTPUT`) BEFORE consensus | the 2026-08-07 silent egress DROP |
| `rpc-exposure` | connects to the RPC port on every routable address of this host and flags a JSON-RPC answer as a FAIL | the fleet-wide public RPC bind found 2026-08-30 |
| `node` / `validator` | if a node answers on loopback, prints its health and validator status | doctor doubles as the no-SSH status command |

## 5. Signals that are deliberately absent

Where the data does not exist in the node, the surface says so instead of
approximating:

1. **Inbound P2P reachability from the internet.** Unknowable from inside
   NAT/firewalls; `doctor` reports the local bind state and tells you to
   test from outside.
2. **Per-epoch duty history / missed-attestation counts over time.** The
   chain state keeps participation for exactly the current and previous
   epoch; nothing stores a longer history. The durable signing-guard
   watermarks plus a scraper's own retention of the two participation
   gauges are the honest substitutes.
3. **"My attestation was received by the aggregators."** The node knows
   only what lands on ITS canonical chain; propagation elsewhere is not
   observable.
4. **A live `doppelganger_state == 3` gauge.** The process exits on alarm
   by design; monitor for the process going down plus the log line.
5. **Pending-penalty beyond `slashed` + the inactivity leak.** The protocol
   has no other deferred-penalty concept; nothing further is inventable.
6. **Distinct-peer count on the devnet transport.** It counts connections
   (a fully-meshed pair counts twice); the libp2p transport counts distinct
   peers. The metric's HELP line says which.
7. **Whether the whole network is down vs this node being deaf.** See the
   `stalled` limitation above — a node alone cannot tell; only your
   monitoring of MULTIPLE nodes can.

## 6. Consensus-impact statement

Everything in this document reads committed state, engine-local counters, or
transport gauges, on the engine thread, and writes nothing. The additions to
the consensus crate (`bloch-pos-committee`) are three read-only getters
(`attested_in_current_epoch`, `attested_in_previous_epoch`, `leaked_of` on
`CommittedState`) that expose values existing rules already compute; no
transition behaviour changes and no state root moves. The `doctor` command
dials only peers the operator configured (one time-probe exchange, the same
frames the boot gate already sends) and the local RPC port.
