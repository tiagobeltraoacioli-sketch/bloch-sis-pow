# Reference integrity — making rot detectable and self-correcting

On 2026-08-31 four systems broke from one cause: a static reference to a node —
a port number, a peer address — written down once, with no owner and nothing
checking it. It broke the socat RPC forwarders, both archival nodes' `--peers`
lists, the public proxy's upstream list, and node4's forwarder. It cost nine
hours.

The reason it cost nine hours and not nine minutes is the shape of the failure.
The devnet transport reconnects dead peers forever and never logs an error, so
rot presents as **latency**, never as a fault. Nothing was down. Nothing was
red. Every system was doing exactly what it had been told to do, to nodes that
no longer existed.

This directory contains four read-only tools and one plan. The principle
underneath all of them:

> **A list nobody maintains cannot rot — so maintain no lists.**
> Discover what is running, by content. Derive everything else from that.
> Keep static only what we own and expect to keep, and verify even that.

---

## The tools

| | what it does | writes anything? |
|---|---|---|
| `inventory.sh` | discovers the fleet **by unit content and by RPC** | no |
| `rot-detector.sh` | unattended check, one verdict line, non-zero exit | no |
| `derive-peers.sh` | derives the private fleet list and the public bootstrap list | no |
| `cleanup-references.sh` | **plans** the cleanup; delegates execution to the rollout | only with an explicit typed flag, and even then it calls the rollout |

Nothing here restarts, edits, enables or disables anything on the fleet. There
is no `systemctl start|stop|restart` in this directory; grep for it.

### `inventory.sh` — the truth

Two rules, both learned the hard way:

**1. Enumerate by unit CONTENT, not by unit name.** `ls bloch-n*.service` is a
guess. Stale `g4-vNN` twins have pointed at the *same* `--data-dir` under a
different name before, and one of them double-signed for 29 hours because
nothing was listing it. Here a node is *any* unit whose resolved `ExecStart`
runs a `bloch-pos` binary with `run` — whatever it is called.

It reads `systemctl show -p ExecStart --value`, not `systemctl cat`, on
purpose: `show` returns the resolved argv on a single line, so a unit written
with backslash continuations (both archival units are) parses identically to
one written on one line. Parsing file text instead is how a node stays
invisible to an audit — it happened to the first draft of this script, which
missed one of the two archival nodes for exactly that reason.

**2. Corroborate by RPC.** A unit file is an intention; an answering RPC on
`16400+i` is a fact. The script probes every listening `164xx` on every box and
cross-references. A unit with no RPC is an `INVISIBLE-NODE`; an RPC with no
unit is an `ORPHAN-RPC`; a `bloch-pos` under no unit at all is an
`ORPHAN-PROCESS` — one that no rollout will ever stop and no reboot will ever
bring back.

Outputs (TSV, in `$STATE_DIR/<timestamp>/`): `nodes.tsv`, `peers.tsv`,
`forwarders.tsv`, `rpc.tsv`, `live-endpoints.txt`, `live-validators.txt`,
`anomalies.txt`. An unreachable host writes a `PARTIAL` marker, and every
consumer refuses to derive or clean from a partial view — otherwise a
momentarily unreachable box looks exactly like a decommissioned one, and the
cleanup amputates nine live validators.

### `rot-detector.sh` — the alarm

Runs from a systemd timer or cron. Read-only. Prints **one** verdict line and
exits non-zero when anything has rotted, so cron mails it, the timer marks the
unit failed, and nobody has to read a log:

```
OK: 63 validators + 2 observers, slot 52375, 1 head, 23 forwarders and
9 upstreams all resolve to live nodes; 0 dead references.
```
```
ROT: 10 finding(s) [PEER-ROT×10] — 4095 dead dial entries in 63/65 units,
63 validators + 2 observers live at slot 52375. Evidence in <dir>.
```

Exit codes: **0** clean · **1** rot found · **2** *could not determine*.
Two is not a shrug. It means we lost the ability to check, which is how the
last outage stayed invisible; the timer must treat it as a failure too.

Classes: `PEER-ROT` (dials matching no live endpoint), `PEER-GAP` (live
endpoints a unit is missing), `FORWARD-ROT` (a forwarder whose
`127.0.0.1:P` has no owner on that box, or that no longer carries a
`getchaininfo` through), `PROXY-ROT` (upstreams disagreeing with the fleet, in
both directions — an upstream naming a host we no longer use, *and* a host
carrying nodes that appears in no upstream), `CONSENSUS`, `STRUCTURE`.

Two deliberate anti-false-alarm rules, both from real incidents:

- **One lost read is not a defect.** Every RPC is tried up to three times,
  in the inventory sweep as well as in the detector. On 2026-08-31 an earlier
  checker declared an archival "mute" that answered three times a minute later;
  the first unattended run of *this* detector repeated the mistake, reporting
  six `INVISIBLE-NODE` findings on six different boxes that all answered on the
  next pass. A box running nine nodes drops the occasional request under load,
  and a single miss is indistinguishable from a dead node.
- **Everything time-varying is compared only within the same slot.** The sweep
  takes about four minutes and a slot is 30 s, so counting distinct values
  across a whole sweep reports a fork on a perfectly converged fleet. The first
  run of this detector did exactly that — "3 distinct heads" turned out to be
  three consecutive slots with one head each — and the naive fix (compare
  *finalized* height instead, since it is monotone) failed the same way one run
  in five: finality advances mid-sweep, so 31,430 and 31,462, exactly one epoch
  apart, looked like a fork. The rules that survive a slow sweep are: nodes
  reading the **same slot** must agree on head and on finality, and no node may
  lag the fleet's maximum finality by more than `FINALITY_SLACK`.

A detector that cries wolf gets ignored, and an ignored detector is worse than
none — it converts a known gap into a false sense of coverage.

### `derive-peers.sh` — lists nobody maintains

Generalises the principle already established in
`~/bloch-rollout/bootnodes-20260831/derive-upstreams.sh` from the observer tier
to the whole fleet.

- **`public`** — only addresses we control *and expect to keep*: the
  observer/archival tier on `:19100`, hosts whose entire job is to have a
  stable address. **No validator address is ever published.** Validators move;
  observers exist precisely so that they do not.
- **`private`** — derived by enumerating active units, every time, from
  scratch. Never copied from a previous list, never read from a file, never
  typed. A validator decommissioned this morning is out of the list this
  afternoon without anyone remembering to remove it.
- **`check`** — running vs derived, per unit; non-zero on drift.

`PEER_SCOPE` (default `validators`) decides what a unit *should* dial.
The default matches what the fleet carries today, which makes the cleanup a
**pure deletion** — the derived list is a subset of every unit's current list —
and a pure deletion is trivially reversible. `PEER_SCOPE=all` would additionally
dial the observers: that *adds* endpoints, so it is a topology decision, not a
cleanup, and it must be taken deliberately rather than inherited from a default.

### `cleanup-references.sh` — the plan

It has no `systemctl`. It cannot restart anything. Restarting validators
outside the rollout's batch discipline risks double-signing — the node holds a
32-minute double-vote guard for a reason, and the rollout refuses to `SUBIR`
before `e+2` because of it.

So its job is to *prove the cleanup is safe and print the commands*:
read-only preflight, the exact new `--peers` string, the ordered command list,
and the rollback for each step. `plan` runs nothing. `run` requires
`--i-have-read-the-plan` and then only calls
`~/bloch-rollout/rollout-release/rollout-release.sh`, which already implements
this cleanup as `PEERS_LIMPAR=1`. We integrate with it rather than competing
with it.

Its most valuable gate is the **cross-derivation check**: this tool discovers
nodes by unit *content*, the rollout discovers them by unit *name*. If the two
disagree, one of them is blind — which is exactly what let a stale twin sign for
29 hours — and nothing runs until the disagreement is explained.

---

## Installing the detector

```sh
sudo install -d /opt/bloch/reference-integrity
sudo install -m 0755 inventory.sh rot-detector.sh derive-peers.sh \
                     cleanup-references.sh /opt/bloch/reference-integrity/
sudo install -m 0600 reference-integrity.conf /opt/bloch/reference-integrity/
sudo cp bloch-rot-detector.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now bloch-rot-detector.timer
```

On the **operator's** machine or a jump box — never on a validator. It needs
the fleet ssh key and nothing else. `crontab.example` is the cron form.

**Uninstall / rollback of the detector itself:**
`systemctl disable --now bloch-rot-detector.timer && rm /etc/systemd/system/bloch-rot-detector.{service,timer} && rm -rf /opt/bloch/reference-integrity`.
It holds no state the fleet depends on; removing it changes nothing but our
ability to see.

---

## Baseline: the fleet as measured 2026-09-01T01:58Z

Read-only, by unit content and by RPC, with the two derivations agreeing.

**63 validators + 2 observers, on 9 hosts. All 65 RPCs answered. One finalized
height (31,398) across all 65. One head per slot. No anomalies.**

- **Validators** `v00`–`v62`, nine per host on seven hosts, unit `bloch-nNN`,
  binary `bloch-pos-cinco`, all `active`+`enabled`, `--listen 19000+i`,
  `--rpc-port 16400+i`, `--rpc-bind 0.0.0.0`.
  **`v63` does not exist anywhere** — the roster is 63, not 64.
- **Observers** `139.180.166.5` and `139.180.173.231`, unit `bloch-archival`,
  binary `bloch-pos-quatro` (**older than the fleet's** — worth rolling), listen
  `19100`, RPC bound to `127.0.0.1:16400`, forwarded publicly on `:8080`.
- **Forwarders** 23: three per fleet host (`8080`/`8880`/`2052`) and one per
  observer (`8080`). All active; **every target owned by a node on its own box
  and answering.** Zero rot here — the 31/08 repair held.
- **Proxy** `g4rpc.js` names nine upstreams: seven fleet hosts + two
  observers. All nine answered, all on the fleet's head. **Zero rot.**
- **No `g4-vNN` twins survive.** No two active units share a `--data-dir`. No
  port collisions, no orphan RPCs, no orphan processes. **No double-sign risk
  today.**

### The rot that remains

**4,095 dead dial entries**, in **63 of 65 units** — every validator, none of
the observers.

Each validator carries 128 `--peers` entries. 63 are live; **65 are dead**,
naming **13 hosts**: the twelve decommissioned "classic" boxes
(`104.238.158.109`, `136.244.82.226`, `136.244.95.190`, `192.248.190.123`,
`45.32.154.137`, `45.76.138.60`, `45.76.82.134`, `45.76.89.225`, `45.76.91.19`,
`45.77.140.22`, `45.77.67.52`, `95.179.166.188`) plus one endpoint on a *live*
host that has no node behind it — `139.84.201.52:19063`, the ghost of `v63`.
That last one is the instructive case: the host is up, the address resolves,
only the node is absent. A reachability check on the host would have passed.

So `bloch-n00` carries 19 distinct peer IPs while the fleet lives on 7 —
consistent with the reported "20", counting the unit's own address.

The peer lists are near-uniform: two variants differing in one entry
(`104.238.158.109:19063` vs `45.77.67.52:19063` — six units carry the latter).
Both are dead, so both vanish in the same cleanup.

### Two findings the derivation surfaced

1. **The observers are invisible to the fleet's peer graph.** No validator
   dials `:19100`, and the two observers do not dial each other. They are
   outbound-only leaves with no path between them. Not rot — nothing points at
   anything dead — but a topology worth a decision (`PEER_SCOPE=all`), taken
   separately from the cleanup.
2. **The observers run `bloch-pos-quatro`** while the fleet runs
   `bloch-pos-cinco`. They should be rolled after the fleet, one at a time;
   they hold no key, so this is the low-risk half.

---

## Cleanup, and how to undo it

`./cleanup-references.sh plan` prints the current version. In summary:

**What changes:** exactly one string per unit — `--peers`, rewritten to the 63
derived live validator endpoints. Same binary, same `--data-dir`, same ports,
same key. `--peers` is a transport hint; it is not consensus.

**How:** `rollout-release.sh` with `PEERS_LIMPAR=1`, in ~11 batches of ≤6, one
node per box, ≥2 epochs apart, `PISO=54` live validators enforced before every
batch. Re-run the detector between batches.

**Rollback:**
- *Per node, immediately:* `rollout-release.sh REVERTER <idx> --imediato`
  restores the exact pre-roll unit the rollout saved before touching it and
  restarts on the **same** `--data-dir` — no state rebuilt, no key moved.
- *Per batch:* revert each index; a batch is ≤6 nodes, never more than one per
  box, so a full revert keeps ≥ `PISO` validators live throughout.
- *Whole change:* the old `--peers` is a **strict superset** of the new one — the
  same 63 live endpoints plus 65 dead ones. Reverting therefore cannot
  disconnect a node from anything it can currently reach. The worst case of a
  full rollback is that nodes resume wasting dials on dead hosts: the status quo.

Nothing in the plan changes consensus, arms an activation constant, or touches
key material.

---

## Cadence

- **Hourly**, unattended: `rot-detector.sh --quiet`. A full sweep of 9 hosts
  and 65 RPCs takes about four minutes, dominated by ssh round-trips; hourly is
  comfortable, per-minute is not.
- **Daily**: `derive-peers.sh check` — catches drift the peer check alone would
  miss, such as a unit added by hand with a hand-typed list.
- **Mandatory after any fleet move, migration or renumbering**, before the
  change is called done. Every one of the 31/08 breakages was a move whose
  references were assumed rather than verified.
- **Owner: founder.** A reference with no owner is the thing this directory
  exists to abolish; it would be absurd for the detector itself to have none.
