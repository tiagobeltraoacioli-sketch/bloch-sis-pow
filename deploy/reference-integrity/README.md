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
| `detector-run.sh` | what the **timer** calls: bounds the run, leaves a receipt | only inside `STATE_DIR`, on this machine |
| `heartbeat.sh` | checks **the checker** — has it run recently, what did it say | no |
| `derive-peers.sh` | derives the private fleet list and the public bootstrap list | no |
| `selftest.sh` | pins the 0/1/2 exit contract of the two above | temp dir only |
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

### `detector-run.sh` + `heartbeat.sh` — checking the checker

The detector answers *has anything rotted?* It cannot answer *did anyone
ask?* — and the second question is the one that cost nine hours. **A check
that silently stopped running looks exactly like a check that keeps passing.
Both are silence.**

So the timer never calls `rot-detector.sh` directly. It calls
`detector-run.sh`, which does two things the detector cannot do for itself:

- **Bounds the run.** A detector that *hangs* is worse than one that fails: a
  systemd oneshot with a wedged ssh sits in `activating` forever, so
  `systemctl --failed` stays empty and the mailbox stays quiet while nothing
  is being checked. The sweep is killed at `DETECTOR_TIMEOUT_S` (1200 s
  against a measured ~4 min) and reported as **2**, never as 0. macOS has no
  `timeout(1)`; the wrapper falls back to `gtimeout`, and if neither exists it
  still runs and says so in the receipt rather than pretending it was bounded.
- **Leaves a receipt**, on *every* exit path including the undetermined one:
  `STATE_DIR/last-run.tsv` = `iso8601 ⇥ epoch ⇥ exit ⇥ verdict`. An exit 2 that
  leaves no trace makes "the detector is broken" and "the detector was never
  started" indistinguishable, which is the confusion this directory exists to
  abolish.

`heartbeat.sh` reads that receipt and speaks the same alphabet — **0** ran
recently and clean, **1** ran recently and found rot, **2** could not
determine: no receipt, unreadable receipt, receipt **stale** past
`HEARTBEAT_MAX_AGE` (3 h against an hourly cadence), a receipt from the
future (a clock that moved cannot judge staleness), or a last run that was
itself undetermined. That last case matters: an expired ssh key mails the same
exit 2 every hour until it becomes wallpaper; here it is a standing failure.

It runs as a **separate** timer, every 30 min. Separate on purpose: a timer
that failed to load, or a script that was deleted, cannot report its own
absence. Two units can fail independently; one cannot fail and still speak.

`selftest.sh` pins the contract — 17 assertions, no fleet host touched,
seconds to run. It exists because running the matrix by hand the first time
found two real defects in this very wrapper: a diagnostic note appended *after*
the verdict was captured, so every receipt recorded the note instead of the
verdict; and an unparsed `-c`, so a run against another conf wrote its receipt
into the default state dir and silently overwrote the real fleet's. Both are
fixed, and the test is what keeps them fixed. Run it after any edit here.

**What it honestly does not cover.** It is a same-machine check. It catches a
timer unloaded, a script removed, a run wedged past its timeout, a key that
expired, a laptop that slept through the window — everything except *the
machine being off*, during which nothing on it can report anything. Closing
that last gap needs the check to live on a second host, which means putting
the fleet ssh key somewhere new. That is a founder decision and is
deliberately **not** taken here.

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

Then the heartbeat, which is what makes a *stopped* detector visible:

```sh
sudo install -m 0755 detector-run.sh heartbeat.sh /opt/bloch/reference-integrity/
sudo cp bloch-rot-heartbeat.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now bloch-rot-heartbeat.timer
```

On the **operator's** machine or a jump box — never on a validator. It needs
the fleet ssh key and nothing else. `crontab.example` is the cron form.

### On macOS, which is where this actually runs

The operator's machine is a Mac, and the detector has to run there:
`PROXY_JS` points at `~/dev/posternlabs-deploy/functions/g4rpc.js`, which is
source on that Mac and nowhere else. **systemd does not exist on macOS**, so
the `.service`/`.timer` pair cannot run on the very host the tool was written
for — and the cron form is a trap there, because modern macOS gates cron under
TCC and ships no configured MTA, so `MAILTO` silently discards every verdict.
A cron job that runs and throws its answer away is this directory's own
failure mode wearing the costume of coverage.

Use the launchd agents instead. The verdict goes to a file, and the heartbeat
is what makes a missing verdict loud:

```sh
install -d ~/bloch-rollout/reference-integrity
install -m 0755 *.sh ~/bloch-rollout/reference-integrity/
install -m 0600 reference-integrity.conf ~/bloch-rollout/reference-integrity/
cp com.postern.bloch.rot-{detector,heartbeat}.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/com.postern.bloch.rot-detector.plist
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/com.postern.bloch.rot-heartbeat.plist
# both RunAtLoad, so a misconfiguration surfaces now rather than in an hour:
tail -5 /tmp/bloch-rot-detector.log /tmp/bloch-rot-heartbeat.log
```

Unload with `launchctl bootout gui/$UID/com.postern.bloch.rot-detector` (and
`…rot-heartbeat`). launchd only fires while the machine is awake: a closed lid
does not run the detector, and nothing here can change that. The heartbeat
reports the resulting gap honestly, which is the most a laptop can offer — and
the reason a laptop is a stopgap, not the final home for this check.

**Uninstall / rollback of the detector itself:**
`systemctl disable --now bloch-rot-detector.timer && rm /etc/systemd/system/bloch-rot-detector.{service,timer} && rm -rf /opt/bloch/reference-integrity`.
It holds no state the fleet depends on; removing it changes nothing but our
ability to see.

---

## Baseline: the fleet as measured 2026-09-01T09:50Z and 09:56Z

Two independent read-only sweeps this morning, plus the 01:58Z one below.
**Nothing has changed between them**, which is itself the finding: the fleet
is stable, still on `bloch-pos-cinco`, and the rot is exactly where it was.

```
ROT: 10 finding(s) [PEER-ROT×10] — 4095 dead dial entries in 63/65 units,
63 validators + 2 observers live at slot 53332.
```

Sharper numbers than the first pass had, from `peers.tsv` directly:

- **65 units carry a peer list**: 63 validators at **128 entries** each,
  2 observers at **63** each.
- **Dead dials: 4,095** = 63 validators × **65 dead each**. The observers have
  **zero** — they already carry exactly the 63 live validators.
- **66 distinct dead endpoints** across the fleet (65 per unit), on 13 hosts.
  The extra one is the variant: **three** peer-list variants exist — 57 units,
  6 units differing only in `45.77.67.52:19063` vs `104.238.158.109:19063`,
  and the 2 observers. Both variant entries are dead, so both vanish together.
- **`PEER-GAP` is zero for all 65 units.** Every unit already carries every
  live validator. This is the empirical proof that the cleanup is a **pure
  deletion**: there is nothing to add, only 65 entries per unit to remove.
- **The ghost**, `139.84.201.52:19063`, is dialled by all 63 units and sits on
  a **live** host — a host-level reachability check passes it. It is the only
  dead endpoint of the 66 whose host is still in service.
- Dead dials by host: `136.244.95.190`, `45.76.91.19`, `45.77.140.22` at 378
  each; `104.238.158.109` 372; `45.77.67.52` 321; seven hosts at 315;
  `139.84.201.52` 63 (the ghost alone).
- **Zero** `FORWARD-ROT`, **zero** `PROXY-ROT`, **zero** `CONSENSUS`, **zero**
  `STRUCTURE`, **zero** anomalies. The 31/08 forwarder and proxy repairs hold;
  the chain is converged, one head per slot, max finalized 32,356.
- Fleet binary is **`bloch-pos-cinco`** on all 63 validators (`active`,
  `enabled`, nine per host on seven hosts); observers on **`bloch-pos-quatro`**.
  **The `seis` roll has not happened yet** — see the sequencing verdict above.

### The 01:58Z baseline, unchanged


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

## Sequencing: this waits for `bloch-pos-seis`

**Verdict: do not run the peer cleanup as a standalone roll. Fold it into the
`seis` rollout, which is already configured to carry it.**

The cleanup itself is trivially safe — one string per unit, a strict deletion,
reversible per node. What is *not* cheap is the thing it requires: **63
restarts**. Measured on the live fleet
(`~/bloch-rollout/rollout-release/work-mainnet/medicao-replay-20260901.md`):

- every restart replays the whole store with the **RPC silent ~21 min** — the
  node says so itself: `replaying 28645 blocks from the log — the RPC stays
  silent until this finishes`;
- the node **emerges behind the tip**. Gaps measured across nine nodes on one
  box: **40, 45, 62, 63, 66, 93, 140, 198 slots**. 198 slots is **6.2 epochs**;
- under `cinco`, closing that gap is the defect. A node behind the clock
  re-derives `rolled_to(wall)` per applied block and copies the entire eUTXO
  (452,726 entries, ~60 MB, ~204 ms) for **every epoch crossed**, with a
  **break-even at 6–10 epochs**. The observed tail lands *inside* that band.

That is not theory: the 31/08 migration ran on top of the break-even and it is
where **v10 and v63 became heads of their own forks**. Two validators, one of
them permanently.

`bloch-pos-seis` (`bed1b9ce`) **is the fix for exactly this** — gap 15:
5.8 s → 82 µs per block; gap 1550: unrunnable → 81 ms. And the rollout's
`SUBIR` installs the new binary *before* starting the node, so the replay and
the catch-up both run under the corrected code.

So the two options are not symmetric:

| | restarts | replay runs under | self-fork exposure |
|---|---|---|---|
| peer cleanup now, then `seis` later | **126** | `cinco`, then `seis` | paid **twice**, once needlessly |
| peer cleanup folded into `seis` | **63** | `seis` | paid **once**, under the fix |

A standalone peers roll would spend 63 restarts inside the defective catch-up
path — the one that has already cost two validators — to buy a reduction in
*latency*. The detector's own framing is that this rot presents as latency and
never as a fault; that makes it real, and it also makes it not worth a
coin-flip on a validator.

`rollout.conf.mainnet` already encodes the right answer: `BIN_NOVO` is
`bloch-pos-seis-linux` **and** `PEERS_LIMPAR=1`. One roll, both changes, one
restart per node. Note that `cleanup-references.sh plan` step 0 still advises
setting `BIN_NOVO` to the *currently running* binary — that instruction
describes the standalone variant and should be read as the option **not**
taken; leave the conf as it stands.

The observers are the exception and stay separate: they hold no key, have
never proposed a block (`proposing block` = 0, and
`/home/ubuntu/g4/archival/validator.key` does not exist), so they cannot
self-fork. Their exposure is availability — they are the first two upstreams
of `g4rpc.js`, whose `QUORUM_MIN` is 2, so **never both in the same window**.
Their peer lists are already clean; they need rolling only for the binary.

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
