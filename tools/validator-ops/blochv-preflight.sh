#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# blochv-preflight.sh — "can this machine actually do the job" — run BEFORE
# the deposit, because the deposit is slow to undo: EXIT_DELAY_EPOCHS = 32
# (~8.5 h) to stop duties, WITHDRAWAL_DELAY_EPOCHS = 2,048 (~22.8 days) to get
# the stake back — and, today, no mechanism that pays it back at all (see the
# runbook's gaps ledger, G1).
#
# ── What "keeping up" means here, in measured numbers ───────────────────────
#
#   slots        one slot every 30 s, 32 slots per epoch. Duties (attest every
#                epoch, propose when drawn) must land inside the slot.
#
#   memory       A COLD START IS THE MEMORY PEAK, NOT STEADY STATE. Replaying
#                mainnet history from genesis peaked at >7.5 GiB RSS on the
#                2026-08 chain and OOM-killed past it (doctor.rs:17,94,362).
#                On 2026-08-21, 22 validators on 8 GB machines were OOM-killed
#                55 s after boot at 7.9 GB (net.rs:152). 8 GB is the FLOOR, and
#                the floor is where the fleet died — this is a measured limit,
#                not a recommendation. It also grows with history: re-measure
#                rather than trusting this line a year from now.
#
#   cpu          replay is SINGLE-THREADED and pins one core for its whole
#                duration (~81 ms per applied block on reference hardware,
#                post the 2026-08-31 per-epoch-clone fix; before that fix a
#                1,550-epoch gap wanted ~93 GB transient and was unrunnable).
#                2 cores minimum: one for replay, one for everything else.
#
#   disk         20 GiB floor, and it only grows.
#
#   clock        the node compares its clock against the MEDIAN of the peers
#                it dialed and REFUSES TO START beyond half an epoch of skew
#                (margin_ms = SLOTS_PER_EPOCH/2 * slot_ms = 480 s on mainnet),
#                symmetrically, with ERR_CLOCK_SKEW. That gate is generous and
#                it is not your safety margin: with zero peer samples the node
#                proceeds anyway, loudly, and an attestation is only admitted
#                in {wall_epoch, wall_epoch+1}. Discipline your clock here.
#
#   one per box  one validator per failure domain. Two validators sharing one
#                box's RAM still both die (the 2026-08 "5-6 per box, one alive"
#                incident); one KEY on two boxes gets slashed, which is worse.
#
# ── Checks ──────────────────────────────────────────────────────────────────
#   1  binary identity + selfcheck, and `bloch-pos doctor` if this build has it
#   2  cores / total RAM / AVAILABLE RAM / free disk
#   3  single-core throughput proxy for the replay budget
#   4  clock: NTP discipline AND a measured offset against an external clock
#   5  open-file limit
#   6  port hygiene: free, no RPC/P2P collision, no accidental routable RPC
#   7  BOOTNODE REACHABILITY — can this machine actually reach the network
#
# PASS / WARN / FAIL per line; exit 0 = all pass, 1 = warnings only,
# 2 = at least one failure.
#
# ── Usage ───────────────────────────────────────────────────────────────────
#   blochv-preflight.sh [--bloch-pos PATH] [--data-dir DIR]
#                       [--rpc-port N] [--p2p-port N]
#                       [--bootstrap FILE | --peers host:port,...]
#                       [--skip-bench]
#
#   --bootstrap FILE   a genesis4-bootstrap.json artifact; peers are read from
#                      .bootstrap.peers. Refuses unresolved placeholders.
#   --peers LIST       comma-separated host:port to probe directly.
#   --rpc-port N       default 16310 (the binary's DEFAULT_RPC_PORT). Note the
#                      runbook and the live fleet use 16400 for RPC, which is
#                      ALSO the libp2p default listen port — check 6 refuses
#                      that collision rather than letting you discover it as a
#                      bind failure at 03:00.

set -u

BLOCH_POS="${BLOCH_POS:-bloch-pos}"
DATA_DIR="${HOME}/bloch-validator/data"
RPC_PORT=16310
P2P_PORT=19100
BOOTSTRAP=""
PEERS=""
SKIP_BENCH=0

# Measured limits. Sources are named so the next operator can re-derive them
# instead of inheriting a number nobody can defend.
SYNC_PEAK_MIB=7680      # >7.5 GiB measured cold-start RSS peak (doctor.rs:17)
DISK_WARN_GIB=20        # doctor.rs:102
DISK_FAIL_GIB=5         # doctor.rs:103
CLOCK_GATE_SECS=480     # half an epoch, time_check.rs:97-99 (mainnet geometry)

while [ $# -gt 0 ]; do
  case "$1" in
    --bloch-pos) BLOCH_POS="$2"; shift 2 ;;
    --data-dir)  DATA_DIR="$2"; shift 2 ;;
    --rpc-port)  RPC_PORT="$2"; shift 2 ;;
    --p2p-port)  P2P_PORT="$2"; shift 2 ;;
    --bootstrap) BOOTSTRAP="$2"; shift 2 ;;
    --peers)     PEERS="$2"; shift 2 ;;
    --skip-bench) SKIP_BENCH=1; shift ;;
    -h|--help) sed -n '2,72p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "blochv-preflight: unknown argument $1 (see --help)" >&2; exit 2 ;;
  esac
done

FAILS=0; WARNS=0
pass() { printf 'PASS  %s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; WARNS=$((WARNS+1)); }
fail() { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS+1)); }

OS="$(uname -s)"
have() { command -v "$1" >/dev/null 2>&1; }

# ── 1. Binary ───────────────────────────────────────────────────────────────
HAVE_BIN=0
if have "$BLOCH_POS"; then
  HAVE_BIN=1
  VER="$("$BLOCH_POS" --version 2>/dev/null | head -1)"
  case "$VER" in
    *+dirty*)        fail "binary is a +dirty build: '$VER'. A validator runs an identifiable release triple; a build nobody can reproduce cannot be blamed or trusted (deploy/RELEASE-INTEGRITY.md)" ;;
    *unknown+nogit*) fail "binary has no commit stamp: '$VER'. Release gates treat this as a hard failure" ;;
    "")              fail "binary found but --version printed nothing" ;;
    *)               pass "binary: $VER" ;;
  esac
  if "$BLOCH_POS" selfcheck >/dev/null 2>&1; then
    pass "selfcheck: frozen consensus parameters verified"
  else
    fail "selfcheck failed. This binary does not link the consensus parameters it claims — it will fork off the network, silently, which is exactly how release genesis4-node-20260814 became consensus-dead at epoch 800"
  fi
  # The node ships its own operator preflight (`doctor`, alias `preflight`) in
  # builds that carry the observability work. When it exists it is the better
  # authority: it reads the real config, not this script's guesses. Run it and
  # keep its verdict.
  if "$BLOCH_POS" doctor --help >/dev/null 2>&1; then
    pass "this build has \`bloch-pos doctor\` — run it too, with your REAL flags:"
    echo "        $BLOCH_POS doctor --data-dir $DATA_DIR --genesis <manifest> [...]"
    echo "        It checks the same machine against the node's own config."
  else
    warn "this build has no \`bloch-pos doctor\` subcommand, so the node cannot self-diagnose. That is expected on releases before the operator-observability work shipped; this script is then your only preflight"
  fi
else
  fail "bloch-pos binary not found ('$BLOCH_POS'). Build it per the runbook §3 and pass --bloch-pos, or set BLOCH_POS"
fi

# ── 2. Cores / RAM / disk ───────────────────────────────────────────────────
if [ "$OS" = "Darwin" ]; then
  CORES="$(sysctl -n hw.ncpu 2>/dev/null || echo 0)"
  RAM_MIB="$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1048576 ))"
  PAGE="$(sysctl -n hw.pagesize 2>/dev/null || echo 4096)"
  FREEP="$(vm_stat 2>/dev/null | awk '/Pages free|Pages inactive|Pages speculative/{gsub("\\.","",$NF); s+=$NF} END{print s+0}')"
  AVAIL_MIB="$(( FREEP * PAGE / 1048576 ))"
else
  CORES="$(nproc 2>/dev/null || echo 0)"
  RAM_MIB="$(( $(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0) / 1024 ))"
  AVAIL_MIB="$(( $(awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null || echo 0) / 1024 ))"
fi

if [ "${CORES:-0}" -ge 2 ] 2>/dev/null; then
  pass "cores: $CORES (>=2; replay is single-threaded and pins one for its whole duration)"
else
  fail "cores: ${CORES:-?}. Replay pins a whole core; with fewer than 2, duties starve during every replay — and a restart is a replay"
fi

if [ "${RAM_MIB:-0}" -ge 8192 ] 2>/dev/null; then
  pass "RAM total: ${RAM_MIB} MiB (>= 8192)"
else
  fail "RAM total: ${RAM_MIB:-?} MiB. A cold start peaked at >${SYNC_PEAK_MIB} MiB RSS on the 2026-08 chain and OOM-killed past it; 22 fleet validators died at 7.9 GB on 8 GB machines 55 s after boot. This machine cannot complete a cold start"
fi

if [ "${AVAIL_MIB:-0}" -ge "$SYNC_PEAK_MIB" ] 2>/dev/null; then
  pass "RAM available now: ${AVAIL_MIB} MiB (>= ${SYNC_PEAK_MIB} MiB measured cold-start peak)"
elif [ "${AVAIL_MIB:-0}" -ge 2048 ] 2>/dev/null; then
  warn "RAM available now: ${AVAIL_MIB} MiB, below the ${SYNC_PEAK_MIB} MiB measured cold-start peak. The node may run once synced and still be OOM-killed the first time it has to replay from cold. Free the memory or stop sharing this box"
else
  fail "RAM available now: ${AVAIL_MIB:-?} MiB. Below 2 GiB the node will not survive its first replay"
fi

mkdir -p "$DATA_DIR" 2>/dev/null
if [ -d "$DATA_DIR" ]; then
  FREE_GIB="$(df -Pk "$DATA_DIR" 2>/dev/null | awk 'NR==2{print int($4/1048576)}')"
  if [ "${FREE_GIB:-0}" -ge "$DISK_WARN_GIB" ] 2>/dev/null; then
    pass "disk: ${FREE_GIB} GiB free at $DATA_DIR (>= $DISK_WARN_GIB)"
  elif [ "${FREE_GIB:-0}" -ge "$DISK_FAIL_GIB" ] 2>/dev/null; then
    warn "disk: ${FREE_GIB} GiB free at $DATA_DIR, below the $DISK_WARN_GIB GiB floor. The block log only grows"
  else
    fail "disk: ${FREE_GIB:-?} GiB free at $DATA_DIR. A node that fills its disk mid-epoch stops signing and may not restart cleanly"
  fi
else
  warn "data dir $DATA_DIR does not exist and could not be created — re-run with --data-dir pointing at the real location, because disk is measured on ITS filesystem, not this one"
fi

# ── 3. Single-core throughput proxy ─────────────────────────────────────────
# Not a consensus benchmark: a floor detector for the class of machine.
# Reference hardware replays ~12 blocks/s (81 ms/block). A core that cannot
# hash 256 MiB in ~3 s is well below that class — burstable and oversold VPS
# cores fail exactly here, and they fail after you have deposited.
if [ "$SKIP_BENCH" -eq 1 ]; then
  warn "cpu proxy skipped (--skip-bench). You have not established that this machine can replay at all"
else
  SHA_BIN="$(command -v sha256sum || command -v shasum || true)"
  now_ms() { python3 -c 'import time;print(int(time.time()*1000))' 2>/dev/null || echo $(( $(date +%s) * 1000 )); }
  if [ -n "$SHA_BIN" ]; then
    START_MS=$(now_ms)
    dd if=/dev/zero bs=1048576 count=256 2>/dev/null | "$SHA_BIN" >/dev/null
    ELAPSED=$(( $(now_ms) - START_MS ))
    if [ "$ELAPSED" -le 3000 ]; then pass "cpu proxy: 256 MiB sha256 in ${ELAPSED} ms (<= 3000)"
    elif [ "$ELAPSED" -le 6000 ]; then warn "cpu proxy: ${ELAPSED} ms — marginal. Expect replay well below the 12 blocks/s reference, which lengthens every restart"
    else fail "cpu proxy: ${ELAPSED} ms. This machine is not in the class that keeps up; a restart's replay will outlast your patience and your duties"; fi
  else
    warn "no sha256sum/shasum found; cpu proxy skipped"
  fi
fi

# ── 4. Clock ────────────────────────────────────────────────────────────────
# Two separate things, and the second is the one that matters:
#   (a) is NTP running   — so the clock stays right,
#   (b) is the clock actually right NOW, measured, in seconds.
# The node's own gate (half an epoch = ${CLOCK_GATE_SECS}s, symmetric,
# ERR_CLOCK_SKEW, refuse-to-start) is a backstop against a spoofed clock
# bypassing the weak-subjectivity gate. It is not a duty-timing margin: an
# attestation is admitted only for {wall_epoch, wall_epoch+1}, so seconds
# matter long before minutes do.
if [ "$OS" = "Darwin" ]; then
  warn "clock: macOS. Verify 'Set date and time automatically' is on. A validator does not belong on a laptop that sleeps: a suspended node misses duties and leaks stake"
elif have timedatectl; then
  if timedatectl show 2>/dev/null | grep -q '^NTPSynchronized=yes'; then
    pass "clock: NTP synchronized (timedatectl)"
  else
    fail "clock: NOT NTP-synchronized. Enable chrony or systemd-timesyncd. A drifting clock makes your attestations refusable network-wide before it ever trips the node's own ${CLOCK_GATE_SECS}s gate"
  fi
elif have chronyc && chronyc tracking >/dev/null 2>&1; then
  pass "clock: chrony answering"
else
  warn "clock: cannot verify NTP state (no timedatectl/chronyc). Verify by hand"
fi

# Measured offset against an external clock. Uses an HTTP Date header, which
# is coarse (1 s) but needs no NTP client and no open UDP — enough to catch
# the failures that matter (minutes and hours, not milliseconds).
if have curl; then
  SKEW="$(python3 - <<'PY' 2>/dev/null
import email.utils, subprocess, time
best = None
for url in ("https://cloudflare.com/cdn-cgi/trace", "https://www.google.com/generate_204"):
    try:
        out = subprocess.run(["curl","-sS","-m","10","-I",url],
                             capture_output=True, text=True, timeout=15)
        t0 = time.time()
        for line in out.stdout.splitlines():
            if line.lower().startswith("date:"):
                remote = email.utils.parsedate_to_datetime(line.split(":",1)[1].strip()).timestamp()
                d = t0 - remote
                if best is None or abs(d) < abs(best):
                    best = d
                break
    except Exception:
        pass
print("" if best is None else int(best))
PY
)"
  if [ -n "${SKEW:-}" ]; then
    ABS="${SKEW#-}"
    if [ "$ABS" -le 2 ]; then
      pass "clock offset: ${SKEW}s vs an external HTTP clock (<= 2s)"
    elif [ "$ABS" -lt 60 ]; then
      warn "clock offset: ${SKEW}s. Under the node's ${CLOCK_GATE_SECS}s gate, so it will start — but duties are timed in 30 s slots, and this is a fraction of a slot away from landing your attestations in the wrong window"
    elif [ "$ABS" -lt "$CLOCK_GATE_SECS" ]; then
      fail "clock offset: ${SKEW}s. The node's gate (${CLOCK_GATE_SECS}s) will still let it START, which is the trap: it will run and miss duties rather than refuse and tell you. Fix NTP first"
    else
      fail "clock offset: ${SKEW}s, beyond the node's ${CLOCK_GATE_SECS}s peer-time gate. The node will refuse to start with ERR_CLOCK_SKEW. Fix NTP; do not look for an override"
    fi
  else
    warn "clock offset: could not measure against an external clock (no egress?). The node's peer-time gate needs at least 3 dialed peers to sample; with zero samples it proceeds ANYWAY, loudly, so an unmeasured clock is an unguarded clock"
  fi
fi

# ── 5. Open files ───────────────────────────────────────────────────────────
NOFILE="$(ulimit -n 2>/dev/null || echo 0)"
case "$NOFILE" in
  unlimited) pass "open files: unlimited" ;;
  *) if [ "${NOFILE:-0}" -ge 65535 ] 2>/dev/null; then pass "open files: $NOFILE (>= 65535)"
     else warn "open files: $NOFILE. Set LimitNOFILE=65535 in the systemd unit; a node that runs out of descriptors drops peers and looks like a network fault"; fi ;;
esac

# ── 6. Ports ────────────────────────────────────────────────────────────────
port_in_use() {
  if have ss; then ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$1\$"
  elif have lsof; then lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
  else netstat -an 2>/dev/null | grep LISTEN | grep -q "[.:]$1 "; fi
}
if [ "$RPC_PORT" = "$P2P_PORT" ]; then
  fail "rpc port and p2p port are both $RPC_PORT. They cannot share a socket"
fi
if [ "$RPC_PORT" = "16400" ]; then
  warn "rpc port 16400 is ALSO the libp2p transport's default listen port (/ip4/0.0.0.0/tcp/16400). The live fleet serves RPC there and the runbook documents it, but the binary's own RPC default is 16310. If you run --transport libp2p without moving one of them, one of the two will fail to bind. Pass --rpc-port explicitly and mean it"
fi
port_in_use "$RPC_PORT" && fail "rpc port $RPC_PORT is already in use — find out by what before you assume it is stale" || pass "rpc port $RPC_PORT free"
port_in_use "$P2P_PORT" && fail "p2p port $P2P_PORT is already in use" || pass "p2p port $P2P_PORT free"

echo
echo "REMINDER: the RPC has NO authentication, NO rate limit, NO per-method"
echo "authorisation, and sendrawtransaction is a write. Bind it to 127.0.0.1"
echo "(the default) and never port-forward it. Expose ONLY the P2P port, and"
echo "firewall even that to known peers while the fleet transport is the"
echo "unauthenticated devnet mesh: a stale node once stopped the whole"
echo "network's block production by dumping 1,270 old blocks into it."
echo
# ── 7. Bootnode reachability ────────────────────────────────────────────────
# A machine that passes every check above and cannot open a TCP connection to
# a peer is a machine that will sit at height 0 forever. Egress firewalls and
# provider-blocked high ports are the common cause, and they are invisible
# until you try.
PEERLIST=""
if [ -n "$BOOTSTRAP" ]; then
  if [ ! -f "$BOOTSTRAP" ]; then
    fail "bootstrap artifact $BOOTSTRAP not found"
  else
    PEERLIST="$(python3 - "$BOOTSTRAP" <<'PY' 2>/dev/null
import json, sys
d = json.load(open(sys.argv[1]))
peers = (d.get("bootstrap") or {}).get("peers") or []
print(",".join(peers))
PY
)"
    if [ -z "$PEERLIST" ]; then
      fail "$BOOTSTRAP carries no .bootstrap.peers list"
    else
      case "$PEERLIST" in
        *"<"*">"*)
          fail "$BOOTSTRAP still contains UNRESOLVED PLACEHOLDERS: $PEERLIST
        This artifact was staged but never filled in — the bootstrap tier does
        not exist yet. You cannot join with it. There is no published peer set
        for Genesis-4 (runbook gap G4): joining today requires an existing
        operator to give you addresses and open a firewall hole for you. Get
        those, then re-run with --peers."
           PEERLIST=""; BOOT_FAILED=1 ;;
        *) pass "bootstrap artifact lists ${PEERLIST}" ;;
      esac
    fi
  fi
elif [ -n "$PEERS" ]; then
  PEERLIST="$PEERS"
fi

if [ -n "${BOOT_FAILED:-}" ]; then
  :   # the bootstrap failure above already said everything worth saying
elif [ -z "$PEERLIST" ]; then
  warn "no reachable peer list to test (pass --peers host:port,... or --bootstrap FILE).
        Reachability is the check that most often turns a 'why is my node at
        height 0' into a five-minute answer. Genesis-4 publishes no bootstrap
        peers today, so until it does, ask the operator who is sponsoring your
        entry for addresses and test them here BEFORE you deposit."
else
  OLDIFS="$IFS"; IFS=','
  REACHED=0; TRIED=0
  for HP in $PEERLIST; do
    IFS="$OLDIFS"
    TRIED=$((TRIED+1))
    H="${HP%:*}"; P="${HP##*:}"
    if python3 -c '
import socket,sys
s=socket.socket(); s.settimeout(6)
try:
    s.connect((sys.argv[1], int(sys.argv[2]))); sys.exit(0)
except Exception:
    sys.exit(1)
finally:
    s.close()' "$H" "$P" 2>/dev/null; then
      pass "peer $HP reachable (TCP connect)"
      REACHED=$((REACHED+1))
    else
      warn "peer $HP NOT reachable from this machine. Either it is down, or your egress blocks that port, or its firewall has not been opened for your address — on the devnet transport the peer side is inbound-firewalled to known IPs by design"
    fi
    IFS=','
  done
  IFS="$OLDIFS"
  if [ "$REACHED" -eq 0 ]; then
    fail "NONE of the $TRIED configured peers is reachable. This node cannot join the network from this machine. Do not deposit until at least one peer answers"
  else
    pass "peer reachability: $REACHED of $TRIED"
    [ "$REACHED" -lt 2 ] && warn "only one reachable peer. A single peer is a single point of failure AND a single point of view — and a node that can hear only one source has no way to notice that source is on a fork"
  fi
fi

echo
if [ "$FAILS" -gt 0 ]; then
  echo "preflight: $FAILS FAIL, $WARNS WARN — do not deposit from this machine yet."
  echo "A deposit takes ~8.5 h to stop duties and ~22.8 days to unwind, and today"
  echo "there is no mechanism that pays the stake back at all (runbook gap G1)."
  exit 2
elif [ "$WARNS" -gt 0 ]; then
  echo "preflight: 0 FAIL, $WARNS WARN — read every warning before proceeding."
  exit 1
else
  echo "preflight: all checks passed."
  echo "Next: blochv-keygen.sh (offline), then blochv-guard.sh before the first"
  echo "start with a key, then blochv-health.sh on a timer."
  exit 0
fi
