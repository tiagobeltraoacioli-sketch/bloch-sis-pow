# NixOS module: interim liveness watchdog for a bloch-pos node.
#
# WHY THIS EXISTS (CRIT-2/HIGH-3). `/health` has existed on the node since
# metrics.rs landed, but nothing polled it and nothing restarted a node that
# stopped answering healthily — HIGH-3 in the Round-2/3 audits: "`/health`
# exists but no WatchdogSec and nothing scrapes it." deploy/monitoring/'s
# Prometheus rules are the real fix (they alert on the meaningful signal —
# finality not advancing — not merely on HTTP status); this timer is the
# interim, coarser backstop for a host that has no Prometheus stack running
# yet, or as a second independent layer alongside it.
#
# DELIBERATELY NOT a naive "restart on any 503": Round-3 audit M-5 found
# `/health` reports `stalled` on a node that is merely busy under RPC load,
# because the staleness check is a slot-loop heartbeat with a fixed
# threshold, not a load-aware one. Restarting a busy-but-healthy validator
# is itself an availability incident — a restart costs real replay time
# (deploy/FLAG-DAY-EPOCH-800.md measured ~2h of replay per node on this
# fleet's hardware) and every restart's replay window is a period the node
# cannot attest at all. This module restarts only on SUSTAINED failure
# (`sustainedFailureThreshold` consecutive failed checks, default 10 minutes'
# worth at the default interval), not a single blip, and only ever calls
# `systemctl restart` on the target unit — it holds no other privilege.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.blochHealthWatchdog;

  checkScript = pkgs.writeShellScript "bloch-health-watchdog-check" ''
    set -euo pipefail
    STATE_FILE="/run/bloch-health-watchdog/consecutive-failures"
    mkdir -p "$(dirname "$STATE_FILE")"
    FAILS=0
    [ -f "$STATE_FILE" ] && FAILS=$(cat "$STATE_FILE") || true

    # A curl exit code OR a non-200 HTTP status both count as one failure.
    # 503 with body {"status":"syncing"} is NOT a failure — that is metrics.rs
    # returning 200 for "alive but catching up" (see the module's own health()
    # contract); only an actual non-2xx is polled for here via -f.
    if ${pkgs.curl}/bin/curl -fsS --max-time 5 "http://127.0.0.1:${toString cfg.healthPort}/health" >/dev/null 2>&1; then
      echo 0 > "$STATE_FILE"
      exit 0
    fi

    FAILS=$((FAILS + 1))
    echo "$FAILS" > "$STATE_FILE"
    echo "bloch-health-watchdog: /health check failed ($FAILS consecutive)"

    if [ "$FAILS" -ge ${toString cfg.sustainedFailureThreshold} ]; then
      echo "bloch-health-watchdog: $FAILS consecutive failures >= threshold ${toString cfg.sustainedFailureThreshold} — restarting ${cfg.targetUnit}"
      echo 0 > "$STATE_FILE"
      ${pkgs.systemd}/bin/systemctl restart "${cfg.targetUnit}"
    fi
  '';
in
{
  options.services.blochHealthWatchdog = {
    enable = lib.mkEnableOption "the interim /health-polling restart watchdog";

    targetUnit = lib.mkOption {
      type = lib.types.str;
      default = "bloch-pos-node.service";
      description = "The systemd unit to restart on sustained /health failure.";
    };

    healthPort = lib.mkOption {
      type = lib.types.port;
      description = ''
        Port /health is served on (the node's --metrics-port — /health and
        /metrics share one listener per metrics.rs). Required: there is no
        safe default, and this MUST match the target unit's actual
        --metrics-port or every check fails permanently and the watchdog
        restarts the node in a loop.
      '';
    };

    checkIntervalSeconds = lib.mkOption {
      type = lib.types.int;
      default = 60;
      description = "How often to poll /health.";
    };

    sustainedFailureThreshold = lib.mkOption {
      type = lib.types.int;
      default = 10;
      description = ''
        Consecutive failed checks before restarting the target unit. At the
        default 60s interval this is 10 minutes of sustained failure — well
        past HEALTH_STALE_SECS (30s, metrics.rs) plus margin for the M-5
        false-positive-under-load case, and well short of letting a genuinely
        wedged node sit unrestarted for hours.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.bloch-health-watchdog = {
      description = "Poll bloch-pos-node /health and restart on sustained failure";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${checkScript}";
        # Deliberately minimal privilege beyond what `systemctl restart` on
        # one named unit requires — this is a polkit/policy concern in a full
        # deployment (restrict via polkit rules to exactly
        # `systemctl restart ${cfg.targetUnit}` rather than granting broad
        # systemctl access); left as an operator follow-up rather than
        # asserted as solved here.
        DynamicUser = true;
        StateDirectory = "bloch-health-watchdog";
        RuntimeDirectory = "bloch-health-watchdog";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectClock = true;
        ProtectHostname = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
        UMask = "0077";
      };
    };

    systemd.timers.bloch-health-watchdog = {
      description = "Timer for bloch-health-watchdog";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "2min"; # let the node clear replay/boot before the first check
        OnUnitActiveSec = "${toString cfg.checkIntervalSeconds}s";
        AccuracySec = "10s";
      };
    };
  };
}
