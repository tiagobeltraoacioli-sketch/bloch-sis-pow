# NixOS module: run the LIVE Genesis-4 proof-of-stake node (`bloch-pos`,
# crate `bloch-pos-node`) as a hardened systemd service.
#
# WHY THIS FILE EXISTS. Before this commit, `os/bloch-node.nix` covers only
# the RETIRED Genesis-3 binary (`bloch`, `legacy/genesis3-node`) — there was
# no NixOS unit at all for the binary the LIVE chain actually runs. A fleet
# deployed from this tree's Nix modules had no declarative, hardened way to
# run `bloch-pos`; every fleet host today is provisioned some other way. This
# module gives `bloch-pos` the same hardening spine as `bloch-node.nix`
# (MemoryMax/TasksMax containment, IPAddressDeny=any perimeter, no
# capabilities, ProtectProc=invisible, etc. — see that file's comments for
# the citations behind each), plus what only this binary needs: loopback RPC
# and metrics by default, and the sealed keystore passphrase delivered via
# systemd's `LoadCredential=`, never an environment variable.
#
# Enable on any NixOS host with `services.blochPos.enable = true;`.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.blochPos;
in
{
  options.services.blochPos = {
    enable = lib.mkEnableOption "the live Genesis-4 proof-of-stake node (bloch-pos)";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.blochPos or (pkgs.callPackage ./package.nix { }); # TODO: a
        # dedicated bloch-pos-node package.nix does not exist yet in os/ —
        # this falls back to the same builder as the legacy `bloch` package,
        # which will NOT produce a `bloch-pos` binary until that derivation
        # is added. Wiring the actual `bloch-pos-node` crate build is a
        # follow-up; do not enable this module in a real deploy until
        # `pkgs.blochPos` (or an override of this option) actually resolves
        # to a package containing `bin/bloch-pos`.
      description = "The bloch-pos package to run. See the default's TODO — no dedicated derivation exists yet.";
    };

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/bloch-pos";
      description = "Validator data directory (holds validator.key and chain data).";
    };

    genesisFile = lib.mkOption {
      type = lib.types.path;
      description = "Path to the genesis manifest this node runs (operator-provided — no safe default).";
    };

    transport = lib.mkOption {
      type = lib.types.enum [ "devnet" "libp2p" "dual" ];
      default = "libp2p";
      description = ''
        Matches --transport. Defaults to libp2p here (the production,
        authenticated stack), NOT the node binary's own compiled-in default
        — see crates/bloch-pos-node/src/main.rs and the Round-3 audit's H-2
        finding for why the binary's own default is contested (four in-tree
        comments say `devnet`, the compiled behaviour is `Dual` on
        0.0.0.0:16400). This module does not inherit that ambiguity: it
        always passes --transport explicitly, so what runs is always exactly
        what this option says, never whatever the binary defaults to today
        or after a future rebuild.
      '';
    };

    rpcPort = lib.mkOption {
      type = lib.types.port;
      default = 16310; # matches the binary's own --rpc-port default
      description = "JSON-RPC port.";
    };

    metricsPort = lib.mkOption {
      type = lib.types.nullOr lib.types.port;
      default = null;
      description = ''
        --metrics-port. null (default) leaves metrics OFF, matching the
        binary's own no-default-port behaviour. Set to enable /health and
        /metrics — see deploy/monitoring/ for the scrape config that expects
        this to be set and bound to loopback.
      '';
    };

    p2pListenPort = lib.mkOption {
      type = lib.types.port;
      default = 16400;
      description = "libp2p TCP listen port (used when transport is libp2p or dual).";
    };

    p2pPeers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "/ip4/203.0.113.7/tcp/16400/p2p/12D3KooW..." ];
      description = "Multiaddrs to dial (--p2p-peer). Empty means bootnodes/dialing is configured some other way.";
    };

    # HIGH-1, same perimeter model as bloch-node.nix: no other egress/ingress
    # control is assumed. libp2p peer traffic legitimately comes from outside
    # loopback (unlike RPC/metrics, which never should), so this option is
    # how an operator states which addresses that traffic is allowed from.
    allowedPeerCIDRs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "203.0.113.0/24" ];
      description = ''
        IPAddressAllow= entries beyond localhost, for the libp2p listen port.
        This list IS the network perimeter for this unit's inbound P2P
        traffic — there is no other firewall assumed. RPC and metrics stay
        loopback-only regardless of this setting (see rpcBindAddress /
        metricsBindAddress below, both fixed to 127.0.0.1 — this module does
        not expose an option to change them, unlike bloch-node.nix's
        rpcBindAddress, because there is no legitimate reason for this
        binary's RPC or metrics to be reachable from anywhere but the host
        itself; anything that needs them remotely should tunnel in, not have
        the node bind wider).
      '';
    };

    memoryMax = lib.mkOption {
      type = lib.types.str;
      default = "75%";
      description = "systemd MemoryMax=. See os/bloch-node.nix's option of the same name for the 2026-08-21 OOM citation this shares.";
    };

    memoryHigh = lib.mkOption {
      type = lib.types.str;
      default = "60%";
      description = "systemd MemoryHigh=.";
    };

    tasksMax = lib.mkOption {
      type = lib.types.int;
      default = 512;
      description = "systemd TasksMax=.";
    };

    # HIGH-1/I-H1: the sealed keystore's passphrase, delivered via systemd
    # LoadCredential — NEVER via Environment= or an env var an operator
    # exports, both of which land in /proc/<pid>/environ, readable by
    # anything with ptrace-adjacent access to this UID (a low bar for a
    # single-purpose service account) and captured whole in a core dump or a
    # process-list snapshot. LoadCredential's file lives under a 0700
    # directory this service's own cgroup exposes at $CREDENTIALS_DIRECTORY,
    # torn down when the unit stops, and never touches the environment block
    # at all.
    keystorePassphraseFile = lib.mkOption {
      type = lib.types.path;
      description = ''
        Path (readable by root, on the HOST filesystem — LoadCredential=
        reads it once at unit start and copies it into the per-unit
        credential store) to a file containing the sealed keystore's
        passphrase. Required — there is no default, because there is no
        safe one.
      '';
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Extra CLI args passed to bloch-pos run.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.bloch-pos = {
      isSystemUser = true;
      group = "bloch-pos";
      home = cfg.dataDir;
    };
    users.groups.bloch-pos = { };

    networking.firewall.allowedTCPPorts =
      lib.mkIf (cfg.transport == "libp2p" || cfg.transport == "dual")
        [ cfg.p2pListenPort ];

    systemd.services.bloch-pos-node = {
      description = "Bloch Genesis-4 proof-of-stake node (bloch-pos)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        # Sealed passphrase via LoadCredential — see keystorePassphraseFile's
        # option doc above. %d expands to $CREDENTIALS_DIRECTORY.
        LoadCredential = [ "keystore-passphrase:${cfg.keystorePassphraseFile}" ];
        Environment = [
          "BLOCH_KEYSTORE_PASSPHRASE_FILE=%d/keystore-passphrase"
        ];

        ExecStart = lib.escapeShellArgs ([
          "${cfg.package}/bin/bloch-pos"
          "run"
          "--data-dir" cfg.dataDir
          "--genesis" cfg.genesisFile
          "--transport" cfg.transport
          "--rpc-bind" "127.0.0.1"
          "--rpc-port" (toString cfg.rpcPort)
        ]
        ++ lib.optionals (cfg.metricsPort != null) [
          "--metrics-bind" "127.0.0.1"
          "--metrics-port" (toString cfg.metricsPort)
        ]
        ++ lib.optionals (cfg.transport == "libp2p" || cfg.transport == "dual") ([
          "--p2p-listen" "/ip4/0.0.0.0/tcp/${toString cfg.p2pListenPort}"
        ] ++ lib.optionals (cfg.p2pPeers != [ ]) [
          "--p2p-peer" (lib.concatStringsSep "," cfg.p2pPeers)
        ])
        ++ cfg.extraArgs);

        User = "bloch-pos";
        Group = "bloch-pos";
        StateDirectory = "bloch-pos";
        Restart = "on-failure";
        RestartSec = 5;

        MemoryMax = cfg.memoryMax;
        MemoryHigh = cfg.memoryHigh;
        TasksMax = cfg.tasksMax;
        LimitNOFILE = 8192;

        # HIGH-1: this allowlist IS the perimeter. Loopback always allowed
        # (RPC/metrics need it); libp2p peer traffic needs allowedPeerCIDRs
        # filled in by the operator, or this node cannot be dialed by anyone.
        IPAddressDeny = "any";
        IPAddressAllow = [ "localhost" ] ++ cfg.allowedPeerCIDRs;

        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ReadWritePaths = [ cfg.dataDir ];
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
        CapabilityBoundingSet = [ ];
        UMask = "0077";
        LimitCORE = 0;
      };
    };
  };
}
