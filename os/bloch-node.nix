# NixOS module: run the Bloch-SIS node as a hardened systemd service.
# Enable on any NixOS host with `services.bloch.enable = true;`.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.bloch;
in
{
  options.services.bloch = {
    enable = lib.mkEnableOption "the Bloch-SIS node";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.bloch or (pkgs.callPackage ./package.nix { });
      description = "The bloch package to run.";
    };

    mine = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Run the node as a miner (Module-SIS PoW).";
    };

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/bloch";
      description = "Node data directory.";
    };

    rpcPort = lib.mkOption {
      type = lib.types.port;
      default = 8645;
      description = "JSON-RPC port.";
    };

    # MED-6: fixed, safe default bind. Previously no --rpc-bind was passed at
    # all, so the port bound whatever the node binary itself defaults to.
    # Loopback unless openFirewall is explicitly set, matching the same
    # reasoning bloch-pos-node/src/main.rs applies to its own RPC listener
    # ("a routable bind is a deliberate act plus a firewall").
    rpcBindAddress = lib.mkOption {
      type = lib.types.str;
      default = if cfg.openFirewall then "0.0.0.0" else "127.0.0.1";
      defaultText = lib.literalExpression ''if cfg.openFirewall then "0.0.0.0" else "127.0.0.1"'';
      description = "Address the JSON-RPC listener binds. Defaults to loopback unless openFirewall is set.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the RPC port in the firewall (LAN exposure — off by default).";
    };

    # HIGH-1: the node has no egress control today. IPAddressDeny=any plus
    # this allowlist IS the perimeter — there is no other firewall boundary
    # assumed around this unit. An empty list means only loopback traffic and
    # anything the kernel itself needs (DNS/NTP are NOT auto-allowed; add
    # them explicitly here if this host's node needs outbound peers beyond
    # loopback, e.g. a devnet/libp2p transport dialing out).
    allowedPeerCIDRs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "203.0.113.0/24" "198.51.100.7/32" ];
      description = ''
        Additional IPAddressAllow= entries (CIDRs or single addresses) beyond
        localhost. This list IS the network perimeter for this unit — there
        is no other firewall assumed. Left empty by default (loopback-only);
        the operator must fill it in for any host that needs to dial or
        accept from specific peers.
      '';
    };

    memoryMax = lib.mkOption {
      type = lib.types.str;
      default = "75%";
      description = ''
        systemd MemoryMax=. 2026-08-21 incident: 22 validators OOM-killed at
        7.9 GB on 8 GB machines when 60 peers answered a get-blocks burst at
        once during replay (Annex-R6). A cgroup limit turns "the kernel
        OOM-killer picks a victim on the box" into "this service restarts,
        everything else on the host survives".
      '';
    };

    memoryHigh = lib.mkOption {
      type = lib.types.str;
      default = "60%";
      description = "systemd MemoryHigh= — soft throttle before MemoryMax kills.";
    };

    tasksMax = lib.mkOption {
      type = lib.types.int;
      default = 512;
      description = "systemd TasksMax= — bounds thread/process explosion under load.";
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Extra CLI args passed to the node.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.bloch = {
      isSystemUser = true;
      group = "bloch";
      home = cfg.dataDir;
    };
    users.groups.bloch = { };

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.rpcPort ];

    systemd.services.bloch = {
      description = "Bloch-SIS node";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        ExecStart = lib.escapeShellArgs ([
          "${cfg.package}/bin/bloch"
          "--data-dir" cfg.dataDir
          "--rpc-port" (toString cfg.rpcPort)
          "--rpc-bind" cfg.rpcBindAddress
        ] ++ lib.optional cfg.mine "--mine" ++ cfg.extraArgs);

        User = "bloch";
        Group = "bloch";
        StateDirectory = "bloch";
        Restart = "on-failure";
        RestartSec = 5;

        # HIGH-2/MED-1: resource containment (2026-08-21 OOM incident — see
        # the memoryMax option doc above for the citation).
        MemoryMax = cfg.memoryMax;
        MemoryHigh = cfg.memoryHigh;
        TasksMax = cfg.tasksMax;
        LimitNOFILE = 8192;

        # HIGH-1: no other egress/ingress control exists for this unit — this
        # allowlist IS the perimeter, not a supplement to one. Loopback is
        # always allowed; allowedPeerCIDRs is the operator-filled extension.
        IPAddressDeny = "any";
        IPAddressAllow = [ "localhost" ] ++ cfg.allowedPeerCIDRs;

        # L2-style hardening (mirrors deploy/hardening): least privilege.
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
        # ProtectProc=invisible + ProcSubset=pid: this process cannot see any
        # other process's /proc entry at all, not even that it exists — closes
        # the BLOCH_KEYSTORE_PASSPHRASE-in-/proc/<pid>/environ exposure class
        # for every OTHER process on the host reading THIS one, and vice versa.
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
        # No capabilities at all — this is a plain user-space TCP/RPC service,
        # not anything that ever needs to bind <1024, trace, or touch devices.
        CapabilityBoundingSet = [ ];
        UMask = "0077";
        # No core dumps (matches the container entrypoint ulimit -c 0).
        LimitCORE = 0;
      };
    };
  };
}
