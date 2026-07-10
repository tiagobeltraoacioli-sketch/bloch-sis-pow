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

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the RPC port in the firewall (LAN exposure — off by default).";
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
        ] ++ lib.optional cfg.mine "--mine" ++ cfg.extraArgs);

        User = "bloch";
        Group = "bloch";
        StateDirectory = "bloch";
        Restart = "on-failure";
        RestartSec = 5;

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
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
        UMask = "0077";
        # No core dumps (matches the container entrypoint ulimit -c 0).
        LimitCORE = 0;
      };
    };
  };
}
