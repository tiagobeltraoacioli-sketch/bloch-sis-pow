# PoS service configuration follow-up — 2026-09-17

The module now requires explicit `package` and `transport` values. It no longer
falls back to a legacy proof-of-work package that lacks `bin/bloch-pos`, or
silently selects libp2p for peers that may only speak the devnet mesh.

Existing configurations relying on these defaults must be updated before
evaluation. Select a reviewed package containing `bin/bloch-pos` and the actual
transport used by the intended peers. The node binary's current default is
devnet; that does not establish what every deployed validator runs.

For devnet or dual mode, set `meshListenPort` and `meshPeers` (`host:port`
strings). The module emits `--listen`, `--listen-addr` and `--peers`. For libp2p
or dual mode it emits the existing `p2pListenPort`/`p2pPeers` options. Dual mode
requires different ports. The host firewall exposes the selected P2P ports;
the existing `allowedPeerCIDRs` service perimeter must still permit the peers.
RPC and metrics remain bound to loopback.

No Nix evaluator is available in this local environment. Source review against
the actual CLI is not a NixOS deployment qualification. Evaluate the module
with the target nixpkgs revision, inspect the generated unit and run an isolated
observer before deploying. No live configuration was changed by this patch.
