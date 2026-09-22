# Internal audit remediation, thirty-third wave — 2026-09-18

Base: `2f32785`; branch `fix/internal-audit-20260917`. This wave reconciles
controls implemented in earlier waves; it does not claim transport
authentication or a fleet topology change.

## Observer frame-push position

NET-12 correctly identifies an architectural fact of the legacy devnet mesh:
an allowlisted observer/bootnode can deliver frames to the validator fleet, the
transport carries no cryptographic peer identity or original-message origin,
and compromise of that host remains a liveness position.

The ledger's generic open status no longer reflected the controls now present:

- per-source count and byte reservations are acquired before the first
  engine-facing queue, preserve headroom for other sources and remain charged
  across forwarding/cloning;
- inbound connections and sync serving have normalized per-IP plus global
  limits, and sync pages have an aggregate byte ceiling;
- exact failed cryptographic inputs avoid repeated verification, while static
  rejection logs are rate-limited and counted;
- proposal admission authenticates the signed header before attacker-sized
  body hashing/decoding;
- the attested-image configuration restricts SSH, and the external bootnode
  verifier fails if a published host exposes any known RPC port.

The five source-budget regressions pass again, including NAT/mapped-IPv6,
reconnect, aggregate-table bounds and honest-source headroom. The external RPC
refusal self-test passes in both directions.

NET-12 therefore moves to partial, not implemented. None of these controls
authenticates the devnet transport, carries end-to-end origin, proves current
firewall allowlists, prevents a compromised allowed host from consuming its
legitimate allowance, or supplies peer penalties. The ledger retains all 200
rows: 66 implemented, 81 partial, 39 open, seven base-changed, four protocol
decisions, one unarmed candidate, one refuted by the original audit and one
verified positive.
