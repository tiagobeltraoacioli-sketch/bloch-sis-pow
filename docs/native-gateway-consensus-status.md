# Dormant canonical federated gateway

The native consensus adapter now accepts bounded sponsored imports (`0x10`) and
withdrawals (`0x11`). Both activation epochs remain `u64::MAX`; there is no live
activation or external custody deployment in this change. Historical transaction
tag assignments are preserved. An all-branch history scan of `transition.rs`
found no previous decoder allocation for either new tag; state-root tags with the
same numeric values belong to a different namespace.

The adapter requires an existing canonical native component and configured route.
It reuses the gateway's issuer, owner and indexed committee authorization and
replay protection. The BLCH sponsor signs the same joint operation digest.
Canonical block price and the five-byte outer frame determine the charge, which
enters ordinary block fee settlement once. Failed execution publishes neither
ledger. Import and withdrawal tags cannot carry the opposite operation.

An import credits the configured native asset against a committee-attested
source transaction, source block, event index and deposit. The existing engine
checks route/nonce and source-event uniqueness, recipient, amount, cap, expiry,
issuer authorization and quorum. A withdrawal burns existing native outputs and
records a unique ordered release. That release is not an external payment.
Neither operation proves source-chain consensus finality: configured federated
attestations are the explicit existing trust model.

## External inputs still required

No production values or authority keys are supplied by this implementation.
Activation requires independently established and reviewed inputs:

- Native admission domain and asset registration, issuer public key, supply cap,
  module/policy configuration and signed zero-supply registration.
- Source domain, actual token and vault addresses, token decimals, vault deployed
  code hash, native asset ID, liability cap, committee public keys and threshold;
  issuer and committee signatures enabling precisely that route.
- Source observation policy and authenticated canonical/finalized event evidence
  used by those committee operators before they jointly attest an import. The
  current native verifier does not independently verify that external evidence.
- Operational issuer, committee and BLCH sponsor signing services, protected keys,
  funded sponsor UTXOs and coordination on the exact joint authorization digest.
- Actual external vault custody and release authorization, asset backing,
  liquidity, relayer funding and reconciliation of native release records to
  confirmed external transactions. No external settlement is emitted by the
  native release record alone.
- A separately reviewed activation plan and compatible validator fleet. All native
  state, bootstrap, import and withdrawal gates stay disabled by default here.

Tests execute import and withdrawal through complete candidate blocks, wire
replay and inactive-gate rejection; adapter tests cover forged quorum/issuer,
expiry, wrong operation tag, frame fees, duplicate execution, ancestor replay,
restored replay protection and persistent burn/release records.
