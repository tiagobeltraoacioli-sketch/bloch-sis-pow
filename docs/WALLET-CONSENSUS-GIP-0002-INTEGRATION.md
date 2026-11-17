# GIP-0002 (WT-03, WT-04): integration record

Branch: `codex/wallet-consensus-20261117` (local only, never pushed).
Base: `4f95205c` (release-candidate line).
Design: `gips/GIP-0002.md`.

**Every activation constant this branch adds or touches is `u64::MAX`
(inert).** Nothing is armed, scheduled, packaged or deployed. Arming is the
owner's decision (§5).

## 1. What the branch contains

| Finding | Change | Gates (all `u64::MAX`) |
| --- | --- | --- |
| WT-03: transfers are not bound to a network | A dual-acceptance window in front of the existing network-bound signing root: from the acceptance epoch a transfer may be signed over `SHA3-256(DS_SPEND2 ‖ genesis-manifest digest ‖ spend root)`, from the enforcement epoch it must be. | `SIGHASH_NETWORK_BINDING_ACCEPT_EPOCH` (new), `SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH` (existing, now the enforcement end) |
| WT-04: delegations do not pin the commission | `FundedDelegateV2` (tag `0x1C`): the `FundedDelegate` intent plus a signed `max_commission_bps`, refused when the validator's commission is above it at admission. | `DELEGATION_COMMISSION_CAP_ACCEPT_EPOCH`, `DELEGATION_COMMISSION_CAP_ENFORCE_EPOCH` (both new) |

No committed state is added: no state-root component, no local-cache
section. The one new wire tag is recorded in `wire_alloc.rs`,
`tests/wire_tag_registry.rs` and `docs/WIRE-NAMESPACE-REGISTRY.md`.

## 2. Unset means unchanged

With the four constants at `u64::MAX`:

- every test that existed on `4f95205c` passes without modification of its
  expectations (§4), including every pinned signing root and state root and
  `transition::tests::hf_gates_leave_transfers_byte_identical`;
- `with_the_window_unset_only_the_legacy_root_exists`: the legacy root is the
  only root at every epoch, with or without a network domain;
- `with_the_window_unset_the_verifier_sees_the_historical_call_sequence`: the
  transition asks the verifier the same questions in the same order as the
  loop it replaced, and stops at the same witness;
- `the_capless_request_keeps_its_bytes_and_its_signing_root`: the `0x0E`
  intent, root, size reservation and wire bytes, rebuilt field by field
  without the encoder;
- `with_the_cap_window_unset_only_the_capless_request_is_valid`: tag `0x1C` is
  refused without touching state, and a `0x0E` request produces the same
  post-state with the window unset and with it armed at a later epoch;
- node: `with_the_window_unset_admission_is_the_historical_rule` (same
  verdicts, one verification per input, no trial) and
  `transaction_rules_are_inert_in_this_build`.

The existing tests whose source changed did so only to keep compiling or to
record the new tag: `wire_alloc.rs` (`NEXT_FREE` is `0x1D`, table length
`0x1C`), `tests/wire_tag_registry.rs` (row and variant arm for `0x1C`),
`validator_payout.rs` (a new `None` field in one fixture), and two inert-value
pins that are skipped under the rehearsal feature.

## 3. Rehearsal build

```
BLOCH_WALLET_CONSENSUS_ACCEPT_EPOCH=<A> BLOCH_WALLET_CONSENSUS_ENFORCE_EPOCH=<E> \
  cargo build --release -p bloch-pos-node --features wallet-consensus-rehearsal
```

arms both windows at `A` and `E` (`A < E`). The epochs are part of
`BLOCH_BUILD_VERSION`; the binary refuses the Genesis-4 mainnet manifest and
any manifest with a carryover. Funded delegation is active from epoch 4669 on
every network, so the delegation half is exercisable only on a development
network past that epoch.

Not done on this branch: a mixed-fleet run of that build on a development
network through both boundaries, and a full-history replay of mainnet. Both
are preconditions for arming (GIP-0002, Activation recommendation).

## 4. Test counts

@@COUNTS@@

## 5. Arming (owner only)

Not executed here. In one release commit:

1. Set the four constants (the non-rehearsal definitions) in
   `crates/bloch-pos-committee/src/params.rs`. The compile-time assertions
   require, per gate, acceptance at least 90 epochs before enforcement, and
   the commission-cap acceptance not before funded delegation.
2. Rewrite the inert pins to the armed values:
   `sighash_network_binding_gate_is_inert` (`transition.rs`),
   `sighash_network_binding_window_is_inert`
   (`transition/wallet_consensus_tests.rs`),
   `delegation_commission_cap_window_is_inert`
   (`transition/funded_delegation/tests.rs`), and in the node
   `transaction_rules_are_inert_in_this_build`, the `getchaininfo` assertions
   in `rpc/tests.rs`, `with_the_window_unset_admission_is_the_historical_rule`
   and `documented_constants_are_what_the_docs_say`.
3. Review the tests that sign transfers at epochs at or above the acceptance
   epoch with the constants armed: fixtures that run at such epochs must sign
   the bound root from the enforcement epoch.
4. Check the release anchor: both acceptance epochs are in
   `GATES_UNARMED_IN_CANONICAL_HISTORY` and must be above it.
5. `cargo test --workspace`, the rehearsal of §3, the full-history replay.

Arming WT-03 changes what a transfer signature must cover. The owner scope
of 2026-10-20 ("nothing that changes how users deposit, transfer or
withdraw") excludes that from a scheduled release until the owner decides
otherwise. Neither gate is in `hard_forks::RELEASE_ARMABLE`.

## 6. Draft release note (for the release that arms the gates)

> **Network-bound transfer signatures and delegation commission caps
> (GIP-0002).** From epoch `A` the network accepts transfers signed over a
> root that includes the network's genesis digest, and delegation requests
> that state the highest validator commission the delegator accepts. From
> epoch `E` it accepts only those. Between the two, both old and new forms
> are valid.
>
> Node operators, indexers and explorers: install this release before epoch
> `A`. Wallets and the delegation signer: update before `A`; they switch on
> their own by reading `getchaininfo.transaction_rules`. Exchanges and
> custodians: sign withdrawals over the network-bound root before `E`.
> Anyone holding a pre-signed, unbroadcast transfer: sign it again before
> `E`; from that epoch the old signature is not valid. Existing delegations
> are not affected. No balance, position or reward changes at either epoch.
