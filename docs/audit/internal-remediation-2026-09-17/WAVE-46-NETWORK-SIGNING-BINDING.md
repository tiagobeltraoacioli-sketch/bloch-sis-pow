# Wave 46: unarmed genesis-bound signing candidates

Date: 2026-09-18. Branch: `codex/audit-network-binding`. Starting point:
`436c2ef`. Scope: inactive signing-root candidates, focused tests, registry
documentation, and audit evidence. No activation constant, live consensus
rule, deployed node, public network, validator key, or funds were changed.

## Recovered source detail

The itemized findings were recovered from repository commit `a79c88b`:

- A1 `TX-04`: the inert spend-binding gate folded a compile-time
  `BLCH4:GENESIS-4:MAINNET` label. Devnets and forks built from the same source
  therefore shared it, unlike funded admission's manifest-derived domain.
- A2 `FC-10`: `DS_ATTEST` and `DS_PROPOSE` roots contained no network or
  genesis identity. Cross-network ordinary duties could become slashable pairs
  if evidence later activates.
- A3 `ST-07`: the same omission makes reused validator secrets produce valid
  evidence across mainnet, devnets, rehearsals, or chain splits. The existing
  distinct-key warning covered exits, not every duty.

The live tree already carries `admission_network_domain`, the canonical genesis
manifest digest, as immutable `CommittedState` context, but deliberately leaves
it outside the historical state-root encoding. Local slashing-protection files
also bind their records to a genesis digest, but that protects one database and
does not prevent the same secret from being used with independent data directories.
`SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH` was already `u64::MAX`; no equivalent
validator-duty candidate existed.

## Candidate changes

### Transaction spend roots (`TX-04`)

`checked_signing_root_for_network` preserves the historical
`spend_signing_root` below the existing inert gate, including for historical
states that predate a network domain. With the rehearsal gate open it folds
`DS_SPEND2 || admission_network_domain || spend_signing_root` and returns no
root when the judging state lacks the domain.

Both V1 and V2 consensus verification and the production mempool door use this
state-derived candidate. The source-tree `network_binding()` label and old
`checked_signing_root(epoch)` API remain for source compatibility but are not
the consensus verification path. This makes an accidental future activation
fail closed rather than silently treating same-source networks as identical.

### Validator-duty roots (`FC-10`, `ST-07`)

`DS_NETSIG2` is a distinct 16-byte domain. Candidate methods fold it with the
genesis-manifest domain and the historical role-specific root:

```text
SHA3-256(DS_NETSIG2 || admission_network_domain || DS_ATTEST-root)
SHA3-256(DS_NETSIG2 || admission_network_domain || DS_PROPOSE-root)
```

The nested roots retain attestation/proposal separation. The historical methods
are unchanged. `VALIDATOR_NETWORK_BINDING_ACTIVATION_EPOCH` is pinned to
`u64::MAX`, and production signing, verification, gossip keys, pending-vote
state, and slashing evidence deliberately do not select the candidate yet.

`DS_NETSIG2` is registered in `DOMAIN_TAGS`, the independent frozen registry,
and the normative protocol table. Those registries now contain 16 distinct
domains.

## Why all three remain unarmed

Activation must be one coordinated protocol change. Before naming an epoch it
still requires:

1. migrate validator signing, block/attestation validation, gossip identity,
   pending-vote state and both slashing-evidence verification paths together;
2. migrate every wallet and offline signer to accept the canonical genesis
   domain and define treatment of transactions signed before the spend flag day;
3. prove historical replay, activation-boundary and mixed-binary partition
   behavior on production-scale state;
4. define chain-split evidence policy and ensure evidence from another genesis
   is rejected rather than interpreted as local equivocation;
5. update keystore/devnet operations so reuse is refused or unmistakably
   warned, then obtain fleet and release approval.

No item above is authorized or performed by this wave.

## Validation

- Candidate attestation/proposal cross-genesis tests: 2 passed.
- Spend binding tests: 6 passed, covering the inert tripwire, historical root,
  two-domain separation, and real verification with the rehearsal gate open.
- Missing-domain replay/fail-closed test: passed.
- `cargo test --locked -p bloch-pos-node admission_authorisation::a_correctly_signed_transfer_is_still_admitted`:
  passed.
- `cargo test --locked -p bloch-pos-committee --test wire_tag_registry`: 9
  passed.
- The unfiltered committee invocation passed 440 unit tests with 4
  intentionally ignored, including the slow state-root cost bound, before an
  independent registry-count guard exposed the newly allocated domain. After
  updating that guard, `cargo test --locked -p bloch-pos-committee -- --skip
  a_small_update_costs_a_bounded_number_of_node_hashes` passed every selected
  unit, integration and doc-test target; the single skipped cost test had
  already passed in the unfiltered run.
- `git diff --check`: passed.

## Ledger result

This branch's 200-row ledger moves FC-10, ST-07 and TX-04 from open to unarmed
candidate: 71 implemented, 92 partial, 6 unarmed candidates, 4 protocol
decisions, 7 base changed, 17 open, 1 refuted in audit, and 2 verified
positives. These counts are branch-relative and must be recomputed when merged
with concurrent Wave 45/46 work.
