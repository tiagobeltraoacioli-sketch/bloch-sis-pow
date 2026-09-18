# Wave 45: mainnet manifest-input tripwires

Date: 2026-09-18. Base: `95e9e20`. Scope: local source, tests, and audit
ledger only. No manifest, state-root encoding, activation rule, node,
validator, release, or deployed configuration was changed.

## Finding

ST-11 records that `admission_network_domain` and `genesis_principal_sat` are
immutable, manifest-derived consensus inputs that historical state roots do
not commit. The network domain is SHA3-256 over the canonical encoded manifest;
the principal map is derived from the launch validator records. A manifest
encoding or construction change could therefore alter later funded-deposit or
withdrawal behavior without introducing a new state-root component.

Committing these fields now would itself change consensus roots and requires a
versioned activation and mixed-binary replay plan. This wave adds a safe
release tripwire without changing accepted blocks.

## Remediation

The existing live-mainnet manifest regression now pins:

- the exact 32-byte admission domain
  `f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966`;
- the 64-record validator count; and
- the checked sum of the launch principal at 1,600,000 BLCH.

The assertions derive both values from the decoded, re-encoded published
manifest. Format drift, a changed validator set, or changed launch stakes now
fails the node test before release.

ST-11 moves from open to partial. The tripwire detects accidental changes but
does not make either input part of historical state roots. Closing the finding
still requires a specified commitment/versioning rule, historical replay
proof, and coordinated mixed-version activation.

## Validation

`cargo test -p bloch-pos-node --bin bloch-pos the_live_mainnet_manifest_still_decodes --offline`
passed with one matching test. Existing workspace warnings remain unrelated to
this change. `git diff --check` is the scoped whitespace gate.
