# Wave 107 — CR-06 explicit CLI disclosure convention

Date: 2026-09-19
Comparison base: `308d6b6`

## Residual addressed

The disclosure API already exposes the two incompatible index-zero families
through `DisclosureKeyConvention`, but the repository's sole production
bundle-creation caller still selected the historical single-key convention
indirectly through the public compatibility wrapper
`DisclosureBundle::create`. The `postern-wallet disclose` command documents
index zero as the base wallet key, so its intended family is unambiguously
`SingleKeyWallet`.

A repository-wide search found one production `DisclosureBundle::create`
caller, in `Cmd::Disclose`; the remaining calls are regressions. HD-v3's
existing regression already calls `create_with_convention` explicitly.

## Change and compatibility

The CLI now pins its product policy in a private
`CLI_DISCLOSURE_KEY_CONVENTION` constant and passes that value to
`DisclosureBundle::create_with_convention`. The public `create` wrapper and
both public convention APIs are unchanged.

The previous wrapper delegates to this exact `SingleKeyWallet` convention, so
the CLI's index derivation, public/secret keys, addresses, signatures, bundle
schema and canonical digest are unchanged. This does not change a public API,
format, KDF, RNG, consensus rule or dependency.

## Validation

```text
cargo test -p bloch-crypto --features wallet-cli \
  cli_disclosure_uses_explicit_single_key_convention \
  --offline -- --nocapture
# 1 passed; 0 failed; 224 filtered out

cargo test -p bloch-crypto --features wallet-cli \
  wallet::cli::audit_cli_input_tests --offline -- --nocapture
# 9 passed; 0 failed; 216 filtered out

cargo test -p bloch-crypto --features wallet-cli \
  wallet::disclosure::tests --offline -- --nocapture
# 12 passed; 0 failed; 213 filtered out

cargo check -p bloch-crypto --no-default-features --features wallet-cli \
  --bin postern-wallet --offline
# passed

cargo test -p bloch-crypto --features wallet-cli --offline
# library: 223 passed; 0 failed; 2 ignored
# wallet binary: 0 tests
# integration: 6 passed; 0 failed
# documentation: 2 ignored
# total: 229 passed; 0 failed; 4 ignored
```

The complete suite ran outside the restricted sandbox so its HTTP tests could
bind loopback sockets. Compiler output contained only the existing workspace
profile/patch warnings.

The focused regression pins the private policy constant. With a fixed seed it
proves that index zero produces the exact base-wallet public key and differs
from HD-v3, while a nonzero index produces identical public-key derivation
under both conventions. It does not make a separate address-equality claim.

## Residual boundary

CR-06 remains `PARTIAL`. This correction makes the repository's existing CLI
consumer explicit; it does not add an HD-v3 selector to that CLI, encode a
derivation family in the disclosure bundle, let verification infer common-seed
origin, or force external API consumers to select the correct family.
