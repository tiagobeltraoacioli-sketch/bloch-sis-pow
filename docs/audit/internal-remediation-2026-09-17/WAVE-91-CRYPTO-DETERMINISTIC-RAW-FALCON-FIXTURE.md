# Wave 91 — deterministic canonical-raw Falcon fixture

Date: 2026-09-19
Comparison base: `2987e02`

## Flake addressed

`canonical_raw_verifier_rejects_padded_falcon_half_without_sniffing` built a
fresh ML-DSA/Falcon keypair and signature with normal randomness. Falcon's
compact encoding has variable length. Occasionally the generated signature
already occupied the padded-form length, so the fixture precondition
`sig.len() < padded_len` failed before either production verifier ran. Wave 90
observed that failure in the full suite and an immediate focused rerun passed.

## Test-only correction

The raw-format test now reuses the exact deterministic inputs already pinned by
the adjacent enveloped-format test:

- key generation seed `[0x58; 32]`;
- signing RNG seed `[0xA5; 32]`; and
- message `b"canonical-enveloped-format"`.

It generates the ordinary suite-enveloped key/signature, uses
`split_envelope` to obtain read-only raw bodies and asserts that both suite IDs
are exactly `SUITE_MLDSA65_FALCON1024` before copying the test fixtures. Every
existing behavioral assertion remains intact: the compact signature must
leave padding room, the compatibility raw verifier accepts the padded form,
the canonical raw verifier rejects it, envelope/raw confusion is rejected and
a different message fails.

Only `#[cfg(test)]` code changed. Production signing remains randomized; no
verifier, API, key, signature, wire format or compatibility policy changed.

## Validation

```text
for i in {1..20}; do
  cargo test -p bloch-crypto --lib \
    crypto::kat::canonical_raw_verifier_rejects_padded_falcon_half_without_sniffing \
    --offline -- --exact --quiet || exit 1
done
# 20 processes passed; each 1 passed, 212 filtered out

cargo test -p bloch-crypto --lib \
  crypto::kat::canonical_enveloped_verifier_rejects_padded_falcon_half \
  --offline -- --exact --nocapture
# 1 passed; 0 failed; 212 filtered out

cargo test -p bloch-crypto --offline
# library: 211 passed; 0 failed; 2 ignored
# integration: 6 passed; 0 failed
# documentation: 2 ignored
# total: 217 passed; 0 failed; 4 ignored
```

The complete suite ran outside the restricted sandbox so its HTTP tests could
bind loopback sockets. Compiler output contained only the existing workspace
profile/patch warnings.

## Residual boundary

The fixture intentionally depends on the repository's scoped deterministic RNG
test seam and current ML-DSA/Falcon backend. A reviewed backend upgrade may
legitimately change the pinned deterministic bytes or compact length and
require a fixture update. This correction does not make production Falcon
signatures deterministic and does not weaken canonical encoding checks.
