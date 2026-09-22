# Wave 161 — CR-07 reuse the authenticated v2 secret allocation

Date: 2026-09-19
Comparison base: `9a9a20f8`

## Residual addressed

The v2 keyfile loader already decoded and authenticated its ciphertext in
place under `Zeroizing<Vec<u8>>`. After authentication, however, it copied both
the master seed and private key into new vectors while retaining the combined
`[seed length | seed | private key]` plaintext until the function returned.
The private-key allocation and copy were repository-owned and unnecessary.

## Correction and invariants

A private splitter now creates only the independent master-seed owner required
by the existing four-value return API. It moves the private-key bytes to the
front of the authenticated plaintext allocation, overwrites former header/seed
prefix, wipes remaining old logical tail, then truncates and returns that same
allocation as the private-key `Zeroizing<Vec<u8>>` owner.

The v2 public API, tuple order, schema, seed-length bounds, validation order,
Argon2 parameters, AES-256-GCM AAD, nonce/tag behavior, RNG operations, error
variants and output bytes are unchanged. The helper is called only after the
existing authenticated layout and seed-length checks, so its offsets do not
introduce a new untrusted-input panic path.

## Adversarial coverage

- `v2_plaintext_split_reuses_secret_allocation_and_wipes_live_owners` pins the
  exact seed/private-key bytes, zeroizing owner type, explicit live wipe and
  pointer/capacity reuse of the original plaintext allocation.
- `v2_roundtrip_recovers_seed_secret_public_network` retains the encrypted v2
  compatibility path and exact returned seed, private key, public key and
  network.

## Validation

```text
cargo test -p bloch-crypto --offline \
  v2_plaintext_split_reuses_secret_allocation_and_wipes_live_owners -- --nocapture
# 1 passed; 0 failed; 229 filtered out

cargo test -p bloch-crypto --offline \
  v2_roundtrip_recovers_seed_secret_public_network -- --nocapture
# 1 passed; 0 failed; 229 filtered out

cargo test -p bloch-crypto --features wallet-cli --offline
# 243 passed; 0 failed; 4 ignored
```

The first complete run inside the restricted sandbox reached 234 passing unit
tests and the two expected ignores, then failed only when three HTTP fixtures
could not bind loopback sockets (`PermissionDenied`). The single complete run
outside the sandbox passed 237 unit tests, six integration tests and left two
unit tests plus two doctests intentionally ignored.

## Residual boundary

- The master seed and private key necessarily remain separate caller-owned
  return values under the compatibility API; this wave removes only the extra
  private-key allocation and combined-plaintext lifetime.
- JSON and Base64 decoding still allocate before authenticated decryption.
  Argon2/AES/backend state, caller inputs and outputs, allocator/compiler/
  register copies and aborts that skip destructors remain outside the claim.
- No post-`Drop` memory observation is claimed. Pointer/capacity identity and
  explicit live zeroization are structural ownership evidence.

CR-07 remains `PARTIAL`.
