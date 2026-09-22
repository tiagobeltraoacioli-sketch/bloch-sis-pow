# Wave 148 — CR-07 zeroize the HD master-key salt

Date: 2026-09-19
Comparison base: `a58e2ad2`

## Residual addressed

The private HD master-key KDF built its 32-byte salt as an ordinary heap
`Vec<u8>`. For wallet versions 2 and later, that buffer contains the
deterministic SHA3-256 digest of the salt domain and mnemonic. It remained an
ordinary repository-owned allocation until the KDF returned. The version-1
branch used a public constant salt but shared the same unnecessary allocation.

All three production consumers converge on this private KDF: HD-wallet create,
mnemonic recovery and authenticated wallet load.

## Correction and invariants

The private `hd_master_key_salt` helper now allocates the exact 32-byte output
inside `Zeroizing<[u8; 32]>` before finalization. `Sha3_256::finalize_into`
writes directly into that owner, avoiding the previous digest-to-`Vec`
conversion and heap allocation. The owner stays under wiping RAII through the
Argon2 call, including error returns and unwinding.

The version branch and inputs are unchanged: version 1 hashes
`bloch-layer-hd-wallet-v1`; versions 2 and later hash
`bloch-sis/hd-wallet/salt/v2 || mnemonic`. Argon2 receives the same 32 salt
bytes with the same input, algorithm, version, parameters and output length.
No public API, schema, serialized byte, KDF policy, RNG operation or derived
output changes.

## Adversarial coverage

- `master_key_salt_has_exact_zeroizing_ownership_and_stable_bytes` pins the
  helper signature and drop-bearing owner, checks exact version-1 and
  version-3 salt bytes, and exercises explicit live zeroization.
- `master_key_kdf_output_has_zeroizing_ownership_and_stable_bytes` continues
  to pin exact version-1 and version-3 Argon2 outputs.
- The complete HD module covers create, recover, authenticated load, legacy
  version compatibility and save/load round trips.

## Validation

```text
cargo test -p bloch-crypto --offline \
  master_key_salt_has_exact_zeroizing_ownership_and_stable_bytes -- --nocapture
# 1 passed; 0 failed; 226 filtered out

cargo test -p bloch-crypto --offline \
  master_key_kdf_output_has_zeroizing_ownership_and_stable_bytes -- --nocapture
# 1 passed; 0 failed; 226 filtered out

cargo test -p bloch-crypto --offline hd_wallet::
# 29 passed; 0 failed; 198 filtered out

cargo test -p bloch-crypto --features wallet-cli --offline
# 240 passed; 0 failed; 4 ignored
```

The first complete wallet-CLI run inside the sandbox reached 231 passing unit
tests and failed only the three loopback HTTP fixtures at socket bind with
`Operation not permitted`. The single rerun outside the sandbox passed all 234
unit tests plus six integration tests; two unit tests and two doctests remain
intentionally ignored.

## Residual boundary

- This change wipes the repository-owned final salt buffer. It does not claim
  to wipe the caller's mnemonic or password, nor internal SHA3 or Argon2
  backend state.
- The version-1 salt is public; the sensitive derived-value hardening applies
  to the mnemonic-bound version-2-and-later branch.
- Allocator/compiler/register copies and aborts that skip destructors remain
  outside the claim. No post-`Drop` memory observation is claimed; ownership
  type plus explicit live zeroization are the structural evidence.
