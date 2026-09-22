# Wave 207 — CR-07 short-lived HD-address load plaintext

Date: 2026-09-19
Base: `c8286491`

## Finding

`HdWallet::load_internal` already decrypted each per-address ciphertext into a
`Zeroizing<Vec<u8>>`, and borrowed ordinary JSON strings from that owner.
However, the plaintext owner and parsed view remained live while the loader
recomputed and compared the address and, for derived records, regenerated the
keypair from the wallet seed. Waves 187 and 199 shortened the analogous HD
mnemonic and legacy-keyfile lifetimes; neither covered this per-address HD
plaintext.

## Correction

A private `decode_keypair_plaintext` helper now consumes the authenticated
zeroizing plaintext, parses the existing borrowed payload, decodes both keys,
then explicitly drops the parsed view and plaintext before returning. The
caller retains only the decoded private key under `Zeroizing<Vec<u8>>` and the
public key when address authentication and the derived-key comparison resume.

The helper preserves canonical borrowed strings and the historical escaped
JSON compatibility path, whose `Cow::Owned` strings already wipe on drop.
Parse-error context still includes the address index, and hex errors are
unchanged. AES-GCM authentication, JSON schema, hex bytes, address and derived
key checks, import classification, KDF/RNG behavior, public APIs and outputs
are unchanged.

## Regression coverage

`authenticated_keypair_decoder_consumes_zeroizing_plaintext_and_preserves_shapes`
pins the consuming function signature, protected private-key return type,
canonical and escaped JSON bytes, live explicit wipe behavior, and indexed
parse-error prefix. Existing focused tests cover authenticated roundtrip,
derived/imported behavior and borrowed/escaped payload compatibility.

Validation:

```text
cargo test -p bloch-crypto --features wallet-cli \
  authenticated_keypair_decoder_consumes_zeroizing_plaintext_and_preserves_shapes --offline
# 1 passed; 0 failed; 248 filtered out; remaining targets 0 tests

cargo test -p bloch-crypto --features wallet-cli create_save_load_roundtrip --offline
cargo test -p bloch-crypto --features wallet-cli \
  load_authenticates_derived_index_and_private_key_but_preserves_imports --offline
cargo test -p bloch-crypto --features wallet-cli \
  decrypted_secret_strings_borrow_plaintext_and_preserve_escaped_json --offline
# each focus: 1 passed; 0 failed; 248 filtered out; remaining targets 0 tests

cargo test -p bloch-crypto --features wallet-cli --offline
# unrestricted: library 247 passed; 0 failed; 2 ignored
# integrations 6 passed; 0 failed; doc tests 0 failed; 2 ignored
# aggregate 253 passed; 0 failed; 4 ignored
```

The restricted full run reached `244 passed; 3 failed; 2 ignored`; all three
failures were unchanged localhost HTTP fixtures rejected at
`TcpListener::bind` with `EPERM`. The unrestricted rerun above passed those
fixtures.

## Boundary and residuals

This is a structural lifetime reduction for one repository-owned plaintext
allocation per loaded address. It does not inspect memory after `Drop` or claim
measured heap, RSS, latency or cryptographic-work savings. The plaintext must
remain live through authenticated decryption, Serde parsing and both hex
decodes. The decoded private key necessarily survives in the returned wallet;
the mnemonic, seed and master key retain their existing required lifetimes.
Caller-owned credentials and inputs, file/ciphertext/Base64/Serde allocations,
AES/KDF/derivation backend state, allocator/compiler/register copies, process
aborts and external copies remain outside this Rust RAII guarantee. `CR-07`
remains `PARTIAL`.
