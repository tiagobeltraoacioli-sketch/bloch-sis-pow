# Wave 90 — CR-07 zeroize mnemonic generation entropy

Date: 2026-09-19
Comparison base: `18da009`

## Residual addressed

`SeedPhrase::generate` filled a repository-owned `[u8; 32]` with the OS CSPRNG
and borrowed it to `bip39::Mnemonic::from_entropy`. The array then remained an
ordinary stack owner until the function returned. It had no explicit wiping
contract despite containing the complete 256 bits from which the new wallet's
24-word mnemonic is derived.

A repository-wide consumer search found one production call to
`SeedPhrase::generate`, in `Wallet::generate`; the other three calls are tests.
Because the residual was inside the public generation API, the same ownership
gap also applied to external callers without depending on their behavior.

## Change and compatibility

A private `fresh_entropy` helper now creates `Zeroizing<[u8; 32]>` and lets
the same OS RNG fill that final array in place. `SeedPhrase::generate` borrows
the exact slice for `Mnemonic::from_entropy`, then explicitly drops the entropy
owner before converting the mnemonic to its canonical phrase string. There is
no entropy clone.

The public API, RNG source, 256-bit entropy length, BIP39 English mnemonic,
24-word output, checksum, normalization and later PBKDF2 derivation are
unchanged. Generated phrases remain intentionally nondeterministic; the
existing deterministic BIP39/PBKDF2 vectors pin compatibility downstream of
the random input.

## Validation

```text
cargo test -p bloch-crypto \
  fresh_entropy_has_zeroizing_ownership_and_wipes_while_live \
  --offline -- --nocapture
# 1 passed; 0 failed; 212 filtered out

cargo test -p bloch-crypto wallet::seed::tests \
  --offline -- --nocapture
# 13 passed; 0 failed; 200 filtered out

cargo test -p bloch-crypto \
  wallet::tests::generate_produces_valid_address \
  --offline -- --nocapture
# 1 passed; 0 failed; 212 filtered out

cargo test -p bloch-crypto --offline
# library: 210 passed; 1 failed; 2 ignored
# failure: unrelated nondeterministic Falcon padding fixture asserted that its
# generated compact signature left padding room; integration/docs did not run

cargo test -p bloch-crypto \
  crypto::kat::canonical_raw_verifier_rejects_padded_falcon_half_without_sniffing \
  --offline -- --exact --nocapture
# focused classification rerun: 1 passed; 0 failed; 212 filtered out
```

The single complete-suite attempt ran outside the sandbox so its HTTP tests
could bind loopback sockets. All Wave 90 and HTTP tests passed. The unrelated
Falcon fixture failed its random compact-length precondition in that run and
passed on the one authorized focused rerun; the full command was not repeated,
so this report does not claim a wholly green complete-suite invocation.

The focused regression proves the helper's owner has drop behavior, the exact
32-byte shape and explicit zeroization while live. It does not inspect memory
after `Drop`.

## Residual boundary

CR-07 remains `PARTIAL`. This change owns only the repository's generation
array. It does not claim to erase OS/RNG internals, `bip39::Mnemonic` backend
state, the returned zeroizing `SeedPhrase`, allocator/compiler/register copies,
PBKDF2/key-generation internals, public seed-return arrays or caller-owned
outputs.
