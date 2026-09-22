# Wave 78 CR-07: bounded public HD-wallet listing

Base: `9eebe9d`; branch `fix/internal-audit-20260917`.

## Scope decision

Wave 77 bounded the two production paths that decrypt an HD-wallet backup, but
the retained Genesis-3 `bloch-cli addresses` path still used an unbounded
`std::fs::read_to_string`, parsed the entire file and printed every address.
Although this command reads only public metadata, the wallet file is still
attacker-controlled input and its byte and record counts remained an avoidable
memory/output amplification surface.

## Change

`HdWalletFile::read_public_bounded` now provides a safe public-metadata reader
using the same ordinary interactive budgets as encrypted restore: 64 MiB and
1,024 address records. `HdWalletFile::read_public_with_limits` exposes explicit
byte and aggregate-record limits for consumers with a reviewed recovery policy.
Both entry points reuse the streaming byte-budget reader and the existing
wallet structural validation before returning parsed metadata.

`bloch-cli addresses` now uses the bounded API by default. The already explicit
`--allow-large-hd-wallet` trusted-backup mode retains compatibility by admitting
up to the absolute 512 MiB file ceiling without the new record-count cap. The
ordinary failure points operators to that explicit recovery mode. No encrypted
payload, KDF, key derivation, file schema, consensus or wire format changed.

## Adversarial regression

The library regression constructs an authentic-shaped public wallet at exactly
1,024 address records and proves that both the default policy and an exact-byte
custom budget accept it. One byte below the actual size fails in the bounded
reader, and the 1,025th unique address fails the aggregate-record check.

The CLI regression proves the production caller rejects 1,025 records and
includes the trusted-backup remediation hint, while the explicit override
accepts the same historical-shaped file.

## Validation

- `cargo test -p bloch-crypto public_metadata_reader_accepts_exact_bounds_and_rejects_each_excess --offline`: focused regression passed.
- `cargo test -p bloch --bin bloch-cli --offline`: 3 passed, 0 failed.
- `cargo test -p bloch-crypto --offline`: library 198 passed, 0 failed, 2 ignored; integration tests 6 passed, 0 failed; doc tests 2 ignored. The successful run was outside the filesystem sandbox because three HTTP tests bind loopback sockets.
- `git diff --check` on the two Rust files and this report: passed.

## Residual risk

CR-07 remains `PARTIAL`. The repository's production HD-wallet decrypt and
public-listing callers are now bounded by default, but external consumers can
still select compatibility APIs, and the explicit trusted-backup override
accepts substantially more input by design. JSON allocation occurs after a
streaming byte bound but before the post-parse record-count check. Historical
load authentication and opaque backend/register or caller-owned secret copies
remain outside this correction.
