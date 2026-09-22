# Internal audit remediation, vault continuation — 2026-09-18

Base: `45ae11e`, branch `codex/audit-crypto-vault`. This wave changes local
construction APIs and tests only. It does not activate a product, alter Bitcoin
or Bloch consensus, move funds, deploy a service, or contact a public network.

## Checked builders without compatibility drift

Commit `e04f354` adds opt-in checked unvault, delayed-spend and clawback
builders. They reject null funding references, values above Bitcoin's monetary
range, fee subtraction underflow, dust outputs and fees above the existing API's
conservative ten-percent limit. New unvault and delayed-spend construction also
requires compressed, distinct hot/recovery keys and a delay of at least 144
blocks. A fallible P2WSH sighash helper refuses an absent input index.

The historical builders were not changed. A compatibility regression pins their
existing zero-delay, null-outpoint and saturating-subtraction behavior so funded
legacy recovery does not silently acquire a different transaction encoding.
`SeparatedDepositV1` delegates its existing validation to the shared checked
path while preserving its public return type.

## API fail-closed adoption

Commit `e21ace6` makes every shield transaction route use the checked builders
and fallible sighash path. Address/parameter construction also rejects identical
hot and recovery keys. An adversarial route regression covers a null outpoint,
dust, excessive fee and value above `MAX_MONEY`, plus a valid case.

This advances BV-05, BV-08, BV-19 and the panic-robustness part of CR-07. All
remain partial: fee estimation and fee ladders are absent, legacy low-level APIs
remain intentionally unchecked, and none of these validations solves covenant,
key-deletion, watchtower authorization or anchor-finality design gaps.

## Validation

- `cargo test -p bloch-pq-vault`: 34 passed, 0 failed.
- `cargo test --manifest-path services/pq-shield-api/Cargo.toml`: 18 passed,
  0 failed; binary and documentation targets also passed with zero tests.
- `git diff --check`: clean after each implementation commit.
