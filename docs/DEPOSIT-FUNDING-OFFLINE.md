# Funding a validator deposit with an encrypted legacy wallet

The `sign-deposit-funding` example is an offline adapter for the funding role.
It consumes the existing encrypted wallet JSON without exporting or converting
its private key. Only its human custodian runs signing, privately offline.
There is no network client or broadcast operation in this tool.

Before wallet unlock it validates deposit shape, matches the exact unsigned
intent and independently approved funding root, verifies the validator's
possession signature, and refuses an existing funding signature. After unlock
it requires the wallet public key, with the suite-1 envelope, to match the
funding authority. Both signatures are verified before creating a new output.
Verification tries matching suite envelopes and legacy raw-hybrid objects
explicitly before the historical mixed-format compatibility fallback.
The password file must be a regular owner-only file. Keep it temporary and
remove it immediately after signing. Never put passwords in command arguments.

Build and test with the pinned Rust toolchain:

```sh
cargo +1.94.1 build --offline --locked -p bloch-pos-node --example sign-deposit-funding
DEPOSIT_FUNDING_BIN="$PWD/target/debug/examples/sign-deposit-funding" \
  cargo +1.94.1 test --offline --locked -p bloch-pos-node \
  --example sign-deposit-funding -- --include-ignored
```

The four tests cover intent/signature tampering before unlock, wrong ownership,
both signature roles, a genuine magic-prefixed raw-signature ambiguity, and a
real CLI roundtrip using a disposable encrypted wallet, including wrong
password, unchanged wallet, output overwrite refusal, and password-file
permissions. They do not qualify mainnet withdrawals or production custody.

Read-only verification, without opening a wallet:

```sh
target/debug/examples/sign-deposit-funding --mode verify-partial \
  --tx validator-signed.hex --approved draft.hex --expected-root FUNDING_ROOT
```

Human-only offline signing adds `--mode sign --wallet ENCRYPTED_JSON
--passphrase-file OWNER_ONLY_TEMP_FILE --out signed.hex` to those three inputs.
Use `--mode verify-complete` on the resulting signed transaction.

The human helper installed at `~/bloch-validator-setup/sign-deposit-funding.py`
pins the reviewed binary, partial transaction, unsigned draft and inspector.
It displays the deposit before prompting, verifies the existing signature
before requesting a password, and removes its temporary password file.
`--verify-only` opens only public files. It never transmits a transaction.

Offline checks do not establish current UTXO availability, expiry, fee adequacy,
registration status or finality. Recheck those against synchronized nodes before
submission. The September 15 designated draft expires inclusively at epoch 3016;
if it expires, rebuild and obtain both signatures again.
