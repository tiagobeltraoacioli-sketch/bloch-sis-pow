# Isolated native laboratory signer

This experimental WASI reactor reuses the canonical native pool/withdrawal
codec, `FundingReview`, ownership resolution and real ML-DSA-65 + Falcon-1024
implementation. It does not replace the production wallet core, activate native
consensus gates, access a network, or broadcast. Import/bootstrap/arbitrary-digest
signing are deliberately absent. The public fixture seed is disposable test data.

## Build and verify

Install Rust target `wasm32-wasip1` and an independently verified official
[WASI SDK 33](https://github.com/WebAssembly/wasi-sdk/releases/tag/wasi-sdk-33).
The tested macOS x86_64 SDK archive SHA-256 is
`18f3f201ba9734e6a4455b0b6410690395a55e9ffa9f6f5066f66083a94b93b3`.
The SDK path is explicit because an inherited `CC` can point to absent Homebrew
LLVM. No dependency or C compiler substitution is required.

```sh
WASI_SDK_ROOT=/path/to/wasi-sdk-33.0-x86_64-macos sh tools/native-wallet-wasm/build-wasi.sh
NATIVE_WASM_FIXTURE_PATH=/tmp/native-wasm-fixture.json cargo test --offline -p bloch-native-wallet-wasm --lib
```

The artifact is `target/wasm32-wasip1/release/bloch_native_wallet_wasm.wasm`.
Pin its SHA-256 in the isolated host before instantiation. WASI preview1
`random_get` must use a cryptographic entropy source; there is no random fallback.
The wallet's `browser/native-core.js` and worker consume this ABI separately from
its pinned production `bw_*` core. A real WebKit worker signature was independently
accepted by the Rust paired-custody executor, with both hybrid components verified.
To repeat that cross-check, write the browser-produced signed transaction as raw
hex text and run the test with `NATIVE_WASM_SIGNED_PATH=/tmp/signed.hex`.

## ABI

Exports: `memory`, `nw_alloc(length)`, `nw_free(pointer,length)` and
`nw_call(pointer,length) -> u64`, packed as `pointer << 32 | length`.
Allocation ownership is tracked; input/output buffers must be freed. Requests and
responses are JSON, bounded to 16 MiB; aggregate outstanding buffers to 32 MiB.
The reactor stores one session and one consumable review. `lock` drops the secret
with zeroization; the host must terminate the worker and wipe Wasm memory on
disposal. JSON seed copies are wiped on all dispatch results. Host custody and
protection against compromised same-origin script remain required.

Request: `{"method":"...","args":{...}}`; response:
`{"ok":true,"result":...}` or `{"ok":false,"error":"..."}`.

- `open`: `seedHex` (32 bytes), `domainHex` (32 nonzero bytes). Returns
  `publicKeyHex` and `domainHex`. Keys use canonical hybrid envelope
  `b10c0100`, followed by ML-DSA-65 and Falcon-1024 bytes (3749-byte public key).
  This does **not** claim compatibility with an existing production mnemonic's
  derivation path; seed import is an isolated laboratory custody interface.
- `review`: `transactionHex`, `context`, `height`. Only canonical outer
  NativePool `0x12` and NativeWithdrawal `0x11` are accepted. Review returns
  `id`, `authorization`, `stateRoot`, `publicKeyHex`, `gas`, `feeSat`, `expires`,
  `fundingSats`, `walletOutputsSats`, and exact `packetHex`. Render the typed packet
  and debits, not only its hash/fee. `finalityVerified` is always false.
- `sign`: same transaction/context/height plus `reviewId` and boolean
  `confirmed:true`. Returns `transactionHex` and canonical Rust `txid` (not a raw
  packet hash), allowing a host to journal before broadcast. Rechecks state/account/expiry and
  exact reviewed packet before signing; review is consumed even on refusal.
  Before releasing signed bytes, the full typed executor validates signatures,
  slippage, reserve transitions and gateway roles on an isolated state clone.
  Declared size must also cover the five-byte canonical outer frame.
- `cancel` clears the pending review; `lock` also clears the key session.

All integer fields, including UTXO `vout`, are canonical unsigned decimal strings.
Hex is lowercase, even length, without `0x`. Packet limit is 262144 bytes.
Variable-length Falcon witnesses must have sufficient declared size **before**
review: the fixture reserves the maximum 4593-byte hybrid witness at each owner
slot. Signing never reprices a fee or silently retries an underdeclared packet.

## Context trust boundary

`context` contains `nativeSnapshotHex` (at most 4 MiB),
`nativeCommitmentHex`, `utxos` (at most 4096 entries, each with `txid`, `vout`,
`value`, `scriptHash`), `baseFeeMillisatPerGas`, `blockGasUsed`, `blockTxBytes`
and `epoch`. The snapshot is the canonical `NativeState` component codec with
zero fee escrow. It validates asset/pool/gateway invariants and every custody lock
against the supplied complete BLCH projection. Duplicate UTXOs and invalid
resource/fee bounds are refused. Never truncate an oversized RPC result.

The host must independently authenticate network, head and this context. Matching
caller-supplied roots is **not** finality verification. `wallet_projection::base`
constructs only a review view; its synthetic head and derived root are not a chain
state root and cannot bootstrap or activate a canonical node. A changed projection
invalidates consent. Other owners' inputs are not signed. Locked reserves are
signed only for an explicit same-owner unconverted-pair close or a validated LP
redemption by the actual LP holder; swap reserve slots remain untouched.
Issuer/module/gateway committee witnesses remain untouched and need their own
authorities. Revalidation against live chain state, pending journaling, wallet
backup UX and broadcast integration are separate host work.

Eight real-hybrid vectors cover create pair, close an unconverted pair,
initialize LP, add, swaps in both directions, remove, and withdrawal after a real gateway import.
The gateway fixture uses distinct issuer, committee and wallet keys. Negative
tests refuse changed reserve roots, revisions, slippage, LP owners, active-pool
close, changed context and forged gateway approvals. A separate test signs and
executes the exact create/initialize/swap packets from the laboratory RPC builder.
Native-input swaps select one sufficient unlocked wallet output, preserve native
change, and pay BLCH separately from fee funding. Tests cover exact consumption,
locked reserve exclusion, slippage, unchanged LP supply and reserve conservation.
Fragmented native inputs are not combined by this bounded builder.

```sh
NATIVE_WASM_VECTORS_PATH=/tmp/vectors.json cargo test --offline -p bloch-native-wallet-wasm --lib full_pool_lifecycle
node tools/native-wallet-wasm/crosscheck.cjs target/wasm32-wasip1/release/bloch_native_wallet_wasm.wasm /tmp/vectors.json /path/to/postern-wallet/browser/native-core.js /tmp/signed-vectors.json
NATIVE_WASM_SIGNED_VECTORS_PATH=/tmp/signed-vectors.json cargo test --offline -p bloch-native-wallet-wasm --lib full_pool_lifecycle
```

The lifecycle harness uses the existing direct executors. Its test-only
`native-wallet-fixtures` feature clears rehearsal fee escrow between review views,
while preserving every already-debited BLCH UTXO. This is not canonical fee
settlement or a block replay proof. The production component codec is unchanged;
the helper is a dev-dependency feature and absent from the release WASM build.
Canonical node snapshots supplied by RPC require no such normalization.


The laboratory withdrawal builder fixes the current route nonce, native owner
input, BLCH payer, recipient, burn amount, change and fee before external
certification. It supports one Supply policy and one sufficient unlocked native
output. Issuer and ordered committee approvals sign the joint authorization;
the wallet signs only its own payer and native input. Rebuilding against current
state rejects stale certificates. `live_withdrawal_builder` checks genuine hybrid
certificates, partial burns, replay, and changed recipient, amount or expiry.
Use `NATIVE_WASM_WITHDRAWAL_VECTOR_PATH` to export its vector and
`NATIVE_WASM_WITHDRAWAL_SIGNED_PATH` to execute the crosscheck driver's exact WASM
result. Laboratory features do not enable production activation gates.
