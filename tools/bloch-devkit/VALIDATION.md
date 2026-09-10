# Validation — 2026-09-10

Host: macOS x86_64. CLI installed through `install.py`.

- Seven Python regression tests pass: existing-project protection, wrong EVM
  chain, artifact tampering, export overwrite, duplicate JSON keys, SVM finalized
  block availability, and runtime persistence/loopback configuration.
- Anvil 1.7.1: Solidity 0.8.28 counter compiled; deployed through Foundry;
  `increment()` succeeded and `number()` returned 1. After Ctrl-C and restart,
  the value remained 1 and the exported observation digest was identical.
- Agave 4.2.2: local validator started, airdrop succeeded and a finalized block
  exported. The SBF counter compiled with platform-tools v1.54, `--arch v3`;
  deployment succeeded. The JavaScript client initialized an account,
  incremented it to 1 and rejected an unauthorized increment without changing
  the value.
- Both exported files passed offline integrity verification. No assertion of
  Bloch inclusion or execution validity is made by this check.
- Institutional website checker passes all eight HTML pages and local links;
  portal/client JavaScript syntax checks pass. Browser screenshot review was
  unavailable because no browser was connected to the computer-use tool.

The SBF compiler emits two upstream entrypoint macro `unexpected_cfgs` warnings
for custom heap/panic feature names. Compilation and execution still pass.
The optional Solana JavaScript client has moderate transitive npm advisories;
see its README. This release has not been validated on Apple Silicon or Linux.
Network settlement, native Bloch replay and bridges are not implemented or tested.

## 0.2.0 source connector increment

- Fifteen Python regressions pass, including the exact canonical hash of a
  real Genesis-4 checkpoint, source freshness, RPC corroboration, failed-sync
  persistence, duplicate JSON and checkpoint changes during reads.
- Both EVM and SVM projects synchronized with the real Genesis-4 RPC.
- The companion native EVM runner executed and statelessly re-verified an
  empty batch bound to source slot 80351, block
  `6900088f293b4de4f8ad79cbb3e261d01df521a786922c2fea2d261b9dd716fc`.
- No mainnet transaction was submitted. The SVM execution adapter and EVM/SVM
  settlement remain pending; this increment validates source-data integration.
