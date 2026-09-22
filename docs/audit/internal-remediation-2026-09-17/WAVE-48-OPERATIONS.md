# Wave 48: operational credential and checkpoint boundaries

Date: 2026-09-18. Starting point: `6edf07f`. Scope: repository-owned
operational clients, ForceCommand implementation, weak-subjectivity release
verification, regressions and ledger evidence. No remote host, SSH key,
validator key, signer arrangement, checkpoint signature, release, activation
or deployment was changed.

## INF-02: the verifier no longer borrows fleet administration

`verify-bootnodes.sh --deep` described a dedicated read-only credential but
silently fell back to `BLOCH_FLEET_KEY`, recreating the exact shared-credential
boundary the role-separation document says to remove. Its SSH command also
carried a shell program even though the documented target was a ForceCommand.

The deep path now:

- requires `BLOCH_VERIFY_RO_KEY` to name a regular file and refuses an
  admin/fleet-key-only environment;
- sends only the fixed original command `verify`; and
- ships `deploy/bootnodes/ssh-verify-readonly.sh`, a root-owned wrapper that
  accepts only that token, never evaluates it, and fixes the key-presence,
  service-transport and loopback-RPC reads in its own source.

The self-test proves public RPC exposure still fails, the fleet-key fallback
is gone, and the dedicated-key invocation produces the expected read-only
facts. INF-02 moves to partial: source-side verification no longer needs the
fleet administrator credential, but no live credential was rotated and the
remaining validator-management paths still require per-role/per-host
migration and independent evidence.

## SR-03: release verification now agrees with fresh boot

`ws-verify` already printed `EXPIRED` when given `--rpc` or `--now-epoch`, but
continued to finish with `VERDICT: ACCEPTED` if the signatures were valid.
That mixed cryptographic validity with fresh-install usability even though a
booting node rejects the same checkpoint at the weak-subjectivity boundary.

The command now returns a refusal for an expired artifact whenever a clock is
supplied. `--require-fresh` additionally refuses to pass without either a
current epoch or an RPC clock. Fresh and stale-within-window artifacts retain
their previous cryptographic verdict; stale remains a publication warning.
Boundary tests cover fresh, stale, exact expiry, future-epoch saturation,
expired refusal and missing-clock refusal. Release/ceremony documentation now
uses the fail-closed form.

SR-03 remains open. These checks cannot create the independent signer keys,
signer-set file or signed checkpoint envelope that the repository still lacks.

## Validation

- `cargo test -p bloch-pos-node --bin bloch-pos 'ws_tool::tests::audit_release_' --offline`:
  two passed.
- `cargo test -p bloch-pos-node --bin bloch-pos audit_future_checkpoint --offline`:
  one passed.
- `bash deploy/bootnodes/verify-bootnodes.selftest.sh`: passed, including the
  admin-key refusal and dedicated-key success cases.
- The ForceCommand refused a non-`verify` original command with exit status 2.
- `bash -n` passed for the verifier, wrapper and self-test; `git diff --check`
  passed.
