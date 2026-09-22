# Internal audit remediation, sixteenth wave — 2026-09-17

Base: `1004cca`; remote-access implementation commit `42cb8e8`; branch
`fix/internal-audit-20260917`. This is local source evidence, not proof that a
NixOS image built, booted or unlocked persistent storage on target hardware.

## Attested-image remote access

INF-17 combined two independent defects. The remote-access half is now
implemented:

- `os/attested.nix` explicitly disables sshd, declines the automatic firewall
  opening and retains deny settings for root, password and keyboard-interactive
  authentication. Its plain assignment overrides the base profile's
  `mkDefault true` while allowing a deployment module to make a deliberate
  stronger-priority choice.
- `os/cloud.nix` is that explicit exception: it uses `mkForce true`, keeps the
  global OpenSSH firewall opening disabled, denies root and interactive/password
  authentication, and permits TCP 22 only on `wg0`. The pre-attestation public
  interfaces therefore expose the Seal gate and WireGuard, not SSH.
- A blocking structural guard and mutation selftest run in both CI definitions.
  Six regressions independently turn the guard red: appliance sshd re-enabled,
  softened cloud override, global port opening, root login, password login and
  removal of the interface-specific firewall rule.
- The existing Nix evaluation script now checks the effective OpenSSH values of
  both wired attested configurations, not merely the installer ISO profiles.

## Persist-volume residual

The encryption half of INF-17 is not declared repaired. `os/attested.nix`
still combines a systemd-repart `Encrypt = "key-file"` image description with
an initrd crypttab TPM2 auto-unlock request and prose that describes TPM2
enrollment. No Nix executable, image build, TPM-backed VM or target hardware
was available in this session. Changing those fields by inference could yield
an unbootable appliance or falsely claim a sealed key slot.

The existing file notice and its build, LUKS-header, token, boot-log and reboot
checks remain mandatory. INF-17 therefore moves from open to partial, rather
than implemented.

## Validation and status

The structural guard, its six-case mutation suite, the prior ISO guard and its
seven-case suite, Python compilation, shell syntax, banned-language gate and
`git diff --check` passed. Details are in `VALIDATION-WAVE-16.txt`.

The ledger retains all 200 rows: 55 implemented locally, 76 partial, 56 open,
seven base-changed, four protocol decisions, one unarmed candidate and one
refuted by the original audit.
