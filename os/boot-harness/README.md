<!--
SPDX-License-Identifier: MIT OR Apache-2.0
Postern OS Mobile — aarch64 build + QEMU-boot harness.
UNAUDITED reference-prototype. built ≠ booted; QEMU ≠ hardware;
reproducible-by-design ≠ reproduced. Never built/booted on the dev host (no Nix).
-->

# Postern OS Mobile — aarch64 builder + QEMU-boot harness

Two rungs of the same ladder for the **Postern OS Mobile** image (the
Mobile-NixOS phone image, device `pine64-pinephone`, wallet-first — see
`os/MOBILE.md` / `os/mobile.nix`):

| Rung | Script | What it does | Where it runs |
|---|---|---|---|
| **0 — build** | `build-aarch64-graviton.sh` | `nix build` the image **natively on aarch64** (a Graviton). No binfmt/qemu-user. | aarch64 Linux + Nix |
| **1 — boot**  | `boot-qemu-aarch64.sh` | Boots that image under `qemu-system-aarch64` (TCG, no KVM), tees the serial console, grades it. | Linux + Nix + `qemu-system-aarch64` |

Rung 1 proves the **software boot chain** only:

> bootloader → kernel → **Mobile-NixOS stage-1** → systemd → getty / login.

**It proves nothing about a phone.** `qemu-system-aarch64 -M virt` models no
PinePhone device tree, DSI display, touch, modem, or power. **QEMU ≠ hardware.**
The device half (real PinePhone + UART serial + photo) is a separate rung.

## The exact commands an operator runs on a Graviton

On an **aarch64** Linux host (AWS Graviton / Ampere / Apple-silicon Linux VM)
with Nix + flakes installed, from the repo root:

```sh
# Rung 0 — BUILD the phone image natively on aarch64 (no emulation).
# Prints the /nix/store/… path on its last line and writes a provenance sidecar.
./os/boot-harness/build-aarch64-graviton.sh

# …or the raw nix invocation it wraps (branch-correct attribute — see note below):
nix build .#packages.x86_64-linux.mobile-image --no-link --print-out-paths

# Rung 1 — BOOT it under QEMU (needs qemu-system-aarch64 on the host).
# With no --image it re-invokes the builder for you:
./os/boot-harness/boot-qemu-aarch64.sh

#   …or boot a prebuilt store path and pick a log file:
./os/boot-harness/boot-qemu-aarch64.sh \
    --image /nix/store/…-mobile-image --log /tmp/boot.log
```

Both scripts are `sh`, self-locating, and take env/flag overrides (`--help`).

### Which flake attribute (branch-specific — important)

In **this branch** the image is exposed as `packages.x86_64-linux.mobile-image`
(`flake.nix` ~line 86), but its *derivation* is pinned to `system =
"aarch64-linux"` internally — the whole closure is aarch64. Nix evaluation is
lazy and platform-independent, so the portable selector is the fully-qualified
`.#packages.x86_64-linux.mobile-image`, and on a Graviton it builds **natively**.

The bare alias `.#mobile-image` resolves via `packages.<current-system>` =
`packages.aarch64-linux.mobile-image` on a Graviton, which this branch's flake
does **not** define — so bare `.#mobile-image` 404s on aarch64 and works only on
an x86_64 host. `build-aarch64-graviton.sh` defaults to the fully-qualified
attr for exactly this reason; override with `--attr` / `ATTR=` if a later flake
change adds an `packages.aarch64-linux.mobile-image` alias.

## Files

| File | What it is |
|---|---|
| `build-aarch64-graviton.sh` | **Rung 0.** Native-aarch64 `nix build` of the mobile image, with a native-arch gate (refuses to silently emulate), store-path-on-last-line contract, and a provenance sidecar. |
| `boot-qemu-aarch64.sh` | **Rung 1.** Builds (via the builder) or takes `--image`, boots under `qemu-system-aarch64` (TCG), tees the serial console to a log, writes an evidence sidecar, and grades the log. |
| `check-boot-log.sh` | Grades a serial log against `success-markers.txt`. **Shared** with the hardware rung so all rungs agree on what "booted" means. |
| `success-markers.txt` | The **shared** required-success / must-not-appear grep contract. Jointly owned — neither rung keeps a private list. |
| `run-fixture-tests.sh` | **HOST self-test.** Feeds the grader the `fixtures/*.log` synthetic logs and asserts each expected exit code. Proves the grader LOGIC on a machine with no Nix/QEMU — it runs on the mac. |
| `fixtures/*.log` | Hand-written synthetic serial logs (a passing ladder + one per failure mode). **Not real boots** — inputs to the self-test only. |
| `evidence/` | Where a graded run's log + sidecars land, plus an index of what has (not) been run. |

## What IS provable on the dev host (macOS, no Nix)

The build and the boot are both VM/host-gated, but the **grader's logic is pure
shell and is HOST-provable**:

```sh
sh os/boot-harness/run-fixture-tests.sh   # => "N passed, 0 failed"; exit 0
shellcheck os/boot-harness/*.sh           # => clean
```

This proves the grader **logic** only — it accepts a good ladder, rejects a
missing/out-of-order one, and lets any failure marker veto an otherwise-complete
ladder. It boots **nothing**. `grader-logic-correct ≠ image-boots`.

## Definition of done (per rung)

- **Rung 0 (build)** — `build-aarch64-graviton.sh` exits 0 on an aarch64 host,
  prints a `/nix/store/…-mobile-image` path, and writes its provenance sidecar.
  *built ≠ booted.*
- **Rung 1 (boot)** — `check-boot-log.sh` finds, in order, `Booting Linux on
  physical CPU` → `systemd[1]:` → `Reached target` → login, with **no** `Kernel
  panic`, `Entering emergency mode`, `Unable to mount root fs`, or stage-1
  emergency shell (exit 0). Then, interactively / via a CI-expect wrapper,
  `bloch-wallet --help` prints usage and `systemctl is-system-running` is
  `running`/`degraded-with-known-reasons`.
- **Evidence kept** — the serial log + `*.evidence` / `*.provenance` sidecars
  (store path + `nix hash path` + `sha256` + host/QEMU + timestamp) are retained.

Exit codes (both harness scripts): `0` pass · `1` required marker missing/out of
order · `2` failure marker present · `3` wrong host / usage · `4` no bootable
artifact produced/located · `5` missing tool.

## Honesty gate — the state of this rung

- **NOT built and NOT booted on the dev workstation** (macOS: no Nix; no KVM).
  `qemu-system-aarch64` happens to be installed here, but there is no image to
  boot and no Nix to build one. These scripts are validated, idiomatic `sh`
  written to run on an aarch64 Linux + Nix host — the honesty gate is **that
  host + a real `nix build` + a real QEMU boot**, none of which has happened for
  this branch. No boot has ever been graded green on this rung.
- **Hardware is a further, uncrossed gate.** A green QEMU run says nothing about
  a PinePhone device tree, DSI display, touch, modem/telephony, or power — none
  are modeled by `-M virt`. That is a separate hardware rung requiring a real
  device (roadmap B4).
- **Reproducibility is a further, uncrossed gate.** Nobody has rebuilt the image
  to a matching hash on a second builder. reproducible-by-design ≠ reproduced.
- Testnet/beta is zero-security by design; a phone wallet holds worthless coins.
