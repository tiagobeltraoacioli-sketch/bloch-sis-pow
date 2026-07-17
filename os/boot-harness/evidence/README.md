<!--
SPDX-License-Identifier: MIT OR Apache-2.0
Postern OS Mobile — aarch64 build/boot evidence index.
UNAUDITED / SCAFFOLD. Read every record's caveats before citing it.
-->

# Boot/build evidence — os/boot-harness (aarch64, Postern OS Mobile)

This directory holds the **raw artifacts** a graded run (or graded *attempt*) of
`build-aarch64-graviton.sh` (Rung 0) and `boot-qemu-aarch64.sh` (Rung 1)
produces — a `*.provenance` sidecar for a build, a serial log + `*.evidence`
sidecar for a boot — plus this index of what each record does and does not
prove. See `../README.md` for the harness and `../success-markers.txt` for the
shared grading ladder.

**Standing caveats — apply to every record, verbatim, no exceptions:**

- `built != booted` — a `nix build` producing an image proves nothing about
  whether that image boots.
- `QEMU/TCG != hardware` — TCG emulation with `-M virt` models **NO PinePhone
  device tree, DSI display, touch, modem, or power**. It can only ever prove the
  software boot chain (bootloader → kernel → stage-1 → systemd → login), never
  real hardware.
- `reproducible-by-design != reproduced` — nobody has independently rebuilt any
  image to a matching hash. "Nix should be reproducible" is not evidence that
  this build was.
- **unaudited scaffold** — the scripts, the grader, and this directory have not
  been security- or correctness-audited. Treat any PASS as "the procedure worked
  once," not a certification.

## Records

_None on this branch yet._ Neither rung has been run for
`feat/kaspa-sync-phase2`: the dev workstation is macOS with no Nix (Rung 0
cannot build) and no image to boot (Rung 1 has nothing to feed QEMU). When an
operator runs the harness on an aarch64 Linux + Nix host, the sidecars land here
(`last-build.provenance`, `<log>.evidence`, and the serial `<log>` itself) and a
dated record gets appended above — recording the store path, `nix hash path`,
`sha256`, host/QEMU versions, and the grader verdict **verbatim**, inventing no
hashes and upgrading no status that a real run did not produce.

## What a future record must NOT do

- Claim a hash/store path for an image that was not actually built (no
  fabricated `nix hash` / `sha256`).
- Grade a boot green without the shared `check-boot-log.sh` ladder passing on a
  real captured serial log.
- Imply anything about a PinePhone, telephony, attestation, or reproducibility
  from a QEMU-`virt` run — those are separate, uncrossed gates.
