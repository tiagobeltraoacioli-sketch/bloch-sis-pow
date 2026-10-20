<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Spike: SLH-DSA suite verification cost and per-suite verify gas (P9f)

**Date:** 2026-10-19. **Host:** 136.244.93.186, Intel Xeon (Cascade Lake), 32 vCPU.
This is the same class as 209.250.236.240. All timings are single-core.

## Native verification time

Command: `cargo run --release -- 400 --dump-kat`. Each figure is the median of
5 batches. Three runs agreed within about 5%.

| Verifier | Valid (µs) | Invalid (µs) | Signature (B) |
|---|---|---|---|
| ML-DSA-65 (PQClean, the node's stack) | 53.6 | 48.5 | 3,309 |
| Falcon-1024 (PQClean) | 102.0 | 101.7 | ~1,272 |
| SLH-DSA-SHAKE-128s (`fips205` 0.4.1) | 2,181.5 | 2,182.2 | 7,856 |
| SLH-DSA-SHAKE-128f (`fips205` 0.4.1) | 6,222.2 | 6,210.0 | 17,088 |

An invalid SLH-DSA signature costs the same as a valid one, because the
verifier does not exit early. Signing one SLH-128s signature takes about 2.2 s.

## RV32IM instructions

These were counted with the same interpreter that produced
`HYBRID_VERIFY_INSTRUCTIONS` (`../prover-cost/emu/rv32.py`). The guest is
`rv32s/`.

- Valid signature: **76,056,212** instructions, `a0 = 1`. Of these, 4,378
  Keccak-f1600 permutations account for 71,737,908 instructions (94.3%).
- Last signature byte flipped (negative control): 76,056,103 instructions, `a0 = 0`.

## Gas

Each suite's gas is `max(instructions / 100, HYBRID_VERIFY_GAS × t_suite / t_hybrid)`.
Applying the rule to suite 0x0001's own halves gives exactly 72,748.

| Suite | By instructions | By native time | **Verify gas** | Relay units |
|---|---|---|---|---|
| 0x0001 ML-DSA-65 ‖ Falcon-1024 | 72,223 | 72,748 | **72,748** | 1 |
| SLH-128s ‖ Falcon-1024 | 773,691 | 1,067,610 | **1,067,610** | 15 |
| SLH-128s ‖ ML-DSA-65 | 819,656 | 1,044,982 | **1,044,982** | 15 |

## Typical transfer and worst-case block

The table below comes from the test
`transition::slhdsa_fee_model_tests` (run with `--nocapture`). The transfer is
a canonical TransferV2 with 1 input and 2 outputs, priced at the floor base fee
of 10 msat/gas. Mainnet sat at that floor at epoch 6017. The block caps are
512 KiB and 60 M gas.

| Suite | tx bytes | Gas today (suite-blind) | Gas per-suite | Fee (sat) | tx/block | Verify per block |
|---|---|---|---|---|---|---|
| 0x0001 | 8,503 | 213,796 | 213,796 | 2,138 | 61 | 9 ms |
| SLH ‖ Falcon | 11,130 | 255,828 | 1,250,690 | 2,559 → 12,507 | 47 | 107 ms |
| SLH ‖ ML-DSA | 13,322 | 290,900 | 1,263,134 | 2,909 → 12,632 | 39 | 87 ms |
