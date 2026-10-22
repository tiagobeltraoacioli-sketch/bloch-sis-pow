# NIST ACVP SLH-DSA-SHAKE-128s (FIPS 205) vectors

Source: NIST's [ACVP-Server repository](https://github.com/usnistgov/ACVP-Server),
pinned commit `975de31eb83d87039ec88934fdc47d8c312b892d` (the same commit the
ML-DSA fixtures use). Original files, downloaded without transformation:

| ACVP file | SHA-256 |
|---|---|
| `gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json` | `d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920` |
| `gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json` | `62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba` |
| `gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json` | `a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792` |

## Extraction

`acvp-slhdsa-shake128s.json` keeps, for `parameterSet = SLH-DSA-SHAKE-128s`,
EVERY test of every group whose `preHash` is `pure` (external interface, the
mode suite 0x0003 uses) or `none` (internal interface):

- keyGen: all 10 cases (tgId 2);
- sigGen: 28 cases — external/pure deterministic (tgId 25) and hedged
  (tgId 61), internal deterministic (tgId 34) and hedged (tgId 70), 7 each;
- sigVer: 28 cases — external/pure (tgId 25) and internal (tgId 34), 14 each:
  2 valid plus modified message, modified R, modified SIGFORS, modified
  SIGHT, too-small and too-large signatures (2 each).

Pre-hash groups (HashSLH-DSA) are omitted: suite 0x0003 never pre-hashes.
Group fields (`tgId`, `signatureInterface`, `deterministic`) are copied onto
each case; `deferred`/`hashAlg` are dropped, and sigVer's unused `sk` /
`additionalRandomness` are dropped. Hex values are lower-cased (bytes
unchanged), matching the ML-DSA fixtures. JSON is Python
`json.dumps(sort_keys=True, indent=1)` plus a final newline. Extracted fixture
SHA-256: `a0603e6c9bf79cdb210bd781ff335363cc0e2d1e7a1745baa790b74750f27531`,
pinned by `tests/acvp_slhdsa.rs`.

The secret keys present are NIST's public test-vector keys, not credentials.

## Qualification boundary

`acvp_slhdsa.rs` runs the vendored `fips205` 0.4.1 (crates/fips205) on the
build host's architecture. It is algorithm-vector evidence for the linked
build, not a CAVP/CMVP validation and not an audit.
