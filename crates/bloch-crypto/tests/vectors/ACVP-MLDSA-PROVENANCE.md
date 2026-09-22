# Official NIST ACVP ML-DSA-65 verification samples

Source: NIST's [ACVP-Server repository](https://github.com/usnistgov/ACVP-Server),
pinned commit `975de31eb83d87039ec88934fdc47d8c312b892d`.
The fixture contains public keys, messages, contexts, signatures and expected
verification results only. It contains no secret keys or signing seeds.

Original files, downloaded without transformation:

- [prompt.json](https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json), 3,125,947 bytes, SHA-256 `e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e`.
- [expectedResults.json](https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json), 13,956 bytes, SHA-256 `e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6`.

Extraction selects `tgId: 3`, `parameterSet: ML-DSA-65`, external signature
interface and pure (not prehashed) messages. All 15 original cases (tcId 31–45)
retain the exact decoded bytes; hex letter case is normalized to lowercase
to avoid accidental credential-pattern matches in public vector data; `testPassed` is joined by tcId from the
same expected-results group. Metadata records the upstream commit, algorithm,
revision and group parameters. JSON uses Python `json.dumps(..., indent=2)` plus
one final newline. Extracted fixture SHA-256:
`852fbdc10ebb41858ac3fa04d7cebda1240752ccb58ce24c6b1fe0db5a2dd7c1`.
The test pins that digest to detect accidental fixture edits; expected answers
are never generated using Bloch's implementation.

## Qualification boundary

`acvp_mldsa.rs` checks the pinned dependency's existing safe
`mldsa65::verify_detached_signature_ctx` against all 15 official outcomes:
three positives and twelve negatives. This exercises the compiled dependency's
selected backend, not every architecture or backend.

All three official positive cases use nonempty contexts. The production
`verify_mldsa65_raw` API uses an empty context and must reject those signatures;
a separate test checks that boundary and the official empty-context negative
(tcId 39). These are **not positive known-answer tests for the production
empty-context wrapper**. They do not qualify seeded key generation, signing,
hybrid envelope policy, consensus behavior, FIPS validation or ACVP certification.
No production algorithm, API, signature encoding or funded derivation changes.
