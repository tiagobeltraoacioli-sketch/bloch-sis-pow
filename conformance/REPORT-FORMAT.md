# Conformance report format — mandatory for every run

A conformance run that prints a bare percentage is not a result. This format
exists so that a number cannot be shipped without the evidence that makes it
readable: which target, which corpus, which vectors were excluded and why, and
whether the harness itself was proven capable of failing.

Every run of a C-front harness MUST emit exactly these fields.

```
target:        <crate> @ <git commit of the code under test>
corpus:        <name> @ <pinned upstream commit>
manifest:      <path> VERIFIED | REFUSED-TO-RUN
harness-gate:  <mutants killed>/<mutants run> @ <results file>
total:         A + E                       # every fixture in the corpus
applicable:    A
  passed:      P
  failed:      F   -> every failing fixture NAMED (a list, not a count)
  divergent:   D   -> each with an ADR/spec citation
excluded:      E   -> per reason code, from filters/*.toml
rate:          "P of A applicable"          # NEVER a bare percentage
```

## The rules, and why each exists

1. **`rate` is written "P of A applicable", never "N%".** A percentage hides its
   denominator, and the denominator is where a conformance claim is usually
   inflated — by quietly shrinking the applicable set. If a percentage is also
   wanted, it goes *after* the fraction, never instead of it.

2. **Failures are NAMED.** "F = 12" is a number; twelve fixture names are a work
   item. An honest 70% with the 30% listed is worth more than a "pass" without a
   number (this front's charter, verbatim).

3. **Exclusions carry a reason code** from `corpora/filters/*.toml`, and the
   per-code counts are printed. A silent skip is indistinguishable from a pass,
   which is how a corpus quietly stops testing anything. Expected-reject cases
   (e.g. `EXCL-BLOB`) are asserted to REJECT — they are not skips.

4. **`DIVERGENT-BY-DESIGN` requires a citation.** Bloch differing from Ethereum
   or Solana on purpose is legitimate; differing without a written decision is a
   bug wearing a filter. No citation, no exemption — it counts as `failed`.

5. **An unverified manifest refuses to report.** A corpus that does not match its
   SHA-256 manifest may have drifted between runs, so the rate is not comparable
   to the last one. `REFUSED-TO-RUN` is the only honest output.

6. **The harness gate is part of the report.** A differ that stays green under a
   deliberately broken engine compares nothing. Every report carries the
   kill count from `mutation/`, and a report whose gate has ANY unanalysed
   survivor is not credible — the first harness-gate run of this front had one
   (H07), and it was closed before the format was declared satisfied
   (`mutation/results/FINDINGS.md`).

7. **An empty applicable set is a FAILURE, not a pass.** `A = 0` means the
   filter or the corpus path is wrong. This is not hypothetical: the sBPF `B2`
   oracle was pinned at a commit where `vm_interp` had been deleted upstream and
   a sparse checkout produced an empty directory (`corpora/PINS.toml`). A harness
   pointed at it would have reported a perfect score over nothing.

## Worked example — the only run this front can honestly report today

```
target:        crates/bloch-euvm @ 751afdae
corpus:        NIST CAVP SHA-256 + SHAKE256 byte vectors (see
               euvm-conformance/vectors/cavp/MANIFEST.toml)
manifest:      euvm-conformance/vectors/cavp/MANIFEST.sha256 VERIFIED
harness-gate:  7/7 @ mutation/results/2026-08-22-harness-gate.tsv
total:         1748
applicable:    507
  passed:      507
  failed:      0
  divergent:   0
excluded:      1241
  OUTPUTLEN-MISMATCH        1241  (SHAKE256VariableOut rows with Outputlen != 256)
  MONTE-NOT-EXPRESSIBLE        -  (whole files, not counted in `total`; see MANIFEST.toml)
  NO-SUCH-OPCODE               -  (whole files, not counted in `total`; see MANIFEST.toml)
rate:          507 of 507 applicable
scope caveat:  this is CRYPTO-CALLBACK conformance for two opcodes. It is NOT
               Ethereum conformance and must never be reported as such —
               bloch-euvm is not an EVM. The EVM and sBPF targets do not exist
               yet, so their honest rate today is: no run, no number.
```
