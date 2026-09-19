# Wave 120 — INF-01 package toolchain pins

Date: 2026-09-19
Comparison base: `c924874`

## Reproduced gap

The unsigned candidate packager extracted only the node crate's toolchain pin
and checked `rustc` from that directory, but invoked Cargo with the archived
repository root as its current directory. Rustup therefore selected the root
pin for the build. If the two files diverged, `BUILD-INFO` named the node pin
while Cargo used the root pin. The ad hoc extraction also did not directly
reject duplicate or injection-shaped channel assignments.

## Correction

Inside the captured source snapshot, the packager now invokes the repository's
existing `pinned-rust-toolchain.py` contract with both root and node pin files.
That parser requires exactly one simple channel assignment in each file and
requires equality. The resulting single channel remains subject to the active
`rustc --version` check from the node directory, while Cargo intentionally
continues to run from the root now proven to carry the same pin.

## Adversarial coverage

The hermetic repository fixture now includes the real parser and both pin
files. Its moving-HEAD race advances both pins together and still proves that
the older captured OID supplies the build. New committed fixtures reject a
root/node mismatch, a duplicate node channel and an injection-shaped channel.
The full source, version, target and digest matrix remains active.

## Validation

```text
bash scripts/package-pos-release-candidate.selftest.sh
# package-pos-release-candidate selftest: PASS

bash -n scripts/package-pos-release-candidate.sh
bash -n scripts/package-pos-release-candidate.selftest.sh
# passed
```

## Residual boundary

This proves textual pin uniqueness, accepted syntax and equality inside the
captured archive. It does not authenticate Python, rustup, Cargo, rustc or the
compiler bytes, nor prove that a tool reporting the expected version is that
compiler. Signing, publication, independent canonical builds and comparison,
approval, rollback rehearsal, staged canary and fleet evidence remain external
release gates. INF-01 remains `PARTIAL`.
