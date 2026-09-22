# Wave 115 — INF-01 package target metadata

Date: 2026-09-19
Comparison base: `c3176ea`

## Reproduced gap

The unsigned candidate packager expanded `rustc -vV | sed ...` directly inside
a successful `printf`. That outer command masked a failed compiler query, and
the metadata accepted zero, multiple or malformed `host:` rows. No host emitted
an empty `target=` field; two hosts injected a second physical line into
`BUILD-INFO`; arbitrary spaces or uppercase text were accepted as a target.

## Correction

The packager now captures `rustc -vV` separately and propagates failure. It
requires exactly one `host:` row, then applies the same architecture-neutral
structural subset used by the canonical wrapper and comparator: lowercase
ASCII letters, digits, underscore and hyphen; no leading, trailing or doubled
hyphen; and at least three nonempty hyphen-separated components. Only that
validated scalar is emitted as `target`.

## Adversarial coverage

The hermetic fake compiler retains the canonical
`x86_64-unknown-linux-gnu` case. New modes make `rustc -vV` exit nonzero, omit
the host, report two different hosts, or emit a host containing uppercase and
spaces; all are refused with the intended diagnostic. The complete earlier
dirty-source, captured-OID race and version-identity matrix remains active.

## Validation

```text
bash scripts/package-pos-release-candidate.selftest.sh
# package-pos-release-candidate selftest: PASS

bash -n scripts/package-pos-release-candidate.sh
bash -n scripts/package-pos-release-candidate.selftest.sh
# passed
```

## Residual boundary

This validates one structural host scalar without pinning an architecture. It
does not prove that Rust recognizes the triple, that it is the effective Cargo
build target, that it matches the binary ABI, or that the compiler/PATH report
is authentic. Signing, publication, independent canonical builds and
comparison, approval, rollback rehearsal, staged canary and fleet evidence
remain external release gates. INF-01 remains `PARTIAL`.
