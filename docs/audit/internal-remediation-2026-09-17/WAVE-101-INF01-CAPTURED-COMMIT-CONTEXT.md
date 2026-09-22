# Wave 101 — INF-01 captured commit context

Date: 2026-09-19
Comparison base: `97f7a1f`

## Reproduced gap

The canonical build wrapper first resolved `HEAD` to a commit OID, but later
used the symbolic `HEAD` again for both the commit timestamp and source
archive. If the ref advanced between those operations, `BLOCH_BUILD_COMMIT`
could name commit A while `SOURCE_DATE_EPOCH` and the build context came from
commit B.

An isolated local Git reproduction captured A, advanced the ref to B, then
executed the wrapper's late commands. The captured OID remained A while the
timestamp and archived `SOURCE-MARKER` came from B. No repository ref in the
working checkout, Docker daemon, systemd host or key material was involved.

## Correction

After validating the captured forty-character lowercase commit OID, the
wrapper now passes that immutable value to both:

```text
git show -s --format=%ct "$commit"
git archive --format=tar "$commit"
```

The build argument, timestamp and archive therefore remain one local Git
object identity even if `HEAD` moves concurrently. All Wave 100 manifest and
post-engine checks remain unchanged.

## Adversarial coverage

The build-wrapper selftest now creates a temporary repository with commits A
and B. A Git shim advances `HEAD` to B immediately after the wrapper captures
A. The fake engine derives its executable from a committed context marker.
The wrapper must pass while its output proves all three A-bound values:

- `source_commit` equals A;
- `source_date_epoch` equals A's timestamp; and
- the executable contains A's archived marker.

The fixture separately confirms that `HEAD` really ended at B. The canonical,
extra-row and omitted-binary manifest cases from Wave 100 remain active.

## Validation

```text
bash scripts/build-pos-release-container.selftest.sh
# build-pos-release-container selftest: PASS

bash -n scripts/build-pos-release-container.sh
bash -n scripts/build-pos-release-container.selftest.sh
# passed
```

## Residual boundary

This proves local consistency among one captured OID, its timestamp and its
archived tree. It does not authenticate the repository or Git object store,
the engine, image, toolchain or builder; prove builder independence; or
provide hosted CI, signing, publication, approval, rollback rehearsal,
deployment or fleet evidence. INF-01 remains `PARTIAL`.
