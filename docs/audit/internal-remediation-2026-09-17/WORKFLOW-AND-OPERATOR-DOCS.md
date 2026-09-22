# Workflow and operator documentation corrections — September 17, 2026

## INF-21: repository-owned workflow

The checked-in `.claude/workflows/roadmap-execution.js` assumed a personal Mac
path, one branch, retired PoW architecture and implementation gaps that no longer
described this checkout. It now resolves the repository from the workflow host's
working directory and derives tasks from current source, roadmap and audit
evidence. Model selection belongs to the host/session. The four proposed delivery
roles explicitly coordinate ownership and keep source corrections, protocol
activation, external qualification and deployment separate. English is required
for contributions.

The template still returns proposed patches as text. Updating it does not invoke
its agents or authorize any release, credential operation or validator restart.
The adjacent README describes the custom host contract. The workflow host and a
JavaScript runtime were unavailable on this machine, so the async body was source
reviewed but not executed or independently parser-checked. INF-21 is implemented
as a source correction; host integration remains separate evidence.

## INF-22: concrete operator drift

The PoS crate toolchain comments now describe the actual Genesis-4 root workspace
and retired Genesis-3 workspace under `legacy/genesis3-node/`. Both active pins
remain Rust 1.94.1; no compiler version changed. The obsolete assertion that the
root still held Genesis-3 halted at 80,000 was removed; the sibling manifest
records retirement at height 39,918.

The legacy Nix service is explicitly labeled Genesis-3 and points operators to
the separate PoS module for Genesis-4. Its default RPC port now matches its
actual binary default, 16210. An existing installation intentionally using 8645
must set `services.bloch.rpcPort = 8645` explicitly before adopting this source
change. No running service configuration was changed. The historical
`Cargo.toml.local-validation` now names ordinary `Cargo.toml` as authoritative
and warns against replacing a release manifest with it.

The PoS module's explicit package/transport wiring and RPC binding were addressed
in earlier waves. The legacy package derivation, Nix evaluation/builds and
production systemd inventory remain unqualified; Nix is unavailable on this host.
INF-22 remains partial, and the broader Nix packaging issues remain INF-18.

## Release diagnostics

The lock-integrity guard still fails on locked metadata-resolution errors. Its
diagnostic now distinguishes possible network/toolchain/lockfile causes and
explicitly avoids recommending lockfile regeneration to bypass an environment
failure. All 14 existing guard self-test cases pass. No lock policy was relaxed.
