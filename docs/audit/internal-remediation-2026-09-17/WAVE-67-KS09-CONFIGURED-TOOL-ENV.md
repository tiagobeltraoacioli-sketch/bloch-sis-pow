# Wave 67 KS-09: configured-tool environment wrappers

Date: 2026-09-18. Base: `0a8e268`. Scope: build-identity parser and configured
tool fingerprinting. No consensus, wire, persistent format, release artifact or
deployed node changed.

## Correction

Configured compiler, linker, archiver and wrapper variables can contain
`env PATH=... tool ...`. The build-environment digest already bound the literal
variable, but executable fingerprinting treated `env` itself as the tool and
could miss both the actual command and a recognized compiler delegated through
`ccache`, `distcc`, `icecc` or `sccache`.

The fail-closed environment-command parser is now shared by rustc's observed
link command and every configured-tool variable. It returns the complete
utility/argument vector plus the effective PATH. Both the selected wrapper/tool
and an unambiguous known delegate are resolved under that path. Ordered PATH
clear/restore semantics and unknown-option refusal remain identical to the
default-linker probe.

## Validation

- `cargo test -p bloch-pos-node --test build_command_parser --offline`: all 5
  parser groups passed, including an `env PATH=... sccache clang` command whose
  arguments and search path remain available for both fingerprints.
- The Wave 67 integration checkpoint records the broad node suite.
- `git diff --check` passes.

## Residual boundary

KS-09 remains `PARTIAL`. Wrapper-specific option grammars are deliberately not
guessed, cross-target probes can remain unavailable, and SDK/native libraries,
operating-system inputs and undeclared tools stay outside the digest.
Independently authenticated hermetic builds, binary comparison and signed
provenance remain release gates.
