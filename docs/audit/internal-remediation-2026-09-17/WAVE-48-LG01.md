# Wave 48 LG-01: historical subsidy provenance boundary

Date: 2026-09-18. Branch: `codex/audit-lg01-subsidy-provenance`.
Starting point: `a085f9c`. Scope: local evidence intake, adversarial tests and
documentation only. No carryover byte, balance, consensus rule, node,
deployment, or live state changed.

## Recovered finding and arithmetic

The exact source is
`a79c88b:docs/audit/deep-audit-2026-09-16/A11-legacy-apps-sdk.md`.
The shipped 452,726-row file totals 381,074,400,000,000,000 Genesis-3
satoshis. Subtracting its 347,544,120,000,000,000-satoshi opening base leaves
exactly 39,917 times the 840,000,000,000-satoshi subsidy, with remainder zero.
The zero-value local-height-0 anchor is not a missing subsidy.

The follow-up verification in A13 narrows the unresolved explanations to two:

1. The frozen snapshot nodes' applied selected tip was 39,917. The published
   39,918 label came from another observation, a stored/announced body, or a
   final block that never reached and applied on those nodes.
2. Block 39,918 was selected, but its effects were absent from the UTXO set.
   The legacy Extension path can produce this state because it logs an
   `apply_block_utxo_mutations` failure and still advances `tip_hash`.

The original stored-height mechanism is not itself evidence for the selected
RPC tip: `getdaginfo.tip_height` reports the selected DAG height, whereas the
height column family contains every persisted block. The historical exporter
decode-skip was also a possible omission mechanism, but current code fails
closed. Re-deriving successfully with current code on each archive can exclude
that mechanism for those exact database copies.

## Evidence intake

`scripts/verify-lg01-provenance.py` validates a strict
`bloch-lg01-provenance-v1` JSON bundle. Every node record independently pins:

- the shipped SHA-256, SHA3-256, set root, row count, and total;
- selected tip height and hash at snapshot time;
- maximum stored height and the height-39,918 block lookup;
- SHA-256 identifiers for the raw DAG, tip metadata, carryover verification,
  and block-lookup outputs; and
- a distinct frozen-archive identity.

At least two records must agree. A 39,917 selected tip classifies as
`LABEL_OR_STALE_SNAPSHOT` only when no record calls block 39,918 selected. A
39,918 selected tip classifies as `SELECTED_BLOCK_EFFECTS_MISSING` only when
each record supplies the matching selected block and it claims at least the
scheduled subsidy. Every other shape is `INCONCLUSIVE` with a nonzero exit.

The input is deliberately strict about fields and primitive types to make
typos and partial reports fail closed. It does not verify operator identity or
prove that asserted fields came from the hashed raw files. Therefore the raw
files, collection commands, archive identities, capture context and detached
operator signatures must still be published and reviewed independently.

## External evidence still required

From each of the two frozen snapshot data directories, retain and authenticate:

1. a reproducible archive/data-directory identity;
2. snapshot-time `getdaginfo.tip_height` and `meta.tip_hash`;
3. maximum stored height, explicitly labelled as non-authoritative for the
   selected chain;
4. a current fail-closed carryover derivation and verification against the
   shipped file; and
5. the raw height-39,918 block lookup, including its selected disposition,
   block hash, coinbase total and transaction count.

If both archives prove the first hypothesis, terminal-height prose can be
corrected to distinguish selected applied height 39,917 from the 39,918 label.
If they prove the second, the snapshot remains the live committed artifact and
the missing 40,000 post-split BLOCH is a documented historical loss unless an
owner separately specifies and qualifies a remedy. This wave neither chooses
that policy nor alters balances.

LG-01 moves from `OPEN` to `PARTIAL`, not `IMPLEMENTED`: repository-side
intake is now deterministic and fail closed, but the deciding facts remain
outside the repository.

## Validation

- `python3 scripts/test-verify-lg01-provenance.py`: nine tests passed,
  covering both classifications, one/duplicate archives, artifact mismatch,
  Python boolean/integer confusion, disagreeing tips, inconsistent selected
  block, underclaimed subsidy, and unknown fields.
- `python3 -m py_compile scripts/verify-lg01-provenance.py scripts/test-verify-lg01-provenance.py`:
  passed.
- `git diff --check`: passed.
