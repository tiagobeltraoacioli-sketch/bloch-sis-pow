<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Branch consolidation — salvage, and what is provably safe to delete

```
Date:      2026-09-01
Scope:     the 131 branches marked for deletion by the consolidation plan
Baseline:  main @ 737078d1
Method:    object-level. Every commit and every tip file in the deletion set
           was tested for reachability from the 190 branches NOT on the list.
Deletion:  NOT performed. This file is evidence for a decision, not the decision.
```

## Summary

Nothing in the 131 branches is lost any more.

- **7 branches held something the plan should look at.** Five were named by
  it; **two were not** — and both of those were committed on 2026-09-01, hours
  before the plan would have deleted them. Only one branch in the whole set
  held a *file* that exists nowhere else.
- The other 121 are safe on evidence, not on inspection: 50 have a tip tree
  byte-identical to a commit already on `main`, and 71 have every commit
  reachable from a branch that survives. (The plan says 51 tree-identical
  duplicates; measured here it is 50, twice, an hour apart. The 51st is
  presumably `worktree-agent-a783f4d0602e0cad4`, which the plan counts in both
  places — its tree is **not** on `main`, and it is the one branch that held a
  file existing nowhere else.)
- 3 belong to a different repository (disjoint root, no merge base with
  `main`). They are safe to delete **from here**, but the DEX repository was
  not checked, so they are tagged rather than waved through.

**Verification after the salvage:** across all 131 branches, **zero** tip files
and **two** commits are unreachable from a surviving ref or a `salvage/` tag.
Both of those two commits have a byte-identical tree *and* an identical subject
to a commit already on `main` (`733c2afc`, `683794d5`) — pre-rewrite duplicates
whose only unique content is the commit object itself.

## What was rescued, and where it is

| What | From | Where it is now |
|---|---|---|
| `kat/vectors.json` + `tests/kat.rs`, 2,345 lines | `worktree-agent-a783f4d0602e0cad4` (`2e76886d`) | Landed on `rescue/salvage-pre-delete`, ported and re-verified; original at `salvage/2026-09-01/kat-vectors` |
| `BLOCH-G4-TRANSACTIONS.md`, 1,257 lines | `worktree-agent-a95fe62ba79532310` (`42653509`) | Landed with 8 inline corrections; original at `salvage/2026-09-01/g4-transactions-doc` |
| `BLOCH-G4-RPC.md`, 1,213 lines | `worktree-agent-afaacd9bb218fa648` (`ef1deeb9`) | Landed with 6 inline corrections; original at `salvage/2026-09-01/g4-rpc-doc` |
| **Sync profiling + indexed `get-blocks`** (not named by the plan) | `perf/network-sync` (`e904a6db`, 2026-09-01 12:56) | `salvage/2026-09-01/perf-network-sync` |
| **Cold-start test rewrite** (not named by the plan) | `probe/cold-start-truth` (`f6eeae4c`, 2026-09-01 12:23) | `salvage/2026-09-01/cold-start-truth` |
| `BlockHeaderV4` draft, 702 lines | `worktree-agent-a866e1876d1227f9f` (`83cae4f1`) | `salvage/2026-09-01/blockheaderv4-draft` — **superseded and partly reversed** by `main`; see below |
| Three superseded drafts | `a4cc97fa`, `a507f9e3`, `a48d92d2` | `salvage/2026-09-01/superseded-draft-*`, `.../genesis4-ceremony-early` |
| Foreign-repo DEX work | `worktree-wf_2f249654-872-{4,5,6}` | `salvage/2026-09-01/foreign-dex-*` |

`kat/vectors.json` and `tests/kat.rs` are the **only two paths in the entire
131-branch set that exist on no surviving ref**. Everything else that looked
unique was either a whole foreign repository or an older revision of a file
`main` has since moved past.

### The one the plan got backwards

`worktree-agent-a866e1876d1227f9f` was flagged as a rescue candidate on the
strength of a subject that appears on no `main` commit. It should not be
landed. Its `header.rs` asserts `signing_root() == block_id()`; `main` pins the
**opposite** and says why (`header.rs:513`, `signing_root_is_not_the_block_id`).
It also carries an MIT/Apache SPDX header where the crate is now AGPL. It is a
design that was tried and rejected. Tagged as a record, not as work to land.

### Three others the plan flagged as "matching subjects, differing trees"

`a48d92d26`, `a4cc97faee` and `a507f9e345` differ from `main` almost entirely
in **deletions** — `main` is ahead by 92,839, 49 and 5,288 lines respectively.
They are earlier states of files that landed and kept growing, not divergent
work. Every file at all three tips exists on a surviving ref.

## Hard constraint: the private keystores

`pmo/wp7-syncmeasure` carries **41 `BPOSKEY1` validator keystore files** (5
distinct blobs, repeated across `bench/` fixture directories), added by
`ff55a1cd`.

Nothing was cherry-picked or merged from that lineage; no `salvage/` tag
touches it; `main` remains clean (0 of the 5 blobs reachable).

**But deleting these 131 branches does not remove the keys from this
repository.** `ff55a1cd` is an ancestor of six branches, and two of them —
`fix/mempool-entende-v2-e-despeja-conflitantes` and `pmo/prova-religada` — are
**not on the deletion list**. All 5 key blobs are reachable from both. A
`git push --all` to GitLab or GitHub publishes them. That is a separate
decision and it is the founder's; this file only records that consolidation
alone will not fix it.

---

## Provably safe to delete

### A. Tip tree byte-identical to a commit already on `main` (50 branches)

Pre-rewrite duplicates. The tree at the tip is the *same object* as a tree on a
`main` commit, so every file at every path is already on `main`. The commits
differ only in identity.

| branch | tip | commits not on a surviving ref |
|---|---|---|
| `worktree-agent-a08927917ed1bb96b` | `aeaf7d4f` | 51 |
| `worktree-agent-a08dbc2f06a3a578c` | `b2844e47` | 27 |
| `worktree-agent-a0ec4487fc11bac11` | `8a1a7c95` | 51 |
| `worktree-agent-a0ff021df0632ac01` | `207f7276` | 27 |
| `worktree-agent-a1045e06099d1b2ae` | `eacddd97` | 51 |
| `worktree-agent-a117e1ce9d2e6dbe1` | `2abe2252` | 118 |
| `worktree-agent-a123b780d04fe6bb3` | `2bf11cb8` | 27 |
| `worktree-agent-a144f95db1bffeabc` | `e8059062` | 98 |
| `worktree-agent-a14dba69a1c1e174c` | `f54c2f9e` | 29 |
| `worktree-agent-a1b9eeb44926477ac` | `aba1a597` | 51 |
| `worktree-agent-a20067e941e4dc85d` | `14060506` | 97 |
| `worktree-agent-a30c7b31cc40c241b` | `d11a95ac` | 98 |
| `worktree-agent-a3b627ab52bba6c8d` | `dcc8accb` | 1 |
| `worktree-agent-a3cbbc9ecb1b52b45` | `9a874c0d` | 51 |
| `worktree-agent-a4126f92d1d535797` | `67abc782` | 127 |
| `worktree-agent-a4b0c1a6cfda0f41b` | `8ed737ab` | 27 |
| `worktree-agent-a4f17aab62a384dff` | `70753841` | 98 |
| `worktree-agent-a5171a3a6e3d98e2c` | `8a514d81` | 1 |
| `worktree-agent-a540f19a21c6ef2e7` | `4a28fa35` | 1 |
| `worktree-agent-a56e9de019b753cff` | `d881df7c` | 51 |
| `worktree-agent-a5b6a1d70fc8918eb` | `c8b35cf4` | 27 |
| `worktree-agent-a5bd25eb8da18311f` | `96170e65` | 51 |
| `worktree-agent-a647193ee03806ca2` | `8a3e0ea0` | 51 |
| `worktree-agent-a6695018d1c04d3a9` | `6d8b6c10` | 1 |
| `worktree-agent-a6b4cafa28b15e5a1` | `6509996e` | 51 |
| `worktree-agent-a6b80fa3189f60f64` | `3d669d4c` | 51 |
| `worktree-agent-a6e4063b7682ff91f` | `25f01eba` | 51 |
| `worktree-agent-a75dbea6375cde000` | `8f8fc12c` | 51 |
| `worktree-agent-a7c41b9dfdecbe094` | `9de844fd` | 51 |
| `worktree-agent-a7f5b824a0051e173` | `08d2df8e` | 97 |
| `worktree-agent-a7f8411f88f857083` | `1170f195` | 51 |
| `worktree-agent-a865811b8d638e4ce` | `0643fce4` | 98 |
| `worktree-agent-a8a45e05bb915bda0` | `5a9ad3b5` | 97 |
| `worktree-agent-a909db2254824f4dc` | `ce26c342` | 98 |
| `worktree-agent-a9df4541bfa548023` | `49dbdeb0` | 1 |
| `worktree-agent-aa1ff3adce2280c27` | `c04a7d9d` | 118 |
| `worktree-agent-ab26f359a3878284b` | `c1ce3a99` | 97 |
| `worktree-agent-ab32a3be4e51cdfe7` | `806ccd0d` | 51 |
| `worktree-agent-ab666ec1dfbe10567` | `8fca774c` | 0 |
| `worktree-agent-ab9af9c7afe8082da` | `88ab8677` | 118 |
| `worktree-agent-ac0c58bf59f99dc61` | `5da43e40` | 51 |
| `worktree-agent-ac227805515c7dc40` | `d2c98967` | 27 |
| `worktree-agent-ac50d5fc17189d5ad` | `c3e5bfcc` | 127 |
| `worktree-agent-acdf7fcf0d62a5826` | `e1657ed8` | 27 |
| `worktree-agent-ad0de1208ddec8ec5` | `c78e24c6` | 51 |
| `worktree-agent-adfb516f5dee0c253` | `0594431f` | 97 |
| `worktree-agent-adfc7ac345c9010b0` | `8da2c814` | 118 |
| `worktree-agent-aee18986113630528` | `0dc31d78` | 51 |
| `worktree-agent-af510f6581717631f` | `e60477d4` | 1 |
| `worktree-agent-afa5a290c7687bf7d` | `eb0a3aad` | 51 |

### B. Every commit reachable from a surviving branch (71 branches)

The tip is an ancestor of, or equal to, a commit on a branch that is not being
deleted. Deleting the ref removes a name, not an object.

| branch | tip | commits not on a surviving ref |
|---|---|---|
| `agent/testnet-deliver` | `2aaa5ad9` | 0 |
| `deploy/fork-mais-recusa` | `6fa24a25` | 0 |
| `deploy/g3-terminal-50000` | `ec8aabca` | 0 |
| `deploy/g3-terminal-height` | `422f1ef6` | 0 |
| `dev4/writeoff-memo` | `531a5d49` | 0 |
| `dev5/decisions` | `531a5d49` | 0 |
| `ensaio/ws-ceremony` | `c9cd4a1d` | 0 |
| `feat/block-bytes-512k` | `2eb4e470` | 0 |
| `fix/admission-rejects-spent-inputs` | `1d1f4f6f` | 0 |
| `fix/mempool-e-proposer-2026-08-26` | `51787600` | 0 |
| `fix/proposer-drops-only-the-culprit` | `e85d7a73` | 0 |
| `fix/select-respects-block-gas` | `4b9dac2d` | 0 |
| `fs2/furo-whistleblower` | `ec7fbc75` | 0 |
| `funded/eutxo-wt` | `ec7fbc75` | 0 |
| `gates/selfcheck-json-land` | `b4448362` | 0 |
| `lastro/exposicao-slash` | `ec7fbc75` | 0 |
| `lastro/teste-integra` | `39a6d26e` | 0 |
| `lead/fila-quota-r2` | `2dec7a9b` | 0 |
| `lead/whistleblower-cap-spec` | `1449f736` | 0 |
| `mempool/admission-price` | `1bc0fbba` | 0 |
| `ops/transporte-libp2p` | `ad535739` | 0 |
| `perf/forkchoice-quadratic` | `7f30255b` | 0 |
| `pmo/integracao` | `472525be` | 0 |
| `pmo/leak-zero` | `49d54778` | 0 |
| `pmo/net-queue-block-reserve` | `2dec7a9b` | 0 |
| `pmo/particao-repro-salvo` | `f082a37d` | 0 |
| `pmo/wp1-libsplit` | `03d535f7` | 0 |
| `pmo/wp11-selectbreak` | `5a3be493` | 0 |
| `pmo/wp2-p2pframe` | `71f5a270` | 0 |
| `pmo/wp3-bytebudget` | `c69ba28d` | 0 |
| `pmo/wp5-storescan` | `be5c6188` | 0 |
| `pmo/wp6-fuzz` | `33f92d35` | 0 |
| `pmo/wp7-syncmeasure` | `b41ee77b` | 0 |
| `pmo10/cunhagem-legacy-deposit` | `a5c20a90` | 0 |
| `pmo10/defeitos-latentes` | `a5c20a90` | 0 |
| `r2/fila-quota` | `1d81f827` | 0 |
| `recovery/auxpow-onto-g3` | `00580dd1` | 0 |
| `relanca/e1400` | `9bde6835` | 0 |
| `relanca/e1400-quatro-portoes` | `0a3a436a` | 0 |
| `rev-adv-evm-pqtx-8842` | `1729d461` | 0 |
| `rev-adv-l1-precompile-8842` | `7b60b151` | 0 |
| `rev-fs-eutxo-audit` | `2191d0d0` | 0 |
| `rev-iso-euvm-1787` | `ca3e960c` | 0 |
| `rev-isolamento-vmhost` | `9df4aa9a` | 0 |
| `rev-svm-corr-8822` | `6c95dd38` | 0 |
| `rev-vm-conformidade-correcao` | `a4600c83` | 0 |
| `rev-vmhost-corr` | `9df4aa9a` | 0 |
| `rev-writeoff-adv` | `1449f736` | 0 |
| `review-iso-sbpf-1787419282` | `133bbfd5` | 0 |
| `review/attack-lens-hold` | `348e88dc` | 0 |
| `review/corr-hold-63066` | `348e88dc` | 0 |
| `spec/funded-epoch-discipline` | `ec7fbc75` | 0 |
| `tokenomics/v4-sem-cliff` | `96c3b041` | 0 |
| `worktree-agent-a087ea83a391a7f0a` | `16ee4b0a` | 0 |
| `worktree-agent-a101bfb4ec149a897` | `61f82dc0` | 0 |
| `worktree-agent-a1315f5708e6838b1` | `6c319e71` | 0 |
| `worktree-agent-a22395c3fedb01315` | `153d3bf1` | 0 |
| `worktree-agent-a26bcc84e23ca2e0e` | `9071ebae` | 0 |
| `worktree-agent-a58dfe6cc066ef5b3` | `7c311b04` | 0 |
| `worktree-agent-a5a0a10bb332b59ca` | `e9c79471` | 0 |
| `worktree-agent-a6dd9e3aeb299f61f` | `d3211c0a` | 0 |
| `worktree-agent-a8d120c5f3f02167b` | `249b835f` | 0 |
| `worktree-agent-a951fd6e3b13ed852` | `1ad75761` | 0 |
| `worktree-agent-a9c4ba491715890b9` | `57bd9a8e` | 0 |
| `worktree-agent-aa6f5cb9b6df96da0` | `6c1c1168` | 0 |
| `worktree-agent-abf46cd00b26aa61a` | `bed1b9ce` | 0 |
| `worktree-agent-ad531a8ccfff9329a` | `13b51672` | 0 |
| `worktree-agent-ae11cce07854da4e6` | `6a95830c` | 0 |
| `worktree-agent-af82db364b6af58db` | `037a8177` | 0 |
| `worktree-wf_a64751d6-225-3` | `090fb32c` | 0 |
| `worktree-wf_bdf284a3-d73-6` | `e41d5b0f` | 0 |

### C. A different repository (3 branches)

Disjoint root commit `81ca189b`; `git merge-base` against `main` is empty. This
is DEX work (Tiago Acioli, 2026-08-21) that was committed into the wrong
checkout. Safe to delete **from this repository** — but its home repository was
not inspected from here, so each tip is tagged first. **Confirm the DEX repo
has this work before removing the tags.**

| branch | tip | tree | commits not elsewhere |
|---|---|---|---|
| `worktree-wf_2f249654-872-4` | `f0a549d6` | tree_unique | 904 |
| `worktree-wf_2f249654-872-5` | `3855050e` | tree_unique | 902 |
| `worktree-wf_2f249654-872-6` | `494a2aa5` | tree_unique | 906 |

### D. Held unique content, now rescued (7 branches)

Safe to delete only because of the landings and tags above.

| branch | tip | tree | commits not elsewhere |
|---|---|---|---|
| `perf/network-sync` | `e904a6db` | tree_unique | 1 |
| `probe/cold-start-truth` | `f6eeae4c` | tree_unique | 1 |
| `worktree-agent-a48d92d26ab7195a5` | `bf0db0df` | tree_unique | 1 |
| `worktree-agent-a4cc97faeeb1fb600` | `b12741c8` | tree_unique | 127 |
| `worktree-agent-a507f9e34561ceb62` | `819fec7d` | tree_unique | 127 |
| `worktree-agent-a783f4d0602e0cad4` | `2e76886d` | tree_unique | 1 |
| `worktree-agent-a866e1876d1227f9f` | `83cae4f1` | tree_unique | 1 |

---

## How to re-run this check

```sh
# the 190 surviving branches
comm -13 DELETE.txt <(git for-each-ref --format='%(refname:short)' refs/heads | sort -u) > keep.txt

# any commit in the deletion set reachable from nothing that survives
for b in $(cat DELETE.txt); do
  n=$(git rev-list --count "$b" --not $(cat keep.txt) $(git tag -l 'salvage/2026-09-01/*'))
  [ "$n" != 0 ] && echo "$b $n"
done

# any tip file whose content exists nowhere else (skip mode 160000 gitlinks —
# a submodule pointer is not a blob and will read as a false positive)
git rev-list --objects $(cat keep.txt) $(git tag -l 'salvage/2026-09-01/*') \
  | awk 'NF>1{print $1}' | sort -u > keep_blobs.txt
for b in $(cat DELETE.txt); do
  git ls-tree -r --format="$b%x09%(objectmode)%x09%(objectname)%x09%(path)" "$b" \
    | awk -F'\t' '$2!="160000"'
done | awk -F'\t' 'NR==FNR{k[$1]=1;next} !($3 in k)' keep_blobs.txt -
```

Both must come back empty. They did on 2026-09-01, except for the two
tree-and-subject duplicates named in the summary.

**Branch tips move.** One branch in this set (`perf/network-sync`) gained a
commit while this analysis was running. Re-run the check immediately before
deleting anything, and compare the tips against the ones recorded above.
