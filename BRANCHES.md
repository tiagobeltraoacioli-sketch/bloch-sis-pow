# Branch index: the lines pushed on 2026-11-17

Which branch is what, which is audited or reviewed, which is work in progress, and how to verify it.
Tips are those of `origin` at 2026-11-17 04:32 UTC; branches keep moving during the day, so read the current tip with
`git ls-remote origin <branch>`. "Audit candidate" and "fit for external audit" are the verdicts of this
project's own reviewers; no external audit has been done. Nothing on any branch is deployed by being here.

| Branch | Tip | What it is | Status |
|---|---|---|---|
| `main` | `857a10ac2` | Bloch L1 node; merges by pull request (another session owns this main) | released node line |
| `codex/l2-r15-recipients-20261116` | `0861278c5` | December build native side with the owner's recipients | superseded by the December merge line |
| `codex/l2-r17-20261117` | `189f31787` | L2 native open items after round 17 (agent 334) | under review (review 335 / 384) |
| `codex/l2-review-r17-20261117` | `b0735cd85` | Reviewer demonstrations | review material, not for merge |
| `codex/native-l2-admission-r17-20261117` | `d8aa062f4` | L2 mempool admission on the release line | WIP |
| `codex/native-l2-dec-merge-r17-20261117` | `f596fb78b` | December L2 native side merged onto the released node (agent 382) | WIP; every L2 gate stays inert; pull request after the consensus-identity proof |
| `codex/wallet-consensus-20261117` | `e6a393730` | Wallet work of another session | not part of the L2/DEX/bridge rounds |
| `codex/wallet-delegation-protocol-20261003` | `46e2f4d29` | Wallet work of another session | not part of the L2/DEX/bridge rounds |
| `merge/node-0067547f-into-main` | `5c0715b98` | The merge of release 0067547f into main (pull request #35) | merged |
| `release/node-0067547f-20261115` | `0067547f1` | Deployed node release 0067547f | release |

Status words: **audit candidate / fit for external audit**: the internal reviewers found no open Critical,
High or Medium finding on that tip; **reviewed**: an internal review pass covered that tip; **WIP**: work in
progress, tests not necessarily green; **superseded**: kept for history, do not build on it; **review
material**: tests and scripts that demonstrate review findings, never merged.

## How to verify a line

```
git fetch origin
git checkout --detach origin/<branch>
cargo test --locked (see the repository README for the release suites)
```

A tip's own documents (the route or package document under `docs/`) give its full test table and rehearsals.
