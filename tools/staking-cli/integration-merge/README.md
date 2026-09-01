# Reference copies of the merged consensus files

`bloch-stake` (this tool) was built and its tests were run against a
`bloch-pos-committee` / `bloch-pos-node` tree that merges the three staking
work-stream branches (see `../INTEGRATION-NOTES.md` for the six integration
decisions that merge required):

- `worktree-agent-a087ea83a391a7f0a` — funded deposit (`DepositV2`)
- `worktree-agent-a1315f5708e6838b1` — signed exit + legacy-tag closure
- `worktree-agent-a9c4ba491715890b9` — withdrawal crank

base commit: `e4083f9684f283af35e6b4a7ff68507b16d9d45f`.

`merged-consensus-files.tar.gz` holds the exact post-merge versions of the
five contested files (the only files more than one stream touched):

- `crates/bloch-pos-committee/src/params.rs`
- `crates/bloch-pos-committee/src/staking.rs`
- `crates/bloch-pos-committee/src/transition.rs`
- `crates/bloch-pos-node/src/engine.rs`
- `crates/bloch-pos-node/src/rpc.rs`

The single-owner files (`interfaces.rs`, node `keys.rs` from the deposit
stream; node `store.rs` from the exit stream) come verbatim from their
branches and are not duplicated here.

These are REFERENCE copies so the verified combination is reproducible when
the branches are merged for real. They are not compiled from this
directory. Delete this directory once the streams have landed.
