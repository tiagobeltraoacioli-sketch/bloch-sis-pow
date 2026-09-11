# Bloch Builders

A developer community around working examples, reproducible feedback and
reviewed contributions. Initial tracks: Solidity/EVM, Solana/SBF and Bloch
network integration.

## Your first contribution

1. Install the DevKit and run `bloch-dev doctor`.
2. Create one starter and deploy it locally using its README.
3. Record your OS, CPU, runtime versions and exact commands.
4. Open a reproducible issue or propose a small pull request. Remove keys,
   mnemonics, credentials and personal data from logs.
5. Include the test you ran and explain the result. All repository
   contributions are in English; community conversations may be multilingual.

GitHub Issues is enabled at
https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/issues.
Repository access may be required. GitHub Discussions is not enabled as of
2026-09-10; no Discord server, office-hours schedule or grant is announced.

## Starter backlog (proposed, not assigned)

| Task | Track | Done when |
|---|---|---|
| Reproduce installation on Apple Silicon | Tooling | Versioned logs, successful deploy/call, restart persistence |
| Add a Solana counter interface | SVM | Uses the included client flow, displays account state and handles wrong-authority errors |
| Add an EIP-1193 starter UI | EVM | Connects to local chain, deploys/calls counter, handles wrong-chain errors |
| Add RPC export failure regressions | Tooling | Tests unavailable finalized blocks, oversized responses and wrong chain |
| Port signed-batch replay to a standalone tool | EVM integration | Existing Bloch L2 verification succeeds on valid input and rejects tampering |
| Specify SVM deterministic execution | SVM integration | Runtime/features, sysvars, account loading and replay vectors are reviewed |

## Founding developer cohort — launch proposal

Start with 10–20 builders. Week 1: installation and first transaction. Week 2:
ship an example or integration test. Week 3: review another contribution and
resolve one reported issue. Week 4: demonstrate the application and document
what blocks Bloch network integration. This is a proposed program, not an
open registration or a published event calendar.

Measure successful first runs, first merged contributions, seven-day returning
builders, time to first maintainer response and reproducible example count.
Follower count alone does not measure developer adoption.

Before launch, assign maintainers and moderation coverage, decide public
repository access, enable a discussion channel and publish a real schedule.
Maintain respectful technical discussions; report abuse privately to repository
maintainers. Do not post security vulnerabilities in public issues; use the
repository's security reporting procedure.
