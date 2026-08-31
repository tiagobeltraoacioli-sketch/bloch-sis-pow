# Coherence SP1 prover on Fly.io

The GPU proving half of the shielded pool. A wallet POSTs `(public, witness)` to
`/prove` and gets back a **raw FRI proof** (post-quantum) that the C1 spend
statement (`check_spend`) held. The node verifies that FRI proof **locally** and
trustlessly — it never calls this service to decide consensus. This box only
does the expensive proving.

```
wallet ──(public, witness)──▶  /prove  ──▶ raw FRI proof ──▶ ShieldedTx.proof
node   ── verifies the FRI proof locally (sp1-sdk verifier) ── no trust in this box
```

## PRIVACY — the operator of this box sees the full witness

"No trust in this box" above is about **consensus** (a bad proof is rejected by
every node). It is NOT about **privacy**: every `/prove` request hands this
service the complete spend witness — input notes with their values, output
notes, Merkle paths, and the wallet's **nullifier key `nk`**, which links that
wallet's past and future shielded spends. Whoever operates this machine (and
its cloud provider) can read all of it, for every wallet that delegates.
Delegated proving exists because local proving needs desktop-class hardware
(83–215 s and ~16 GB for a 2-in/2-out spend — `COHERENCE-PROOF-SIZE-2026-08-29`);
it is a hardware workaround, not a private protocol. Self-host it, or accept
showing your entire shielded history to the operator. Never market this
endpoint as "private".

## Why this shape

- **Proving is heavy** (seconds–minutes, GBs of RAM, ~GPU) → a dedicated,
  scale-to-zero GPU machine. **Verifying is cheap** → stays in the node.
- **Self-hosted, not a third party.** For a privacy chain, the prover runs on
  infra you control (see the Succinct Network alternative below).
- **Post-quantum coherence:** the service proves with `SP1ProofMode::Core`
  (STARK/FRI) and never `.groth16()/.plonk()` — an elliptic-curve wrap would be
  Shor-breakable. It also refuses to serve or validate non-Core envelopes.

## Best-practice setup (what this config does)

- **GPU L40S, scale-to-zero.** Idle → 0 machines → \$0. A `/prove` request
  cold-starts the GPU (seconds), proves, and the machine stops again after the
  idle window. You pay GPU only while proving.
- **Artifact cache on a volume** (`/data`, `SP1_HOME`). SP1 downloads circuit
  artifacts / proving keys (GBs) on first use; the volume keeps them across cold
  starts so wakes are fast.
- **Bearer-token auth** on `/prove` (`PROVER_AUTH_TOKEN` secret) so the GPU isn't
  an open compute faucet. `/health` and `/verify` are cheap and unauthenticated.
- **Concurrency 1/machine** — one proving job per GPU; scale out with more
  machines, not by overloading one.

## Deploy

```bash
fly launch  --config deploy/sp1-prover/fly.toml --no-deploy
fly volumes create sp1_artifacts --size 20 --region ord
fly secrets set PROVER_AUTH_TOKEN=$(openssl rand -hex 32)
fly deploy  --config deploy/sp1-prover/fly.toml --dockerfile deploy/sp1-prover/Dockerfile
```

Test:
```bash
curl https://bloch-sp1-prover.fly.dev/health          # -> ok
curl -X POST https://bloch-sp1-prover.fly.dev/prove \
  -H "authorization: Bearer $PROVER_AUTH_TOKEN" \
  -H 'content-type: application/json' \
  -d @spend.json                                       # -> {"proof_b64":"..."}
```

## GPU vs CPU vs Succinct Network

| Option | Speed | Cost | Trust | When |
|---|---|---|---|---|
| **GPU (this config)** | fast | GPU/hr, only while proving | self-hosted | default |
| **CPU fallback** | slow (min) | cheap CPU machine | self-hosted | low volume / no GPU region |
| **Succinct Prover Network** | fast | network credits | third party | burst scale, no infra |

CPU fallback: remove the `[[vm]]` GPU block from `fly.toml`, build with
`--build-arg CUDA_FEATURE=""`, and swap the CUDA base images in the Dockerfile
for `rust:1-bookworm`. Everything else is identical (the service auto-uses the
CPU prover without the `cuda` feature).

## Gaps to close (honest)

- **The image build is untested until deployed.** The crates now compile and
  prove locally against the pinned toolchain (`sp1up --version v6.5.0`,
  `sp1-sdk =6.5.0` — pinned in the Dockerfile via `SP1UP_VERSION`), but this
  Docker/Fly recipe itself has not been exercised end-to-end on a GPU box.
- **Proof size is an open consensus problem.** Core is 5.3x and Compressed 2.4x
  the V2 block-tx cap (`COHERENCE-PROOF-SIZE-2026-08-29`). This service can
  produce proofs no block can carry yet.
- **Node-side verifier not wired yet.** The node still stubs proof verification
  to `false` (rejects shielded txs). Wiring `sp1-sdk`'s FRI verifier into the
  node's `verify_proof` closure (replacing the stub) is the step that actually
  turns shielded transactions on. That is a node change, tracked separately.
- **No privacy claim** until the whole pipeline is audited (Coherence C4).
