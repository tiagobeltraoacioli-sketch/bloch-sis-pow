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

## Why this shape

- **Proving is heavy** (seconds–minutes, GBs of RAM, ~GPU) → a dedicated,
  scale-to-zero GPU machine. **Verifying is cheap** → stays in the node.
- **Self-hosted, not a third party.** For a privacy chain, the prover runs on
  infra you control (see the Succinct Network alternative below).
- **Post-quantum coherence:** the service uses `.core()` (STARK/FRI) and never
  `.groth16()/.plonk()` — an elliptic-curve wrap would be Shor-breakable.

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

- **Untested until deployed.** No SP1 toolchain runs in the dev sandbox, so this
  is a validated *recipe*, not a proven binary. Pin your SP1 version and confirm
  the `prove().core().run()` / `verify()` surface for it.
- **Node-side verifier not wired yet.** The node still stubs proof verification
  to `false` (rejects shielded txs). Wiring `sp1-sdk`'s FRI verifier into the
  node's `verify_proof` closure (replacing the stub) is the step that actually
  turns shielded transactions on. That is a node change, tracked separately.
- **No privacy claim** until the whole pipeline is audited (Coherence C4).
