export const meta = {
  name: 'roadmap-execution',
  description: 'Advance the Bloch-SIS roadmap: audit every track to its gate, plan per-track, implement the top buildable workstreams (P1 FRI verifier, S3 multi-node harness, P4 view keys, S5 cargo-audit+metrics) as reviewable patches, synthesize progress + remaining gates',
  phases: [
    { title: 'Audit' },
    { title: 'Plan' },
    { title: 'Implement' },
    { title: 'Synthesis' },
  ],
}

const REPO = '/Users/tiagoacioli/dev/BlochSISPoW-project'

const CTX = `
PROJECT: Bloch-SIS — a post-quantum, privacy-first blockchain (node + SIS-gated hashcash PoW + hybrid Falcon‖ML-DSA signatures + attestation L1-L3 + the Coherence shielded-tx privacy layer + SP1/FRI prover + clients). REPO: ${REPO} (branch euvm/integrate).

THE ROADMAP (ROADMAP.md + docs/ROADMAP-GATED-ITEMS.md). North star: maximize SECURITY and PRIVACY; add DEPTH not surface.
Security track: S1 canonical PoW security claim (freeze k=8/β=q/16 gate params + no-shortcut proof + calibrate difficulty — RESEARCH-GATED); S2 independent audit + fuzzing (EXTERNAL-GATED, but continuous differential fuzzing harnesses are buildable); S3 live multi-node network (deploy ≥3 seeds is gated, but the in-process two-NetworkNode convergence + adversarial harness is BUILDABLE); S4 attestation on real SEV-SNP/TDX hardware (HARDWARE-GATED); S5 supply-chain + key hygiene (cargo-audit CI + SLSA + reorg observability metrics bloch_reorg_* are BUILDABLE; PAT/HSM rotation is operator-gated); S6 on-chain k-of-n multisig custody GIP-008 (descriptor-hash output type + consensus verification is BUILDABLE; activation is live-net-gated); S7 FFG-BFT finality overlay (scaffold exists at bft/postern-bft-finality; gated on S1+S2).
Privacy track (Coherence): P1 turn shielded tx ON — wire the node-side FRI verifier replacing the reject-all verify=false stub, into the block-verify/reorg path (the verifier + integration is BUILDABLE; SP1-prover GPU deploy is the external gate); P2 external audit (GATED); P3 network metadata privacy — Dandelion++ routing core done (src/dandelion.rs), the unicast stem transport is BUILDABLE (live-net test gated); P4 wallet privacy — diversified addresses done (crypto::diversified_*, WalletCore::address_at/sign_at), REMAINING & BUILDABLE: surface rotation in client UIs, encrypted-at-rest keystores, and VIEW KEYS / selective disclosure (MatRiCT-Au-style opt-in, user-side, never a protocol backdoor); P5 lattice upgrade (AUDIT-GATED).
Enablers: OS images (Nix-host-gated), mobile wallet UI, Blochscan explorer hosting, whitepaper (threat model written docs/THREAT-MODEL.md; consolidated whitepaper pending).
RULE OF ENGAGEMENT: engineering builds EVERYTHING up to each item's gate and STATES the gate; nothing gated is reported "done". No consensus break without a GIP + node-operator signaling. No inflation/premine beyond genesis 17%. No misleading claims.

DELIVERY MODE: produce REVIEWABLE artifacts as TEXT (unified diffs, full new files, plans). DO NOT modify files in ${REPO} — return diffs/contents; the human operator applies them in an isolated worktree, builds, and tests. Consensus/crypto code is high-risk: prefer additive, well-tested, gate-aware changes.
`

const FINDINGS_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['area', 'implemented', 'engineering_gap', 'gate', 'buildable_now', 'files', 'recommended_deliverable'],
  properties: {
    area: { type: 'string' },
    implemented: { type: 'string', description: 'What already exists in the codebase for this area (with file refs)' },
    engineering_gap: { type: 'string', description: 'What engineering work remains BEFORE the external gate' },
    gate: { type: 'string', description: 'The external gate (audit / hardware / live-net / legal / research) — or "none, fully buildable"' },
    buildable_now: { type: 'boolean' },
    files: { type: 'array', items: { type: 'string' } },
    recommended_deliverable: { type: 'string', description: 'The concrete buildable artifact to produce now' },
  },
}

const AUDIT_AREAS = [
  { key: 'S1-pow-params', label: 'assist:S1-pow-hardness',
    prompt: 'Audit S1 (canonical PoW security claim). Read crates/bloch-sis-pow (verify/solver/params), legacy/specs/POW-HARDNESS.md, deploy/pow-estimator. What k/β params exist, where is the relaxed testnet regime vs canonical, what is buildable now (param freeze plumbing, calibration harness, estimator runs) vs research-gated (the no-shortcut proof).' },
  { key: 'S2-fuzz', label: 'assist:S2-fuzzing',
    prompt: 'Audit S2 fuzzing surface. Identify the consensus engine, tx/block deserialization, PoW verify, and PEX entry points that need differential/continuous fuzzing. What fuzz harnesses (cargo-fuzz/libfuzzer/proptest) exist or are buildable now. The external audit itself is gated; the fuzz harnesses are buildable.' },
  { key: 'S3-multinode', label: 'assist:S3-multinode',
    prompt: 'Audit S3. Find the NetworkNode/network stack (src/network, gossipsub, sync). Is there an in-process two-node convergence harness (inherited Sprint EE)? What adversarial cases (equivocation, invalid blocks, eclipse) are testable in-process. Deploying real seeds is gated; the in-process harness is BUILDABLE.' },
  { key: 'S5-supplychain', label: 'assist:S5-supplychain-metrics',
    prompt: 'Audit S5. Is there cargo-audit in CI, SLSA/signed-release config, and reorg observability metrics (bloch_reorg_*, inherited Sprint FF)? Where would the metrics hook into the DAG/reorg path. cargo-audit CI + metrics are BUILDABLE; PAT/HSM rotation is operator-gated.' },
  { key: 'S6-multisig', label: 'assist:S6-multisig-gip008',
    prompt: 'Audit S6 / GIP-008. Read gips/ and docs/research/MOFN-CUSTODY-DECISION.md and the output/script model (core). GIP-008 is APPROVED for an on-chain k-of-n hybrid Falcon‖ML-DSA descriptor-hash output type. What consensus code (new output type + verification) is buildable now; activation is live-net-gated. Assess risk (consensus change).' },
  { key: 'P1-fri', label: 'assist:P1-FRI-verifier',
    prompt: 'Audit P1. Find the Coherence shielded-tx path + the reject-all verify=false stub for the node-side FRI verifier (grep verify=false / FRI / SP1 / coherence). What is needed to wire a real node-side FRI verifier into the block-verify/reorg path. The verifier+integration is BUILDABLE; the SP1-prover GPU deploy is the external gate.' },
  { key: 'P3-dandelion', label: 'assist:P3-dandelion-stem',
    prompt: 'Audit P3. Read src/dandelion.rs (routing core, DandelionRelay, RelayAction). The routing core is done+unit-tested. What is needed for the unicast stem transport (gossipsub is broadcast-only) and wiring the relay into the tx path (Fluff=gossipsub publish works today). Live-net test is the gate; the transport code is BUILDABLE.' },
  { key: 'P4-wallet-privacy', label: 'assist:P4-viewkeys-wallet',
    prompt: 'Audit P4. Diversified addresses are done (crypto::diversified_{seed,keypair,address}, WalletCore::address_at/sign_at). REMAINING & BUILDABLE: surfacing rotation in the client UIs, encrypted-at-rest keystores, and VIEW KEYS / selective disclosure (MatRiCT-Au-style, user opt-in). Find the wallet core + client UI code; specify the buildable view-key / selective-disclosure design (never a protocol backdoor).' },
]

phase('Audit')
const audit = (await parallel(AUDIT_AREAS.map(a => () =>
  agent(`${CTX}\n\nYOU ARE A ROADMAP-AUDIT ASSISTANT for area: ${a.key}.\n${a.prompt}\n\nRead the actual code before answering. Distinguish clearly what is BUILDABLE NOW vs blocked on an external gate. Return structured findings.`,
    { label: a.label, phase: 'Audit', schema: FINDINGS_SCHEMA })
))).filter(Boolean)
log(`Audit complete: ${audit.length}/${AUDIT_AREAS.length} areas; buildable-now: ${audit.filter(a=>a.buildable_now).length}`)

phase('Plan')
const PLAN_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['track', 'ordered_items', 'top_buildable_workstream'],
  properties: {
    track: { type: 'string' },
    ordered_items: { type: 'array', items: { type: 'object', additionalProperties: false,
      required: ['item', 'buildable_deliverable', 'gate', 'risk'],
      properties: { item: {type:'string'}, buildable_deliverable: {type:'string'}, gate: {type:'string'}, risk: {type:'string', enum:['low','medium','high']} } } },
    top_buildable_workstream: { type: 'string', description: 'The single highest-value buildable deliverable in this track, specified concretely enough for a dev to implement' },
  },
}
const TRACKS = [
  { key: 'PMO-Security', prompt: 'You own the SECURITY track (S1,S2,S3,S5). Synthesize the audit into an ordered, gate-aware plan; pick the top BUILDABLE security deliverable (likely the S3 in-process multi-node convergence+adversarial harness).' },
  { key: 'PMO-Privacy', prompt: 'You own the PRIVACY track (P1,P3,P4). Synthesize into an ordered plan; pick the top BUILDABLE privacy deliverable (P1 node-side FRI verifier wiring is the biggest privacy win, or P4 view keys).' },
  { key: 'PMO-Enablers', prompt: 'You own ENABLERS + supply-chain (S5 cargo-audit CI + reorg metrics, whitepaper, Blochscan, mobile UI, OS images). Pick the top BUILDABLE deliverable (S5 cargo-audit CI + bloch_reorg_* metrics).' },
  { key: 'PMO-Consensus', prompt: 'You own CONSENSUS-GATED items (S6 GIP-008 multisig, S7 FFG-BFT). Assess what consensus code is buildable-but-not-activatable (descriptor-hash output type; FFG scaffold buildout) and the GIP/activation gates. Flag risk honestly.' },
]
const plans = (await parallel(TRACKS.map(t => () =>
  agent(`${CTX}\n\nAUDIT FINDINGS (JSON):\n${JSON.stringify(audit)}\n\nYOU ARE ${t.key}. ${t.prompt}\nReturn a gate-aware ordered plan for your track and your single top buildable workstream.`,
    { label: t.key, phase: 'Plan', schema: PLAN_SCHEMA, effort: 'high' })
))).filter(Boolean)
log(`Plans done for ${plans.length} tracks`)

phase('Implement')
const PATCH_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['title', 'workstream', 'files_touched', 'unified_diff', 'new_files', 'gate_stated', 'how_to_build_and_test'],
  properties: {
    title: { type: 'string' },
    workstream: { type: 'string' },
    files_touched: { type: 'array', items: { type: 'string' } },
    unified_diff: { type: 'string', description: 'git-applyable unified diff for edits to existing files (empty if only new files)' },
    new_files: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['path','contents'], properties: { path:{type:'string'}, contents:{type:'string'} } } },
    gate_stated: { type: 'string', description: 'The external gate this deliverable stops at (per the rule of engagement)' },
    how_to_build_and_test: { type: 'string' },
  },
}
const DEVS = [
  { key: 'dev1-P1-FRI', prompt: 'YOU ARE DEV-1 (Fable-5). Implement P1: wire a node-side FRI verifier that REPLACES the reject-all verify=false stub in the Coherence shielded-tx path, integrated into the block-verify/reorg wiring, feature-gated/config-gated so it is safe to land before the SP1-prover GPU deploy (the external gate). Additive, well-tested. Read the real Coherence/verify code first. Return the patch + tests; STATE the SP1-deploy gate. Do not modify repo files.' },
  { key: 'dev2-S3-harness', prompt: 'YOU ARE DEV-2 (Fable-5). Implement S3: an in-process two-NetworkNode convergence + adversarial (equivocation / invalid-block / eclipse) test harness proving consensus/reorg/gossip without real seeds. Read src/network. Return the harness + test cases as a patch; STATE the live-seed-deploy gate. Do not modify repo files.' },
  { key: 'dev3-P4-viewkeys', prompt: 'YOU ARE DEV-3 (Fable-5). Implement P4: VIEW KEYS / selective disclosure (MatRiCT-Au-style, user opt-in, NEVER a protocol backdoor) on top of the existing diversified-address wallet core, plus encrypted-at-rest keystore hardening. Read the wallet core + crypto::diversified_*. Return the patch + tests; STATE any audit gate for the disclosure-proof claim. Do not modify repo files.' },
  { key: 'dev4-S5-ci-metrics', prompt: 'YOU ARE DEV-4 (Fable-5). Implement S5 buildable pieces: (1) cargo-audit + a supply-chain check in CI (GitLab CI is used — .gitlab-ci.yml), (2) reorg observability metrics bloch_reorg_* hooked into the DAG/reorg path (inherited Sprint FF). Read the CI config + the reorg/DAG code. Return the patch(es)/new files + how to verify; STATE the SLSA/HSM operator gates. Do not modify repo files.' },
]
const patches = (await parallel(DEVS.map(d => () =>
  agent(`${CTX}\n\nRELEVANT PLANS (JSON):\n${JSON.stringify(plans)}\n\n${d.prompt}`,
    { label: d.key, phase: 'Implement', schema: PATCH_SCHEMA, model: 'fable', effort: 'high' })
))).filter(Boolean)
log(`Dev patches ready: ${patches.length}/${DEVS.length}`)

phase('Synthesis')
const REPORT_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['headline', 'delivered', 'apply_order', 'remaining_gates', 'updated_next_moves'],
  properties: {
    headline: { type: 'string' },
    delivered: { type: 'array', items: { type: 'string' } },
    apply_order: { type: 'array', items: { type: 'string' }, description: 'Exact order to apply/build/test the patches in an isolated worktree' },
    remaining_gates: { type: 'array', items: { type: 'string' }, description: 'Per roadmap item, the external gate still open (audit/hardware/live-net/legal/research)' },
    updated_next_moves: { type: 'array', items: { type: 'string' } },
  },
}
const report = await agent(
  `${CTX}\n\nPLANS:\n${JSON.stringify(plans)}\n\nDEV PATCHES (metadata + gates; diffs truncated):\n${JSON.stringify(patches.map(p=>({title:p.title,workstream:p.workstream,files:p.files_touched,gate:p.gate_stated,test:p.how_to_build_and_test}))).slice(0,40000)}\n\nYOU ARE THE LEAD PMO. Produce the roadmap-progress hand-off: what was delivered (buildable-now), the exact apply/build/test order for the patches in an isolated worktree, the honestly-stated remaining external gates per item (nothing gated marked done), and the updated "next three moves".`,
  { label: 'PMO:roadmap-synthesis', phase: 'Synthesis', effort: 'high', schema: REPORT_SCHEMA })

return { audit, plans, patches, report }