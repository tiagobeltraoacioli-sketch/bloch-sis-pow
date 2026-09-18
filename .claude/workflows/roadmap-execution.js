export const meta = {
  name: 'roadmap-execution',
  description: 'Audit the checked-out Bloch source and current roadmap, derive scoped work from verified findings, and return reviewable patches with validation and remaining gates',
  phases: [
    { title: 'Audit' },
    { title: 'Plan' },
    { title: 'Implement' },
    { title: 'Synthesis' },
  ],
}

// Run the workflow host from the repository root. No personal checkout or branch is assumed.
const REPO = '.'

const CTX = `
PROJECT: Bloch. Repository root: ${REPO}, resolved from the workflow host's working directory. Read AGENTS.md and inspect the actual checkout, branch, Cargo workspace and current roadmap before planning. Do not infer fleet state, activation status or implementation gaps from this template.

SOURCE OF TRUTH: the checked-out code and tests, ROADMAP.md where present, current integration/release documents, and docs/audit/internal-remediation-2026-09-17/FINDINGS.md where present. Older audit records are evidence tied to their original source revisions, not automatically current defects. Distinguish live Genesis-4 PoS crates from retired Genesis-3 code and experimental subsystems. Locate files before citing them.

CONSTRAINTS: keep code, comments, reports and user-facing software text in English. Verify current consensus gates; never infer that a planned gate is active or silently change a historical validity rule. Treat the Coherence spend-authorization and funded-vault design questions as separate from proof verification or infrastructure deployment; wiring a verifier alone does not make a funded product safe. Do not assume an audit, hardware qualification or production deployment has occurred.

DELIVERY MODE: return reviewable patches, new-file contents and exact validation instructions as text. This workflow does not edit the checkout, publish artifacts, deploy, restart validators, issue credentials or authorize external messages. Report missing runtime/test capabilities honestly. Coordinate file ownership with any other active workstreams before proposing overlapping changes. No model/provider or founder-specific path is required by this template.
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
  {key: 'node-consensus', label: 'audit:node-consensus', prompt: 'Audit the live node and committee transition, fork choice, transaction status and current consensus gates. Separate source correctness from activation and independent-validator rollout. Find a reproducible defect before proposing behavior changes.'},
  {key: 'recovery', label: 'audit:recovery', prompt: 'Audit restart caches, log/index crash consistency, checkpoint validation, slashing protection and keystore handling. Preserve signing history and cache-format compatibility; quantify test scope rather than inventing restart SLAs.'},
  {key: 'network-admission', label: 'audit:network-admission', prompt: 'Audit actual transports, bounded queues, source admission, sync requests and RPC. Review existing tests before proposing another harness. Distinguish local admission policy from block validity.'},
  {key: 'supply-chain', label: 'audit:supply-chain', prompt: 'Audit both checked-in CI definitions, scanner enforcement, release/rollback tooling, pinned inputs and metrics. Hosted CI, canonical Linux builds, signatures and fleet parity require separate evidence.'},
  {key: 'crypto-wallet', label: 'audit:crypto-wallet', prompt: 'Audit current and optional/legacy wallet consumers, input amounts, signature encodings, secret lifetime and external verification vectors. Preserve funded derivations and distinguish primitive tests from standards certification.'},
  {key: 'shielded-vault', label: 'audit:shielded-vault', prompt: 'Audit the shared Coherence statement, SP1 service and vault construction/evaluator. Read current authorization blockers before proposing proof wiring. Keep funded activation blocked until its actual design and validation requirements are met.'},
  {key: 'legacy-carryover', label: 'audit:legacy-carryover', prompt: 'Audit retired Genesis-3 exporters and compatibility tools that affect the carried ledger. Do not present legacy network/mining paths as the active PoS node or silently rewrite committed carryover data.'},
  {key: 'integration-roadmap', label: 'audit:integration-roadmap', prompt: 'Read the actual roadmap and integration notes, including EVM, DEX, bridge and aggregator ownership where available. Identify cross-component contracts and remaining evidence without assuming another agent has or has not completed a task.'},
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
  { key: 'Plan-Node', prompt: 'Plan verified node/network corrections from this audit, ordered by impact and evidence. Assign concrete file ownership and distinguish admission policy from consensus validity. Do not prescribe a feature already implemented.' },
  { key: 'Plan-Recovery', prompt: 'Plan verified restart, checkpoint, durable-signing and key-handling corrections. State compatibility and rollback constraints. Keep deployment and measured recovery SLA separate from source work.' },
  { key: 'Plan-Wallet', prompt: 'Plan verified crypto/wallet/vault corrections, preserving funded derivations and existing formats. Separate primitive correctness, product authorization, external audits and activation requirements.' },
  { key: 'Plan-Infrastructure', prompt: 'Plan verified CI, release, observability and explorer corrections. Identify coordination with other integration workstreams and required hosted/Linux/GPU evidence. Do not treat a local patch as deployment.' },
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
  {key: 'dev-node', prompt: 'Take the highest-priority verified node/network finding from the plans. Return the smallest compatible patch and meaningful regression. Preserve consensus gates and state encoding. Coordinate recovery ownership and state what remains unresolved.'},
  {key: 'dev-recovery', prompt: 'Take the highest-priority verified recovery/key-handling finding from the plans. Return a patch with crash/fallback or secret-handling regressions as appropriate. Preserve durable signing history and state/cache compatibility; do not promise production recovery time without measurements.'},
  {key: 'dev-wallet', prompt: 'Take the highest-priority verified crypto/wallet/vault finding from the plans. Return a compatible implementation and adversarial tests. Do not turn infrastructure improvements into a funded-authorization claim or silently replace funded derivations.'},
  {key: 'dev-infrastructure', prompt: 'Take the highest-priority verified CI/release/observability/explorer finding from the plans. Return a reviewable patch with relevant validation. Distinguish local checks from hosted CI, Linux/GPU qualification and fleet deployment.'},
]
const patches = (await parallel(DEVS.map(d => () =>
  agent(`${CTX}\n\nRELEVANT PLANS (JSON):\n${JSON.stringify(plans)}\n\n${d.prompt}`,
    { label: d.key, phase: 'Implement', schema: PATCH_SCHEMA, effort: 'high' })
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