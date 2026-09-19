# Bloch Genesis-4
## Exchange integration corrections
12 September 2026 | Addendum to Edition 2

### 1. Phase-A ceremony: no confirmed date available
No confirmed ceremony or publication date is available in the evidence reviewed for this addendum. We cannot commit to a date or certify that a production checkpoint has been published. The 6 September note is a dated operator statement, not proof of the current operational state. Production deposit crediting remains blocked for the exchange's stated setup until the required trust bootstrap and independent observers are available.

Classification: OPERATOR-ASSERTED / UNCONFIRMED. Scheduling, signer participation and production publication require an operator confirmation. Local signing artifacts do not establish that a production ceremony was completed or that a checkpoint was publicly distributed. This addendum does not repeat the unverified claim that no keys have ever been generated.

To close this blocker, the operator must provide the ceremony outcome, a sufficiently recent signed checkpoint envelope, its signer-set file and policy, the checkpoint epoch/root, and matching digests through at least two trusted publication channels. A bare checkpoint is not the signed envelope. Successful fresh-node bootstrap and finality comparison must then be demonstrated. Publishing artifacts alone does not complete exchange production readiness.

### 2. Seeded data directories: not sufficient for crediting
Your reading is correct for the proposed setup. Copying blocks.log, meta.bin and ws_latest.bin from an operator does not, by itself, satisfy the independently operated observer requirement. It imports that supplier's historical trust anchor. Two copies of the same operator-supplied state do not provide independent corroboration of that history, even when run on separate machines.

Such a setup may support integration exercises, subject to trusting the supplier. It must not be described as meeting the normative production crediting rule. Independent operation and independent validation after an authenticated weak-subjectivity bootstrap are still required. Independent observers may use the same properly authenticated signed checkpoint: weak subjectivity explicitly requires a trust anchor, and this differs from accepting an unauthenticated data-directory copy.

Classification: POLICY CLARIFICATION. The portal's previous phrase that seeded nodes were "unaffected" was too broad and is replaced by this distinction.

### 3. Third path and the production gate
No verified third path is available for the exchange's stated situation today. In principle, two already-running, independently operated observers with established trust histories could supply corroboration, if their independence, provenance and access were verified and the exchange accepted that operating model. No such pair has been established in this review. Two endpoints belonging to one operator, a proxy quorum, or an explorer are not evidence of two independent operators.

Keep deposit crediting disabled until all requirements can be met: finalized_height >= H; approximately 30 epochs (8 hours) of continued, uninterrupted finality advance beyond that threshold; and agreement between two independently operated validating nodes on the finalized root at the same epoch. Reverify before releasing funds. A transaction-format exercise or gettxout response does not satisfy this gate.

### 4. Error -32010: endpoint split is useful, terminal split is wrong
At the read proxy, -32010 means no read quorum. Withhold credit, back off and retry the read; a retry is not permission to accept disputed data. VERIFIED-IN-CODE for the local explorer edge implementation; the deployed public endpoint's version remains OPERATOR-ASSERTED / UNCONFIRMED.

At the node, -32010 is TX_REFUSED_SOURCE_CAP: this spend-authority source already has 64 pending transactions. It is a temporary admission-capacity refusal, not terminal invalidity of those transaction bytes. Wait for a pending transaction from that source to leave the mempool, then retry if the transaction is still valid. There is no fixed until_slot promised for this code. Do not automatically rebuild or permanently fail a withdrawal solely because of -32010. VERIFIED-IN-CODE.

The terminal code is -32008 (TX_REFUSED). Code -32009 is a different retryable refusal with until_slot. Classify using endpoint, RPC method and the raw error body: a proxy forwarding sendrawtransaction may relay a node error. The exchange's read-proxy/direct-node routing distinguishes the meanings, but both -32010 cases are conditionally retryable. No error-code remap is claimed or deployed by this correction.

### 5. gettxout and the corrections delivered
gettxout(txid, vout) remains the exact lookup for a known outpoint and avoids reliance on a capped address-output listing. It does not enumerate unknown deposits or independently prove settlement. Its usefulness for addresses beyond 1,000 outputs is preserved. VERIFIED-IN-CODE for the RPC surface.

The local developer portal now states the production block next to the crediting rule, removes the seeded-directory implication of readiness, qualifies the old ceremony status, and explicitly corrects the -32010 retry guidance. Edition-2 reference, readiness confirmation and operator memo receive a prominent pointer to this addendum. No consensus logic, trust-window bypass, signing keys, production configuration or deployed endpoint is changed.

### Evidence and limits
Code review: bloch-sis-pow revision 4eec48b; developer portal baseline edf6d1c; explorer baseline f842811. Node evidence: crates/bloch-pos-node/src/rpc.rs, TX_REFUSED_SOURCE_CAP and gettxout; src/engine.rs, Refusal::TooManyFromSource mapping; src/ws_boot.rs, bootstrap enforcement. Proxy evidence: edge/governor.js, NO_QUORUM; edge/core.js, divergent_archivals response. Operational requirements: docs/CHECKPOINT-CEREMONY-CHECKLIST.md and docs/specs/BLOCH-WEAK-SUBJECTIVITY.md.

VERIFIED-IN-CODE describes inspected source behavior, not live deployment verification. OPERATOR-ASSERTED / UNCONFIRMED marks unresolved operational facts. POLICY CLARIFICATION explains how the existing crediting requirement applies. This addendum is a documentation correction, not a production-readiness certificate. No live node validation or confirmed publication record was obtained.
