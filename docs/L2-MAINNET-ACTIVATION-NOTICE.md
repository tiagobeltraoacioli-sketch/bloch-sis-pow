# NOTICE — Bloch native L2 activation on mainnet (mandatory node upgrade)

> **TEMPLATE — not yet published.** Every `{{…}}` is a placeholder that must be
> filled before publication. Publish only after all of the following are true
> (docs/L2-MAINNET-ACTIVATION.md, "What remains before arming"): the attestor
> set is committed (`mainnet::ATTESTOR_SET`), the SP1 program and L2 genesis
> are committed (`mainnet::PROGRAM`), the archival replay of mainnet history
> is PASS, and `scripts/l2-activation/final-qualification.sh` is PASS on the
> final commit. The notice must go out **at least 14 days before epoch E**.
> A Portuguese version is in `L2-MAINNET-ACTIVATION-NOTICE.pt-BR.md`; keep
> both in sync.

| | |
| --- | --- |
| Published | {{PUBLICATION DATE, UTC}} (T−14 days or earlier) |
| Activation epoch **E** | **{{E}}** — first slot {{32·E}}, expected around {{DATE/TIME UTC}} (30 s slots, 32 slots per epoch; the epoch number, not the clock time, is binding) |
| Release | `bloch-pos` {{VERSION}}, commit `{{FULL 40-HEX COMMIT}}` |
| Binary SHA-256 (Linux x86-64) | `{{SHA256}}` |
| Release signing key | `{{bloch-release-YYYYMMDD.pub}}` (minisign), fingerprint `{{KEY ID}}` |
| Download | `{{RELEASE URL}}` and `releases/bloch-pos-{{YYYY-MM-DD}}/` in the repository |
| Who must act | **every** validator, archival / RPC node, bootnode, explorer, indexer and exchange node |

## 1. Summary

At the first block of epoch **E**, Genesis-4 mainnet activates the **native
L2 settlement layer** (EVM-compatible L2, chain id **700770**). This is a
**consensus change (hard fork)**: from that block on, the L1 state root
carries a new L2 component. A node that has not upgraded **rejects that block
(`StateRootMismatch`) and stops following the chain at epoch E.** There is no
runtime switch and no way to opt out on mainnet.

Nothing changes before epoch E: the new release behaves exactly like the
current one, produces identical blocks and state roots, and refuses every L2
transaction until E. Upgrading early is safe and is what we ask for.

## 2. What changes at epoch E

- **L2 installation.** The boundary into epoch E installs the L2 with the
  policy pinned in the release; the first block of E is the L2's native height 1.
  Historical blocks and roots are unchanged.
- **New L1 transaction types become valid**: asynchronous L2 settlements
  (0x13), native deposits into the L2 inbox (0x14), L2 data availability
  (0x15) and L2 withdrawal claims (0x16). Before E they are refused by the
  mempool and invalid in blocks. Synchronous settlements (0x12) stay refused
  by the node.
- **Settlement mode: asynchronous.** Deposits and withdrawals exist only in
  this mode; every L2 batch is published on L1 (data availability) and
  settled with a succinct proof against the pinned SP1 program
  (`{{PROGRAM / ELF HASH}}`, L2 genesis `{{INITIAL L2 STATE}}`).
- **Attestor set, fixed at activation**: **3-of-5** post-quantum hybrid keys
  (ML-DSA-65 + Falcon-1024), five operators on separate hosts. Set hash
  `{{ATTESTOR SET HASH}}`. Set-once: there is no rotation, no admin key and
  no upgrade path other than a new, publicly announced activation.
- **Escrow.** BLCH deposited into the L2 is held in a consensus escrow on L1;
  the escrow is conserved by every block (checked by every node).

## 3. Withdrawal rules (L2 → L1)

All claims require that the settlement containing the withdrawal is
**FFG-finalized** on L1; the delays below come on top of finality.

| Claim amount | Requirement | Delay after the withdrawal's settlement |
| --- | --- | --- |
| **< 100 BLCH** | proof against a finalized settlement | **64 blocks** (two epochs, ≈ 32 min at full slot occupancy) |
| **≥ 100 BLCH** | the above **plus 3-of-5 attestor signatures** | **2 880 blocks** (≈ 24 h at full slot occupancy) |

**Release window (rate limit).** In every window of **2 880 blocks** the
total released to L1 is capped at **10 % of the escrow, with a floor of
10 BLCH**. Only an attested first claim of a window may exceed the cap. A
claim that would exceed the cap waits for the next window; it is not lost.

Attestors sign only roots they have rebuilt themselves from the L1 data
availability batches. These limits are consensus constants of this release
and cannot be changed without a new announced activation.

## 4. What you must do

1. **Upgrade before epoch E** to `bloch-pos` {{VERSION}} (commit
   `{{COMMIT}}`). Follow `docs/L2-MAINNET-UPGRADE-RUNBOOK.md`. Recommended:
   as soon as the release candidate is out (T−7 days); **required: before
   T−2 days**, so the readiness check below counts you.
2. **Verify the binary** before installing it:

   ```bash
   minisign -Vm SHA256SUMS -p {{bloch-release-YYYYMMDD.pub}}
   sha256sum --check SHA256SUMS          # must print: bloch-pos: OK
   ./bloch-pos --version                 # must name commit {{COMMIT_SHORT}}
   ./bloch-pos buildinfo                 # build_version must carry no "+devnet" / "rehearsal" marker
   ```

   Reproducible build: `git checkout {{COMMIT}} && cargo build --release -p
   bloch-pos-node` and compare against the published SHA-256 (see `REPRO.md`).
   Never install a binary whose checksum or signature does not verify, and
   never one received by private message.
3. **Report your version** (validators): send the output of
   `getbuildinfo` (or `bloch-pos --version`) and your validator index to
   {{READINESS CONTACT / FORM}} so your stake is counted.
4. **Bootnodes and archivals upgrade first.** Upgraded validators must reach
   each other directly, not only through not-yet-upgraded relays (our
   mixed-fleet test showed that an upgraded node attached only through an old
   relay is cut off at E).
5. **Exchanges and custodians**: upgrade your nodes; L1 BLCH deposits and
   withdrawals keep working unchanged. We recommend pausing BLCH deposits and
   withdrawals from epoch **E−1** until epoch **E+2** is finalized on your
   upgraded node, and crediting only finalized blocks during that period. Do
   not credit L2 assets until your own node shows the L2 installed
   (`getl2settlement` → `profile.activated = true`).

## 5. What happens to nodes that do not upgrade

They follow the chain normally until the last block before epoch E. They
**reject the first block of epoch E** with `StateRootMismatch`, finalize
nothing at or after E and stay on a dead branch. A validator on the old
binary stops earning rewards and is subject to the inactivity penalties of
the network from that point. This is what the mixed-fleet qualification
observed: the old binary and an un-armed build diverged exactly at the first
block of the activation epoch, while the upgraded side (3 of 4 stake) kept
finalizing.

Recovery after E: install the new release and restart. If the old node only
stopped at E, the new release continues from its last valid block. If it
stored blocks of a minority (old-release) branch after E, the new release
refuses to replay them ("durable block log failed consensus replay"): restore
the data directory from a backup taken before E (the runbook asks for one) or
bootstrap from a snapshot (`docs/SNAPSHOT-BOOTSTRAP.md`). Upgrading before E
avoids all of this.

## 6. Timeline

| When | What |
| --- | --- |
| **T−14 d** ({{DATE}}) | This notice. Epoch E, attestor set hash, program identity and the policy are final. |
| **T−7 d** ({{DATE}}) | **Release candidate**, consensus-identical to the final release (same activation epoch, same policy). Bootnodes, archivals and validators may install it. First readiness count. |
| **T−2 d** ({{DATE}}) | **Final binary** (signed, checksums). **Go / no-go**: readiness check (§7). |
| **E** ({{DATE/TIME UTC}}) | Activation at the first block of epoch E. |
| E → E+2 | Monitoring: finality of E, E+1, E+2 on upgraded nodes; `getl2settlement` shows the L2 installed. |

The release candidate and the final binary carry the **same activation
epoch and policy**. If any consensus-relevant change becomes necessary after
the release candidate, the epoch is postponed (§7) rather than compressed.

## 7. Go / no-go and postponement

- **Readiness threshold: at least 90 % of active stake on the new release
  at T−2 d** (the usual readiness bar for coordinated hard forks; the chain
  itself needs > 2/3 to finalize, the margin covers outages and late
  operators). Bootnodes and both published archivals must also be upgraded.
- **If the threshold is not met at T−2 d, or a blocking defect is found,
  the activation is postponed.** Because the epoch is compiled into the
  binary (no runtime override), postponing means a **replacement release**
  that moves the gate to a later epoch or disarms it. We build and sign that
  release together with the final binary so it can be published immediately;
  **every node already upgraded must install the replacement before epoch
  E**. A new epoch is then announced with a fresh notice of at least 14 days.
- **No rollback after E.** Once the first block of epoch E is finalized, the
  L2 is part of consensus history; the remedy for a defect after E is a new
  forward release, not a return to the old binary. Before E, rolling back to
  the previous binary is safe (see the runbook).
- Decisions and any postponement are published on {{OFFICIAL CHANNELS}} and
  signed with the release key.

## 8. Contacts

- Announcements: {{OFFICIAL CHANNEL(S)}}
- Operator coordination / readiness reports: {{CONTACT}}
- Security issues (private): {{SECURITY CONTACT}} (see `SECURITY.md`)
- Exchanges: {{EXCHANGE CONTACT}}

Only messages on the channels above, signed with the release key, are
authoritative. We will never ask for keys, passphrases or seed material.
