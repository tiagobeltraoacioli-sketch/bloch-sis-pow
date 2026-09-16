# Native custody migration review

Status: **not approved; migration readiness remains unresolved**. This is a
proposal for operational review, not a deployment, activation, signing instruction,
recovery guarantee or authorization to move funds. No keys or contracts were changed.

## Reviewed evidence

The source repository is the local sibling `bloch-l2-bridge-source-lab`, at base
commit `11be84e05820b9c70d03f6da9b48f05b9e1624d6` with uncommitted changes.
The initially reviewed working files are `contracts/usdt/MainnetSourceVault.sol` and
`mainnet-custody/README.md`; that commit alone does not identify their current
contents. Initial SHA-256: contract `3760e7248f2fc1af7d22d330cac56a8b434d4eab382472ef1b42551847f1dc76`; README `2c11d03bdf30af1b414d445b58985228422ad213c8f93e21b0cf3a907cf82823`. A separate authorized candidate adds permanent deposit closure; its exact reviewed artifact and tests must be attached before approving this plan. Native behavior was checked at local commit
`fa7fe5960e49e86df6144ffee96a892272e08f39` in:

- `crates/bloch-euvm/src/ustav/gateway.rs`: `enable`, import accounting and
  withdrawal accounting.
- `crates/bloch-pos-committee/src/transition/native_dex/bootstrap.rs`:
  canonical registration followed by route enablement.

These are local revision references, not claims of published GitHub revisions.

## Contract constraints that the migration must preserve

The source vault fixes the token, domains, asset, cap and five signers. Three
signatures queue a release; two pause the vault. There is no signer rotation,
upgrade, rescue, administrative reserve transfer or automatic migration function.
A new vault address changes the route ID even with otherwise identical inputs.

A pause blocks **both deposits and releases**, invalidates existing release queues
through the safety epoch and clears a pending resume. It is not a deposits-only
halt. Resume requires three signatures and the immutable delay (at least 48 hours
on Ethereum mainnet). Once resumed, arbitrary callers can deposit again. Removing
an old route from wallet deposit screens does not prevent direct contract calls.
The initial artifact therefore cannot guarantee an enforceable drain-only period
or finite retirement date while allowing old-route claims to be paid.

A separately authorized candidate is being implemented with `closeDeposits`:
three of five source signatures permanently set `depositsClosed`, with action,
vault/chain/domains, control nonce, safety epoch and deadline binding. Deposit
closure must not block release queueing/execution, change existing pause semantics,
or become reversible through resume. The phased plan below depends on this
candidate passing independent review and tests. It is not present in an old
immutable deployment merely because successor source code implements it. An
existing vault without this function still has the limitation above.

Release queues reserve backing but do not pay users. On mainnet, execution waits
at least 24 hours, must precede certificate expiry, and requires an unpaused vault.
Expired or safety-invalidated queues can be cancelled permissionlessly; this only
reclaims reservations. Successful released nonce/burn flags remain permanent.
A new certificate must use the current safety epoch, exact old route, canonical
inner native burn, amount, recipient and nonce. It must not reuse the outer
sponsored authorization as the burn identifier.

Native `Gateway::enable` requires both zero asset supply and zero next mint nonce.
The canonical bootstrap also registers the asset before enabling the route.
Consequently, draining an already imported asset back to zero supply does not
make it a never-minted asset, and the existing path is not a general mechanism to
attach a successor route to a circulating or previously imported asset. Neither
source custody nor this proposal rotates the native issuer. A same-asset migration
needs a separately designed and reviewed canonical operation; it is not available
merely by changing a manifest.

## Candidate operational sequence

1. **Approve a complete inventory before scheduling anything.** Independently
   reconcile finalized source deposits, native imports, native burns and source
   payments for each route. Record both chain anchors, vault/runtime pins, token
   implementation observations, asset, issuer, committee, cap, safety/control
   epochs, deposit count, release nonces, all queued IDs and outstanding claims.
   Include deposited-but-not-imported funds and burned-but-not-paid claims;
   current native supply alone understates pending source obligations. Record
   token balance and `totalLocked` separately: direct token donations are not
   credited deposits and have no rescue path.
2. **Select a reviewed successor identity and custody configuration.** Under the
   currently implemented canonical path, plan a separately registered asset and
   new route with independently established authorities, cap, approved activation
   and audited deployment evidence. Label both assets/routes explicitly in the
   wallet; do not silently relabel old balances, pool positions or liquidity as
   successor claims. A same-asset successor is a blocked alternative pending new
   protocol design, not an interchangeable configuration choice.
3. **Retain the old authorities and redemption infrastructure.** Verify continued
   availability of the old source quorum, native issuer/committee and sponsor,
   and an independently monitored source release window. Stop promoting old
   deposits and publish exact routing/cutover notices. For a vault deployed with the reviewed closure candidate, obtain a separate
   three-signature permanent deposit-closure authorization, verify its exact
   control nonce/domain/deadline, and observe canonical inclusion and
   `depositsClosed == true`. Enumerate deposits through the closure transaction,
   including any earlier transactions in the same block, before publishing the
   final old-deposit inventory. Confirm queue/execute remain available when
   unpaused and resume cannot reopen deposits. A protective pause remains a
   distinct incident action that also suspends redemptions. If the actual old
   deployment lacks closure, explicitly reject or accept its drain-only
   limitation; do not pretend this code can be retrofitted.
4. **Honor each old claim against old backing.** The holder explicitly authorizes
   an old-route native withdrawal. Source signers independently verify finality,
   the canonical release record and inner burn, then review the exact delayed
   release certificate. Monitor its entire delay and confirm canonical execution,
   matching events and exact token balance deltas. Reconcile stale queues before
   fresh queueing. Never treat a queue, cancelled reservation or native burn as an
   Ethereum payment. Do not direct a user's backing to the successor vault without
   a separately explicit user instruction; no administrator can sweep it there.
5. **Make successor deposits separate user actions.** After confirmed old-route
   payment, a willing holder approves and deposits into the reviewed new vault,
   then receives the separately authorized successor native import. This is not
   atomic: either leg can stall and requires its own receipt, reconciliation and
   user-visible recovery status. Users may instead retain the redeemed Ethereum
   token. No old balance is forcibly converted, and no old burn can collateralize
   both routes. Existing pool positions require their normal holder-authorized
   unwinding before any spend; they are not moved by a custody migration.
6. **Retire only after proving all obligations extinguished.** Reconcile pending
   deposits/imports, native supply, burns awaiting payment, all queue reservations
   and source accounting, including transactions arriving before permanent deposit closure. A final pause prevents further deposits but must not strand a claim
   accepted before it. Keep public historical receipts and replay records. Zero
   native supply or an empty queue alone is insufficient. If obligations remain,
   retain the old redemption service; do not declare migration complete.

## Failure boundaries and required decisions

Loss of enough old source keys to leave fewer than three usable signers prevents
new release certificates and resume proposals. Previously valid queued releases
may still execute if every existing condition holds, but that does not restore
quorum or provide a general recovery path. Without such an executable certificate,
old backing cannot be recovered by deploying a new vault, cancelling queues or
changing wallet routing. Recovery is unavailable under this contract; any new
recovery design requires independent review and a stakeholder process, and must
not be represented as able to extract immutable old custody automatically.

Two hostile signers can repeatedly pause and deny service, even if three others
can sign releases. Loss of the required native issuer or committee authority can
also prevent generating valid new burns/imports. Token-issuer pauses, blacklisting
or reserve destruction can independently prevent payment. None is repaired by
this migration proposal, and emergency financial compensation would be a separate
funding/governance decision, not on-chain rescue.

Required closure review evidence includes successful 3-of-5 closure, rejection
of fewer signatures and replay/wrong-domain certificates, irreversible closure
through pause/resume, refusal of every subsequent deposit, and continued valid
release queue/execution while unpaused. The paused/unused source deployment
preflight must inspect the new field and require the intended initial value;
existing runtime pins must not silently accept a changed contract.

Before accepting production deposits, reviewers must decide whether these
availability and retirement limits are acceptable, establish actual independent
custody and continuity procedures, define incident reconciliation responsibilities,
and approve a concrete successor/old-claim policy. Record named approvals and
artifacts; do not substitute this document or a consistency-only preflight report
for those approvals. Default production gates remain unchanged. The migration
blocker remains open.
