# Mempool admission of the L2 transaction kinds: where each release stands

Written for the L2 audit list, item B1 ("the released node admits L2 kinds on a signature alone", review
R308-3) and item B2 ("entries sharing one funding output compete by tip"). Both were opened against release
`78d4921c` and the L2 development line that branches from it. This note records what the later node releases
already do, what is left, and what a fleet running two releases does. Node policy only: nothing here is a
consensus rule, a state format or a fork height.

## 1. Result

**On this release line the item is closed by code that is already released.** The state preflight of the three
fee-paying L2 kinds (deposit 0x14, DA batch 0x15, withdrawal claim 0x16) entered the node with the security
fixes of 2026-11-10 (commit `9cbd441f`, with `58ea6c19`, `3914e5cb`, `e52f1a49`, `b317a987`, `b7a559bd`,
`de045122`) and is part of releases `node-7f1c116e-20261112` and `node-906336fd-20261113`. It is not in
`node-78d4921c-20261029` or earlier.

So no new node change has to be decided for B1 or B2. What remains is a rollout question: a node is covered
from the moment it runs release `7f1c116e` or later.

## 2. What the released check does (`engine/admission.rs`, `check_l2_funded`)

Before the signature is verified, a deposit, DA batch or withdrawal claim is judged by the transition's own
check functions against the committed state, at the base fee of the next block
(`CommittedState::l2_deposit_refusal_at`, `l2_data_availability_refusal_at`, `l2_withdraw_claim_refusal_at`).
Those functions are the ones the block transition calls, so admission refuses nothing a block could carry and
admits nothing a block would refuse on state. Two relay bounds are added: the block byte budget and the
declared-size slack.

| Check named by the L2 review (R308-3, R308-2P-2, R308-3P-1) | Release 78d4921c (as the reviews of it state; not re-read line by line here) | Releases 7f1c116e, 906336fd (read in this tree) |
|---|---|---|
| Funding inputs present in committed state | no | yes (`MissingInput`) |
| Funding key owns its inputs | no | yes (`Ownership`) |
| Value conserved at the next base fee | no | yes (`Conservation`) |
| Tip ceiling, gas ceiling | no | yes (`TipAboveCeiling`, `GasCeiling`) |
| This network; this L2 chain; a shape consensus accepts | deposit domain only | yes (`Network`, the chain and shape refusals of each kind) |
| DA batch inside the unsettled window and not a recorded commitment | no | yes (`Number`, `Duplicate`, `Full`) |
| Withdrawal claim one consensus would apply (leaf unclaimed, root retained, matured, final, window, escrow, attestation) | no | yes; finality is not held against a claim when the block is in a later epoch than the head (`de045122`) |
| Declared size far above the encoding | no | refused (relay bound) |
| An entry of these kinds that stops being backed leaves under capacity pressure | no | yes (`candidate_is_backed`) |
| Two pending entries spending one output (B2) | both pooled | the second is refused while the first is backed; a dead first one is planned out (`plan_input_conflicts`) |
| Signature work per peer | unmetered for these kinds | metered per source (`e52f1a49`) |
| The proposer's selection | a refused entry cost the block what it displaced | re-selection after a refusal; entries that exclude each other are not selected together |

Tests on this line: `engine::l2_preflight_tests` (the EXE-1, EXE-2, EXE-3, V2-1, W1-1, W1-2 cases) and, added
on this branch, `r308_3_unbacked_l2_entries_at_the_highest_tip_take_no_place_in_the_pool`: 36 unbacked entries
of the three kinds at the highest tip, from 36 keys and 36 peers, are all refused and the pool stays empty;
two deposits of one key spending one output hold one place; the paying deposit and a transfer are admitted
and proposed.

## 3. What a mixed fleet does

A fleet in which some nodes run `78d4921c` (or a build of that line) and others run `7f1c116e` or later:

- **Each upgraded node is protected from its own restart on.** Unbacked entries are refused at its door,
  whether they arrive by RPC or from a peer, and are not relayed by it.
- **No peer is penalised for sending them.** A refused transaction from gossip is answered `Ignore`, never
  `Reject` (`engine.rs`, the `NetEvent::Transaction` arm): an old node that relays an attacker's entries
  keeps its score on the upgraded nodes. The two releases stay in one mesh.
- **Old nodes stay exposed among themselves.** Their pools can still be filled through any old node, and
  entries travel between old nodes. A transfer handed to an old node with a full pool is refused
  `AtCapacity`; the same transfer handed to an upgraded node is admitted and relayed to the other upgraded
  nodes.
- **Blocks.** An upgraded proposer builds from its own pool and is not affected. An old proposer with a held
  pool proposes what its pool has: the unbacked entries are refused by its own probe and the transfers they
  kept out are missing from that block. So the delay to users scales with the share of slots old nodes
  propose and disappears when the last proposer is upgraded. No block becomes invalid either way.
- **Order of rollout.** Any order works. Public RPC nodes first shortens the exposure most, because that is
  where users hand in transfers.

Not exercised: a two-release private net under a real flood. The statements above are read from the code of
both releases and from the tests named in section 2.

## 4. For the December fork build

The L2 development line (`codex/l2-r15-recipients-20261116`, native `0861278c`) branches from the release
line before these fixes and carries its own admission checks for the same three kinds
(`check_l2_funding`, `check_l2_applicable`, `check_da_recordable`, `check_claim_applicable`), written
independently for review R308-3, plus the parts that only exist with the fork: the forced-inclusion envelope
(0x1C), its reserved room in a full pool and the registered DA key's displacement. The two implementations
edit the same functions; a merge of the two lines conflicts in `engine/admission.rs` and `engine.rs`.

Recommendation for that merge: keep this line's `check_l2_funded` for the three existing kinds (it shares
its checks with the transition and cannot drift from consensus), and bring from the L2 line only what has no
counterpart here: the forced-envelope arm (price of entry, gas range), the reserved room, the DA key
displacement, and their tests. The L2 line's tests for R308-3, R308-2P-2 and R308-3P-1 should then pass
against the merged door unchanged, or be adapted where a refusal text differs.
