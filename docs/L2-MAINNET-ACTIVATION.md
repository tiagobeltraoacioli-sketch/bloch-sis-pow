# Native L2 on the running Genesis-4 mainnet (M8 part 2)

Status: the activation gate is implemented and **inert**. Nothing here changes
consensus while `params::L2_SETTLEMENT_ACTIVATION_EPOCH == u64::MAX`.

## The gate

- `params::L2_SETTLEMENT_ACTIVATION_EPOCH` (sentinel `u64::MAX`) and
  `params::l2_settlement_active(epoch)`, same shape as the funded-delegation flag day.
- `l2_settlement::activation_policy() -> Option<(Policy, asynchronous)>`: `None`
  until the mainnet policy is decided.
- `CommittedState::close_epoch`: when the new epoch is past the gate, the state has
  no L2, and the pinned policy names this network's admission domain
  (`policy.identities[0]`), the boundary installs `State::genesis(policy)` (or
  `genesis_async`). The first block of that epoch is the L2's native height 1.

Before the gate, a network without an L2 policy has no L2 state. The L2 state
component (`TAG_L2_SETTLEMENT`, 0x21) is absent from the state root, so historical
roots are unchanged, and every L2 transaction (0x12–0x16) is refused with
`NotActive`, as a build without the L2 refuses it.

Tests (`transition/l2_settlement_tests.rs`):

| Test | Pins |
| --- | --- |
| `l2_settlement_gate_is_inert` | sentinel value, no policy |
| `armed_l2_gate_has_a_policy` | an armed epoch must come with a valid pinned policy |
| `inert_boundary_keeps_the_state_root` | a pinned policy alone changes nothing |
| `activation_installs_the_policy_at_the_boundary` | sync and async; root changes only by the L2 leaf; installed once |
| `activation_ignores_other_networks` | other domain or unbound network: no install |
| `activation_never_replaces_existing_l2_state` | networks with an L2 genesis keep theirs |
| `settlements_are_refused_before_and_admitted_after_activation` | real blocks across the boundary |

## Before arming (decisions and work, in order)

1. **Mainnet capability.** User transactions (`USER_TRANSACTIONS_ENABLED`) and
   the claim attestor set exist only with the `devnet-l2-user-txs` feature. A
   mainnet build today would activate an L2 that settles empty blocks only: no
   DEX, no bridges, no withdrawals of user funds. Decide which of M3–M6 enter the
   mainnet build, and with which limits. This is the M9 scope.
2. **Policy.** L2 genesis (`initial_l2_parent/state`), chain id (700771 or a
   mainnet id), the SP1 program identity (ELF, KoalaBear/BN254 keys; the
   real-Groth16 fixture must be regenerated for this tree), the proof policy
   version (V2/V3), sync or async settlement, and the attestor keys (k-of-n).
3. **Historical replay.** Replay the complete mainnet history with this build
   (`run --replay-from-genesis` on a copy of a node's chain data, isolated from
   the network) and require every block's state root to match.
4. **Mixed fleet.** On a devnet: nodes on the current release and nodes on this
   build follow the same chain and finalize until the gate. After the gate, only
   this build follows. The old nodes diverge at the first block of the
   activation epoch, because its state root includes the L2 leaf; they do not
   last until the first L2 transaction.
5. **Coordinated epoch.** Pick an epoch that leaves time for every validator and
   archival node to upgrade. Then set the constant, pin the policy, and the
   inert-gate test changes in the same commit.
