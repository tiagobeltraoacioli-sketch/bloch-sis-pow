# L1 treasury collection and the L2 fee sweep (owner runbook)

Two revenue destinations exist, one per layer. Neither needs anyone's
permission to receive; each needs exactly one owner action to be moved.

| | L1 protocol treasury | L2 fee-sweep recipient |
|---|---|---|
| Address | `bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073` | `0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544` |
| Form | carried-form script: 20 bytes of SHA3-256 of ONE raw legacy hybrid public key, twelve zero bytes (`tokenomics_v4::FOUNDER_WITHDRAWAL_H160`) | externally owned secp256k1 address on the L2 (chain 700770) |
| What arrives | from the December fork on: the crossing fee and the forced-inclusion surcharge, as output index 2 of L2 deposits (0x14), claims (0x16) and forced envelopes (0x1C). On the released node `906336fd` no such rule exists: every output at this script today is the founder's own holding (carryover, genesis buckets) | both L2 fee vaults (`0x4200…0019` base fee, `0x4200…0011` priority fees) after the December fork |
| Who can move it | only the holder of that one key, by an L1 transfer it signs | anyone triggers the sweep; the funds can only go to the compiled recipient |
| Tool | `bloch-pos treasury-collect` + `examples/sign-treasury-spend.rs` (this document) | any transaction to a vault (cast, a wallet); `revenue_monitor.py` watches |

The treasury script is the same script as the founder's carryover and the
genesis allocation buckets (review R335-6): protocol revenue is separable from
those holdings by outpoint only, never by address. Public accounting uses the
revenue monitor (`getl2settlement.forced.treasury`, index 2 of the three
transaction kinds), not the balance of the address.

## Part 1. Collecting the L1 treasury

### What the tool does and does not do

- `treasury-collect observe` (online, read-only) reads the treasury's outputs
  from TWO different nodes and writes only what both report identically, with
  both nodes' head and finalized checkpoint. It refuses when the two nodes name
  different finalized checkpoints, are more than 4 slots apart, quote different
  next base fees, disagree on any output they both report, or when finality
  moves during the read.
- `treasury-collect prepare` (offline) builds ONE unsigned `TransferV2`: the
  treasury key's PUBLIC half as the one witness key, the eligible outputs as
  inputs, the payments in order, the remainder to the treasury (or
  `--change-to`). With no payment it is a consolidation. It never opens a key.
- `examples/sign-treasury-spend.rs` (offline, the owner's machine) re-runs the
  full inspection, compares the signing root with the one the owner approved,
  only then unlocks the encrypted legacy wallet, signs, and inspects again.
  Same wallet discipline as the founder's existing offline signers
  (`sign-deposit-funding`, `native-funding-plan`).
- Nothing broadcasts. Submission is the owner's own `sendrawtransaction`.

Refusals (each tested; see "Evidence"):

| Refusal | Why |
|---|---|
| wrong key | the key's SHA3-256 does not open the treasury script |
| the enveloped form of the right key | a carried script opens only under the RAW key (3,745 bytes) the Genesis-3 address came from; `b10c0100‖raw` hashes differently and consensus would refuse every input |
| foreign output | an observation that names an output of another script was edited or written for another address |
| genesis allocation outpoint | `unlock_epoch` is not enforced today, but the vesting-lock flag day requires the founder and team allocation outpoints to still be unspent (`rpc.rs`, `TxOut`); the tool never spends any of the six buckets (computed from the trusted manifest) |
| dust output | below 1,000 sat; every node's mempool refuses it |
| uneconomic input (left out, listed) | an output worth no more than the fee its input adds (7 sat at the floor) would be destroyed by spending it |
| fee above `--max-fee`; tip above the consensus ceiling; declared size above 131,072 bytes; more than 1,000 inputs | the owner's cap and the stated bounds |
| a network-bound signing root at the inclusion epoch | the tool does not know the state's network domain; it fails closed (the gate is inert in `906336fd`) |
| a draft whose inputs, outputs and fee do not account exactly against the observation | exact conservation, re-derived before and after the signature |

### Fees (measured, not estimated)

`TransferV2` charges one hybrid verification per witness key and 16 gas per
declared byte. At the floor base fee (10 millisat/gas) and no tip, the exact
fee of a consolidation is printed by
`treasury_spend::tests::consolidation_fee_by_input_count_at_the_floor`
(`TREASURY_FEE_MEASURE` lines; numbers in the pull request and in agent 386's
report). Agent 335 measured about 2,131 sat to move one output alone and about
6 sat per further input; small outputs are therefore worth collecting only in
batches. A draft is valid only at the base fee it was built for (exact
conservation): if the next block's base fee differs, the transaction is refused
(never a loss): observe and prepare again.

### How often, and who triggers

- No collection is needed for safety: an output at the treasury already belongs
  to the owner's key. Collect for two reasons only: to keep the output count
  (and the cost of a later spend) small, and to move value the owner wants
  elsewhere.
- Recommended cadence: when the revenue monitor shows at least 100 protocol
  revenue outputs at the treasury, or once a month, whichever comes later; one
  draft per `listunspent` page (1,000 outputs; the node has no cursor, so the
  next page appears only after the first page's spend is final).
- Who: anyone may run `observe` and `prepare` (public data and the public key
  only); only the owner signs, on the offline machine.

### Owner commands

On an online machine with this repository built (`cargo +1.94.1 build --locked
-p bloch-pos-node --release`), two independent nodes `NODE_A` and `NODE_B`:

```sh
./target/release/bloch-pos treasury-collect observe --rpc NODE_A:8080 --rpc NODE_B:8080 --genesis genesis/mainnet.manifest --out treasury-observation.txt
```

```sh
./target/release/bloch-pos treasury-collect prepare --observation treasury-observation.txt --genesis genesis/mainnet.manifest --pubkey legacy-public.hex --tip 0 --max-fee 20000 --out treasury-draft.hex
```

For a payment instead of a consolidation add `--pay DESTINATION:SAT` (repeat
for several; `DESTINATION` is a `bloch1q…` address or a 64-digit script) and
optionally `--change-to DESTINATION`. To collect only named outputs (for
example the protocol revenue outpoints the monitor lists) give
`--outpoint TXID:VOUT` to `observe`, once per output.

Copy `treasury-observation.txt`, `treasury-draft.hex` and
`genesis/mainnet.manifest` to the offline machine. There, read the whole
inspection (every input, every output, the fee and the signing root):

```sh
./target/release/bloch-pos treasury-collect inspect --observation treasury-observation.txt --genesis genesis/mainnet.manifest --tx treasury-draft.hex --max-fee 20000
```

Sign with the encrypted legacy wallet (passphrase in a temporary owner-only
file; delete it afterwards), giving the signing root you just read:

```sh
./target/release/examples/sign-treasury-spend --observation treasury-observation.txt --genesis genesis/mainnet.manifest --tx treasury-draft.hex --expected-root SIGNING_ROOT --max-fee 20000 --wallet WALLET.json --passphrase-file PASSFILE --out treasury-signed.hex
```

Back online, submit and follow it to finality:

```sh
curl -s -X POST -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sendrawtransaction\",\"params\":[\"$(cat treasury-signed.hex)\"]}" http://NODE_A:8080/
```

```sh
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"gettxstatus","params":["TRANSACTION_ID"]}' http://NODE_B:8080/
```

Repeat from `observe` for the next page after the status reads `finalized`.

### What the owner sees

`prepare`, `inspect` and the signer print the same block: the treasury script
and address, the observation's SHA3-256, both endpoints' head and finalized
checkpoint, every input (outpoint and satoshis), every output in order with
"THE TREASURY ITSELF" marked, input and output totals, the exact fee with its
base and priority parts, gas, base fee and tip, declared bytes, the inclusion
epoch, the signing root and the transaction id. `prepare` also lists every
observed output it left out and why.

## Part 2. The L2 fee sweep

- Mechanism (December rules, `src/chainspec.rs` `fee_vault_sweep_code` in
  bloch-l2-evm): both fee vaults carry a 37-byte program with no owner, no
  storage and no selector; ANY call sends the vault's whole balance to the
  compiled recipient `0x775a…0544`. The recipient cannot be changed without new
  guests, new program keys, a native release and a fork.
- Who triggers: anyone with a funded L2 account. The recipient's key never needs
  to be online for it: use a separate low-value L2 account as the caller. Because
  anyone may trigger, a stolen recipient key cannot be starved of sweeps
  (R335-6); fees still in the vaults are not protected by not sweeping.
- How often: when either vault holds at least 0.05 BLCH or 7 days after the last
  sweep, the thresholds `revenue_monitor.py` alerts on (`l2_sweep_min_wei`,
  `l2_sweep_max_age_days`). Cost: 55,334 and 30,334 gas for the two vaults
  (agent 333, real proofs), at the L2 base fee plus the 1 gwei tip floor.
- What the owner sees: `revenue_monitor.py` (runbook section 7 of bloch-l2-evm
  `docs/MAINNET-OPS-RUNBOOK.md`): vault balances to zero, the recipient's balance
  up by exactly the swept amount; check the recipient with `eth_getBalance` on two
  RPC endpoints at one block.

Owner commands (L2 RPC `L2_RPC`; a caller keystore that is NOT the recipient's):

```sh
cast send 0x4200000000000000000000000000000000000019 --value 0 --rpc-url L2_RPC --keystore CALLER_KEYSTORE
```

```sh
cast send 0x4200000000000000000000000000000000000011 --value 0 --rpc-url L2_RPC --keystore CALLER_KEYSTORE
```

```sh
cast balance 0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544 --rpc-url L2_RPC
```

Moving the swept BLCH from the L2 to L1 is an ordinary L2 withdrawal by the
recipient key (claim on L1 after maturity; large claims need the attestors'
3-of-5); it is not part of the sweep.

## Evidence

- `engine::treasury_collect_tests` (private in-process chain, real hybrid keys,
  real mempool door and transition): a stand-in treasury of the mainnet shape
  (carried form of a THROWAWAY raw legacy key) holding a crossing-fee-shaped,
  a surcharge-shaped, a carryover-sized and a dust output plus a genesis
  allocation; a foreign output of another key. Observed through the node's own
  RPC answers; refusals (wrong key, enveloped key, foreign output, dust payment,
  fee cap, allocation input); the stranger's signature and the stranger's key
  refused at the mempool door; a tampered output refused; the consolidation
  admitted and included, only the fee leaving the script; then a payment with
  change from the merged output.
- `treasury_collect::tests` (two-endpoint agreement: every disagreement refused),
  `treasury_spend::tests` (address, ownership rule, observation format, fees),
  `examples/sign-treasury-spend.rs` tests (refusal before unlock, wrong wallet,
  encrypted wallet file, passphrase-file permissions).

## Not done / not proven

- The owner's key was not exercised (it cannot be): possession is shown only by
  the owner's first real spend.
- `observe` against two live mainnet nodes was not run by the author; the HTTP
  client is the one `equivocation-watch` uses, and the parsing is tested on the
  node's own RPC answers.
- Protocol-revenue outpoints are not classified by this tool (it sees the
  script, not the creating transaction); use the revenue monitor's list with
  `--outpoint`.
- The L2 sweep commands were not run against a live L2 (none exists yet); the
  sweep itself was proven by agent 333 on a private December net.
