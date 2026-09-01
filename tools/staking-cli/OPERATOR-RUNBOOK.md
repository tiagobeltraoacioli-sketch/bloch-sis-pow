# `bloch-stake` — validator staking transactions, operator runbook

`bloch-stake` is the client side of the Genesis-4 staking lifecycle. It is
the only tool that can construct the staking wire formats — the node's
`submit-tx` builds transfers only. It builds, previews, signs and broadcasts:

| action     | what it is                                                        | status today |
|------------|-------------------------------------------------------------------|--------------|
| `deposit`  | funded validator registration (`DepositV2`, wire tag `0x07`)      | full flow; format INERT until `DEPOSIT_FUNDING_ACTIVATION_EPOCH` is armed |
| `exit`     | signed voluntary exit (`staking::ExitTx`)                          | plan + sign produce the artifact; **no wire carrier exists yet**, broadcast refuses |
| `delegate` | funded delegation                                                  | refuses: the wire format has not been designed anywhere yet |
| `withdraw` | unauthenticated crank paying an exited bond to its fixed credentials | full flow; format INERT until `WITHDRAWAL_ACTIVATION_EPOCH` is armed |

Every consensus quantity — signing roots, canonical bytes, txids, fees, the
per-validator cap — is imported from `bloch-pos-committee`, the crate the
fleet runs. This tool re-derives nothing, because conservation on this chain
is an exact equality: a one-satoshi disagreement is a rejection, not a
discount.

## The rails (none overridable by flag)

- **Build-time refusal of what the chain would refuse**, with the reason:
  a format whose flag day has not arrived (the epoch is named), a bond below
  `MIN_DEPOSIT_SAT` (25,000 BLCH) or above the per-validator cap (1% of
  committed active stake, floored at the minimum), sub-dust change (< 546
  sat), a withdrawal before the record's committed `withdrawable_epoch`, an
  exit signed by a key that does not control the validator.
- **Typed confirmation at a real terminal.** The phrase restates what moves
  (`BOND 25000 BLCH VALIDATOR 3f9c02aa`, `EXIT VALIDATOR 3 EPOCH 1500`,
  `WITHDRAW VALIDATOR 9`). Piped stdin, redirected stdout, EOF: refused.
  There is no `--yes`.
- **`plan` / `sign` / `broadcast` are separate steps.** `plan` is read-only
  and touches no key. `sign` runs offline. `broadcast` re-derives and
  re-checks everything before bytes leave the machine — the JSON files are
  data, not authority; any tamper (a satoshi of change, a moved withdrawal
  address, a fee term) breaks a committed root and is refused.
- **`--rehearsal`** lifts exactly one gate — the activation epoch — and
  poisons the artifact: `broadcast` refuses a rehearsal file unconditionally.
  Use it to walk the runbook before a flag day; nothing else changes.

## Deposit — registering a funded validator

The funded deposit spends real coins into the bond. Three parties may be
three different keys:

- the **funding key** owns the coins being spent (a wallet key);
- the **validator key** (the node keystore's hybrid key) proves possession
  of itself over the §7.1 root, which also covers the withdrawal
  credentials — so neither can be swapped under someone else's proof;
- the **withdrawal address** is where the principal returns after exit +
  withdrawal delay. It is fixed at deposit time, forever. A compromise of
  the hot validator key can never redirect it. Use a cold address.

### 1. Generate the validator key (on the validator machine)

```
bloch-pos keygen --dir /var/lib/bloch/keys --index <n>
bloch-pos keygen-public --dir /var/lib/bloch/keys > validator-public.tsv
```

`validator-public.tsv` carries only public material (pubkey + RANDAO
commitment). Carry it to the planning machine; the keystore stays put.

### 2. Plan (on a machine that can reach a node; no keys needed)

```
bloch-stake deposit plan --rpc http://127.0.0.1:16400 \
    --funding bloch1q...          \
    --amount 25000                \
    --withdrawal bloch1q...cold   \
    --public-line validator-public.tsv \
    [--commission-bps 250] [--tip 1000] \
    --out deposit-plan.json
```

The plan prints in full — inputs, change, fee, conservation equation, the
DS_DEPOSIT_FUND spend root, the DS_DEPOSIT PoP root, the txid — and is
refused outright if the chain would refuse it. The fee is priced at the
node's next base fee; **a deposit is valid at exactly one price point**, so
if the base fee moves before broadcast you re-plan (broadcast checks).

### 3. Sign (offline-capable; the two roles may sign on different machines)

Both on one machine:

```
bloch-stake deposit sign --plan deposit-plan.json --out signed.json \
    --keystore-dir /var/lib/bloch/keys \
    (--seed | --keyfile wallet.json | --funding-keystore-dir <dir>)
```

Split custody — the coin owner signs first, the validator box second (order
does not matter):

```
bloch-stake deposit sign --plan deposit-plan.json --out half.json --only funding --seed
# carry half.json to the validator machine
bloch-stake deposit sign --signed half.json --out signed.json --only pop \
    --keystore-dir /var/lib/bloch/keys
```

Each signature is verified back before it is written; a key that does not
own the funding address, or is not the plan's validator key, is refused
before anything is signed.

### 4. Broadcast

```
bloch-stake deposit broadcast --rpc http://127.0.0.1:16400 --signed signed.json
```

Preflight re-checks: the flag day (still) arrived, the base fee still
matches, every input is still unspent, the key was not registered
meanwhile. Then the preview, the typed phrase, and `sendrawtransaction`.

After inclusion the validator enters the activation queue: eligible after
`ACTIVATION_DELAY_EPOCHS` (8), at most `MAX_ACTIVATIONS_PER_EPOCH` (4)
per epoch. Watch with `getvalidator`.

## Exit — leaving the validator set

```
bloch-stake exit plan --rpc <url> --validator <index> --out exit-plan.json
bloch-stake exit sign --plan exit-plan.json --keystore-dir <dir> --out signed-exit.json
```

Facts to know before typing the phrase:

- an exit is **irrevocable**;
- duties continue for `EXIT_DELAY_EPOCHS` (32) after inclusion — an exit is
  not an escape from assigned duties or their slashing exposure;
- the bond unlocks `WITHDRAWAL_DELAY_EPOCHS` (2,048) after inclusion
  (roughly 10 days at 32 slots × 13.6s epochs) — the weak-subjectivity
  margin, during which the stake remains slashable;
- the exit's **epoch is inside its signing root** and must match the epoch
  of inclusion — sign and submit promptly, or re-sign.

`exit broadcast` refuses today and says why: the consensus seam that
applies a signed exit exists (behind `SIGNED_EXIT_ACTIVATION_EPOCH`), but
no `PosTransaction` variant carries an `ExitTx` yet — there are no bytes a
block could include. The signed artifact is still worth producing in a
rehearsal (custody drills); a real exit will need a fresh signature at
inclusion time anyway.

## Delegate

`bloch-stake delegate` refuses, naming `FUNDED_STAKING_ACTIVATION_EPOCH`
and the actual gap: the funded delegation's wire format — which outputs are
bonded, how the delegator authorises — has not been designed in any work
stream. This tool does not invent consensus wire formats; a delegation
encoding drafted in a wallet would define the chain's bytes by accident.

## Withdraw — paying out an exited bond

```
bloch-stake withdraw plan --rpc <url> --validator <index> --out withdraw-plan.json
bloch-stake withdraw broadcast --rpc <url> --plan withdraw-plan.json
```

The crank is **unauthenticated by design**: after the delay, the payout to
the credentials fixed at deposit is the only thing that can happen to these
coins, so there is nothing a signature could protect and no sign step.
Anyone may crank any matured validator; the payout still lands at
`(txid, 0)` locked to the deposit-time credentials.

Build-time refusals mirror consensus exactly: no exit on record
(`NotExited`), the committed `withdrawable_epoch` not reached
(`DelayNotElapsed` — both epochs are named; note every slashing included
meanwhile EXTENDS the committed field), already withdrawn
(`AlreadyWithdrawn`). Broadcast re-derives the whole verdict from the
chain's current state, not from the plan file.

## Files and their trust model

Every artifact (`deposit-plan.json`, `signed.json`, `exit-plan.json`,
`signed-exit.json`, `withdraw-plan.json`) is re-derived and re-verified by
every subsequent step. Editing a field changes a committed root and the
file is refused. Carrying them on a USB stick between machines is the
intended use; nothing in them is secret (signatures and public keys only —
key material never enters an artifact).

## Troubleshooting

- **"the chain's next base fee is now X but this deposit was priced at Y"**
  — conservation is exact; re-run `deposit plan` and re-sign.
- **"input …:n is no longer unspent"** — the funding address moved; re-plan.
- **"funded deposits are not active … DEPOSIT_FUNDING_ACTIVATION_EPOCH"** —
  the flag day has not been armed or reached. This is the chain's state,
  not a tool bug. Rehearse with `--rehearsal` if you want to drill the
  procedure.
- **"refusing to sign: stdin/stdout is not a terminal"** — the tool has no
  unattended mode; run it interactively.
