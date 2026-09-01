# Partner send — operator sheet

One page: what you run, what you will see, what you type, and what the
partner runs to confirm receipt. Genesis-4 has **no transaction ids** at the
wallet layer — the partner's address balance **is** the receipt, which is why
their side of this has a tool too.

## Rails (none can be turned off by flag)

- Amount and destination are **required**; there are no defaults and no batch
  mode — one run, one transfer, one destination.
- Hard cap **10,000 BLCH per run** (`MAX_PARTNER_SEND_SAT`). Raising it means
  editing source and rebuilding — a diff, not a flag.
- Refuses to create **any output under 546 sat** (the dust floor; sub-dust
  outputs have poisoned blocks before). It tells you the exact alternative
  amounts instead.
- Confirmation is a **typed phrase at a real terminal**. Piped input, `yes`,
  redirection, cron — all refused. There is no unattended path.
- Change always returns to the source address. Fee sanity cap: 1 BLCH.
- The key is loaded only after you confirm, from a source you name
  explicitly: `--seed` (BIP39, hidden prompt), `--keyfile` (encrypted wallet
  file, hidden password prompt), or `--keystore-dir` (BPOSKEY1). **Never
  point it at treasury key material** — use the dedicated integration wallet.

## What you run (one attended command)

```
cargo build --release -p bloch-partner-send
./target/release/bloch-partner-send send \
    --rpc http://127.0.0.1:16400 \
    --from  bloch1q<integration-wallet-address> \
    --to    bloch1q<partner-address> \
    --amount 25 \
    --seed
```

(Key-off-this-machine variant: `plan --out plan.json` here, `sign` on the
offline machine, `broadcast` back here. Same previews, same typed phrase.)

## What you will see before anything is signed

```
── TRANSFER TO BE SIGNED ─────────────────────────────────────
  network      mainnet
  from         bloch1q<integration-wallet-address>
  to           bloch1q<partner-address>
  amount       25 BLCH  (2500000000 sat)
  inputs       1 coin(s), 5000000000 sat total
               abababababababab:0  5000000000 sat
  change       24.99779508 BLCH (2499779508 sat) back to the source address
  fee          220492 sat  (218308 gas @ base 10 + tip 1000 millisat/gas)
  tx_bytes     8785 (declared, inside the signing root)
  signing root 4ae18a42…bff9f30a
  txid         1b61947c…553f71e9
──────────────────────────────────────────────────────────────
To sign-and-broadcast, type exactly:  SEND 25 BLCH TO <last-8-of-partner-address>
>
```

Type the phrase **exactly** (it restates the amount and the destination
tail — that restatement is the approval). Then the seed prompt appears
(hidden input), the transfer is signed, verified locally, and broadcast.
Anything else — a typo three times, Ctrl-C, EOF — aborts with nothing sent.

Before the prompt the tool has already re-checked, against the node: the
current base fee still matches the plan (a transfer is valid at exactly one
price point) and every input is still unspent.

## What the partner runs (their receipt)

Send them `tools/partner-send/verify_receipt.py` (Python 3 stdlib, no
dependencies) and the amount. Against **their own node** if they run one:

```
python3 verify_receipt.py bloch1q<partner-address> \
    --rpc http://<their-node>:16400 --expect 25
```

It validates the address checksum, derives the **carryover** `script_hash`
(the 20 bytes after `bloch1q`, zero-extended to 32), baselines the balance,
polls
`getbalance`, lists the exact outputs that arrive, then waits for the
chain's **explicit finality** on the receiving epoch (16–32 min) and prints
a receipt. Exit 0 = received and matches; exit 2 = received but a different
amount; exit 3 = timeout.

> **This tool is for Genesis-3 carryover holders, who are named by address.**
> A native Genesis-4 key is named by a 64-hex `script_hash` —
> `SHA3-256(pubkey)`, all 32 bytes — and that is a *different key in the eUTXO
> set* from the address's 20 bytes zero-extended. Consensus opens both, so
> paying the wrong one is silent: the payee queries their own `script_hash`,
> sees nothing, and reports the transfer as missing. If a partner sends you 64
> hex characters instead of a `bloch1q…`, do not convert it and do not use this
> tool — pay the `script_hash` with `bloch-pos submit-tx --pay` or
> `bloch-withdraw`.

## If it refuses

Every refusal states its reason and, where there is one, the exact remedy
(e.g. dust change: the two nearest amounts that avoid it; base-fee drift:
re-plan). A refusal never leaves anything half-done: nothing is signed and
nothing is broadcast until the phrase is typed, and nothing is broadcast
that wasn't verified byte-for-byte against the plan you confirmed.
