# Live supply — the measured ledger

**Every figure in this file describes the chain at one measured moment, not a
timeless fact.** That distinction is why this file exists. Before 2026-09-01,
`docs/PROJECT-STATUS.md` and `SECURITY.md` published the *genesis* holding of
one address in the present tense; the address had by then moved
18,128,356,145.07452011 BLCH, and nothing in the repository could notice.

    measured_at        2026-09-01
    slot               54663
    height             33768
    epoch              1708
    block_id           2697776ca636f1c3f4a96fc952057f6a98b376a4dc50dc6203e27cc09bef6695
    state_root         706fc23c0031280a51bbb46a52987c1d9191cc190b6ba905c586c1a600fa2095
    corroborated_by    139.180.166.5, 139.180.173.231   (archival, keyless)

## Measured, or declared — never blurred

Two kinds of statement live in this file and they carry different weight. Every
figure is labelled, and the labels are load-bearing:

- **MEASURED** — re-derivable by anyone, two ways (below), against two archival
  nodes. If a measured figure here is wrong, the chain will say so.
- **DECLARED** — told to us by the founder. The chain cannot check it and does
  not corroborate it. It is recorded because it is the only available answer,
  not because it is verified.

The single most important declared fact on this page is *who* holds the
18,128,356,145.07452011 BLCH that left the founder address. The chain shows the
movement in full and **cannot attribute control of any destination address to
anybody**. That limit is permanent and it is not a gap in this audit; it is
what an unattributed ledger is.

## How to re-derive it

Two ways, and they must agree. `tests/published_supply_claims.rs` runs the
first always and the second when `BLOCH_ARCHIVAL_RPC` is set.

1. **Poll.** `getbalance` on each `script_hash` below, against *two* archival
   nodes, and require both to return the same `balance_sat` and `utxo_count`.
   Never a validator: the RPC shares a thread with consensus there.
2. **Replay.** Build the genesis eUTXO set from `carryover.tsv.gz` (split
   x100/21 per row, then the dust remainder onto the highest-value entry —
   `genesis::read_carryover_snapshot`) plus the five allocation outputs
   (`Manifest::allocation_outputs`), then apply every transfer in an archival's
   `blocks.log` in order. The two archivals' logs are not byte-identical (they
   carry different tails) and must still produce the same ledger.

## Genesis — fixed, derivable from the shipped artefacts

    genesis issued          5714640000000000000 sat   57,146,400,000.00000000 BLCH
      carryover                                       18,146,400,000 BLCH (452,726 outputs, 16 addresses)
      five vested buckets                             39,000,000,000 BLCH (5 outputs, all unlock_epoch 0)

    founder script hash     e986db51…  5604682938086017913 sat  426,199 outputs
                                       56,046,829,380.86018372 BLCH = 98.0759% of issued
      of which carryover                17,046,829,380.86018372 BLCH = 93.9406% of the carryover
      of which allocations              39,000,000,000.00000000 BLCH

## Live — the state that moves

    live eUTXO supply       5714639999993280844 sat   57,146,399,999.93280792 BLCH
    burned in fees                      6719156 sat            0.06719156 BLCH
    outputs                                                       70,890
    holders (script hashes with a balance)                            28

Supply is conserved exactly: `genesis - live` equals the fees, to the satoshi.
Fees are destroyed by omission (`transition.rs` credits the producer's share to
`pending_fee_rewards`, which compounds into *stake*, never into an eUTXO), so
the eUTXO total is monotonically non-increasing and no transfer has ever minted.

    script_hash (h160, zero-extended)              balance_sat  utxos    share
    e986db5149cff7499b282a048272a09aff0af4ff  3791847323578565997   45149  66.3532%
    f844d776e8ee007060e1c72ae7980334e0e7efd3   353500000000000000     125   6.1859%
    977d7bf347e63f1aea314b11e3e54e48678c6173   306450615000000000     235   5.3626%
    2c825a239edd7ff5bc752b87e26cb56289bc4233   301548430200000000     158   5.2768%
    9bdf65b1eb3a915e20b630fc86992eb92f795032   300028948800000000     135   5.2502%
    a57c36a066c165318bf6e1734022afa5342fc5e6   291981808999997833     147   5.1094%
    7560b9402e741730936bb8b3f1c0c754b4e034c7   203100000000000000      66   3.5540%
    be7c81e18f20e62e572caeb88139f8068e5265e6    84316000000000000   21079   1.4754%
    cb339d2ef2e502d36864689192891567ba87f91c    56912966477430518      83   0.9959%
    3d36e8984af3bee4ed290a583143efb349d72b8a     7091699399997833      71   0.1241%
    556b6f1a717f08c24b68bab3b5bf1040fff72ce6     6071899999997862    1518   0.1063%
    e9861664c76f31cdda5b54a0ce48cb54fbd5f5d1     5335619047619047    1323   0.0934%
    ce3ea055d2c8b6c1656ccfccba8fe665e8d0d93f     2999998999997833       3   0.0525%
    5b4a530379a56a3ea3e1af0f5735d1afe4e06035     1504000000000000     376   0.0263%
    7f27a9fd01452308a9336dd41b082981b8f18a85      852000000000000     213   0.0149%
    ca0ebdf61e8da57d6ec562252cbbc256382155d2      236007400000000       7   0.0041%
    04c1b2641251a1c96156fb2292e033450116d924      236000000000000      59   0.0041%
    5b00d538273d2a1d1e19d90151c4aa9941db7093      224000000000000      56   0.0039%
    5d493bc420d4a741380cf5ec882dd140d2cb2132      196000000000000      49   0.0034%
    de276e5c29a16832e98e57262d2cbb6a359b16ff      190476190476189       2   0.0033%
    c88949a07ad298f2f8a54a2cb69ed54e6157bee4       16000000000000       4   0.0003%
    c7c4341f7c0278a81da5a471ef2504141f20637a         100000000000       1   0.0000%
    85c196a286c3769074b6d0542fcbf1248661f7df          49785199199       4   0.0000%
    e3333b6b68f67a5da907cec4b7aecaac617a4393          45019036725       2   0.0000%
    bcf32fff5c461789be4928e5475752ad9708d4db          10000000000       1   0.0000%
    eaa6206c5db4c309a456e7f13e398b4b24e8e41e           1000000000       1   0.0000%
    8f674944bd83d5b605b4d13627b2002275778a7c             80370521       1   0.0000%
    2212f5ced7f7e2e10e0a613fcd93d0b8f6cf2a6e             14591287      22   0.0000%

## What moved, and when

Between slot 5,909 and slot 51,805 (epochs 184–1618) the chain carried **1,051
transactions**, all of them transfers — no deposit, no exit, no delegation, no
slashing evidence has ever been included. Those 1,051 transactions consumed
**383,940 outputs** and created **2,099**, at roughly 900 inputs each: this is
consolidation, not payment traffic.

The founder script hash went from 426,199 outputs to 45,149 and from
56,046,829,380.86018372 to 37,918,473,235.78565979 BLCH, a net move of
**18,128,356,145.07452011 BLCH**. It is concentrated in time — 1% of it had
moved by slot 28,944, 50% by slot 36,591, 99% by slot 38,966:

    slots         epochs        net change on the founder script hash
    4000–9999     125–312            -19,214,003.02 BLCH
    20000–27999   625–874            -23,400,200.00 BLCH
    28000–31999   875–999           -520,000,000.00 BLCH
    32000–33999   1000–1062       -3,355,211,723.01 BLCH
    34000–35999   1062–1124       -4,076,139,413.01 BLCH
    36000–37999   1125–1187       -5,843,390,806.01 BLCH
    38000–39999   1187–1249       -4,261,000,000.01 BLCH
    46000–51999   1437–1624         -30,000,000.00 BLCH

All five vested buckets were spent, in epochs 1052–1167 — LIQUIDITY at slot
33,665, MARKETING at 33,993, FOUNDER at 34,927, TEAM at 35,212, VC at 37,351.
Their `unlock_epoch` is 0 and nothing in `bloch-pos-committee` reads that field,
so they were spendable from height 0; "vested" describes the manifest, not a
rule.

### Where it went

Fourteen script hashes received it. Six of them held nothing at genesis and now
hold between 2.0 and 3.5 billion BLCH each:

    f844d776…  +3,535,000,000.00000000   slots 37641–38823   epochs 1176–1213
    977d7bf3…  +3,064,506,150.00000000   slots 33037–34256   epochs 1032–1070
    2c825a23…  +3,015,484,302.00000000   slots 34265–34949   epochs 1070–1092
    9bdf65b1…  +3,000,289,488.00000000   slots 34956–36932   epochs 1092–1154
    a57c36a0…  +2,919,818,089.99997807   slots 20403–37629   epochs  637–1175
    7560b940…  +2,031,000,000.00000000   slots 38824–38974   epochs 1213–1217
    cb339d2e…    +532,257,760.01239997   slots  5909–37428   epochs  184–1169
    3d36e898…     +70,916,993.99997833   slots 18039–48054   epochs  563–1501
    ce3ea055…     +29,999,989.99997833   slots 46470–51805   epochs 1452–1618
    ca0ebdf6…      +2,360,074.00000000
    c7c4341f…          +1,000.00000000
    85c196a2…            +354.99961104
    bcf32fff…            +100.00000000
    eaa6206c…             +10.00000000

Every one is in the same 20-byte-plus-12-zeros carryover form; **none is a
native 32-byte `SHA3-256(pubkey)` lock**, and none appears anywhere in this
repository.

**MEASURED:** the coins moved, in the amounts and at the slots above. The chain
cannot say who controls any destination address, and never will.

**DECLARED (founder, 2026-09-01):** the 18,128,356,145.07452011 BLCH were
**private sales to third parties**. The destinations are buyers' addresses, not
the founder's own wallets.

The audit reached this page with two live readings and no way to choose between
them; the founder's statement chooses. Recorded as declaration rather than
folded into the measurements, because a later auditor re-deriving this file will
reproduce every measured number and will **not** be able to reproduce this one.
If the declaration is wrong, concentration is 98.26% rather than 66.35% and
nothing on chain would betray the difference.

Four addresses lost value by spending their own coins, not the founder's:
`2212f5ce…` -70,917,619.00, `8f674944…` -1,999,523.00, `e3333b6b…` -360,026.00,
`556b6f1a…` -1,000.00 BLCH.

## The three denominators — always label which one

`27.04%`, `37.92%` and `66.35%` are all in circulation, all describe the
founder, and all mean different things. A reader who compares any two of them
without the denominator concludes something false — for instance that the
position *grew* from 27.04% to 37.92%, when in truth it shrank from 56.05%.
**Never print one of these without saying what it is a share of.**

There are three denominators, and only three:

    cap          100,000,000,000 BLCH   the hard cap (TOTAL_SUPPLY_BLOCH)
    issued        57,146,400,000 BLCH   in existence today (GENESIS_ISSUED_SAT).
                                        The other 42,853,600,000 (42.85% of the
                                        cap) is future validator emission that
                                        has not been minted.
    carryover     18,146,400,000 BLCH   the Genesis-3 balance set only

    figure                              BLCH          /cap   /issued  /carryover
    founder at genesis (M)  56,046,829,380.86       56.05%    98.08%          —
    founder now        (M)  37,918,473,235.79       37.92%    66.35%          —
    sold               (D)  18,128,356,145.07       18.13%    31.72%          —
    founder's carryover(M)  17,046,829,380.86       17.05%    29.83%      93.94%

(M) measured, (D) declared. The `27.04%` figure is on none of these lines: it
is a fourth thing, and it is wrong — see below.

## `FOUNDER_TOTAL_BLOCH` understates the founder by 29 billion BLCH

**This is a defect by construction, not staleness.** It has been wrong since
genesis, before any sale, and no re-measurement fixes it.

    tokenomics_v4.rs:445   FOUNDER_TOTAL_BLOCH = LARGEST_CARRYOVER_ADDRESS_BLOCH + FOUNDER_BLOCH
                                               = 17,046,829,380 + 10,000,000,000
                                               = 27,046,829,380          (2704 bps, 27.04%)

`FOUNDER_BLOCH` is **one of five** allocation buckets, and `main.rs:605-622`
writes all five to the *same* script hash — the founder's — under one
`script_hash` expression, with one ownership convention. The other four are
`VC_BLOCH` + `TEAM_BLOCH` + `MARKETING_BLOCH` + `LIQUIDITY_BLOCH` =
**29,000,000,000 BLCH**, and the constant silently drops every one of them.

The value it should hold:

    pub const FOUNDER_TOTAL_BLOCH: u128 = LARGEST_CARRYOVER_ADDRESS_BLOCH
        + FOUNDER_BLOCH + VC_BLOCH + TEAM_BLOCH + MARKETING_BLOCH + LIQUIDITY_BLOCH;
    const _: () = assert!(FOUNDER_TOTAL_BLOCH * 10_000 / TOTAL_SUPPLY_BLOCH == 5604);

    = 56,046,829,380 BLCH = 56.05% of the cap, 98.08% of issued

That figure is independently confirmed: replaying the chain from genesis gives
the founder script hash **56,046,829,380.86018372 BLCH at height 0**, which is
the corrected constant to the whole BLOCH. The constant and the chain agree —
once the constant stops omitting four fifths of the allocations.

`FOUNDER_TOTAL_BLOCH` has **no consumer in `bloch-pos-committee` or
`bloch-pos-node` outside `tokenomics_v4.rs` itself**: it is a reporting
constant, so correcting it moves no consensus behaviour and no state root. It
is nonetheless compile-pinned, so the fix is two lines and both must move
together.

### Where the wrong number is published

Three *different* wrong values are in the tree, all understating the same way.
`tokenomics_v4.rs` disagrees with itself across three lines of one file:

    tokenomics_v4.rs:95     26.89%   doc comment
    tokenomics_v4.rs:439    27.02%   doc comment on the constant
    tokenomics_v4.rs:446    2704     the live compile-time assert (27.04%)

    docs/specs/BLOCH-TOKENOMICS-V4.md:66     27.04%
    docs/specs/BLOCH-TOKENOMICS-V4.md:519    27.04%  (table, with 16.89% liquid)
    docs/audit/CERTIK-CENTRALIZATION.md:77   26.886549523809524%, "pinned at 2688 bps"
    docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md:153  26.89%
    docs/whitepaper/ED2-ECONOMICS-GOVERNANCE.md:228-229  26.89%
    docs/site/SITE-PLAN.md:101               26.89%, cites "assert == 2688"
    docs/site/COPY.md:304                    26.89% ("16.89% liquid + 10% locked")
    docs/site/COPY.md:712                    26.89%
    apps/site/supply.html:212,218            26.89%  ← the live public page

The two CertiK files are the sharp end: a centralization dossier prepared for
an external auditor understates the founder's genesis position by 29 billion
BLCH, and cites a bps pin (2688) that the code no longer contains.

**The public page is the worst of them**, and it is worse than the constant it
quotes. `apps/site/supply.html` publishes *two* superseded measurements on top
of the construction error:

    published on the site        current constant / measurement      out by
    largest address  16,886,549,523      17,046,829,380 (17,046,829,380.86 M)   -160M
    carryover total  17,970,880,000      18,146,400,000                         -176M
    founder combined         26.89%      56.05% of cap (98.08% of issued)     -29.16pp

Its own source comment cites `tokenomics_v4.rs:96-99,234-237,239-241` — line
numbers that no longer hold the constants named. One sentence on that page is
now *confirmed* correct and should stay: the balance is **"liquid from slot
0"**. The adjacent phrase "the new vested grant" should not — nothing about it
is vested in any sense a node enforces.

`COPY.md:304`'s gloss — "16.89% liquid at genesis plus 10% locked for a decade"
— is wrong twice over: the liquid carryover share is 17.05% of the cap, and
nothing was ever locked (next section).

## Nothing sold was ever locked on chain

**MEASURED.** All five allocation buckets carry `unlock_epoch = 0`, and
`unlock_epoch` has **zero occurrences in `bloch-pos-committee`**, the crate that
authorises spends. It is encoded in the manifest, decoded from it, and folded
into each allocation's txid — every node agrees on the number and no node ever
reads it to decide whether an output may move. Commit `fa4ad9be` on `main`
documents this and pins it with two tests, both verified by violating them.

So the buckets were spendable from height 0, and all five have been spent:

    LIQUIDITY   slot 33,665   epoch 1052
    MARKETING   slot 33,993   epoch 1062
    FOUNDER     slot 34,927   epoch 1091
    TEAM        slot 35,212   epoch 1100
    VC          slot 37,351   epoch 1167

"Vested" describes the manifest, not a rule. **There is no on-chain lockup on
any coin that was sold, and none on any coin the founder still holds.** If a
contractual lockup was agreed with buyers, it is on paper; the chain neither
encodes it, enforces it, nor evidences it, and no observer can verify it from
the ledger. A reader who saw "10% locked for a decade" in the site copy and
inferred a consensus guarantee inferred something that has never been true.

## The arithmetic, closing

    founder net change            -1,812,835,614,507,451,916 sat
    other addresses gained        +1,820,163,431,301,194,602 sat
    other addresses lost             -7,327,816,800,461,842 sat
    ----------------------------------------------------------
    sum of every delta                          -6,719,156 sat
    fees burned                                  6,719,156 sat

Nothing is missing. The 18.1 billion BLCH was never lost, never stranded at an
unqueryable script hash, and never minted: it was spent, on chain, to addresses
that are perfectly visible to `getbalance` — nobody had asked.

What the chain proves is the movement, to the satoshi. What it cannot prove is
the buyers, or that they are buyers at all. Those two sentences should stay
next to each other wherever this is retold.
