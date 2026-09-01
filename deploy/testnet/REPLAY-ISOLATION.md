# Why a signature made on the Bloch testnet cannot move coins on mainnet

Status: normative for anyone building, reseeding, or funding a Bloch testnet.
Audience: our own operators first, integration partners second.

This is the security argument the hosted testnet rests on. It is written out in
full because the honest version of it is narrower than the version people
assume, and the gap between the two is where a catastrophe fits.

---

## 1. The claim people assume, and why it is false

The comfortable assumption is that a testnet signature is harmless on mainnet
because the two are "different chains" — different genesis, different network
id, different peers. For most chains that is true, because the thing being
signed contains a chain identifier. Ethereum has EIP-155. Cosmos signs the
chain id. Bitcoin separates by address prefix and by having no shared history.

**Bloch Genesis-4 has no such field.** The root a spender signs is, verbatim
(`crates/bloch-pos-committee/src/transition.rs:474-530`):

```
spend_signing_root =
    SHA3-256( DS_SPEND
            ‖ n_spends ‖ (txid ‖ vout)*
            ‖ n_outputs ‖ (value ‖ script_hash)*
            ‖ tx_bytes
            ‖ tip )
```

There is no chain id, no network id, no genesis digest, and no epoch. A spend
signature is a statement about **outpoints**, and nothing else.

`DS_SPEND` (`params.rs:657`) does not close this. Domain tags in this protocol
separate *message types* — a spend from an attestation from a block proposal —
so that one signature cannot be reinterpreted as another kind of message. Every
Bloch network, testnet and mainnet alike, uses the byte-identical tag
`BLCH4:SPEND`. It separates *what kind of thing* was signed. It does not
separate *which chain* it was signed for.

`network_id` does not close it either. It exists
(`crates/bloch-pos-node/src/ws_boot.rs:110`), it is derived from the genesis
manifest digest, and it is used in exactly one place: binding weak-subjectivity
checkpoints. It never reaches transaction validation, the fee market, or the
state transition.

**Consequence, stated plainly.** Take a transaction out of a testnet block.
Rebroadcast its bytes to a mainnet node. If the outpoints it names exist on
mainnet under the same `script_hash`, mainnet accepts it, because from
mainnet's side it is indistinguishable from a genuine spend by the rightful
owner. There is no rule it breaks.

---

## 2. The one thing that actually provides isolation

Isolation between any two Bloch networks rests on a single property:

> **Their unspent-output sets must be disjoint.** No `(txid, vout)` may exist
> on both chains.

If that holds, a testnet-signed transaction names inputs that mainnet has never
heard of, and mainnet rejects it as an unknown outpoint. That rejection is the
entire defence. It is a *data* property, not a *protocol* property — the code
does not enforce it, and cannot, because a node validating a transaction has no
way to know another chain exists.

So the question "is this testnet safe?" reduces entirely to: **can any outpoint
on it also exist on mainnet?**

---

## 3. Where testnet outpoints come from, and how they are kept disjoint

A fresh testnet has exactly one source of coins: genesis allocations. Their
outpoints are derived in `Manifest::allocation_outputs`
(`crates/bloch-pos-node/src/genesis.rs:1067`):

```
txid = SHA3-256( "BLCH4:genesis-alloc\0" ‖ purpose ‖ script_hash ‖ amount_sat ‖ unlock_epoch )
vout = 0
```

Read that preimage carefully, because it is the crux: **it contains no network
binding.** Not the genesis time, not the slot length, not the validator set,
not the manifest digest. Two entirely unrelated networks that happen to define
one allocation with the same four fields mint the **same outpoint**.

Therefore the testnet is safe if and only if **no testnet allocation reproduces
a mainnet allocation's `(purpose, script_hash, amount_sat, unlock_epoch)`
tuple.**

In practice one field carries the whole argument: `script_hash`. It is
SHA3-256 of the owner's hybrid public key. The testnet's faucet allocation is
funded by a key generated on the testnet host, with `bloch-pos keygen`, that
has never existed anywhere else. For its `script_hash` to collide with a
mainnet allocation's, someone would have to find a second preimage for a
SHA3-256 output — or steal the mainnet key and deliberately reuse it.

That is the argument. It is sound, and it is *narrow*: it is a statement about
the freshness of one 32-byte value, not a structural guarantee the protocol
provides.

### Why every derived outpoint inherits the property

Coins minted after genesis do not weaken it. Every subsequent outpoint is
`txid = SHA3-256(DS_TXID ‖ spend_signing_root)`
(`transition.rs:534-551`), and the signing root covers the inputs being spent.
So every outpoint on the testnet is a hash chain rooted in a genesis allocation
that mainnet does not have. Disjointness at genesis propagates forward to the
whole chain by induction.

---

## 4. The one input that would destroy this: the carryover

**Never seed a testnet from the mainnet carryover.** This is not a style
preference; it is the difference between a test network and an attack on our
own users.

The Genesis-3 carryover snapshot is ingested with the original outpoint
**preserved unchanged** — deliberately, because wallets and existing signed
transactions depend on it (`genesis.rs:643-648`: "The Genesis-3 outpoint
crosses unchanged"). A testnet built from it would therefore reproduce
**452,726 mainnet outpoints exactly**, each locked to the `script_hash` of a
real holder who still controls the corresponding live mainnet key.

On such a network, every spend a user signs is a valid mainnet spend of their
real money. The testnet would not merely be unsafe; it would be a machine for
harvesting live-key authorisations from people who were told the coins were
worthless. Anyone who could read the testnet's blocks could sweep mainnet.

**What prevents it today:**

- `bloch-pos genesis` — the command that builds a devnet/testnet manifest — has
  **no carryover flag at all** (`main.rs:genesis_cmd`). The capability is not
  there to misuse.
- Only `genesis-mainnet` constructs a `CarryoverCommitment`, and only `run
  --carryover` ingests a snapshot.
- `deploy/testnet/hosted-testnet-up.sh` and `local-testnet-up.sh` never pass
  either, and say so in their headers.
- `a_testnet_manifest_commits_to_no_carryover` (`genesis.rs`, test module)
  fails if a testnet manifest ever grows one.

---

## 5. What is machine-checked, and what is only discipline

Honesty about which is which matters more than the count of tests.

**Machine-checked** (`crates/bloch-pos-node/src/genesis.rs`, test module):

| Test | Property |
|---|---|
| `a_freshly_keyed_testnet_allocation_cannot_collide_with_mainnet` | A different owning key mints a different outpoint — the half that saves us |
| `reproducing_a_mainnet_allocation_tuple_mints_the_same_outpoint` | Reproducing the tuple mints an identical outpoint — the half that would sink us, pinned so nobody can "optimise" the testnet into it without deleting an assertion that explains why not |
| `the_allocation_outpoint_carries_no_network_binding` | Changing genesis time, slot length or validator set does not move the txid; changing any of the four preimage fields does |
| `a_testnet_manifest_commits_to_no_carryover` | A testnet manifest carries no carryover commitment and no ingested entries |

**Discipline only — not enforced by any code path:**

- That the operator generates the faucet key freshly on the testnet host rather
  than importing one.
- That no mainnet key is ever loaded into testnet tooling.
- That a future testnet reset does not copy allocation tuples from an older
  manifest that shared them with mainnet.

The tests make the *rule* legible and its violation loud. They cannot make the
operator generate a fresh key.

---

## 6. What would make this structural, and why we have not done it

The clean fix is to fold a network tag into the allocation txid preimage —
empty for mainnet (preserving every existing mainnet outpoint bit-for-bit) and
non-empty for every testnet, so collision becomes impossible rather than merely
improbable.

It is deliberately **not** done in this change, because the manifest is hashed
to produce the genesis digest, the digest produces the `network_id`, and nodes
re-synthesise genesis from the manifest whenever they sync from an empty data
directory. Adding a serialised field is a genesis-format change on a running
mainnet. That is a flag-day-shaped decision, not a change to be smuggled in
alongside a testnet deployment.

**Recommendation for the founder:** schedule this. Until it lands, the sentence
"testnet and mainnet outpoints are disjoint" is a fact about how we operate,
not a fact the protocol guarantees — and it should be described that way in
partner-facing material, which is why the onboarding document no longer says
"by construction".

---

## 7. What an integrator should take from this

1. Key reuse across networks is **not** what breaks isolation — outpoint
   collision is, and with a properly built testnet the outpoints differ. But
   you cannot verify our genesis construction for every future reset, so treat
   testnet keys as throwaway and never load a mainnet key into testnet tooling.
   It costs nothing and removes you from the blast radius entirely.
2. Test BLCH is not redeemable, convertible, or bridgeable. There is no
   mechanism by which a testnet coin becomes a mainnet coin.
3. If you ever see a Bloch testnet whose balances mirror real mainnet holdings,
   **do not use it and tell us immediately.** That is the failure mode this
   document exists to prevent, and it is visible from the outside: check that
   your own mainnet address holds nothing on the testnet.
