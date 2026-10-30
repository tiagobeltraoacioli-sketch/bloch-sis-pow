#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Reference checks for exchanges integrating Bloch L1 (Genesis-4) and the
native L2 bridge (chain 700770). Read-only, standard library only.

Subcommands:

  address BLOCH1Q_ADDRESS
      Validate a bloch1q address (checksum) and print its carried-form
      script_hash (the 32-byte key every balance/UTXO RPC takes).

  tx TXID [--vout N --script-hash HEX --amount SAT] [--wait SECONDS]
      Check an L1 transaction (deposit, withdrawal, L2 deposit 0x14 or L2
      claim 0x16) to finality on every node given with --rpc. CREDITABLE only
      when every node reports gettxstatus "finalized", every node is synced,
      every node reports the same finalized checkpoint (epoch and root) and
      the hard-fork schedule of the armed release, and, if --vout is given,
      the output exists with the expected script_hash/amount.

  claim --index I --sats S [--wait SECONDS]
      Check whether L2 withdrawal number I (its nonce on the L2 outbox) of S
      sat can be claimed on L1 in the next block: getl2settlement must offer a
      claimable root that covers the index, the root must be finalized on this
      chain's own checkpoint, the index must not be claimed yet. Reports the
      attestation and release-window conditions that the claim must also meet.

  l2tx TXHASH --l2-rpc URL [--wait SECONDS]
      Check an L2 (EVM) transaction: receipt status 0x1 and block number at or
      below the L2 "finalized" tag.

Exit status: 0 = final/claimable, 1 = not yet, 2 = refused, disagreement or
error. Every node in --rpc must be an independent, upgraded node; the defaults
are the public read-only endpoints, which are fine for testing but are not a
substitute for your own node.
"""

import argparse
import hashlib
import json
import sys
import time
import urllib.request

DEFAULT_RPCS = ["http://80.240.16.185:8080", "http://199.247.22.8:8080"]
GENESIS_TIME = 1786656679
EPOCH_SECONDS = 960
MAINNET_L2_CHAIN_ID = 700770
# Gates of the armed release (78d4921c and its descendants, e.g. fa980367).
EXPECTED_GATES = {"hf1_claim_finality": 7180, "hf2_sig_canonical": 7270, "hf3_slh": 7360}
MAX_BEHIND_SLOTS = 2

FINAL, NOT_YET, REFUSED = 0, 1, 2


class RpcError(Exception):
    pass


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            doc = json.loads(resp.read().decode())
    except Exception as exc:
        raise RpcError(f"{url} {method}: {exc}") from exc
    if doc.get("error"):
        raise RpcError(f"{url} {method}: {doc['error']}")
    return doc.get("result")


def hex32(text, what):
    text = text.lower().removeprefix("0x")
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        raise SystemExit(f"{what} must be 32 bytes of hex")
    return text


def epoch_utc(epoch):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(GENESIS_TIME + epoch * EPOCH_SECONDS))


# ---------------------------------------------------------------- address

def address_to_script_hash(address):
    """bloch1q + hex(20-byte hash || 4-byte checksum); checksum is
    SHA3-256(SHA3-256(hash))[:4]; carried script_hash = hash || 12 zero bytes."""
    if not address.startswith("bloch1q") or len(address) != 55:
        raise ValueError("not a bloch1q address (55 characters)")
    try:
        body = bytes.fromhex(address[7:])
    except ValueError as exc:
        raise ValueError("address body is not hex") from exc
    digest, checksum = body[:20], body[20:]
    expected = hashlib.sha3_256(hashlib.sha3_256(digest).digest()).digest()[:4]
    if checksum != expected:
        raise ValueError("address checksum mismatch")
    return (digest + bytes(12)).hex()


def cmd_address(args):
    try:
        print(address_to_script_hash(args.address))
    except ValueError as exc:
        print(f"REFUSED: {exc}")
        return REFUSED
    return FINAL


# ---------------------------------------------------------------- node health

def node_view(url):
    """Health of one node. Returns (problems, finalized (epoch, root), info)."""
    info = rpc(url, "getchaininfo", [])
    problems = []
    if info.get("behind_by_slots", 0) > MAX_BEHIND_SLOTS:
        problems.append(f"{url}: behind by {info['behind_by_slots']} slots")
    if info.get("finalized_height") is None and info["finalized"]["epoch"] > 0:
        problems.append(f"{url}: finalized checkpoint is not on this node's canonical chain (possible split)")
    forks = info.get("hard_forks") or {}
    for key, epoch in EXPECTED_GATES.items():
        got = (forks.get(key) or {}).get("activation_epoch")
        if got != epoch:
            problems.append(f"{url}: hard_forks.{key} = {got}, expected {epoch} (node not on the armed release)")
    return problems, (info["finalized"]["epoch"], info["finalized"]["root"]), info


def fleet_view(urls):
    problems, finals = [], {}
    for url in urls:
        p, fin, _ = node_view(url)
        problems += p
        finals[url] = fin
    # Nodes finalize one after another; compare roots at the lowest common
    # epoch only when the epochs are equal, else just require the same root
    # when they report the same epoch.
    by_epoch = {}
    for url, (epoch, root) in finals.items():
        by_epoch.setdefault(epoch, set()).add(root)
    for epoch, roots in by_epoch.items():
        if len(roots) > 1:
            problems.append(f"nodes disagree on the finalized root at epoch {epoch}: {sorted(roots)}")
    return problems, finals


# ---------------------------------------------------------------- tx

def check_tx(args):
    txid = hex32(args.txid, "txid")
    problems, finals = fleet_view(args.rpc)
    if problems:
        for p in problems:
            print("HALT:", p)
        return REFUSED
    statuses = {url: rpc(url, "gettxstatus", [txid])["status"] for url in args.rpc}
    for url, status in statuses.items():
        print(f"{url}: gettxstatus={status} finalized_epoch={finals[url][0]}")
    if any(s == "unknown" for s in statuses.values()) and any(s != "unknown" for s in statuses.values()):
        print("WAIT: nodes disagree on whether the transaction exists")
        return NOT_YET
    if args.vout is not None:
        for url in args.rpc:
            out = rpc(url, "gettxout", [txid, args.vout])
            utxo = out.get("utxo")
            if not out.get("unspent") or utxo is None:
                # A spent output is not an error after the deposit was swept.
                print(f"{url}: output {txid}:{args.vout} is not unspent (spent already, or not on this chain)")
                if all(s == "finalized" for s in statuses.values()):
                    print("NOTE: transaction final; the output was already spent")
                continue
            if args.script_hash and utxo["script_hash"] != hex32(args.script_hash, "script hash"):
                print(f"REFUSED: output pays {utxo['script_hash']}, not your script_hash")
                return REFUSED
            if args.amount is not None and int(utxo["value_sat"]) != args.amount:
                print(f"REFUSED: output value {utxo['value_sat']} sat, expected {args.amount}")
                return REFUSED
    if all(s == "unknown" for s in statuses.values()):
        print("WAIT: unknown on every node (not broadcast, dropped, or older than the node's "
              "65,536-transaction status index; for old transactions use gettxout/getutxos)")
        return NOT_YET
    if all(s == "finalized" for s in statuses.values()):
        print("CREDITABLE: finalized on every node, same finalized checkpoint, armed release")
        return FINAL
    print("WAIT: not finalized on every node yet")
    return NOT_YET


# ---------------------------------------------------------------- claim

def claimed(bitmap, index):
    word = index // 256
    if word < bitmap["floor"]:
        return True
    bit = index % 256
    for entry in bitmap["words"]:
        if entry["word"] == word:
            bits = bytes.fromhex(entry["bits"])
            return bits[bit // 8] & (1 << (bit % 8)) != 0
    return False


def check_claim_on(url, args):
    """One node's verdict: (status, root or None, messages)."""
    s = rpc(url, "getl2settlement", [])
    msgs = []
    if s is None:
        return REFUSED, None, [f"{url}: no L2 installed on this node's chain"]
    if s["chain_id"] != MAINNET_L2_CHAIN_ID:
        return REFUSED, None, [f"{url}: chain_id {s['chain_id']} is not {MAINNET_L2_CHAIN_ID}"]
    if not s["profile"]["activated"]:
        return REFUSED, None, [f"{url}: L2 not activated"]
    w = s["withdrawals"]
    if not w["escrow_conserved"]:
        return REFUSED, None, [f"{url}: escrow_conserved is false: stop all L2 crediting"]
    if s["accepted"] is None:
        return NOT_YET, None, [f"{url}: no L2 settlement accepted yet (L2 at genesis)"]
    if claimed(w["claimed"], args.index):
        return REFUSED, None, [f"{url}: withdrawal {args.index} is already claimed"]
    large = args.sats >= int(w["large_claim_sat"])
    key = "claimable_large" if large else "claimable"
    root = w[key]
    fc = w["finalized_checkpoint"]
    if fc["own_chain_rule_active"]:
        if fc["own_root"] is None:
            return NOT_YET, None, [f"{url}: HF1 claim pause: no own checkpoint recorded for finalized epoch "
                                   f"{fc['epoch']} yet (claims resume once an epoch >= 7180 checkpoint finalizes)"]
        if fc["own_root"] != fc["root"]:
            return REFUSED, None, [f"{url}: finalized checkpoint epoch {fc['epoch']} is not this chain's own "
                                   f"(own_root={fc['own_root']}): treat as a split, do not claim or credit"]
    if root is None:
        return NOT_YET, None, [f"{url}: no {key} root yet (delay {w['large_delay_blocks' if large else 'delay_blocks']} "
                               f"blocks and L1 finality pending; finalized epoch {fc['epoch']})"]
    if not root["finalized"]:
        return REFUSED, None, [f"{url}: {key} root not finalized (node inconsistency)"]
    if args.index >= root["count"]:
        return NOT_YET, None, [f"{url}: {key} root covers withdrawals 0..{root['count'] - 1}; index {args.index} "
                               f"is in a later settlement that is not matured and finalized yet"]
    if w["attestor_set"] is not None and args.sats >= int(w["attested_claim_sat"]):
        msgs.append(f"{url}: amount >= attested_claim_sat ({w['attested_claim_sat']} sat): the claim needs "
                    f"k-of-n attestor partials (claim version 2)")
    window = w["release_window"]
    if args.sats > int(window["remaining_sat"]):
        msgs.append(f"{url}: release window {window['window']} has {window['remaining_sat']} sat left; a claim "
                    f"of {args.sats} sat fits only a later window, or as the first claim of a window if it "
                    f"carries attestor signatures (mainnet has an attestor set)")
    msgs.append(f"{url}: CLAIMABLE against root {root['root']} (L2 block {root['l2_number']}, "
                f"L1 height {root['height']}, finalized checkpoint epoch {fc['epoch']})")
    return FINAL, root["root"], msgs


def check_claim(args):
    problems, _ = fleet_view(args.rpc)
    if problems:
        for p in problems:
            print("HALT:", p)
        return REFUSED
    verdicts = [check_claim_on(url, args) for url in args.rpc]
    for _, _, msgs in verdicts:
        for m in msgs:
            print(m)
    codes = {v[0] for v in verdicts}
    if REFUSED in codes:
        return REFUSED
    if codes == {FINAL}:
        roots = {v[1] for v in verdicts}
        if len(roots) > 1:
            print("WAIT: nodes offer different claimable roots (one is a block ahead); retry")
            return NOT_YET
        print("CLAIMABLE on every node. After broadcasting the claim, run: tx <claim txid> --vout <recipient vout>")
        return FINAL
    return NOT_YET


# ---------------------------------------------------------------- l2tx

def check_l2tx(args):
    url = args.l2_rpc
    chain = int(rpc(url, "eth_chainId", []), 16)
    if chain != MAINNET_L2_CHAIN_ID:
        print(f"REFUSED: eth_chainId {chain} is not {MAINNET_L2_CHAIN_ID}")
        return REFUSED
    receipt = rpc(url, "eth_getTransactionReceipt", [args.txhash])
    if receipt is None:
        print("WAIT: no receipt yet")
        return NOT_YET
    if receipt["status"] != "0x1":
        print("REFUSED: transaction reverted (status 0x0)")
        return REFUSED
    fin = rpc(url, "eth_getBlockByNumber", ["finalized", False])
    if fin is None:
        print("WAIT: the RPC serves no finalized block (follower not verified)")
        return NOT_YET
    block, final = int(receipt["blockNumber"], 16), int(fin["number"], 16)
    if block <= final:
        canonical = rpc(url, "eth_getBlockByNumber", [hex(block), False])
        if canonical is None or canonical["hash"] != receipt["blockHash"]:
            print("REFUSED: receipt block is not the canonical block at that number")
            return REFUSED
        print(f"CREDITABLE: block {block} <= finalized {final}")
        return FINAL
    print(f"WAIT: block {block} > finalized {final}")
    return NOT_YET


# ---------------------------------------------------------------- main

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rpc", action="append", help="L1 node RPC URL (repeat for each independent node)")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("address")
    a.add_argument("address")
    t = sub.add_parser("tx")
    t.add_argument("txid")
    t.add_argument("--vout", type=int)
    t.add_argument("--script-hash")
    t.add_argument("--amount", type=int, help="expected output value in sat")
    t.add_argument("--wait", type=int, default=0, help="poll until final, up to this many seconds")
    c = sub.add_parser("claim")
    c.add_argument("--index", type=int, required=True, help="withdrawal nonce on the L2 outbox")
    c.add_argument("--sats", type=int, required=True)
    c.add_argument("--wait", type=int, default=0)
    e = sub.add_parser("l2tx")
    e.add_argument("txhash")
    e.add_argument("--l2-rpc", required=True)
    e.add_argument("--wait", type=int, default=0)
    args = p.parse_args()
    args.rpc = args.rpc or DEFAULT_RPCS
    run = {"address": cmd_address, "tx": check_tx, "claim": check_claim, "l2tx": check_l2tx}[args.cmd]
    deadline = time.time() + getattr(args, "wait", 0)
    while True:
        try:
            code = run(args)
        except RpcError as exc:
            print("ERROR:", exc)
            code = REFUSED
        if code != NOT_YET or time.time() >= deadline:
            return code
        time.sleep(30)


if __name__ == "__main__":
    sys.exit(main())
