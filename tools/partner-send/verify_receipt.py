#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""verify_receipt.py — the partner's receipt for a Bloch Genesis-4 transfer.

Genesis-4 has NO transaction ids at the wallet layer: a transfer carries no
id you can look up, and the node's `gettransaction` refuses by design. The
address's balance and UTXO set ARE the receipt — which makes this script the
receipt mechanism, not a convenience.

What it does, with nothing but the Python 3 standard library:

  1. Validates your `bloch1q…` address (length, hex, SHA3-256 checksum).
  2. Derives the `script_hash` the chain keys your outputs by: the 20 bytes
     after the prefix, zero-padded to 32.
  3. Takes a baseline of your balance and outputs, then polls `getbalance`.
  4. When the balance rises, lists exactly which outputs arrived
     (`getutxos`), each with its value and the slot it landed in.
  5. Waits until the chain FINALIZES the receiving epoch
     (`getchaininfo.finalized.epoch` — explicit finality, not a confirmation
     count) and prints the receipt. Settlement is typically 16–32 minutes
     after inclusion.

Usage:
    python3 verify_receipt.py bloch1q… --rpc http://<your-node>:16400 \
        [--expect 25]            # BLCH amount you were told to expect
        [--interval 15]          # seconds between polls
        [--timeout 120]          # minutes before giving up
    python3 verify_receipt.py --selftest

Exit codes: 0 received (and matches --expect, when given); 2 received but
the amount differs from --expect; 3 timeout; 1 usage/RPC errors.

Run it against YOUR OWN node if you have one — that is the point of a
receipt. Requires Python 3.6+ (hashlib.sha3_256).
"""

import argparse
import hashlib
import json
import sys
import time
import urllib.request

MAINNET_PREFIX = "bloch1q"
TESTNET_PREFIX = "bloch1t"
SAT_PER_BLCH = 100_000_000


# ── Address → script_hash ───────────────────────────────────────────────────

def parse_address(addr):
    """Validate a Bloch address and return (network, 20-byte hash).

    Layout: prefix ‖ hex(20-byte pubkey hash ‖ 4-byte checksum), where the
    checksum is SHA3-256(SHA3-256(hash))[:4].
    """
    if addr.startswith(MAINNET_PREFIX):
        network, payload = "mainnet", addr[len(MAINNET_PREFIX):]
    elif addr.startswith(TESTNET_PREFIX):
        network, payload = "testnet", addr[len(TESTNET_PREFIX):]
    else:
        raise ValueError("address must start with bloch1q (mainnet) or bloch1t (testnet)")
    if len(payload) != 48:
        raise ValueError("address payload must be 48 hex chars (20-byte hash + 4-byte checksum), "
                         "got %d" % len(payload))
    try:
        raw = bytes.fromhex(payload)
    except ValueError:
        raise ValueError("address payload is not valid hex")
    hash20, checksum = raw[:20], raw[20:]
    inner = hashlib.sha3_256(hash20).digest()
    expected = hashlib.sha3_256(inner).digest()[:4]
    if checksum != expected:
        raise ValueError("address checksum mismatch — the address is mistyped or corrupted")
    return network, hash20


def script_hash_hex(hash20):
    """The UTXO-set key for an ADDRESS: its 20 bytes, zero-extended to 32.

    Mirrors bloch_pos_committee::script_hash::carried_from_g3_hash160, which is
    the one implementation; this is a re-statement in Python because a receipt
    verifier must run with nothing installed, and it is guarded by
    crates/bloch-pos-committee/tests/one_script_hash_derivation.rs.

    NOT the derivation for a native Genesis-4 key. That key's outputs are keyed
    by SHA3-256(pubkey) -- all 32 bytes -- which is a DIFFERENT key in the UTXO
    set. Consensus opens both, so paying the wrong one is silent and the payee
    reads a zero balance. This function is for Genesis-3 carryover addresses,
    which is the population partner-send exists to pay.
    """
    return (hash20 + bytes(12)).hex()


def format_blch(sat):
    whole, frac = divmod(sat, SAT_PER_BLCH)
    if frac == 0:
        return str(whole)
    return "%d.%s" % (whole, ("%08d" % frac).rstrip("0"))


def parse_blch(s):
    """Strict BLCH decimal → satoshis (mirrors the sender tool's parser)."""
    s = s.strip()
    whole, _, frac = s.partition(".")
    if not (whole + frac) or not (whole + frac).isdigit() or len(frac) > 8:
        raise ValueError("`%s` is not a BLCH amount (digits, at most 8 decimals)" % s)
    return int(whole or "0") * SAT_PER_BLCH + int((frac or "0").ljust(8, "0"))


# ── JSON-RPC ────────────────────────────────────────────────────────────────

def rpc(url, method, params, timeout=15, _open=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    opener = _open or urllib.request.urlopen
    with opener(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode())
    err = payload.get("error")
    if err:
        raise RuntimeError("%s: node error %s: %s"
                           % (method, err.get("code"), err.get("message")))
    if "result" not in payload:
        raise RuntimeError("%s: response has no result" % method)
    return payload["result"]


def sat_int(v):
    """Amounts arrive as decimal strings (they exceed 2^53); accept numbers too."""
    if isinstance(v, int):
        return v
    return int(str(v).strip())


def get_balance(url, sh, _open=None):
    r = rpc(url, "getbalance", [sh], _open=_open)
    return sat_int(r["balance_sat"]), int(r.get("utxo_count", 0))


def get_outpoints(url, sh, _open=None):
    r = rpc(url, "getutxos", [sh, 1000], _open=_open)
    utxos = {}
    for u in r.get("utxos", []):
        utxos[(u["txid"], int(u["vout"]))] = {
            "value_sat": sat_int(u["value_sat"]),
            "at_slot": int(u.get("at_slot", 0)),
        }
    return utxos, bool(r.get("truncated", False))


def get_chain(url, _open=None):
    return rpc(url, "getchaininfo", [], _open=_open)


# ── The watch ───────────────────────────────────────────────────────────────

def watch(url, address, expect_sat=None, interval=15, timeout_minutes=120,
          _open=None, _sleep=time.sleep, out=sys.stdout):
    network, hash20 = parse_address(address)
    sh = script_hash_hex(hash20)
    print("address     %s (%s)" % (address, network), file=out)
    print("script_hash %s" % sh, file=out)

    chain = get_chain(url, _open=_open)
    slots_per_epoch = int(chain.get("slots_per_epoch", 32))
    print("chain       height %s, epoch %s, finalized epoch %s"
          % (chain.get("height"), chain.get("epoch"),
             chain.get("finalized", {}).get("epoch")), file=out)

    base_balance, base_count = get_balance(url, sh, _open=_open)
    base_outpoints, truncated = get_outpoints(url, sh, _open=_open)
    if truncated:
        print("WARNING: this address already has >1000 outputs; new-output "
              "detection may be incomplete. The balance delta is still exact.",
              file=out)
    print("baseline    %s BLCH (%d sat) across %d output(s)"
          % (format_blch(base_balance), base_balance, base_count), file=out)
    if expect_sat is not None:
        print("expecting   +%s BLCH (%d sat)"
              % (format_blch(expect_sat), expect_sat), file=out)
    print("polling getbalance every %ds (Ctrl-C to stop)…" % interval, file=out)

    deadline = time.monotonic() + timeout_minutes * 60
    while True:
        if time.monotonic() > deadline:
            print("TIMEOUT: no funds arrived within %d minutes." % timeout_minutes,
                  file=out)
            return 3
        try:
            balance, count = get_balance(url, sh, _open=_open)
        except Exception as e:  # noqa: BLE001 — a receipt tool retries, loudly
            print("rpc error (will retry): %s" % e, file=out)
            _sleep(interval)
            continue
        if balance > base_balance:
            break
        if balance < base_balance:
            print("note: balance DECREASED to %s sat (something spent from "
                  "this address); re-baselining." % balance, file=out)
            base_balance, base_count = balance, count
            base_outpoints, _ = get_outpoints(url, sh, _open=_open)
        _sleep(interval)

    delta = balance - base_balance
    print("\nFUNDS ARRIVED: +%s BLCH (%d sat), balance now %s BLCH"
          % (format_blch(delta), delta, format_blch(balance)), file=out)

    outpoints, _ = get_outpoints(url, sh, _open=_open)
    new = {k: v for k, v in outpoints.items() if k not in base_outpoints}
    max_slot = 0
    for (txid, vout), info in sorted(new.items()):
        print("  output %s:%d  %s BLCH (%d sat)  at slot %d"
              % (txid, vout, format_blch(info["value_sat"]), info["value_sat"],
                 info["at_slot"]), file=out)
        max_slot = max(max_slot, info["at_slot"])

    # Settlement: Genesis-4 finality is explicit. The funds are settled when
    # the epoch of the receiving slot is <= the finalized epoch.
    target_epoch = max_slot // slots_per_epoch if max_slot else None
    if target_epoch is not None:
        print("waiting for finality of epoch %d (explicit finality, "
              "typically 16-32 min after inclusion)…" % target_epoch, file=out)
        while True:
            try:
                chain = get_chain(url, _open=_open)
                fin = int(chain.get("finalized", {}).get("epoch", -1))
                if fin >= target_epoch:
                    break
                if time.monotonic() > deadline:
                    print("received but NOT yet finalized (finalized epoch %d "
                          "< %d) when the timeout expired. Keep watching "
                          "getchaininfo.finalized.epoch before crediting." % (fin, target_epoch),
                          file=out)
                    return 3
            except Exception as e:  # noqa: BLE001
                print("rpc error (will retry): %s" % e, file=out)
            _sleep(interval)

    print("\n── RECEIPT ─────────────────────────────────────────────", file=out)
    print("received   +%s BLCH (%d sat)" % (format_blch(delta), delta), file=out)
    print("address    %s" % address, file=out)
    print("balance    %s BLCH (%d sat), %d output(s)"
          % (format_blch(balance), balance, count), file=out)
    if target_epoch is not None:
        print("finality   epoch %d FINALIZED — settled, safe to credit" % target_epoch,
              file=out)
    print("chain      height %s, state_root %s"
          % (chain.get("height"), chain.get("state_root")), file=out)
    print("────────────────────────────────────────────────────────", file=out)

    if expect_sat is not None and delta != expect_sat:
        print("MISMATCH: expected +%s BLCH but received +%s BLCH"
              % (format_blch(expect_sat), format_blch(delta)), file=out)
        return 2
    if expect_sat is not None:
        print("amount matches what was expected.", file=out)
    return 0


# ── Self-test (no network) ──────────────────────────────────────────────────

def selftest():
    import io

    # 1. Address derivation vectors, checksum included.
    hash20 = bytes(range(20))
    checksum = hashlib.sha3_256(hashlib.sha3_256(hash20).digest()).digest()[:4]
    good = MAINNET_PREFIX + (hash20 + checksum).hex()
    net, h = parse_address(good)
    assert net == "mainnet" and h == hash20
    assert script_hash_hex(h) == hash20.hex() + "00" * 12
    assert len(script_hash_hex(h)) == 64

    tnet, _ = parse_address(TESTNET_PREFIX + (hash20 + checksum).hex())
    assert tnet == "testnet"

    for bad in [
        "bloch2q" + (hash20 + checksum).hex(),          # bad prefix
        good[:-2],                                      # bad length
        good[:-1] + ("0" if good[-1] != "0" else "1"),  # bad checksum
        MAINNET_PREFIX + "zz" * 24,                     # bad hex
    ]:
        try:
            parse_address(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("must refuse %r" % bad)

    # 2. Amount formatting/parsing.
    assert format_blch(2500000000) == "25"
    assert format_blch(100000001) == "1.00000001"
    assert parse_blch("25") == 2500000000
    assert parse_blch("0.00000546") == 546
    for bad in ["", "1e3", "1.000000001", "-1", "1,5"]:
        try:
            parse_blch(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("must refuse amount %r" % bad)

    # 3. End-to-end watch against a scripted fake node: baseline empty,
    #    then one 25-BLCH output lands at slot 96 (epoch 3), then finality
    #    reaches epoch 3. No sleeping, no sockets.
    sh = script_hash_hex(hash20)
    state = {"poll": 0}

    def fake_result(method, params):
        if method == "getchaininfo":
            fin = 3 if state["poll"] >= 2 else 1
            return {"height": 200, "epoch": 4, "slots_per_epoch": 32,
                    "finalized": {"epoch": fin}, "state_root": "ab" * 32}
        if method == "getbalance":
            assert params[0] == sh, "must query the derived script_hash"
            bal = 2500000000 if state["poll"] >= 1 else 0
            return {"script_hash": sh, "balance_sat": str(bal),
                    "utxo_count": 1 if bal else 0}
        if method == "getutxos":
            if state["poll"] >= 1:
                return {"truncated": False, "utxos": [
                    {"txid": "cd" * 32, "vout": 0,
                     "value_sat": "2500000000", "at_slot": 96}]}
            return {"truncated": False, "utxos": []}
        raise AssertionError("unexpected method %s" % method)

    class FakeResponse:
        def __init__(self, body):
            self.body = body
        def read(self):
            return self.body
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_open(req, timeout=None):
        payload = json.loads(req.data.decode())
        result = fake_result(payload["method"], payload["params"])
        return FakeResponse(json.dumps(
            {"jsonrpc": "2.0", "id": 1, "result": result}).encode())

    def fake_sleep(_seconds):
        state["poll"] += 1

    out = io.StringIO()
    code = watch("http://fake:16400", good, expect_sat=2500000000,
                 interval=0, timeout_minutes=1, _open=fake_open,
                 _sleep=fake_sleep, out=out)
    text = out.getvalue()
    assert code == 0, "watch must succeed, output:\n%s" % text
    assert "FUNDS ARRIVED: +25 BLCH" in text, text
    assert ("%s:0" % ("cd" * 32)) in text, text
    assert "epoch 3 FINALIZED" in text, text
    assert "amount matches" in text, text

    # 4. Amount mismatch is reported and exits 2.
    state["poll"] = 0
    out = io.StringIO()
    code = watch("http://fake:16400", good, expect_sat=2400000000,
                 interval=0, timeout_minutes=1, _open=fake_open,
                 _sleep=fake_sleep, out=out)
    assert code == 2 and "MISMATCH" in out.getvalue()

    print("selftest: all checks passed")
    return 0


# ── CLI ─────────────────────────────────────────────────────────────────────

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Watch a Bloch Genesis-4 address until funds arrive and "
                    "are finalized — the receipt on a chain with no txids.")
    ap.add_argument("address", nargs="?", help="your bloch1q… address")
    ap.add_argument("--rpc", help="node RPC, e.g. http://127.0.0.1:16400 "
                                  "(use your own node if you run one)")
    ap.add_argument("--expect", help="BLCH amount you were told to expect")
    ap.add_argument("--interval", type=int, default=15, help="poll seconds (default 15)")
    ap.add_argument("--timeout", type=int, default=120, help="give up after N minutes (default 120)")
    ap.add_argument("--selftest", action="store_true", help="run the built-in tests (no network)")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.address or not args.rpc:
        ap.error("address and --rpc are required (or use --selftest)")
    try:
        expect_sat = parse_blch(args.expect) if args.expect else None
        return watch(args.rpc, args.address, expect_sat=expect_sat,
                     interval=args.interval, timeout_minutes=args.timeout)
    except (ValueError, RuntimeError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
