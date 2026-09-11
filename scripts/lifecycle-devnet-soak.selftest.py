#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prove the pure parts of `lifecycle-devnet-soak.py` in both directions, with no node binary.

  relay     bytes cross a harness relay; `cut()` resets the live connection and
            refuses new dials; `heal()` accepts and forwards again.
  parser    the `[slot N] applied <id> by v<i> — head root <root>, …` line is
            parsed (last line per slot wins); forbidden lines are caught, and the
            boot line `DOPPELGANGER PROTECTION: DISABLED` is NOT a hit.
  verdict   converged input → CONVERGED; a fork → DIVERGED with the slot named;
            a single node → NO-DATA (a failure); a pair with no shared slot →
            NO-DATA.
  rewriter  a synthetic params.rs/staking.rs is armed exactly as designed; a
            missing constant, a duplicated one, or a drifted pinned value refuses
            the whole rewrite.
  clock     the BPOSMAN header read; wall slot/epoch arithmetic.
  rpc       a stub JSON-RPC server: result returned, `error` object raised as
            RpcError, a closed port raised as RpcTransportError, `Json::sat`
            strings coerced by as_int.
  finality  frozen inside the split window passes; movement inside, a drop, or
            a stall outside fails.
  bin       the `Bin` wrappers parse a stub `bloch-pos` (allocation lines,
            `Transaction id:`, the keygen-public TSV) and refuse a non-zero exit.

Run: python3 scripts/lifecycle-devnet-soak.selftest.py   (exit 0 = all cases hold)
"""
from __future__ import annotations

import http.server
import json
import os
import socket
import stat
import struct
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lifecycle_devnet_soak_lib as lib  # noqa: E402

FAILED: list[str] = []


def expect(label: str, condition: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if condition else 'FAIL'} {label}{(' — ' + detail) if detail and not condition else ''}")
    if not condition:
        FAILED.append(label)


def expect_raises(label: str, fn, needle: str) -> None:
    try:
        fn()
    except lib.SoakError as e:
        expect(label, needle in str(e), f"got: {e}")
        return
    expect(label, False, "did not raise")


# ── relay ───────────────────────────────────────────────────────────────────


def echo_server() -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=pump, args=(conn,), daemon=True).start()

    def pump(conn):
        try:
            while data := conn.recv(4096):
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()
    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1]


def test_relay() -> None:
    print("relay")
    srv, echo_port = echo_server()
    relay = lib.Relay(lib.free_port(), echo_port)
    relay.start()
    with socket.create_connection(("127.0.0.1", relay.listen_port), timeout=2) as c:
        c.sendall(b"ping through relay")
        c.settimeout(2)
        expect("bytes are forwarded and echoed back", c.recv(64) == b"ping through relay")
        expect("relay counted the bytes", relay.forwarded_bytes >= 2 * len(b"ping through relay"))
        relay.cut()
        try:
            got = c.recv(64)
            expect("cut: existing connection ends (EOF)", got == b"", repr(got))
        except (ConnectionResetError, OSError):
            expect("cut: existing connection ends (reset)", True)
    try:
        socket.create_connection(("127.0.0.1", relay.listen_port), timeout=1).close()
        expect("cut: new dials refused", False, "connect succeeded")
    except (ConnectionRefusedError, OSError):
        expect("cut: new dials refused", True)
    relay.heal()
    with socket.create_connection(("127.0.0.1", relay.listen_port), timeout=2) as c:
        c.settimeout(2)
        c.sendall(b"after heal")
        expect("heal: forwarding again", c.recv(64) == b"after heal")
    relay.close()
    srv.close()
    mesh = lib.RelayMesh(3, 40000, 30000)
    expect("mesh: relay(i,j) port formula", mesh.relay_port(2, 1) == 40000 + 2 * 16 + 1)
    expect("mesh: peers_for lists relays to every other slot", mesh.peers_for(1) == ["127.0.0.1:40016", "127.0.0.1:40018"])
    expect("mesh: cross pairs are both directions", sorted(mesh.cross_pairs({0}, {1, 2})) == [(0, 1), (0, 2), (1, 0), (2, 0)])


# ── parser + verdict ────────────────────────────────────────────────────────

LOG_A = """transport: devnet bound — devnet mesh on 127.0.0.1:19610
DOPPELGANGER PROTECTION: DISABLED (BLOCH_NO_DOPPELGANGER is set). This node
[slot 1] applied aaaa1111 by v0 — head root a1a1a1a1, justified e0, finalized e0
[slot 2] applied bbbb2222 by v1 — head root b2b2b2b2, justified e0, finalized e0
[slot 3] applied cccc3333 by v2 — head root c3c3c3c3, justified e0, finalized e0
[slot 3] applied dddd3333 by v2 — head root c3c3c3c3, justified e0, finalized e0
"""
LOG_B = LOG_A.replace("[slot 3] applied dddd3333", "[slot 3] applied eeee3333")  # the LAST slot-3 line differs


def test_parser_and_verdict() -> None:
    print("parser")
    a = lib.parse_applied(LOG_A)
    expect("three slots parsed", sorted(a) == [1, 2, 3])
    expect("proposer index parsed", a[2] == ("bbbb2222", "b2b2b2b2", 1))
    expect("last line per slot wins", a[3][0] == "dddd3333")
    expect("proposing/attested regexes", lib.PROPOSING_RE.search("[slot 9] proposing block ab12 (3 attestations, 0 txs, mempool 0)") is not None
           and lib.ATTESTED_RE.search("[slot 9] attested (epoch 0, head ab12, target cd34)") is not None)
    expect("boot DOPPELGANGER PROTECTION line is not forbidden", not lib.forbidden_hits(LOG_A))
    hits = lib.forbidden_hits(LOG_A + "DOPPELGANGER DETECTED: validator 1 produced a duty\nthread 'main' panicked at x\n")
    expect("DOPPELGANGER DETECTED and panicked are forbidden", set(hits) == {"DOPPELGANGER DETECTED", "panicked"})
    print("verdict")
    same = {"n0": lib.parse_applied(LOG_A), "n1": lib.parse_applied(LOG_A), "n2": lib.parse_applied(LOG_A)}
    cv = lib.chain_verdict(same)
    expect("identical logs → CONVERGED", cv.status == "CONVERGED" and cv.ok and cv.common_slots == 3 and cv.highest_common_slot == 3)
    cv = lib.chain_verdict({"n0": lib.parse_applied(LOG_A), "n1": lib.parse_applied(LOG_B)})
    expect("a differing (id, root) at one slot → DIVERGED naming the slot", cv.status == "DIVERGED" and not cv.ok and cv.forks[0]["slot"] == 3)
    cv = lib.chain_verdict({"n0": lib.parse_applied(LOG_A)})
    expect("a single node → NO-DATA and not ok", cv.status == "NO-DATA" and not cv.ok)
    cv = lib.chain_verdict({"n0": {1: ("a", "r", 0)}, "n1": {2: ("b", "r", 1)}})
    expect("no shared slot → NO-DATA with the pair named", cv.status == "NO-DATA" and cv.pairs_without_common == [["n0", "n1"]])
    cv = lib.chain_verdict({})
    expect("no nodes → NO-DATA", cv.status == "NO-DATA")


# ── rewriter ────────────────────────────────────────────────────────────────


def synthetic_sources(*, drop: str | None = None, duplicate: str | None = None, pinned_drift: bool = False) -> dict[str, str]:
    params = ["pub const SLOTS_PER_EPOCH: u64 = 32;", "pub const RANDAO_CHAIN_LENGTH: u32 = 8_192;",
              "pub const LEAKED_ROSTER_ACTIVATION_EPOCH: u64 = 1400;", "pub const TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH: u64 = 800;",
              "pub const BLOCK_BYTES_V2_ACTIVATION_EPOCH: u64 = 800;", "pub const ANCESTRY_SEED_ACTIVATION_EPOCH: u64 = u64::MAX;",
              "pub const LEAK_RECOVERY_ACTIVATION_EPOCH: u64 = 2_700;",
              f"pub const DEPOSIT_ACTIVATION_EPOCH: u64 = {'7' if pinned_drift else 'u64::MAX'};"]
    params += [f"pub const {g}_ACTIVATION_EPOCH: u64 = u64::MAX;" for g in
               ("EXIT_AUTH", "SLASHING_EVIDENCE", "RANDAO_RECOMMIT", "WITHDRAWAL", "FUNDED_VALIDATOR_ADMISSION")]
    staking = ["pub const ACTIVATION_DELAY_EPOCHS: u64 = 8;", "pub const EXIT_DELAY_EPOCHS: u64 = 32;",
               "pub const WITHDRAWAL_DELAY_EPOCHS: u64 = 2048;"]
    lines = {lib.PARAMS: params, lib.STAKING: staking}
    for file, ls in lines.items():
        if drop:
            ls[:] = [l for l in ls if drop not in l]
        if duplicate:
            ls += [l for l in ls if duplicate in l]
    return {f: "// synthetic\n" + "\n".join(ls) + "\n" for f, ls in lines.items()}


def test_rewriter() -> None:
    print("rewriter")
    out, changes = lib.rewrite_constants(synthetic_sources())
    armed = out[lib.PARAMS] + out[lib.STAKING]
    expect("every armed constant now carries its design value",
           all(f"pub const {name}: {ty} = {new};" in armed for _, name, ty, new in lib.ARMED_CONSTANTS))
    expect("no shipping value survives", "= 2048;" not in armed and "= 8_192;" not in armed and "= 2_700;" not in armed and "= 1400;" not in armed)
    expect("pinned constants untouched", "pub const DEPOSIT_ACTIVATION_EPOCH: u64 = u64::MAX;" in armed
           and "pub const ANCESTRY_SEED_ACTIVATION_EPOCH: u64 = u64::MAX;" in armed and "pub const ACTIVATION_DELAY_EPOCHS: u64 = 8;" in armed)
    expect("SLOTS_PER_EPOCH untouched", "pub const SLOTS_PER_EPOCH: u64 = 32;" in armed)
    expect("changes report from→to for 12 armed + 3 pinned", len(changes) == 15
           and {c["name"]: c.get("from") for c in changes}["WITHDRAWAL_DELAY_EPOCHS"] == "2048")
    expect_raises("missing constant refuses the rewrite", lambda: lib.rewrite_constants(synthetic_sources(drop="EXIT_DELAY_EPOCHS")),
                  "EXIT_DELAY_EPOCHS must be declared exactly once")
    expect_raises("duplicated constant refuses the rewrite", lambda: lib.rewrite_constants(synthetic_sources(duplicate="SLASHING_EVIDENCE")),
                  "SLASHING_EVIDENCE_ACTIVATION_EPOCH must be declared exactly once")
    expect_raises("drifted pinned constant refuses the rewrite", lambda: lib.rewrite_constants(synthetic_sources(pinned_drift=True)),
                  "DEPOSIT_ACTIVATION_EPOCH is 7")
    expect_raises("missing file refuses the rewrite", lambda: lib.rewrite_constants({lib.STAKING: "x"}), "not in the source set")


# ── clock, ints, metrics, outpoints, finality ──────────────────────────────


def test_small_helpers(tmp: Path) -> None:
    print("clock")
    genesis_ms = 1_700_000_000_000
    (tmp / "g.blg").write_bytes(b"BPOSMAN1" + struct.pack("<QQ", genesis_ms, 500) + b"\0" * 16)
    expect("manifest header read", lib.manifest_clock(tmp / "g.blg") == (genesis_ms, 500))
    (tmp / "bad.blg").write_bytes(b"NOTAMANIFEST" + b"\0" * 20)
    expect_raises("bad magic refused", lambda: lib.manifest_clock(tmp / "bad.blg"), "BPOSMAN")
    clock = lib.Clock(lib.Clock.now_ms() - 500 * 70, 500)
    expect("wall slot/epoch/slot_in_epoch arithmetic", clock.wall_slot() in (70, 71) and clock.wall_epoch() == 2 and clock.slot_in_epoch() in (6, 7))
    expect("before genesis the wall slot is 0", lib.Clock(lib.Clock.now_ms() + 60_000, 500).wall_slot() == 0)
    print("as_int / metrics / outpoints")
    expect("Json::sat strings and Json::u numbers both coerce", lib.as_int("2500000000000") == 2_500_000_000_000 and lib.as_int(7) == 7)
    expect_raises("a float string is refused", lambda: lib.as_int("1.5"), "expected an integer")
    expect_raises("a bool is refused", lambda: lib.as_int(True), "boolean")
    text = "# HELP x\nbloch_pos_equivocations_observed_total 3\nbloch_pos_blocks_applied_total{kind=\"x\"} 12\n"
    expect("metric_value plain and labelled", lib.metric_value(text, "bloch_pos_equivocations_observed_total") == 3
           and lib.metric_value(text, "bloch_pos_blocks_applied_total") == 12 and lib.metric_value(text, "missing") is None)
    view = {"unspent": True, "utxo": {"txid": "t", "vout": 0, "value_sat": "99", "script_hash": "sh"}}
    expect("outpoint_matches accepts the expected shape", lib.outpoint_matches(view, {"unspent": True, "value_sat": 99, "script_hash": "sh"}))
    expect("outpoint_matches refuses a wrong value", not lib.outpoint_matches(view, {"value_sat": 98}))
    expect("outpoint_matches on a spent view", lib.outpoint_matches({"unspent": False, "utxo": None}, {"unspent": False}))
    expect("sha3 of hex bytes", lib.sha3_hex("00") == "5d53469f20fef4f8eab52b88044ede69c77a6a68a60728609fc4a65ff531e7d0")
    print("finality")
    frozen = [(n, e, f) for n in ("a", "b") for e, f in [(2, 1), (6, 4), (10, 4), (14, 4), (16, 4), (20, 7), (26, 10)]]
    ok, ev = lib.finality_progress(frozen, (8, 17))
    expect("frozen inside the split window and rising outside passes", ok, str(ev["problems"]))
    ok, ev = lib.finality_progress(frozen + [("a", 12, 5)], (8, 17))
    expect("movement inside the window fails", not ok and any("inside the split window" in p for p in ev["problems"]))
    ok, ev = lib.finality_progress([("a", 2, 3), ("a", 4, 2), ("a", 9, 5)], None)
    expect("a drop fails", not ok and any("fell" in p for p in ev["problems"]))
    ok, ev = lib.finality_progress([("a", 2, 3), ("a", 8, 3), ("a", 12, 4)], None)
    expect("a ≥ 4-epoch stall outside the window fails", not ok and any("stuck" in p for p in ev["problems"]))
    ok, _ = lib.finality_progress([("a", 2, 0), ("a", 3, 0)], None)
    expect("two samples within one epoch are not a stall", ok)


# ── rpc against a stub server ───────────────────────────────────────────────


class StubRpc(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert self.headers["content-type"] == "application/json"
        method = body["method"]
        if method == "getchaininfo":
            reply = {"jsonrpc": "2.0", "id": body["id"], "result": {"wall_slot": 41, "total_active_stake_sat": "120000000000000"}}
        else:
            reply = {"jsonrpc": "2.0", "id": body["id"],
                     "error": {"code": -32008, "message": "funded validator admission is not active: unarmed — this transaction cannot be admitted"}}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


def test_rpc() -> None:
    print("rpc")
    server = http.server.HTTPServer(("127.0.0.1", 0), StubRpc)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    result = lib.rpc(port, "getchaininfo")
    expect("result returned and a sat string coerces", result["wall_slot"] == 41 and lib.as_int(result["total_active_stake_sat"]) == 120_000_000_000_000)
    try:
        lib.rpc(port, "sendrawtransaction", ["00"])
        expect("error object raises RpcError", False, "no exception")
    except lib.RpcError as e:
        expect("error object raises RpcError with code and message", e.code == -32008 and "not active" in e.message and e.as_dict()["method"] == "sendrawtransaction")
    server.shutdown()
    server.server_close()
    try:
        lib.rpc(port, "getchaininfo", timeout=1)
        expect("closed port raises RpcTransportError", False, "no exception")
    except lib.RpcTransportError:
        expect("closed port raises RpcTransportError", True)


# ── Bin wrappers against a stub bloch-pos ───────────────────────────────────

STUB = r'''#!/bin/sh
case "$1" in
  keygen-public) printf '4294967295\tb10c0100abcd\t%s\t\t\t\n' 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ;;
  genesis) shift; n=0; while [ $# -gt 0 ]; do if [ "$1" = "--alloc" ]; then sh="${2%%:*}"; sat="${2##*:}";
             [ $n -lt 2 ] && echo "allocation $n: txid=$(printf '%064d' $n) vout=0 value_sat=$sat script_hash=$sh"; n=$((n+1)); shift; fi; shift; done
           : > "$OUT" ;;
  validator-deposit) echo "Network domain: x"; echo "Transaction id: $(printf 'ab%062d' 7)" ;;
  validator-lifecycle) echo "Transaction id: $(printf 'cd%062d' 1)" ;;
  fail) echo "boom" >&2; exit 3 ;;
  *) echo "unexpected: $*" >&2; exit 2 ;;
esac
'''


def test_bin(tmp: Path) -> None:
    print("bin")
    stub = tmp / "bloch-pos"
    stub.write_text(STUB)
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    b = lib.Bin(stub, dict(os.environ, OUT=str(tmp / "g.out")), tmp / "commands.log")
    idx, pub, randao = b.keygen_public(tmp)
    expect("keygen-public TSV parsed (index, pubkey, randao)", idx == "4294967295" and pub == "b10c0100abcd" and len(randao) == 64)
    sh = "11" * 32
    allocs = b.genesis([tmp], tmp / "g.out", 500, 20, [(sh, 2_500_100_000_000), ("22" * 32, 5)])
    expect("genesis allocation lines parsed", len(allocs) == 2 and allocs[0]["script_hash"] == sh and allocs[0]["value_sat"] == 2_500_100_000_000 and allocs[1]["n"] == 1)
    expect_raises("fewer allocation lines than --alloc flags refused", lambda: b.genesis([tmp], tmp / "g.out", 500, 20, [(sh, 1)] * 3), "allocation lines")
    txid, _ = b.deposit_inspect(tmp / "x.hex")
    expect("inspect Transaction id parsed", txid == "ab" + "0" * 61 + "7")
    expect("lifecycle withdraw Transaction id parsed", b.lifecycle_withdraw(3, tmp / "w.hex") == "cd" + "0" * 61 + "1")
    expect_raises("non-zero exit raises with stderr", lambda: b.run(["fail"], timeout=5), "boom")
    expect("commands were logged", "genesis" in (tmp / "commands.log").read_text())


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="lifecycle-devnet-soak-selftest-") as temp:
        tmp = Path(temp)
        test_relay()
        test_parser_and_verdict()
        test_rewriter()
        test_small_helpers(tmp)
        test_rpc()
        test_bin(tmp)
    if FAILED:
        print(f"\nSELFTEST FAILED: {len(FAILED)} case(s): {FAILED}")
        return 1
    print("\nselftest: all cases hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
