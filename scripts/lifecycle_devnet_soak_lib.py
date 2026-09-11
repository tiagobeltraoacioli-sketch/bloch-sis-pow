#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Helpers for `scripts/lifecycle-devnet-soak.py` (Python 3.10+, stdlib only).

Everything in here is exercised WITHOUT a node binary by
`scripts/lifecycle-devnet-soak.selftest.py`: the constants rewriter, the
manifest clock, the JSON-RPC client, the log parser, the CONVERGED /
DIVERGED / NO-DATA verdict and the harness-owned TCP relays.

The `Bin` class at the bottom is the ONE place that knows the `bloch-pos`
command lines and output formats the harness relies on. Every shape is
marked VERIFIED with the source line it was read from on 2026-09-11 (the
three devnet subcommands — `genesis --alloc`, `transfer-v2`,
`devnet-equivocate` — from the uncommitted `devnet_tools.rs`). If the first
real run disagrees with any of them, correct it here, nowhere else.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

SLOTS_PER_EPOCH = 32  # params.rs:43 — never rewritten (main.rs self_check pins it)
SAT_PER_BLOCH = 10**8


class SoakError(RuntimeError):
    """A harness-level failure; the message carries the last observation."""


def as_int(value: Any, what: str = "value") -> int:
    """`Json::sat` renders satoshi amounts as decimal STRINGS (rpc.rs:398);
    `Json::u` renders as numbers. Accept both, refuse anything else."""
    if isinstance(value, bool):
        raise SoakError(f"{what}: expected an integer, got a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value):
        return int(value)
    raise SoakError(f"{what}: expected an integer or decimal string, got {value!r}")


def sha3_hex(hex_bytes: str) -> str:
    """SHA3-256 of hex-encoded bytes, as hex. `keygen` prints only 8 hex chars
    of the pubkey hash (codec.rs:208-210); the harness derives the full
    32-byte `pubkey_hash` / `script_hash` from `keygen-public` column 2."""
    return hashlib.sha3_256(bytes.fromhex(hex_bytes.strip())).hexdigest()


def jdump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


# ── Armed-copy constants (vad04-design.md D2) ───────────────────────────────

PARAMS = "crates/bloch-pos-committee/src/params.rs"
STAKING = "crates/bloch-pos-committee/src/staking.rs"

# (file, name, rust type, armed value). The compile-time asserts at
# params.rs:1999-2005 need the five ADR-041 gates equal, DEPOSIT at u64::MAX
# and CORRELATION_WINDOW_EPOCHS (4096) >= 2 * WITHDRAWAL_DELAY_EPOCHS.
ARMED_CONSTANTS: list[tuple[str, str, str, str]] = [
    (PARAMS, "FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH", "u64", "0"),
    (PARAMS, "EXIT_AUTH_ACTIVATION_EPOCH", "u64", "0"),
    (PARAMS, "WITHDRAWAL_ACTIVATION_EPOCH", "u64", "0"),
    (PARAMS, "SLASHING_EVIDENCE_ACTIVATION_EPOCH", "u64", "0"),
    (PARAMS, "RANDAO_RECOMMIT_ACTIVATION_EPOCH", "u64", "0"),
    (PARAMS, "LEAK_RECOVERY_ACTIVATION_EPOCH", "u64", "0"),
    (PARAMS, "LEAKED_ROSTER_ACTIVATION_EPOCH", "u64", "0"),
    (PARAMS, "TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH", "u64", "0"),
    (PARAMS, "BLOCK_BYTES_V2_ACTIVATION_EPOCH", "u64", "0"),
    (PARAMS, "RANDAO_CHAIN_LENGTH", "u32", "256"),
    (STAKING, "WITHDRAWAL_DELAY_EPOCHS", "u64", "64"),
    (STAKING, "EXIT_DELAY_EPOCHS", "u64", "4"),
]
# (file, name, rust type, value that must be present exactly once, unchanged).
PINNED_CONSTANTS: list[tuple[str, str, str, str]] = [
    (PARAMS, "DEPOSIT_ACTIVATION_EPOCH", "u64", "u64::MAX"),
    (PARAMS, "ANCESTRY_SEED_ACTIVATION_EPOCH", "u64", "u64::MAX"),
    (STAKING, "ACTIVATION_DELAY_EPOCHS", "u64", "8"),
]


def const_pattern(name: str, rust_type: str) -> re.Pattern:
    return re.compile(rf"^pub const {name}: {rust_type} = (u64::MAX|\d[\d_]*);$", re.M)


def rewrite_constants(
    sources: dict[str, str],
    armed: list[tuple[str, str, str, str]] = ARMED_CONSTANTS,
    pinned: list[tuple[str, str, str, str]] = PINNED_CONSTANTS,
) -> tuple[dict[str, str], list[dict]]:
    """Exactly-one-match discipline: a constant that is missing or declared
    twice refuses the whole rewrite, so a renamed constant can never leave a
    half-armed copy that boots and looks armed."""
    out = dict(sources)
    changes: list[dict] = []
    for file, name, rust_type, new in armed:
        src = out.get(file)
        if src is None:
            raise SoakError(f"{file} is not in the source set; cannot rewrite {name}")
        pattern = const_pattern(name, rust_type)
        hits = pattern.findall(src)
        if len(hits) != 1:
            raise SoakError(f"{name} must be declared exactly once in {file}; found {len(hits)}")
        out[file] = pattern.sub(f"pub const {name}: {rust_type} = {new};", src, count=1)
        changes.append({"file": file, "name": name, "from": hits[0], "to": new})
    for file, name, rust_type, expected in pinned:
        hits = const_pattern(name, rust_type).findall(out.get(file, ""))
        if len(hits) != 1:
            raise SoakError(f"{name} must be declared exactly once in {file}; found {len(hits)}")
        if hits[0].replace("_", "") != expected.replace("_", ""):
            raise SoakError(f"{name} is {hits[0]} in {file}; the harness pins {expected}")
        changes.append({"file": file, "name": name, "pinned": hits[0]})
    return out, changes


# ── Manifest clock ──────────────────────────────────────────────────────────


def manifest_clock(path: Path) -> tuple[int, int]:
    """(genesis_time_ms, slot_ms) from the fixed offsets behind the BPOSMAN
    magic — the same read `arm-lifecycle-epoch.py` does."""
    head = path.read_bytes()[:24]
    if len(head) < 24 or not head.startswith(b"BPOSMAN"):
        raise SoakError(f"{path} does not start with the BPOSMAN manifest magic")
    genesis_ms, slot_ms = struct.unpack_from("<QQ", head, 8)
    if slot_ms == 0:
        raise SoakError(f"{path} declares slot_ms = 0")
    return genesis_ms, slot_ms


class Clock:
    def __init__(self, genesis_ms: int, slot_ms: int) -> None:
        self.genesis_ms, self.slot_ms = genesis_ms, slot_ms

    @staticmethod
    def now_ms() -> int:
        return int(time.time() * 1000)

    def wall_slot(self) -> int:
        return max(self.now_ms() - self.genesis_ms, 0) // self.slot_ms

    def wall_epoch(self) -> int:
        return self.wall_slot() // SLOTS_PER_EPOCH

    def slot_in_epoch(self) -> int:
        return self.wall_slot() % SLOTS_PER_EPOCH

    def sleep_slots(self, slots: float) -> None:
        time.sleep(max(slots, 0.0) * self.slot_ms / 1000)


# ── JSON-RPC 2.0 over HTTP (rpc.rs: POST only, JSON content-type, loopback Host)


class RpcError(SoakError):
    """The node answered with a JSON-RPC `error` object."""

    def __init__(self, method: str, code: Any, message: Any, data: Any = None) -> None:
        super().__init__(f"{method}: rpc error {code}: {message}")
        self.method, self.code, self.message, self.data = method, code, message, data

    def as_dict(self) -> dict:
        return {"method": self.method, "code": self.code, "message": self.message, "data": self.data}


class RpcTransportError(SoakError):
    """No JSON-RPC answer at all (refused, timed out, non-JSON)."""


def rpc(port: int, method: str, params: list | None = None, *, host: str = "127.0.0.1",
        timeout: float = 3.0) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    request = urllib.request.Request(
        f"http://{host}:{port}/", data=body, method="POST",
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as e:  # R4: JSON-RPC errors ride HTTP 200; this is transport-level
        raw = e.read()
        try:
            doc = json.loads(raw)
        except ValueError:
            raise RpcTransportError(f"{method} on :{port}: HTTP {e.code} {raw[:200]!r}") from None
    except (urllib.error.URLError, OSError) as e:
        raise RpcTransportError(f"{method} on :{port}: {e}") from None
    else:
        try:
            doc = json.loads(raw)
        except ValueError:
            raise RpcTransportError(f"{method} on :{port}: non-JSON reply {raw[:200]!r}") from None
    if not isinstance(doc, dict):
        raise RpcTransportError(f"{method} on :{port}: reply is not an object")
    if doc.get("error") is not None:
        err = doc["error"] if isinstance(doc["error"], dict) else {"message": doc["error"]}
        raise RpcError(method, err.get("code"), err.get("message"), err.get("data"))
    if "result" not in doc:
        raise RpcTransportError(f"{method} on :{port}: reply carries neither result nor error")
    return doc["result"]


def http_get(port: int, path: str, *, host: str = "127.0.0.1", timeout: float = 3.0) -> str:
    try:
        with urllib.request.urlopen(f"http://{host}:{port}{path}", timeout=timeout) as response:
            return response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:  # /health answers 503 with a body while syncing
        return e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        raise RpcTransportError(f"GET {path} on :{port}: {e}") from None


def metric_value(text: str, name: str) -> int | None:
    hit = re.search(rf"^{re.escape(name)}(?:\{{[^}}]*\}})? (\d+)", text, re.M)
    return int(hit.group(1)) if hit else None


# ── Node log parsing and the chain verdict (engine.rs:3317 line shape) ──────

APPLIED_RE = re.compile(r"^\[slot (\d+)\] applied ([0-9a-f]+) by v(\d+) — head root ([0-9a-f]+)", re.M)
PROPOSING_RE = re.compile(r"^\[slot (\d+)\] proposing block ([0-9a-f]+)", re.M)
ATTESTED_RE = re.compile(r"^\[slot (\d+)\] attested \(epoch (\d+)", re.M)
REPLAYED_RE = re.compile(r"^replayed (\d+) blocks: head slot (\d+)", re.M)

# Any of these in any node log fails the run. `DOPPELGANGER DETECTED` and not
# the bare word: every flagged node prints `DOPPELGANGER PROTECTION: DISABLED`
# at boot (engine.rs:4810). The two enum names are joined by the sentences
# `run` prints for them (engine.rs:4976-4999) so a wording change is caught
# either way.
FORBIDDEN_LINES = [
    "FINALITY_LATCH",
    "REFUSED OWN BLOCK",
    "RandaoMismatch",
    "WrongValidator",
    "DOPPELGANGER DETECTED",
    "belongs to a different network",
    "panicked",
    "is registered to a DIFFERENT public key",
    "does not open the commitment in the committed registry",
]


def parse_applied(text: str) -> dict[int, tuple[str, str, int]]:
    """slot -> (block id prefix, head root prefix, proposer). The LAST line
    per slot wins: after a reorg the node re-applies the winning branch and
    its final view is what convergence is measured on."""
    out: dict[int, tuple[str, str, int]] = {}
    for slot, block_id, proposer, root in APPLIED_RE.findall(text):
        out[int(slot)] = (block_id, root, int(proposer))
    return out


def forbidden_hits(text: str) -> dict[str, dict]:
    hits: dict[str, dict] = {}
    for needle in FORBIDDEN_LINES:
        count = text.count(needle)
        if count:
            first = next(line for line in text.splitlines() if needle in line)
            hits[needle] = {"count": count, "first": first[:300]}
    return hits


@dataclass
class ChainVerdict:
    status: str  # CONVERGED | DIVERGED | NO-DATA
    nodes: int
    common_slots: int
    highest_common_slot: int | None
    forks: list[dict]
    pairs_without_common: list[list[str]]

    @property
    def ok(self) -> bool:
        return self.status == "CONVERGED"

    def as_dict(self) -> dict:
        return {"status": self.status, "nodes": self.nodes, "common_slots": self.common_slots,
                "highest_common_slot": self.highest_common_slot, "forks": self.forks[:20],
                "fork_count": len(self.forks), "pairs_without_common": self.pairs_without_common}


def chain_verdict(maps: dict[str, dict[int, tuple[str, str, int]]]) -> ChainVerdict:
    """CONVERGED iff every slot applied by >= 2 nodes carries one (id, root)
    on all of them AND every pair of nodes shares at least one slot. One node,
    or no shared slot, is NO-DATA — a failure, never a pass (a harness that
    cannot say CONVERGED is not measuring anything)."""
    names = sorted(maps)
    if len(names) < 2:
        return ChainVerdict("NO-DATA", len(names), 0, None, [], [])
    by_slot: dict[int, dict[str, tuple[str, str, int]]] = {}
    for name in names:
        for slot, view in maps[name].items():
            by_slot.setdefault(slot, {})[name] = view
    common = {slot: views for slot, views in by_slot.items() if len(views) >= 2}
    if not common:
        return ChainVerdict("NO-DATA", len(names), 0, None, [], [[a, b] for a in names for b in names if a < b])
    forks = [
        {"slot": slot, "views": {n: [v[0], v[1]] for n, v in sorted(views.items())}}
        for slot, views in sorted(common.items())
        if len({(v[0], v[1]) for v in views.values()}) > 1
    ]
    pairs = [[a, b] for a in names for b in names if a < b and not (set(maps[a]) & set(maps[b]))]
    status = "DIVERGED" if forks else ("NO-DATA" if pairs else "CONVERGED")
    return ChainVerdict(status, len(names), len(common), max(common), forks, pairs)


# ── Harness-owned TCP relays (vad04-design.md D4) ───────────────────────────


class Relay:
    """One TCP relay: dials to `listen_port` are forwarded to `target_port`.
    `cut()` resets every live connection (SO_LINGER 0 → RST) and closes the
    listener so new dials are refused; `heal()` rebinds it."""

    def __init__(self, listen_port: int, target_port: int, host: str = "127.0.0.1") -> None:
        self.listen_port, self.target_port, self.host = listen_port, target_port, host
        self.forwarded_bytes = 0
        self.connections_accepted = 0
        self._lock = threading.Lock()
        self._enabled = True
        self._closing = False
        self._listener: socket.socket | None = None
        self._conns: set[socket.socket] = set()
        self._unbound = threading.Event()  # set by the accept thread once it dropped its listener
        self._thread = threading.Thread(target=self._accept_loop, daemon=True,
                                        name=f"relay-{listen_port}->{target_port}")

    def start(self) -> None:
        self._bind()
        self._thread.start()

    def _bind(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.listen_port))
        listener.listen(64)
        listener.settimeout(0.2)
        with self._lock:
            self._listener = listener

    @property
    def bound(self) -> bool:
        with self._lock:
            return self._listener is not None

    def _accept_loop(self) -> None:
        while not self._closing:
            with self._lock:
                listener, enabled = self._listener, self._enabled
            if listener is None:
                if enabled:
                    try:
                        self._bind()
                    except OSError:
                        time.sleep(0.1)
                else:
                    self._unbound.set()
                    time.sleep(0.05)
                continue
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                continue  # listener shut down by cut(); the next turn sees it gone
            if not self._enabled:
                client.close()
                continue
            try:
                upstream = socket.create_connection((self.host, self.target_port), timeout=2.0)
            except OSError:
                client.close()
                continue
            client.settimeout(None)
            upstream.settimeout(None)
            with self._lock:
                self._conns.update({client, upstream})
                self.connections_accepted += 1
            threading.Thread(target=self._pump, args=(client, upstream), daemon=True).start()
            threading.Thread(target=self._pump, args=(upstream, client), daemon=True).start()

    def _pump(self, src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
                self.forwarded_bytes += len(data)
        except OSError:
            pass
        finally:
            self._drop(src, reset=False)
            self._drop(dst, reset=False)

    def _drop(self, sock: socket.socket, *, reset: bool) -> None:
        with self._lock:
            self._conns.discard(sock)
        try:
            if reset:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def cut(self, wait: float = 2.0) -> None:
        """Refuse new dials at once and reset live connections. `shutdown()` on
        the listener takes it out of LISTEN immediately — merely closing the fd
        would let the kernel keep completing handshakes into the backlog until
        the accept thread's blocking call returned."""
        with self._lock:
            self._enabled = False
            self._unbound.clear()
            listener, self._listener = self._listener, None
            conns = list(self._conns)
        if listener is not None:
            try:
                listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            listener.close()
        for sock in conns:
            self._drop(sock, reset=True)
        if self._thread.is_alive() and not self._unbound.wait(wait):
            raise SoakError(f"relay :{self.listen_port} accept thread did not acknowledge the cut within {wait}s")

    def heal(self, wait: float = 2.0) -> None:
        with self._lock:
            self._enabled = True
            self._unbound.clear()
        deadline = time.monotonic() + wait
        while not self.bound and time.monotonic() < deadline:
            time.sleep(0.02)
        if not self.bound:
            raise SoakError(f"relay :{self.listen_port} did not rebind within {wait}s")

    def close(self) -> None:
        self._closing = True
        try:
            self.cut(wait=0.5)
        except SoakError:
            pass  # the thread is exiting anyway
        self._thread.join(timeout=1.0)


class RelayMesh:
    """One relay per ORDERED pair (i, j): node i dials `relay_port(i, j)`,
    which forwards to node j's real listen port. Nodes never learn a real
    port, so closing the cross-half relays is a real partition."""

    def __init__(self, n: int, relay_base: int, mesh_base: int, host: str = "127.0.0.1") -> None:
        self.n, self.relay_base, self.mesh_base, self.host = n, relay_base, mesh_base, host
        self.relays: dict[tuple[int, int], Relay] = {
            (i, j): Relay(self.relay_port(i, j), mesh_base + j, host)
            for i in range(n) for j in range(n) if i != j
        }

    def relay_port(self, i: int, j: int) -> int:
        return self.relay_base + i * 16 + j

    def start_all(self) -> None:
        for relay in self.relays.values():
            relay.start()

    def peers_for(self, i: int) -> list[str]:
        return [f"{self.host}:{self.relay_port(i, j)}" for j in range(self.n) if j != i]

    def cross_pairs(self, side_a: set[int], side_b: set[int]) -> list[tuple[int, int]]:
        return [(i, j) for i in sorted(side_a) for j in sorted(side_b)] + \
               [(j, i) for i in sorted(side_a) for j in sorted(side_b)]

    def cut_between(self, side_a: set[int], side_b: set[int]) -> list[tuple[int, int]]:
        pairs = self.cross_pairs(side_a, side_b)
        for pair in pairs:
            self.relays[pair].cut()
        return pairs

    def heal_between(self, side_a: set[int], side_b: set[int]) -> list[tuple[int, int]]:
        pairs = self.cross_pairs(side_a, side_b)
        for pair in pairs:
            self.relays[pair].heal()
        return pairs

    def close_all(self) -> None:
        for relay in self.relays.values():
            relay.close()


# ── Node processes ──────────────────────────────────────────────────────────


@dataclass
class Node:
    name: str
    slot: int  # roster slot: 0..2 genesis validators, 3 joiner, 4 observer
    data_dir: Path
    rpc_port: int
    mesh_port: int
    metrics_port: int
    cmd: list[str]
    env: dict[str, str]
    log_path: Path
    has_key: bool
    proc: subprocess.Popen | None = None
    pids: list[int] = field(default_factory=list)
    _log_fh: Any = None

    def start(self) -> int:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._log_fh = open(self.log_path, "ab")
        self.proc = subprocess.Popen(self.cmd, stdout=self._log_fh, stderr=subprocess.STDOUT,
                                     env=self.env, start_new_session=True)
        self.pids.append(self.proc.pid)
        (self.data_dir / "pid").write_text(f"{self.proc.pid}\n")
        return self.proc.pid

    @property
    def pid(self) -> int | None:
        return self.proc.pid if self.proc else None

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self, term_timeout: float = 10.0) -> str:
        if self.proc is None:
            return "never-started"
        if self.proc.poll() is not None:
            return f"already-exited({self.proc.returncode})"
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=term_timeout)
            outcome = f"terminated({self.proc.returncode})"
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5.0)
            outcome = "killed"
        if self._log_fh:
            self._log_fh.close()
            self._log_fh = None
        return outcome

    def log_text(self) -> str:
        return self.log_path.read_text(errors="replace") if self.log_path.exists() else ""

    def log_size(self) -> int:
        return self.log_path.stat().st_size if self.log_path.exists() else 0


# ── bloch-pos command wrappers ──────────────────────────────────────────────

TXID_RE = re.compile(r"Transaction id: ([0-9a-f]{64})")
# VERIFIED devnet_tools.rs:236-250 (`allocation_report`): one line per --alloc.
ALLOC_RE = re.compile(r"allocation (\d+): txid=([0-9a-f]{64}) vout=(\d+) value_sat=(\d+) script_hash=([0-9a-f]{64})")


class Bin:
    """Every `bloch-pos` invocation the harness makes, one method each."""

    def __init__(self, path: Path, env: dict[str, str], command_log: Path | None = None) -> None:
        self.path, self.env, self.command_log = path, env, command_log

    def run(self, args: list[str], *, timeout: float, cwd: Path | None = None) -> subprocess.CompletedProcess:
        cmd = [str(self.path), *args]
        if self.command_log is not None:
            with open(self.command_log, "a") as fh:
                fh.write(" ".join(cmd) + "\n")
        try:
            proc = subprocess.run(cmd, env=self.env, cwd=cwd, text=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise SoakError(f"`bloch-pos {' '.join(args[:3])}` exceeded {timeout}s") from None
        if proc.returncode != 0:
            raise SoakError(f"`bloch-pos {' '.join(args[:3])}` exited {proc.returncode}: "
                            f"{(proc.stderr or proc.stdout)[-1500:]}")
        return proc

    def version(self) -> str:  # VERIFIED main.rs:105-128
        return self.run(["--version"], timeout=30).stdout.strip()

    def buildinfo(self) -> dict:  # VERIFIED main.rs:130
        return json.loads(self.run(["buildinfo"], timeout=30).stdout)

    def selfcheck(self) -> str:  # VERIFIED main.rs:132-135
        return self.run(["selfcheck"], timeout=30).stdout.strip()

    def keygen(self, directory: Path, index: int | str) -> str:  # VERIFIED main.rs:841-861
        directory.mkdir(parents=True, exist_ok=True)
        return self.run(["keygen", "--dir", str(directory), "--index", str(index)], timeout=600).stdout.strip()

    def keygen_public(self, directory: Path) -> tuple[str, str, str]:  # VERIFIED main.rs:676-691
        """(index, pubkey_hex, randao_commitment_hex) — TSV columns 1..3."""
        row = self.run(["keygen-public", "--dir", str(directory)], timeout=600).stdout.strip().split("\t")
        if len(row) < 3 or not re.fullmatch(r"[0-9a-f]+", row[1]) or not re.fullmatch(r"[0-9a-f]{64}", row[2]):
            raise SoakError(f"keygen-public printed an unexpected row: {row[:3]}")
        return row[0], row[1], row[2]

    def genesis(self, key_dirs: list[Path], out: Path, slot_ms: int, start_in: int,
                allocs: list[tuple[str, int]]) -> list[dict]:
        """VERIFIED main.rs:278-280 / 1075-1090 (flags), main.rs:308-316 and
        devnet_tools.rs:188-250 (`--alloc <script_hash_hex64>:<sat>`, repeatable,
        at most 64, and the `allocation n: …` report lines)."""
        args = ["genesis", "--keys", ",".join(str(d) for d in key_dirs), "--out", str(out),
                "--slot-ms", str(slot_ms), "--start-in", str(start_in)]
        for script_hash, sat in allocs:
            args += ["--alloc", f"{script_hash}:{sat}"]
        proc = self.run(args, timeout=600)
        found = [{"n": int(n), "txid": txid, "vout": int(vout), "value_sat": int(sat), "script_hash": sh}
                 for n, txid, vout, sat, sh in ALLOC_RE.findall(proc.stdout + "\n" + proc.stderr)]
        if len(found) != len(allocs):
            raise SoakError(f"genesis printed {len(found)} allocation lines for {len(allocs)} --alloc "
                            f"flags (ALLOC_RE in lifecycle_devnet_soak_lib.py):\n{proc.stdout[-2000:]}")
        return found

    # validator-deposit: VERIFIED validator_deposit.rs:18-31 (flags), :243 (txid line)
    def deposit_prepare(self, genesis: Path, funding_pub: Path, validator_pub: Path, randao: str,
                        withdrawal: str, change: str, stake_sat: int, inputs: list[tuple[str, int, int]],
                        max_base_fee: int, tip: int, expiry_epoch: int, commission_bps: int, out: Path) -> None:
        args = ["validator-deposit", "prepare", "--genesis", str(genesis), "--funding-pubkey", str(funding_pub),
                "--validator-pubkey", str(validator_pub), "--randao", randao, "--withdrawal", withdrawal,
                "--change", change, "--stake", str(stake_sat)]
        for txid, vout, sat in inputs:
            args += ["--input", f"{txid}:{vout}:{sat}"]
        args += ["--max-base-fee", str(max_base_fee), "--tip", str(tip), "--expiry", str(expiry_epoch),
                 "--commission", str(commission_bps), "--out", str(out)]
        self.run(args, timeout=120)

    def deposit_sign(self, genesis: Path, tx: Path, role: str, keystore: Path, out: Path) -> None:
        self.run(["validator-deposit", "sign", "--genesis", str(genesis), "--tx", str(tx), "--role", role,
                  "--dir", str(keystore), "--out", str(out)], timeout=600)

    def deposit_inspect(self, tx: Path) -> tuple[str, str]:
        text = self.run(["validator-deposit", "inspect", "--tx", str(tx)], timeout=60).stdout
        hit = TXID_RE.search(text)
        if not hit:
            raise SoakError(f"validator-deposit inspect printed no `Transaction id:` line:\n{text[-1500:]}")
        return hit.group(1), text

    # validator-lifecycle: VERIFIED validator_lifecycle.rs:9-13, :106
    def lifecycle_exit(self, keystore: Path, epoch: int, out: Path) -> str:
        text = self.run(["validator-lifecycle", "exit", "--dir", str(keystore), "--epoch", str(epoch),
                         "--out", str(out)], timeout=600).stdout
        return _txid_from(text, "validator-lifecycle exit")

    def lifecycle_withdraw(self, validator_index: int, out: Path) -> str:
        text = self.run(["validator-lifecycle", "withdraw", "--validator", str(validator_index),
                         "--out", str(out)], timeout=60).stdout
        return _txid_from(text, "validator-lifecycle withdraw")

    def transfer_v2(self, genesis: Path, keystore: Path, inputs: list[tuple[str, int, int]], to_script_hash: str,
                    base_fee: int, tip: int, epoch: int, out: Path) -> str:
        """VERIFIED devnet_tools.rs:63-89 (TRANSFER_V2_HELP) / :458-510: one
        witness key, every --input, one output of (inputs − fee) to --to, fee
        priced at --base-fee — which must be the NEXT block's base fee
        (getvalidatoradmission.next_base_fee_millisat_per_gas), submitted at
        once. --epoch feeds checked_signing_root (inert until SIGHASH_NETWORK
        _BINDING arms). Prints `Transaction id:`."""
        args = ["transfer-v2", "--genesis", str(genesis), "--dir", str(keystore)]
        for txid, vout, sat in inputs:
            args += ["--input", f"{txid}:{vout}:{sat}"]
        args += ["--to", to_script_hash, "--base-fee", str(base_fee), "--tip", str(tip), "--epoch", str(epoch),
                 "--out", str(out)]
        return _txid_from(self.run(args, timeout=600).stdout, "transfer-v2")

    def devnet_equivocate(self, genesis: Path, keystore: Path, data_dir: Path, slot: int, to: str) -> dict:
        """VERIFIED devnet_tools.rs:91-105 (EQUIVOCATE_HELP) / :604-640: reads
        the block at `slot` from `data_dir` (live dir, read-only, no LOCK
        taken), refuses a block `keystore` did not sign, flips state_root[0],
        re-signs, sends a FRAME_BLOCK to the devnet port `to` (no ack). Returns
        the printed original/conflicting block ids."""
        text = self.run(["devnet-equivocate", "--genesis", str(genesis), "--dir", str(keystore), "--data-dir",
                         str(data_dir), "--slot", str(slot), "--to", to], timeout=120).stdout
        ids = dict(re.findall(r"^(original|conflicting) block id:\s+([0-9a-f]{64})", text, re.M))
        return {"original": ids.get("original"), "conflicting": ids.get("conflicting"), "stdout": text[-600:]}


def _txid_from(text: str, what: str) -> str:
    hit = TXID_RE.search(text)
    if not hit:
        raise SoakError(f"{what} printed no `Transaction id:` line:\n{text[-1500:]}")
    return hit.group(1)


def read_hex_file(path: Path) -> str:
    return path.read_text().strip()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_until(predicate: Callable[[], bool], timeout: float, step: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return predicate()


# ── Tree copy, build, and pure verdict rules used by the driver ─────────────


def copy_tree(root: Path, dest: Path) -> int:
    """Copy tracked + untracked-not-ignored files (the rehearsal script's
    inventory). Returns the file count. Never touches `root`."""
    files = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                                    cwd=root).decode().split("\0")
    copied = 0
    for name in files:
        if not name:
            continue
        rel = Path(name)
        if rel.is_absolute() or ".." in rel.parts:
            raise SoakError(f"unexpected path in the source inventory: {name}")
        src = root / rel
        if src.is_file():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / rel)
            copied += 1
    return copied


def cargo_build(src_tree: Path, target: Path, pin: str, env: dict[str, str], log_path: Path, timeout: float) -> Path:
    """`cargo +<pin> build --locked --release -p bloch-pos-node --bin bloch-pos`
    with CARGO_TARGET_DIR=target (never the shipping target for an armed copy:
    measured contamination, see arm-lifecycle-epoch.py). Returns the binary."""
    cmd = ["cargo", f"+{pin}", "build", "--locked", "--release", "-p", "bloch-pos-node", "--bin", "bloch-pos"]
    with open(log_path, "w") as fh:
        fh.write(" ".join(cmd) + f"\n# cwd={src_tree} CARGO_TARGET_DIR={target}\n")
        fh.flush()
        proc = subprocess.run(cmd, cwd=src_tree, env=dict(env, CARGO_TARGET_DIR=str(target)),
                              stdout=fh, stderr=subprocess.STDOUT, timeout=timeout)
    if proc.returncode != 0:
        raise SoakError(f"cargo build failed (rc {proc.returncode}); see {log_path}")
    binary = target / "release" / "bloch-pos"
    if not binary.is_file():
        raise SoakError(f"cargo build produced no {binary}")
    return binary


def finality_progress(samples: list[tuple[str, int, int]], split_window: tuple[int, int] | None) -> tuple[bool, dict]:
    """(ok, evidence) over (node, wall_epoch, finalized_epoch) samples.

    Never decreasing; FROZEN between samples that both fall inside the
    declared split window (from the first post-cut sample: the boundary right
    after the cut may still finalize on attestations exchanged before it);
    rising over any ≥ 4-epoch stretch that lies wholly outside the window
    once finality has started; and higher at the end than at the start."""
    by_node: dict[str, list[tuple[int, int]]] = {}
    for name, epoch, fin in samples:
        by_node.setdefault(name, []).append((epoch, fin))
    lo, hi = split_window or (-1, -1)
    problems: list[str] = []
    for name, points in by_node.items():
        points.sort()
        for (e1, f1), (e2, f2) in zip(points, points[1:]):
            if f2 < f1:
                problems.append(f"{name}: finalized fell {f1}→{f2} between epochs {e1}-{e2}")
            inside = lo < e1 <= hi and lo < e2 <= hi
            outside = e2 <= lo or e1 > hi
            if inside and f2 != f1:
                problems.append(f"{name}: finalized moved {f1}→{f2} inside the split window {lo}-{hi}")
            if outside and e2 - e1 >= 4 and f2 <= f1 and f1 >= 1:
                problems.append(f"{name}: finalized stuck at {f1} from epoch {e1} to {e2} outside the split")
        if points and points[-1][0] - points[0][0] >= 4 and points[-1][1] <= points[0][1]:
            problems.append(f"{name}: finalized never rose ({points[0]} → {points[-1]})")
    return not problems, {"problems": problems, "samples": {k: v[-6:] for k, v in by_node.items()}}


def outpoint_matches(view: dict, expect: dict) -> bool:
    """A `gettxout` reply against {unspent: bool, script_hash: hex, value_sat: int}."""
    utxo = view.get("utxo") or {}
    for key, val in expect.items():
        if key == "unspent":
            if view.get("unspent") is not val:
                return False
        elif key == "script_hash":
            if utxo.get("script_hash") != val:
                return False
        elif as_int(utxo.get(key, -1), key) != val:
            return False
    return True


def check_table(checks: list[dict]) -> str:
    lines = ["=" * 100, f"{'CHECK':<86} RESULT"]
    for c in checks:
        lines.append(f"{c['name'][:86]:<86} {'PASS' if c['ok'] else 'FAIL'}")
        if not c["ok"]:
            lines.append(f"    evidence: {jdump(c['evidence'])[:600]}")
    lines.append("=" * 100)
    return "\n".join(lines)
