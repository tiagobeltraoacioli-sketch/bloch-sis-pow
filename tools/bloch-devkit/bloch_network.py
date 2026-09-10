"""Genesis-4 source connector. RPC trust is explicit; no settlement is claimed."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

RPC_URL = "https://posternlabs.com/g4rpc"
NETWORK_ID = 1228832244
GENESIS_ROOT = "9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415"
GENESIS_TIME = 1788131209 - 49151 * 30
PIN = {"slot": 49151, "block_id": "d5b3a12207af3010a611b737be15877db476ce9629520e08c552b8995bf23d32",
       "state_root": "84cceba212f6443cc5d9fd67ce578a3ae0f34cba5e5877d8082748b282db0780"}
SCHEMA = "bloch.genesis4.source/1"
LIMIT = 2 * 1024 * 1024


def integer(value, bits=64):
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ValueError("Invalid unsigned integer in Genesis-4 response")
    return value


def hash_bytes(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Invalid Genesis-4 hash")
    return bytes.fromhex(value)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def decode(data):
    if len(data) > LIMIT:
        raise ValueError("Source response exceeds 2 MiB")
    return json.loads(data, object_pairs_hook=unique_object)


def source_rpc(method, params, endpoint=RPC_URL):
    url = urlsplit(endpoint)
    if (url.username or url.password or url.fragment or
            not (url.scheme == "https" or
                 (url.scheme == "http" and url.hostname in ("127.0.0.1", "localhost")))):
        raise ValueError("Source RPC requires HTTPS or loopback HTTP")
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    # curl is used for the same TLS transport exercised by deployment checks.
    # No shell, no redirect following, no credentials in argv, bounded time/file.
    with tempfile.TemporaryFile() as output:
        run = subprocess.run(["curl", "--fail", "--silent", "--show-error", "--max-time", "20",
            "--max-filesize", str(LIMIT), "--proto", "=https,http", "--url", endpoint,
            "-H", "Content-Type: application/json", "--data-binary", "@-"],
            input=body.encode(), stdout=output, stderr=subprocess.PIPE, timeout=25)
        if run.returncode:
            raise ValueError(f"Source RPC transport failed (curl {run.returncode})")
        output.seek(0)
        envelope = decode(output.read(LIMIT + 1))
    if (not isinstance(envelope, dict) or envelope.get("jsonrpc") != "2.0"
            or envelope.get("id") != 1 or "error" in envelope or "result" not in envelope):
        raise ValueError(f"Source RPC rejected {method}")
    return envelope["result"]


def verify_header(block):
    """Independently reproduce header.rs's 304-byte canonical encoding."""
    if integer(block["version"], 32) != 0xB10C0005:
        raise ValueError("Not a Genesis-4 block")
    raw = struct.pack("<I", block["version"])
    for key in ("parent", "state_root", "body_root"):
        raw += hash_bytes(block[key])
    raw += struct.pack("<QI", integer(block["slot"]), integer(block["proposer_index"], 32))
    for key in ("randao_reveal", "randao_mix", "justified_root", "finalized_root", "attestation_root", "coherence_root"):
        raw += hash_bytes(block[key])
    assert len(raw) == 304
    actual = hashlib.sha3_256(b"BLCH4:BLOCK\x00\x00\x00\x00\x00" + raw).hexdigest()
    if actual != block["block_id"]:
        raise ValueError("Genesis-4 header hash mismatch")
    if integer(block["timestamp"]) != GENESIS_TIME + block["slot"] * 30:
        raise ValueError("Genesis-4 block clock mismatch")
    if block.get("epoch") != block["slot"] // 32:
        raise ValueError("Genesis-4 block epoch mismatch")
    return actual


def validate_view(view, now):
    slot = integer(view["slot"])
    expected_wall = int((now - GENESIS_TIME) // 30)
    if abs(integer(view["wall_slot"]) - expected_wall) > 2:
        raise ValueError("Source clock is stale or ahead of local time")
    if not -1 <= expected_wall - slot <= 8 or integer(view["behind_by_slots"]) > 8:
        raise ValueError("Source head is not synchronized")
    if view.get("slots_per_epoch") != 32 or view.get("epoch") != slot // 32:
        raise ValueError("Unexpected Genesis-4 epoch configuration")
    final = view["finalized"]
    epoch = integer(final["epoch"])
    hash_bytes(final["root"])
    if not 0 <= slot // 32 - epoch <= 4:
        raise ValueError("Finalized checkpoint is too old or in the future")
    evidence = view.get("corroboration", {})
    if evidence.get("corroborated") is not True or integer(evidence.get("witnesses", 0)) < 2:
        raise ValueError("Source checkpoint lacks RPC corroboration")
    return final


def collect(previous=None, call=source_rpc, now=None):
    now = time.time() if now is None else now
    pin = call("getblockbyslot", [PIN["slot"]])
    verify_header(pin)
    if any(pin[key] != value for key, value in PIN.items()):
        raise ValueError("Source does not match the configured Bloch checkpoint")
    view = call("getchaininfo", [])
    final = validate_view(view, now)
    block = call("getblockbyid", [final["root"]])
    verify_header(block)
    if block["block_id"] != final["root"] or block.get("finalized") is not True:
        raise ValueError("Finalized block lookup disagrees with the source view")
    if not PIN["slot"] <= block["slot"] <= view["slot"]:
        raise ValueError("Finalized source position is outside the accepted range")
    if not final["epoch"] - 1 <= block["epoch"] <= final["epoch"]:
        raise ValueError("Finalized source block is inconsistent with its checkpoint epoch")
    if previous:
        validate_record(previous)
        old = previous["block"]
        if final["epoch"] < previous["finalized_epoch"] or block["slot"] < old["slot"]:
            raise ValueError("Finalized source regression; previous state retained")
        if (final["epoch"] == previous["finalized_epoch"] or block["slot"] == old["slot"]) and block["block_id"] != old["block_id"]:
            raise ValueError("Conflicting finalized checkpoint; previous state retained")
        canonical = call("getblockbyslot", [old["slot"]])
        verify_header(canonical)
        if canonical["block_id"] != old["block_id"] or canonical.get("finalized") is not True:
            raise ValueError("Previously finalized block changed canonical status")
    # A reorg or checkpoint change during the reads must not create a mixed view.
    after = validate_view(call("getchaininfo", []), now)
    if after != final:
        raise ValueError("Checkpoint changed during sync; retry")
    return {"schema": SCHEMA, "network_id": NETWORK_ID, "genesis_root": GENESIS_ROOT,
            "trust": "operator-rpc-corroborated", "observed_at": int(now),
            "finalized_epoch": final["epoch"], "block": block,
            "capabilities": {"source_connected": True, "execution_settled": False,
                             "deposits_enabled": False, "withdrawals_enabled": False}}


def validate_record(record):
    if (record.get("schema") != SCHEMA or record.get("network_id") != NETWORK_ID
            or record.get("genesis_root") != GENESIS_ROOT
            or record.get("trust") != "operator-rpc-corroborated"):
        raise ValueError("Source record belongs to another network or trust model")
    verify_header(record["block"])
    integer(record["finalized_epoch"])
    integer(record["observed_at"])
    if record["block"]["slot"] < PIN["slot"] or not record["finalized_epoch"] - 1 <= record["block"]["epoch"] <= record["finalized_epoch"]:
        raise ValueError("Invalid stored source position")


def sync(path, call=source_rpc, now=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.with_suffix(".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous = None
        if path.exists():
            with path.open("rb") as stored:
                previous = decode(stored.read(LIMIT + 1))
        result = collect(previous, call, now)
        fd, name = tempfile.mkstemp(prefix=".checkpoint-", dir=path.parent)
        try:
            with os.fdopen(fd, "w") as output:
                json.dump(result, output, sort_keys=True, indent=2, allow_nan=False)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(name, path)
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)
        return result
