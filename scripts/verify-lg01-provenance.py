#!/usr/bin/env python3
"""Fail-closed classifier for the external evidence needed by audit finding LG-01.

This tool checks the shape and internal consistency of reports copied from the
two archival Genesis-3 snapshot nodes.  It does not authenticate those reports;
their raw inputs and operator signatures must be published separately.
"""

import argparse
import json
import pathlib
import re
import sys


SCHEMA = "bloch-lg01-provenance-v1"
TERMINAL_HEIGHT = 39_918
PREVIOUS_HEIGHT = TERMINAL_HEIGHT - 1
SUBSIDY_SAT = 840_000_000_000
EXPECTED_ROWS = 452_726
EXPECTED_TOTAL_SAT = 381_074_400_000_000_000
EXPECTED_SHA256 = "84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6"
EXPECTED_SHA3 = "3d67246e94881a17d302b464f79fee55886d8068794e76fed43081117fbe308d"
EXPECTED_SET_ROOT = "7c756ee8ffff9529b40c124b36bd3e1a9934a15f063affe5596913fb858efbdf"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class EvidenceError(ValueError):
    pass


def exact_keys(value, expected, where):
    if type(value) is not dict:
        raise EvidenceError(f"{where}: expected object")
    actual = set(value)
    expected = set(expected)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise EvidenceError(f"{where}: wrong fields (missing={missing}, extra={extra})")


def string(value, where):
    if type(value) is not str or not value:
        raise EvidenceError(f"{where}: expected non-empty string")
    return value


def integer(value, where):
    if type(value) is not int or value < 0:
        raise EvidenceError(f"{where}: expected non-negative integer")
    return value


def boolean(value, where):
    if type(value) is not bool:
        raise EvidenceError(f"{where}: expected boolean")
    return value


def digest(value, where):
    value = string(value, where)
    if not HEX64.fullmatch(value):
        raise EvidenceError(f"{where}: expected lowercase 64-character hex digest")
    return value


def check_snapshot(snapshot, where):
    exact_keys(snapshot, ("rows", "total_sat", "uncompressed_sha256", "sha3_256", "set_root"), where)
    expected = {
        "rows": EXPECTED_ROWS,
        "total_sat": EXPECTED_TOTAL_SAT,
        "uncompressed_sha256": EXPECTED_SHA256,
        "sha3_256": EXPECTED_SHA3,
        "set_root": EXPECTED_SET_ROOT,
    }
    for field, wanted in expected.items():
        got = integer(snapshot[field], f"{where}.{field}") if type(wanted) is int else digest(snapshot[field], f"{where}.{field}")
        if got != wanted:
            raise EvidenceError(f"{where}.{field}: {got!r} does not match the pinned carryover artifact")


def check_node(node, index):
    where = f"nodes[{index}]"
    exact_keys(
        node,
        (
            "node_id", "archive_identity_sha256", "capture_utc",
            "selected_tip_height_at_snapshot", "selected_tip_hash_at_snapshot",
            "max_stored_height", "snapshot", "raw_evidence_sha256", "block_39918",
        ),
        where,
    )
    string(node["node_id"], f"{where}.node_id")
    digest(node["archive_identity_sha256"], f"{where}.archive_identity_sha256")
    string(node["capture_utc"], f"{where}.capture_utc")
    selected_height = integer(node["selected_tip_height_at_snapshot"], f"{where}.selected_tip_height_at_snapshot")
    digest(node["selected_tip_hash_at_snapshot"], f"{where}.selected_tip_hash_at_snapshot")
    max_stored_height = integer(node["max_stored_height"], f"{where}.max_stored_height")
    if max_stored_height < selected_height:
        raise EvidenceError(f"{where}.max_stored_height: cannot be below the selected tip")
    check_snapshot(node["snapshot"], f"{where}.snapshot")
    raw = node["raw_evidence_sha256"]
    exact_keys(raw, ("daginfo", "tip_meta", "carryover_verification", "block_lookup"), f"{where}.raw_evidence_sha256")
    for name, value in raw.items():
        digest(value, f"{where}.raw_evidence_sha256.{name}")

    block = node["block_39918"]
    if block is None:
        return
    if max_stored_height < TERMINAL_HEIGHT:
        raise EvidenceError(f"{where}.block_39918: block record exceeds maximum stored height")
    exact_keys(block, ("hash", "selected", "coinbase_total_sat", "tx_count"), f"{where}.block_39918")
    digest(block["hash"], f"{where}.block_39918.hash")
    boolean(block["selected"], f"{where}.block_39918.selected")
    integer(block["coinbase_total_sat"], f"{where}.block_39918.coinbase_total_sat")
    if integer(block["tx_count"], f"{where}.block_39918.tx_count") < 1:
        raise EvidenceError(f"{where}.block_39918.tx_count: selected block must contain a coinbase")


def classify(bundle):
    exact_keys(bundle, ("schema", "nodes"), "bundle")
    if bundle["schema"] != SCHEMA:
        raise EvidenceError(f"bundle.schema: expected {SCHEMA!r}")
    nodes = bundle["nodes"]
    if type(nodes) is not list or len(nodes) < 2:
        raise EvidenceError("bundle.nodes: reports from at least two archival nodes are required")
    for index, node in enumerate(nodes):
        check_node(node, index)

    node_ids = [node["node_id"] for node in nodes]
    archive_ids = [node["archive_identity_sha256"] for node in nodes]
    if len(set(node_ids)) != len(node_ids):
        raise EvidenceError("bundle.nodes: node_id values must be distinct")
    if len(set(archive_ids)) != len(archive_ids):
        raise EvidenceError("bundle.nodes: archive identities must be distinct")

    heights = {node["selected_tip_height_at_snapshot"] for node in nodes}
    tip_hashes = {node["selected_tip_hash_at_snapshot"] for node in nodes}
    if len(heights) != 1 or len(tip_hashes) != 1:
        raise EvidenceError("bundle.nodes: archival nodes disagree on the selected tip")

    height = next(iter(heights))
    if height == PREVIOUS_HEIGHT:
        for index, node in enumerate(nodes):
            block = node["block_39918"]
            if block is not None and block["selected"]:
                raise EvidenceError(f"nodes[{index}]: height 39,918 cannot be selected above a selected tip at 39,917")
        return "LABEL_OR_STALE_SNAPSHOT"

    if height == TERMINAL_HEIGHT:
        for index, node in enumerate(nodes):
            block = node["block_39918"]
            if block is None or not block["selected"]:
                raise EvidenceError(f"nodes[{index}]: selected tip 39,918 requires a selected block-39,918 record")
            if block["hash"] != node["selected_tip_hash_at_snapshot"]:
                raise EvidenceError(f"nodes[{index}]: block 39,918 hash does not equal the selected tip hash")
            if block["coinbase_total_sat"] < SUBSIDY_SAT:
                raise EvidenceError(f"nodes[{index}]: block 39,918 did not claim the full scheduled subsidy")
        block_hashes = {node["block_39918"]["hash"] for node in nodes}
        if len(block_hashes) != 1:
            raise EvidenceError("bundle.nodes: archival nodes disagree on block 39,918")
        return "SELECTED_BLOCK_EFFECTS_MISSING"

    raise EvidenceError(
        "bundle.nodes: selected tip must be exactly 39,917 or 39,918 to classify LG-01"
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=pathlib.Path, help="two-node JSON evidence bundle")
    args = parser.parse_args(argv)
    try:
        with args.bundle.open("r", encoding="utf-8") as handle:
            bundle = json.load(handle)
        result = classify(bundle)
    except (OSError, json.JSONDecodeError, EvidenceError) as error:
        print(f"LG-01 INCONCLUSIVE: {error}", file=sys.stderr)
        return 1
    print(f"LG-01 {result}")
    print("Evidence is internally consistent but not authenticated; publish the raw inputs and signatures.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
