#!/usr/bin/env python3
"""Offline consistency check of an operator-authored activation plan; never activates."""
import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

NETWORK = {
    "format": "BPOSMAN1",
    "domain": "f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966",
    "genesis": "9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415",
}
GATES = ("state", "transfer", "bootstrap", "import", "withdrawal", "pool")
MAX_FILE = 2 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def load(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_FILE + 1)
    require(len(raw) <= MAX_FILE, "artifact exceeds size bound")
    return json.loads(raw, object_pairs_hook=unique), raw


def integer(value, name):
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value), name + " must be a canonical decimal string")
    number = int(value)
    require(number < 2**64 - 1, name + " is unset/disabled or out of range")
    return number


def digest(value, name, length=64):
    require(isinstance(value, str) and re.fullmatch("[0-9a-f]{" + str(length) + "}", value), name + " must be lowercase hex")
    require(value != "0" * length, name + " cannot be zero")
    return value


def artifact(root, reference):
    require(isinstance(reference, dict) and set(reference) == {"path", "sha256"}, "missing artifact reference")
    require(isinstance(reference["path"], str), "artifact path required")
    relative = Path(reference["path"])
    require(not relative.is_absolute(), "artifact paths must be relative")
    path = (root / relative).resolve()
    require(root in path.parents, "artifact escapes profile directory")
    value, raw = load(path)
    require(hashlib.sha256(raw).hexdigest() == digest(reference["sha256"], "artifact hash"), "artifact hash mismatch")
    return value


def identity(value):
    require(value.get("network") == NETWORK, "official network identity mismatch")


def recent(value, now):
    observed = integer(value.get("observedAtUnix"), "observedAtUnix")
    require(0 <= now - observed <= 600, "readiness/chain observation is stale or future-dated")


def validate(path, now=None):
    now = int(time.time()) if now is None else now
    path = Path(path).resolve()
    profile, _ = load(path)
    root = path.parent
    require(profile.get("schema") == "bloch.native-mainnet-activation.v1", "wrong activation schema")
    identity(profile)
    gates = profile.get("gateEpochs")
    require(isinstance(gates, dict) and set(gates) == set(GATES), "all six gate epochs are required")
    epochs = {name: integer(gates[name], name + " epoch") for name in GATES}
    require(all(epochs["state"] <= value for value in epochs.values()), "native state must activate before every operation")
    require(epochs["bootstrap"] <= epochs["import"] <= epochs["withdrawal"], "bootstrap/import/withdrawal ordering is inconsistent")
    require(epochs["bootstrap"] <= epochs["transfer"] and epochs["import"] <= epochs["pool"], "asset funding prerequisites are not ordered")
    release = profile.get("release", {})
    digest(release.get("commit"), "release commit", 40)
    digest(release.get("binarySha256"), "release binary hash")
    require(release.get("buildProfile") == "release", "release build required")
    features = release.get("features")
    require(isinstance(features, list) and all(isinstance(f, str) for f in features) and len(features) == len(set(features)), "unique build features required")
    require("native-wallet-rpc" in features and "native-lab" not in features, "official build must enable native-wallet-rpc without native-lab")
    custody = artifact(root, profile.get("custodyManifest"))
    require(custody.get("schema") == "postern.mainnet-custody.v1", "reviewed custody manifest required")
    route_manifest = custody.get("route_manifest", {})
    require(route_manifest.get("synthetic") is False and route_manifest.get("native_domain") == "0x" + NETWORK["domain"], "custody native domain mismatch")
    native_asset = route_manifest.get("native_asset")
    require(isinstance(native_asset, str) and native_asset.startswith("0x"), "custody native asset is unset")
    digest(native_asset[2:], "custody native asset")
    activation = custody.get("activation", {})
    require(activation.get("format") == NETWORK["format"] and activation.get("genesis") == "0x" + NETWORK["genesis"], "custody activation network mismatch")
    custody_epoch = activation.get("epoch")
    if isinstance(custody_epoch, int) and not isinstance(custody_epoch, bool): custody_epoch = str(custody_epoch)
    require(integer(custody_epoch, "custody activation epoch") == epochs["state"], "custody activation epoch differs from plan")
    routes = route_manifest.get("routes")
    require(isinstance(routes, list) and len(routes) == 1 and routes[0].get("network") == "ethereum-mainnet" and routes[0].get("chain_id") == "eip155:1", "selected Ethereum custody route required")
    vault = routes[0].get("vault")
    require(isinstance(vault, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", vault) and int(vault, 16) != 0, "custody vault is unset")
    # Detailed source custody validity belongs to its separate validator. This
    # pins the operator-reviewed artifact without treating its observations as
    # native activation/finality evidence.
    observation = artifact(root, profile.get("chainObservation"))
    identity(observation)
    recent(observation, now)
    head = integer(observation.get("headSlot"), "headSlot")
    wall = integer(observation.get("wallSlot"), "wallSlot")
    require(head <= wall <= head + 32, "chain observation is ahead of clock or not synchronized")
    digest(observation.get("head"), "observed head")
    finalized = integer(observation.get("finalizedEpoch"), "finalizedEpoch")
    require(finalized <= head // 32, "finalized epoch exceeds head")
    digest(observation.get("finalizedRoot"), "finalized root")
    lead = integer(profile.get("minimumLeadEpochs"), "minimumLeadEpochs")
    require(lead >= 4, "at least four lead epochs are required for coordinated review")
    require(min(epochs.values()) >= wall // 32 + lead, "activation is past, current, or lacks reviewed lead time")
    roster = artifact(root, profile.get("validatorRoster"))
    identity(roster)
    require(roster.get("head") == observation["head"], "validator roster is not bound to observed head")
    validators = roster.get("activeValidators")
    require(isinstance(validators, list) and 1 <= len(validators) <= 4096, "bounded active validator roster required")
    expected = {}
    for item in validators:
        validator = integer(item.get("id"), "validator id")
        require(validator not in expected, "duplicate validator")
        public_hash = digest(item.get("publicKeySha256"), "validator public key hash")
        require(public_hash not in expected.values(), "duplicate validator key")
        expected[validator] = public_hash
    references = profile.get("validatorReadiness")
    require(isinstance(references, list) and len(references) == len(expected), "every active validator requires readiness evidence")
    ready = set()
    for reference in references:
        evidence = artifact(root, reference)
        identity(evidence)
        recent(evidence, now)
        validator = integer(evidence.get("validatorId"), "readiness validator id")
        require(validator in expected and validator not in ready, "unknown or duplicate readiness validator")
        require(evidence.get("publicKeySha256") == expected[validator], "validator identity mismatch")
        require(evidence.get("release") == release and evidence.get("gateEpochs") == gates, "readiness does not bind exact release and gates")
        require(evidence.get("observedHead") == observation["head"], "readiness does not bind observed chain")
        checks = evidence.get("checks")
        require(isinstance(checks, dict) and set(checks) == {"canonicalReplayPassed", "historicalRootsUnchanged", "rollbackPrepared"} and all(value is True for value in checks.values()), "required readiness checks missing")
        require(isinstance(evidence.get("operatorApprovalReference"), str) and 1 <= len(evidence["operatorApprovalReference"]) <= 512, "operator approval reference required")
        ready.add(validator)
    # This consistency check does not authenticate operators or deploy a release.
    return {"consistentForOperatorReview": True, "activationAuthorized": False,
            "operatorSignaturesVerified": False, "validatorsCovered": len(ready),
            "earliestEpoch": str(min(epochs.values())), "network": NETWORK}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.profile), sort_keys=True))
    except ValueError as error:
        # Validation messages name the failed requirement, never artifact contents.
        print("Activation profile refused: " + str(error), file=sys.stderr)
        return 1
    except (OSError, TypeError, KeyError, AttributeError, RecursionError):
        print("Activation profile refused: unreadable or malformed bounded evidence.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
