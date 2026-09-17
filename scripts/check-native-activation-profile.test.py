#!/usr/bin/env python3
"""Activation profile consistency regressions; fixtures are not deployment evidence."""
import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("activation", Path(__file__).with_name("check-native-activation-profile.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class ActivationProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.now = 2000000000
        self.gates = {key: "110" for key in m.GATES}
        self.release = {"commit": "ab" * 20, "binarySha256": "cd" * 32, "buildProfile": "release", "features": ["native-wallet-rpc"]}
        self.observation = {"network": m.NETWORK, "observedAtUnix": str(self.now), "headSlot": "3200", "wallSlot": "3201", "head": "01" * 32, "finalizedEpoch": "98", "finalizedSlot": "3135", "finalityRule": "canonical-checkpoint-slot-v1", "finalizedRoot": "02" * 32}
        self.roster = {"network": m.NETWORK, "head": self.observation["head"], "activeValidators": [{"id": "0", "publicKeySha256": "03" * 32}]}
        self.readiness = {"network": m.NETWORK, "observedAtUnix": str(self.now), "validatorId": "0", "publicKeySha256": "03" * 32, "observedHead": self.observation["head"], "release": self.release, "gateEpochs": self.gates, "checks": {"canonicalReplayPassed": True, "historicalRootsUnchanged": True, "rollbackPrepared": True, "withdrawalSimulationPassed": True, "sourceReleaseRehearsalPassed": True}, "operatorApprovalReference": "fixture-only:no-production-approval"}
        self.custody = {"schema": "postern.mainnet-custody.v1", "route_manifest": {"synthetic": False, "native_domain": "0x" + m.NETWORK["domain"], "native_asset": "0x" + "11" * 32, "routes": [{"network": "ethereum-mainnet", "chain_id": "eip155:1", "vault": "0x" + "22" * 20}]}, "activation": {"format": m.NETWORK["format"], "genesis": "0x" + m.NETWORK["genesis"], "epoch": "110"}}
        self.profile = {"schema": "bloch.native-mainnet-activation.v1", "network": m.NETWORK, "gateEpochs": self.gates, "minimumLeadEpochs": "4", "sourceDepositsOpenEpoch": "110", "release": self.release}

    def artifact(self, name, value):
        raw = json.dumps(value).encode()
        (self.root / name).write_bytes(raw)
        return {"path": name, "sha256": hashlib.sha256(raw).hexdigest()}

    def save(self):
        self.profile["custodyManifest"] = self.artifact("custody.json", self.custody)
        self.profile["chainObservation"] = self.artifact("observation.json", self.observation)
        self.profile["validatorRoster"] = self.artifact("roster.json", self.roster)
        self.profile["validatorReadiness"] = [self.artifact("ready.json", self.readiness)]
        path = self.root / "profile.json"
        path.write_text(json.dumps(self.profile))
        return path

    def test_complete_future_profile_is_only_consistency_not_authorization(self):
        result = m.validate(self.save(), self.now)
        self.assertTrue(result["consistentForOperatorReview"])
        self.assertFalse(result["activationAuthorized"])
        self.assertFalse(result["operatorSignaturesVerified"])
        self.assertEqual(result["validatorsCovered"], 1)

    def test_unset_past_or_misordered_gates_are_refused(self):
        for gate in m.GATES:
            for value in (None, "99", "100", "103", str(2**64 - 1), "0110"):
                with self.subTest(gate=gate, value=value):
                    original = self.gates[gate]
                    self.gates[gate] = value
                    with self.assertRaises(ValueError): m.validate(self.save(), self.now)
                    self.gates[gate] = original
        self.gates["bootstrap"] = "111"
        with self.assertRaises(ValueError): m.validate(self.save(), self.now)

    def test_network_build_freshness_roster_and_readiness_binding(self):
        cases = [(self.profile, "network", {**m.NETWORK, "format": "BPOSLAB1"}),
                 (self.release, "features", ["native-wallet-rpc", "native-lab"]),
                 (self.release, "binarySha256", None),
                 (self.observation, "observedAtUnix", str(self.now - 601)),
                 (self.observation, "observedAtUnix", str(self.now + 1)),
                 (self.observation, "wallSlot", "4000"),
                 (self.roster, "head", "07" * 32),
                 (self.readiness, "publicKeySha256", "08" * 32),
                 (self.readiness, "validatorId", "1"),
                 (self.readiness, "release", {**self.release, "binarySha256": "09" * 32}),
                 (self.readiness, "gateEpochs", {**self.gates, "pool": "111"}),
                 (self.readiness, "operatorApprovalReference", ""),
                 (self.readiness, "checks", {}),
                 (self.custody["route_manifest"], "native_asset", None),
                 (self.custody["activation"], "epoch", "111")]
        for target, key, bad in cases:
            with self.subTest(field=key):
                old = target[key]
                target[key] = bad
                with self.assertRaises(ValueError): m.validate(self.save(), self.now)
                target[key] = old

    def test_exit_order_and_finality_lag_policy(self):
        cases = [(self.gates, "pool", "111"),
                 (self.profile, "sourceDepositsOpenEpoch", "109"),
                 (self.observation, "finalizedSlot", "3103"),
                 (self.observation, "finalizedSlot", "3201"),
                 (self.observation, "finalityRule", "epoch-only")]
        for target, key, bad in cases:
            old = target[key]
            target[key] = bad
            with self.subTest(field=key), self.assertRaises(ValueError):
                m.validate(self.save(), self.now)
            target[key] = old
        for key in ("withdrawalSimulationPassed", "sourceReleaseRehearsalPassed"):
            self.readiness["checks"][key] = False
            with self.assertRaises(ValueError): m.validate(self.save(), self.now)
            self.readiness["checks"][key] = True

    def test_hash_tampering_missing_readiness_duplicate_json_and_unarmed_template(self):
        path = self.save()
        (self.root / "ready.json").write_text("{}")
        with self.assertRaises(ValueError): m.validate(path, self.now)
        path = self.save()
        data = json.loads(path.read_text()); data["validatorReadiness"] = []
        path.write_text(json.dumps(data))
        with self.assertRaises(ValueError): m.validate(path, self.now)
        path.write_text('{"schema":"a","schema":"b"}')
        with self.assertRaises(ValueError): m.validate(path, self.now)
        template = Path(__file__).resolve().parents[1] / "docs/native-mainnet-activation.template.json"
        with self.assertRaises(ValueError): m.validate(template, self.now)

if __name__ == "__main__":
    unittest.main()
