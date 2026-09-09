#!/usr/bin/env python3
"""ADR-041 withdrawal guard mutations in a disposable source copy.

The original checkout is never edited. A mutation counts as killed only if
the test binary compiled, executed, and reported a failed test. Compiler
errors, missing tools and infrastructure failures are not successful checks.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FILE = Path("crates/bloch-pos-committee/src/transition/lifecycle.rs")
MUTATIONS = [
    ("activation", "!Self::withdrawal_active(self.epoch) || ", ""),
    ("maturity", "            || self.epoch < rec.withdrawable_epoch\n", ""),
    ("one-shot", "            || rec.staked_sat == 0\n", ""),
    ("indeterminate", " || self.is_write_off_indeterminate(index)", ""),
    ("credential", "<[u8; 32]>::try_from(rec.withdrawal_credentials.as_slice())\n            .map_err(|_| TxReject::StakingRule)?",
     "<[u8; 32]>::try_from(rec.withdrawal_credentials.as_slice()).unwrap_or([0; 32])"),
    ("narrowing", "u64::try_from(payout).map_err(|_| TxReject::StakingRule)?", "payout as u64"),
    ("collision", "if self.eutxos.contains_key(&(txid, 0)) {", "if false {"),
    ("write-off-overflow", ".checked_add(unbacked)\n            .ok_or(TxReject::StakingRule)?", ".saturating_add(unbacked)"),
]


def main():
    source = (ROOT / FILE).read_text()
    for name, old, _ in MUTATIONS:
        if source.count(old) != 1:
            raise SystemExit(f"Review mutation {name}: its source anchor changed")
    files = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
    ).decode().split("\0")
    with tempfile.TemporaryDirectory(prefix="bloch-withdrawal-mutations-") as temp:
        checkout = Path(temp)
        for name in files:
            if not name:
                continue
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise SystemExit("Unexpected source path")
            origin = ROOT / relative
            if origin.is_file():
                destination = checkout / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(origin, destination)
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(ROOT / "target" / "validator-lifecycle-mutations")
        command = ["cargo", "+1.94.1", "test", "--locked", "-p", "bloch-pos-committee",
                   "--lib", "transition::tests::validator_lifecycle::", "--", "--nocapture"]
        for name, old, new in [("control", None, None), *MUTATIONS]:
            (checkout / FILE).write_text(source if old is None else source.replace(old, new))
            result = subprocess.run(command, cwd=checkout, env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if name == "control":
                passed = result.returncode == 0 and "test result: ok." in result.stdout
            else:
                passed = result.returncode != 0 and "test result: FAILED." in result.stdout
            if not passed:
                print(result.stdout)
                raise SystemExit(f"Mutation check failed: {name}")
            print(f"{name}: {'passed' if old is None else 'killed'}", flush=True)
    if (ROOT / FILE).read_text() != source:
        raise SystemExit("Shipping source changed during mutation verification")
    print("All eight withdrawal guard mutations killed; shipping source unchanged.")


if __name__ == "__main__":
    main()
