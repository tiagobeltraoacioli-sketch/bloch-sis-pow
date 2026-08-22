#!/usr/bin/env python3
"""Mutation campaign over bloch-euvm (and over this front's own KAT harness).

WHY THIS EXISTS (repo discipline rule 3): a test that survives the deactivation
of the rule it claims to test is decorative — a review on 2026-08-22 showed two
reverted consensus sites surviving a 489-test suite. This script proves, mutant
by mutant, which euvm rules the 331-test suite actually pins, and reports the
survivors BY NAME instead of hiding them (deliverable of front C4 in
docs/specs/BLOCH-VM-DIFFERENTIAL-CONFORMANCE.md).

SAFETY: the repo tree is NEVER mutated. Each run copies the crates into a scratch
directory (env MUTATION_SCRATCH or a mkdtemp), applies ONE mutant there, runs
`cargo test --no-fail-fast`, records the outcome, and restores the pristine file.
Editing the shared tree is exactly how a reviewer's mutant got committed as
production code once already; this script makes that impossible by construction.

Targets:
  --target euvm     mutants of crates/bloch-euvm, detector = its own 331 tests
  --target harness  mutants of the engine AND of conformance/euvm-conformance's
                    parser/controls, detector = the CAVP KAT suite (the §4 gate
                    of the conformance spec: a differ that stays green under a
                    mutated engine compares nothing)

Output: TSV rows (id, target, file, killed, n_failed, failing tests) on stdout;
commit the measured file under results/.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# (id, relative file, old, new, rationale). `old` must occur EXACTLY ONCE in the
# pristine file or the run aborts — a mutant that silently fails to apply would
# report a fake "survivor".
EUVM_MUTANTS = [
    ("M01-sha256d-single", "crates/bloch-euvm/src/lib.rs",
     "let twice = Sha256::digest(once);",
     "let twice = once;",
     "Op::Sha256d applies the hash ONCE instead of twice"),
    ("M02-gas-free", "crates/bloch-euvm/src/lib.rs",
     "*gas = gas.checked_sub(cost).ok_or(VmError::OutOfGas)?;",
     "*gas = gas.checked_sub(cost.min(0)).ok_or(VmError::OutOfGas)?;",
     "interpreter charges 0 gas for every op (DoS bound gone)"),
    ("M03-expectdepth-relax", "crates/bloch-euvm/src/lib.rs",
     "if st.len() != *n as usize {",
     "if st.len() < *n as usize {",
     "ExpectDepth accepts DEEPER stacks (padded-redeemer Pick-shift attack reopens)"),
    ("M04-verify-noop", "crates/bloch-euvm/src/lib.rs",
     """            Op::Verify => {
                let top = pop!();
                if !top.truthy()? {
                    return Err(VmError::Assert);
                }
            }""",
     """            Op::Verify => {
                let top = pop!();
                let _ = !top.truthy()?;
            }""",
     "Op::Verify never aborts (all mid-program assertions vacuous)"),
    ("M05-verifysig-accept", "crates/bloch-euvm/src/lib.rs",
     "st.push(Val::Int(verifier.verify(&msg, &pk, &sig) as i128));",
     "st.push(Val::Int((verifier.verify(&msg, &pk, &sig) || true) as i128));",
     "VerifySig accepts every signature"),
    ("M06-spend-hash-unchecked", "crates/bloch-euvm/src/lib.rs",
     "if validator_hash(program) != output.validator_hash {",
     "if validator_hash(program) != output.validator_hash && false {",
     "spend() no longer requires the revealed program to hash to the output's validator_hash"),
    ("M07-conservation-allows-loss", "crates/bloch-euvm/src/lib.rs",
     "if in_sum != out_plus_fee {",
     "if in_sum < out_plus_fee {",
     "validate_tx conservation only rejects inflation, silently allows value destruction"),
    ("M08-fee-burn-swap", "crates/bloch-euvm/src/lib.rs",
     "(burned, fee - burned)",
     "(fee - burned, burned)",
     "fee_burn returns (burn, validators) swapped"),
    ("M09-lt-off-by-one", "crates/bloch-euvm/src/lib.rs",
     "st.push(Val::Int((a < b) as i128));",
     "st.push(Val::Int((a <= b) as i128));",
     "Op::Lt becomes <= (boundary heights/amounts flip)"),
    ("M13-shake-truncated-read", "crates/bloch-euvm/src/lib.rs",
     """                let mut r = h.finalize_xof();
                let mut out = [0u8; 32];
                r.read(&mut out);""",
     """                let mut r = h.finalize_xof();
                let mut out = [0u8; 32];
                r.read(&mut out[..31]);""",
     "Op::Shake256 reads 31 XOF bytes, last byte always 0"),
    ("M14-eq-always-true", "crates/bloch-euvm/src/lib.rs",
     "st.push(Val::Int((a == b) as i128));",
     "st.push(Val::Int(((a == b) || true) as i128));",
     "Op::Eq always answers 1"),
    ("M15-gas-hash-flat", "crates/bloch-euvm/src/lib.rs",
     "Op::Sha256d | Op::Shake256 => 60u64.saturating_add(words(top_len())),",
     "Op::Sha256d | Op::Shake256 => 60u64.saturating_add(words(top_len().min(0))),",
     "hash ops lose the byte-proportional gas term (the exact F2 regression: 1-byte and 8-MB hash cost the same)"),
    ("M10-minting-negative-supply", "crates/bloch-euvm/src/minting.rs",
     """        if new_supply < 0 {
            return Err(MintTxError::SupplyNegative { asset });
        }""",
     """        if new_supply < 0 && false {
            return Err(MintTxError::SupplyNegative { asset });
        }""",
     "burns may drive an asset's supply below zero"),
    ("M11-stateproof-sibling-swap", "crates/bloch-euvm/src/state.rs",
     "cur = if bit_at(&kh, depth) == 0 {",
     "cur = if bit_at(&kh, depth) == 1 {",
     "verify() folds siblings in the mirrored order (membership forgery surface)"),
    ("M12-amm-fee-removed", "crates/bloch-euvm/src/batcher.rs",
     "let fee_num = (10_000i128).checked_sub(fee_bps.min(10_000) as i128)?; // 10000 − fee",
     "let fee_num = (10_000i128).checked_sub(0i128)?; // 10000 − fee",
     "amm_out ignores the LP fee entirely"),
    ("M16-kirpich-never-denies", "crates/bloch-euvm/src/kirpich.rs",
     "let denied = findings.iter().any(|f| f.severity == Severity::Deny);",
     "let denied = findings.iter().any(|f| f.severity == Severity::Deny) && false;",
     "the fail-closed audit gate never fails closed"),
]

# Harness-gate mutants (§4 of the conformance spec): the DETECTOR here is the
# CAVP KAT suite in conformance/euvm-conformance. H01-H03 mutate the ENGINE and
# must turn the KATs red (a KAT suite green under a broken engine verifies
# nothing); H04-H06 mutate the HARNESS itself (parser/controls) and must be
# caught by the suite's own count/trap/control assertions. H07 is a predicted
# EQUIVALENT-ON-GREEN-PATH mutant, included deliberately so the report shows a
# survivor being ANALYSED rather than hidden.
HARNESS_MUTANTS = [
    ("H01-engine-shake-truncated", "crates/bloch-euvm/src/lib.rs",
     EUVM_MUTANTS[9][2], EUVM_MUTANTS[9][3],
     "engine regression: truncated XOF read — KATs must go red"),
    ("H02-engine-sha256d-single", "crates/bloch-euvm/src/lib.rs",
     EUVM_MUTANTS[0][2], EUVM_MUTANTS[0][3],
     "engine regression: single application — KATs must go red"),
    ("H03-engine-eq-always-true", "crates/bloch-euvm/src/lib.rs",
     EUVM_MUTANTS[10][2], EUVM_MUTANTS[10][3],
     "engine regression: Eq tautology — the CONTROL halves must go red"),
    ("H04-parser-no-len0-truncate", "conformance/euvm-conformance/src/lib.rs",
     "m.truncate((lb / 8) as usize);",
     "// m.truncate((lb / 8) as usize);",
     "parser feeds the literal `00` byte for Len=0 (the .rsp trap) — trap tests must die"),
    ("H05-parser-drops-rows", "conformance/euvm-conformance/src/lib.rs",
     """            out.push(KatVector {
                len_bits: lb,""",
     """            if lb % 16 == 0 { continue; }
            out.push(KatVector {
                len_bits: lb,""",
     "parser silently drops ~half the corpus — count assertions must die"),
    ("H06-control-not-corrupted", "conformance/euvm-conformance/src/lib.rs",
     "c[0] ^= 0x01;",
     "c[0] ^= 0x00;",
     "corrupt() becomes identity — every negative control must die"),
    ("H07-harness-swallow-vmerror", "conformance/euvm-conformance/src/lib.rs",
     """        Ok(b) => b,
        Err(e) => panic!("VM error in KAT (harness bug, not a vector outcome): {e:?}"),
    }""",
     """        Ok(b) => b,
        Err(_e) => false,
    }""",
     "harness swallows VmError as a mismatch (a broken harness would report as failing vectors). SURVIVED the first run — no test observed the error path; closed by cavp_shake256.rs::harness_surfaces_vm_errors_instead_of_reporting_them_as_mismatches, and the arm was de-duplicated into unwrap_kat() so this mutant has exactly one site"),
]


def sh(cmd, cwd, timeout=1200):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def copy_tree(scratch, target):
    """Fresh pristine copy of exactly the crates the target needs, laid out at the
    same relative paths so the path-deps in Cargo.toml resolve unchanged."""
    for rel in ["crates/bloch-euvm"] + (
        ["conformance/euvm-conformance"] if target == "harness" else []
    ):
        dst = os.path.join(scratch, rel)
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        # target/ carries GBs of build cache from the repo — never copy it; the
        # scratch keeps its OWN target/ across mutants for incremental rebuilds.
        shutil.copytree(os.path.join(REPO, rel), dst,
                        ignore=shutil.ignore_patterns("target"))


def failing_tests(output):
    # The ` - should panic` infix is NOT decoration: libtest prints
    # `test <name> - should panic ... FAILED` for a #[should_panic] test that
    # did not panic. A regex without it silently reports n_failed=0 for a
    # mutant that WAS killed — the kill verdict survives (it comes from the
    # exit code) but the evidence column goes blank, which is exactly the kind
    # of quietly-empty number this front exists to prevent. Found by
    # scrutinising H07's suspicious 0-with-a-kill row on 2026-08-22.
    return sorted(set(re.findall(r"^test (\S+)(?: - should panic)? \.\.\. FAILED", output, re.M)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", choices=["euvm", "harness"], required=True)
    args = ap.parse_args()

    mutants = EUVM_MUTANTS if args.target == "euvm" else HARNESS_MUTANTS
    test_dir_rel = ("crates/bloch-euvm" if args.target == "euvm"
                    else "conformance/euvm-conformance")

    scratch = os.environ.get("MUTATION_SCRATCH") or tempfile.mkdtemp(prefix="euvm-mut-")
    os.makedirs(scratch, exist_ok=True)
    copy_tree(scratch, args.target)
    test_dir = os.path.join(scratch, test_dir_rel)

    # Baseline MUST be green: a killed/survived verdict over a red baseline is
    # meaningless (the failure could predate the mutant).
    base = sh(["cargo", "test", "--no-fail-fast"], test_dir)
    if base.returncode != 0:
        sys.exit(f"BASELINE RED in scratch — refusing to run campaign:\n{base.stdout}\n{base.stderr}")

    print("id\ttarget\tfile\tkilled\tn_failed\tfailing_tests")
    for mid, rel, old, new, _why in mutants:
        path = os.path.join(scratch, rel)
        with open(path) as f:
            pristine = f.read()
        n = pristine.count(old)
        if n != 1:
            sys.exit(f"{mid}: old-string occurs {n} times in {rel} (need exactly 1) — mutant table is stale")
        with open(path, "w") as f:
            f.write(pristine.replace(old, new, 1))
        try:
            r = sh(["cargo", "test", "--no-fail-fast"], test_dir)
            out = r.stdout + r.stderr
            if "error[" in out or "error: could not compile" in out:
                verdict, fails = "COMPILE-ERROR", []
            else:
                fails = failing_tests(out)
                verdict = "yes" if (r.returncode != 0 or fails) else "NO-SURVIVED"
            print(f"{mid}\t{args.target}\t{rel}\t{verdict}\t{len(fails)}\t{','.join(fails[:8])}",
                  flush=True)
        finally:
            with open(path, "w") as f:
                f.write(pristine)


if __name__ == "__main__":
    main()
