#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Independent review 503: do the crate's tests notice a broken signer?

Applies one deliberate defect at a time to src/lib.rs, runs the crate tests
(with `state-acceptance`), records whether any test failed, and restores the
file with `git checkout`. Run from the workspace root of a CLEAN worktree:

    CARGO_TARGET_DIR=... python3 tools/l2-deposit-wallet-wasm/review/mutation-503.py

A mutant that SURVIVES is a behaviour no test of the crate pins.
"""
import subprocess
import sys

LIB = "tools/l2-deposit-wallet-wasm/src/lib.rs"

MUTANTS = [
    ("M1 fingerprint ignores the per-input values",
     "        for (_, value) in &funding {\n            h.update(value.to_le_bytes());\n        }\n", ""),
    ("M2 sign does not consume the review (reusable)",
     "let expected = self.pending.take().ok_or(\"review required\")?;",
     "let expected = self.pending.ok_or(\"review required\")?;"),
    ("M3 a failed call no longer clears the review (dispatch and nw_call)",
     "                s.pending = None;\n            }\n        });\n    }",
     "                let _ = &s;\n            }\n        });\n    }"),
    ("M4 sign trusts the reviewId argument, not the rebuilt fingerprint",
     "if hash(args, \"reviewId\")? != expected || id != expected {",
     "if hash(args, \"reviewId\")? != expected {"),
    ("M5 sign ignores the reviewId argument",
     "if hash(args, \"reviewId\")? != expected || id != expected {",
     "if id != expected {"),
    ("M6 open_mnemonic takes the first derivation whatever key was expected",
     "                if pk == public {", "                if pk == public || true {"),
    ("M7 hex accepts upper case",
     "!s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))",
     "!s.bytes().all(|b| b.is_ascii_hexdigit())"),
    ("M8 nw_call alone no longer clears the review on a bad buffer / bad JSON",
     "    let result = request.and_then(dispatch);\n    if result.is_err() {",
     "    let result = request.and_then(dispatch);\n    if false {"),
    ("M9 change goes to a script hash that is not the owner's",
     "change: TransferOutput { value: 0, script_hash: address_script(&owner) },",
     "change: TransferOutput { value: 0, script_hash: digest(&owner) },"),
    ("M22 change goes to the full key hash, not the address form",
     "change: TransferOutput { value: 0, script_hash: address_script(&owner) },",
     "change: TransferOutput { value: 0, script_hash: owner },"),
    ("M23 the address form keeps the whole key hash",
     "    script[..20].copy_from_slice(&key_hash[..20]);\n    script\n}\n\nstruct Built",
     "    script.copy_from_slice(key_hash);\n    script\n}\n\nstruct Built"),
    ("M10 the released signature is not verified",
     "if !crypto::verify(&self.public, &root, &signature) {", "if false {"),
    ("M11 the released bytes are not decoded back",
     "if PosTransaction::from_canonical_bytes(&encoded).ok().as_ref() != Some(&wire)\n            || declared < encoded.len() as u64",
     "if false"),
    ("M12 lock keeps the session",
     "        if method == \"lock\" {\n            *slot = None;", "        if method == \"lock\" {\n            let _ = &slot;"),
    ("M13 a new open keeps the previous session when it fails",
     "        SESSION.with(|s| *s.borrow_mut() = None);\n        if string(args, \"domainHex\")? != DOMAIN {",
     "        if string(args, \"domainHex\")? != DOMAIN {"),
    ("M14 review does not replace an older pending review on failure",
     "        self.pending = None;\n        let built = self.build(args, false)?;", "        let built = self.build(args, false)?;"),
    ("M15 unknown fields are ignored",
     "    if map.keys().all(|k| allowed.iter().any(|set| set.contains(&k.as_str()))) {", "    if map.keys().all(|k| allowed.iter().any(|set| set.contains(&k.as_str()))) || true {"),
    ("M16 the secret is not checked against the public key at open",
     "        if !crypto::verify(&public, &challenge, &proof) {", "        if false {"),
    ("M17 secret strings in the request are not zeroized",
     "            s.zeroize();", "            let _ = &s;"),
    ("M19 the tip may exceed the base fee (R503-1 rule 1 removed)",
     "if tip > base_fee.saturating_mul(MAX_TIP_PER_BASE_FEE) {", "if false {"),
    ("M20 no absolute fee ceiling (R503-1 rule 2 removed)",
     "if fee > MAX_FEE_SAT {", "if false {"),
    ("M21 the fee ceiling is judged against the base part only",
     "if fee > MAX_FEE_SAT {", "if charge.base_fee_sat > MAX_FEE_SAT {"),
    ("M18 the tip is left out of the conservation",
     "charge.base_fee_sat.checked_add(charge.priority_fee_sat).ok_or(\"fee overflow\")?;",
     "charge.base_fee_sat.checked_add(0).ok_or(\"fee overflow\")?;"),
]


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def main():
    if run(["git", "diff", "--quiet", "--", LIB]).returncode != 0:
        sys.exit("src/lib.rs is not clean")
    original = open(LIB).read()
    survivors = []
    for name, old, new in MUTANTS:
        if original.count(old) < 1:
            print(f"SKIP {name}: pattern not found")
            continue
        open(LIB, "w").write(original.replace(old, new))
        try:
            result = run(["cargo", "test", "--locked", "--offline", "-p", "bloch-l2-deposit-wallet-wasm",
                          "--features", "state-acceptance", "--lib"])
        finally:
            run(["git", "checkout", "--", LIB])
        out = result.stdout + result.stderr
        if "error[" in out or "could not compile" in out:
            print(f"BUILD-ERROR {name}")
            continue
        failed = [line.split()[1] for line in out.splitlines() if line.startswith("test ") and line.endswith("FAILED")]
        if result.returncode == 0:
            survivors.append(name)
            print(f"SURVIVED {name}")
        else:
            print(f"killed   {name} ({len(failed)} failing: {', '.join(t.split('::')[-1] for t in failed[:3])}{'...' if len(failed) > 3 else ''})")
    print(f"{len(survivors)} survivor(s) of {len(MUTANTS)}")
    assert open(LIB).read() == original


if __name__ == "__main__":
    main()
