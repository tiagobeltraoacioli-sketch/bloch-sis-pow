#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Proof by mutation (BLOCH-L1-EVM-PQ-TX §9.3).

A review on 2026-08-21 reverted two consensus sites and 489 tests stayed
green. A passing suite is therefore not evidence. This harness breaks the
crate on purpose, one site at a time, and requires the suite to notice.

Each mutation must turn the suite RED. A surviving mutant is a missing test,
and the missing test gets written before the PR moves.

Usage:  python3 mutants/mutants.py [--list]
Exit 0 iff every mutant was killed.
"""
import subprocess, sys, os, pathlib, re

CRATE = pathlib.Path(__file__).resolve().parent.parent
SRC = CRATE / "src"

# (id, label, file, needle, replacement)
MUTANTS = [
    ("M01", "hybrid AND -> OR", "verify.rs",
     "&& verifier.verify_falcon1024(falcon_pk, &root, falcon_sig);",
     "|| verifier.verify_falcon1024(falcon_pk, &root, falcon_sig);"),

    ("M02a", "signature split point +1", "verify.rs",
     "sig_body.split_at(MLDSA65_SIG_BYTES)",
     "sig_body.split_at(MLDSA65_SIG_BYTES + 1)"),
    ("M02b", "signature split point -1", "verify.rs",
     "sig_body.split_at(MLDSA65_SIG_BYTES)",
     "sig_body.split_at(MLDSA65_SIG_BYTES - 1)"),

    ("M03a", "pubkey split point +1", "verify.rs",
     "pk_body.split_at(MLDSA65_PK_BYTES)",
     "pk_body.split_at(MLDSA65_PK_BYTES + 1)"),
    ("M03b", "pubkey split point -1", "verify.rs",
     "pk_body.split_at(MLDSA65_PK_BYTES)",
     "pk_body.split_at(MLDSA65_PK_BYTES - 1)"),

    ("M04", "signature length guard <= -> <", "verify.rs",
     "if sig_body.len() <= MLDSA65_SIG_BYTES {",
     "if sig_body.len() < MLDSA65_SIG_BYTES {"),

    ("M05", "address consistency check deleted", "verify.rs",
     "    if address_from_pubkey(pk_enveloped) != tx.sender {\n        return Err(AuthReject::AddressMismatch);\n    }\n",
     "\n"),

    ("M06", "address compared on 8 bytes only", "verify.rs",
     "if address_from_pubkey(pk_enveloped) != tx.sender {",
     "if address_from_pubkey(pk_enveloped)[..8] != tx.sender[..8] {"),

    ("M07", "RedundantPubkey relaxed to 'present and equal is fine'", "verify.rs",
     "        (Some(_), Some(_)) => return Err(AuthReject::RedundantPubkey),",
     "        (Some(recorded), Some(revealed)) => {\n"
     "            if recorded != revealed { return Err(AuthReject::RedundantPubkey); }\n"
     "            recorded\n"
     "        }"),

    ("M08", "MissingPubkey relaxed to 'verify against nothing, accept'", "verify.rs",
     "        (None, None) => return Err(AuthReject::MissingPubkey),",
     "        (None, None) => {\n"
     "            let r = signing_root(tx)?;\n"
     "            return Ok(Authorized { sender: tx.sender, evm_txid: evm_txid(&r), pubkey_to_record: None });\n"
     "        }"),

    ("M09", "suite check == 0x0001 -> != 0x0000", "verify.rs",
     "Some((suite, body)) if suite == SUITE_MLDSA65_FALCON1024 => Ok(body),",
     "Some((suite, body)) if suite != 0x0000 => Ok(body),"),

    ("M10", "strict envelope -> legacy fallback", "lib.rs",
     "    if bytes[0] != SUITE_MAGIC[0] || bytes[1] != SUITE_MAGIC[1] {\n        return None;\n    }",
     "    if bytes[0] != SUITE_MAGIC[0] || bytes[1] != SUITE_MAGIC[1] {\n        return Some((SUITE_MLDSA65_FALCON1024, bytes));\n    }"),

    ("M11", "trailing-byte rejection deleted from the decoder", "codec.rs",
     "        if self.pos == self.bytes.len() {\n            Ok(())\n        } else {\n            Err(CodecError::TrailingBytes)\n        }",
     "        let _ = self.pos;\n        Ok(())"),

    ("M12a", "activation gate >= -> > (strictly after)", "verify.rs",
     "    if epoch < ACTIVATION_EPOCH {",
     "    if epoch <= ACTIVATION_EPOCH {"),
    ("M12b", "activation gate deleted entirely", "verify.rs",
     "    if epoch < ACTIVATION_EPOCH {\n        return Err(AuthReject::NotActivated);\n    }",
     "    let _ = epoch;"),

    ("M13", "chain_id dropped from the signing-root preimage", "root.rs",
     "    tx.encode_unsigned_into(&mut preimage)?;",
     "    {\n        let mut tmp = Vec::new();\n        tx.encode_unsigned_into(&mut tmp)?;\n        preimage.extend_from_slice(&tmp[8..]);\n    }"),

    ("M14", "sender dropped from the signing-root preimage", "root.rs",
     "    preimage.extend_from_slice(&tx.sender);\n",
     ""),

    ("M15", "DS_EVM_CALL dropped from the precompile message", "precompile.rs",
     "    let message = call_message(chain_id, &msg32);",
     "    let message = msg32;"),

    ("M16", "precompile gas charged only on success", "precompile.rs",
     "    let gas = PQ_VERIFY_BASE_GAS.saturating_add((input.len() as u64).saturating_mul(GAS_PER_BYTE));\n"
     "    let ok = decode_and_verify(input, chain_id, verifier).unwrap_or(false);",
     "    let ok = decode_and_verify(input, chain_id, verifier).unwrap_or(false);\n"
     "    let gas = if ok {\n"
     "        PQ_VERIFY_BASE_GAS.saturating_add((input.len() as u64).saturating_mul(GAS_PER_BYTE))\n"
     "    } else { 0 };"),
]

TEST_LINE = re.compile(r"^test (\S+) \.\.\. FAILED", re.M)


def run_suite():
    env = dict(os.environ)
    # Repo-root `target/mutants`: covered by the existing `/target` ignore, and
    # a separate lock from `target/`, so a mutation run never collides with a
    # workspace build. NEVER inside the crate — build artefacts under a source
    # directory end up staged.
    env.setdefault("CARGO_TARGET_DIR", str(CRATE.parent.parent / "target" / "mutants"))
    p = subprocess.run(
        ["cargo", "test", "-p", "bloch-l1-evm-auth", "--no-fail-fast"],
        cwd=CRATE, capture_output=True, text=True, env=env)
    return p.returncode, p.stdout + p.stderr


def main():
    if "--list" in sys.argv:
        for m in MUTANTS:
            print(f"{m[0]}  {m[1]}  ({m[2]})")
        return 0

    print(f"Baseline: the suite must be GREEN before anything is mutated.")
    code, out = run_suite()
    if code != 0:
        print("BASELINE IS RED. Fix that first; mutation proves nothing against a broken suite.")
        print(out[-4000:])
        return 2
    passed = sum(int(m.group(1)) for m in re.finditer(r"(\d+) passed", out))
    print(f"Baseline green: {passed} test results passed.\n")

    results = []
    for mid, label, fname, needle, repl in MUTANTS:
        path = SRC / fname
        original = path.read_text()
        if original.count(needle) != 1:
            results.append((mid, label, "UNAPPLIED", f"needle matched {original.count(needle)}x in {fname}"))
            print(f"{mid} {label}: UNAPPLIED (needle matched {original.count(needle)}x)")
            continue
        path.write_text(original.replace(needle, repl))
        try:
            code, out = run_suite()
        finally:
            path.write_text(original)
        if "error[E" in out or "error: could not compile" in out:
            results.append((mid, label, "BUILD_ERROR", "mutant does not compile"))
            print(f"{mid} {label}: BUILD ERROR")
            continue
        killers = TEST_LINE.findall(out)
        if code != 0 and killers:
            results.append((mid, label, "KILLED", ", ".join(sorted(set(killers)))))
            print(f"{mid} {label}: KILLED by {len(set(killers))} test(s)")
        else:
            results.append((mid, label, "SURVIVED", ""))
            print(f"{mid} {label}: *** SURVIVED ***")

    print("\n" + "=" * 78)
    survived = [r for r in results if r[2] != "KILLED"]
    for mid, label, status, detail in results:
        print(f"{mid:6} {status:12} {label}")
        if status == "KILLED":
            for t in detail.split(", "):
                print(f"       killed by: {t}")
        elif detail:
            print(f"       {detail}")
    print("=" * 78)
    if survived:
        print(f"{len(survived)} mutant(s) not killed. Each one is a missing test.")
        return 1
    print(f"All {len(results)} mutants killed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
