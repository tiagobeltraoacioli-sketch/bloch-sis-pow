#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Source patches for DISPOSABLE rehearsal copies. Never a checkout."""
import sys
from pathlib import Path

def sub(path, old, new):
    t = path.read_text()
    if t.count(old) != 1:
        sys.exit(f"patch: anchor not found once in {path}: {old[:50]!r}")
    path.write_text(t.replace(old, new))

mode, root = sys.argv[1], Path(sys.argv[2])
if (root / ".git").exists():
    sys.exit("refusing a git tree")
node = root / "crates/bloch-pos-node/src"
if mode == "tooling":
    sub(node / "main.rs", "mod devnet_tools;\n", "mod devnet_tools;\nmod gate_probe;\n")
    sub(node / "main.rs", '        Some("devnet-equivocate") => {\n',
        '        Some("gate-probe") => {\n            if let Err(error) = gate_probe::main(&args[1..]) {\n'
        '                eprintln!("gate-probe: {error}");\n                exit(2);\n            }\n        }\n'
        '        Some("devnet-equivocate") => {\n')
    sub(node / "net.rs", "pub fn send_block(addr: &str, env: &BlockEnvelope) -> std::io::Result<()> {\n",
        "pub fn send_attestation(addr: &str, att: &Attestation) -> std::io::Result<()> {\n"
        "    let mut sock = TcpStream::connect(addr)?;\n    write_frame(&mut sock, &att_frame(att))\n}\n\n"
        "pub fn send_block(addr: &str, env: &BlockEnvelope) -> std::io::Result<()> {\n")
elif mode == "pin-fault":
    # FAULT INJECTION: under the CompatiblePinned policy only (the consensus
    # route of the pin gate), refuse signatures whose ML-DSA half starts with
    # the marker byte. The relay policy calls verify_pinned directly and is not
    # touched, so a marked transaction still reaches blocks. It gives the pin
    # gate an observable effect on a private net. Nothing else changes.
    sub(root / "crates/bloch-crypto/src/crypto/mod.rs",
        "        SignaturePolicy::CompatiblePinned => verify_pinned(public_key_bytes, message, signature_bytes),",
        "        SignaturePolicy::CompatiblePinned => signature_bytes.get(4) != Some(&0xA5) && verify_pinned(public_key_bytes, message, signature_bytes),")
else:
    sys.exit("unknown mode")
