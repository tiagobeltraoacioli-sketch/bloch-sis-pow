// SPDX-License-Identifier: AGPL-3.0-or-later
//! Decode the operational reservation through the real signing-protection code.

#[allow(dead_code)]
#[path = "../src/slashprot.rs"]
mod slashprot;

// The journal module uses this only to abbreviate public digests in errors.
mod codec {
    pub fn hex8(bytes: &[u8; 32]) -> String {
        bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[test]
fn legacy_reservation_survives_restart_and_blocks_old_or_surrounding_duties() {
    use slashprot::{Binding, Refusal, SlashingProtection};
    use std::{fs, process::Command};

    assert_eq!(bloch_pos_committee::params::SLOTS_PER_EPOCH, 32);
    let dir = std::env::temp_dir().join(format!("bloch-recovery-fence-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let meta = dir.join("meta.bin");
    let mut bytes = b"BPOSMETA".to_vec();
    bytes.extend_from_slice(&bloch_pos_committee::header::VERSION_G4.to_le_bytes());
    bytes.extend_from_slice(&[2; 32]);
    fs::write(&meta, bytes).unwrap();
    let journal = dir.join(slashprot::FILE_NAME);
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/prepare-validator-recovery-fence.py");
    let run = || {
        Command::new("python3")
            .arg(&script)
            .arg("--meta")
            .arg(&meta)
            .arg("--pubkey-hash")
            .arg("01".repeat(32))
            .arg("--through-slot")
            .arg("320")
            .arg("--output")
            .arg(&journal)
            .output()
            .unwrap()
    };
    let prepared = run();
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let original = fs::read(&journal).unwrap();
    let invalid_output = dir.join("invalid.bin");
    for slot in ["0", "-1", "18446744073709551615"] {
        let rejected = Command::new("python3")
            .arg(&script)
            .arg("--meta")
            .arg(&meta)
            .arg("--pubkey-hash")
            .arg("01".repeat(32))
            .arg("--through-slot")
            .arg(slot)
            .arg("--output")
            .arg(&invalid_output)
            .output()
            .unwrap();
        assert!(!rejected.status.success());
        assert!(
            !invalid_output.exists(),
            "invalid fence must not create a journal"
        );
    }
    let valid_meta = fs::read(&meta).unwrap();
    fs::write(&meta, [0; 44]).unwrap();
    let rejected = Command::new("python3")
        .arg(&script)
        .arg("--meta")
        .arg(&meta)
        .arg("--pubkey-hash")
        .arg("01".repeat(32))
        .arg("--through-slot")
        .arg("320")
        .arg("--output")
        .arg(&invalid_output)
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "invalid network metadata must be refused"
    );
    assert!(!invalid_output.exists());
    fs::write(&meta, valid_meta).unwrap();
    assert!(
        !run().status.success(),
        "an existing journal must never be replaced"
    );
    assert_eq!(fs::read(&journal).unwrap(), original);
    let binding = Binding {
        validator_pubkey_sha3: [1; 32],
        genesis_digest: [2; 32],
    };
    let mut protection = SlashingProtection::open_bound(&dir, binding).unwrap();
    assert!(matches!(
        protection.guard_proposal(320, || panic!("signed old proposal")),
        Err(Refusal::Proposal { .. })
    ));
    assert!(matches!(
        protection.guard_attestation(320, 10, 11, || panic!("signed old slot")),
        Err(Refusal::AttestationSlot { .. })
    ));
    assert!(matches!(
        protection.guard_attestation(352, 10, 10, || panic!("double vote")),
        Err(Refusal::DoubleVote { .. })
    ));
    assert!(matches!(
        protection.guard_attestation(352, 9, 11, || panic!("surround vote")),
        Err(Refusal::SurroundVote { .. })
    ));
    drop(protection);
    let mut reopened = SlashingProtection::open_bound(&dir, binding).unwrap();
    assert_eq!(reopened.watermarks().proposal_slot, Some(320));
    assert_eq!(reopened.watermarks().source_epoch, Some(10));
    reopened.guard_proposal(352, || ()).unwrap();
    reopened.guard_attestation(352, 10, 11, || ()).unwrap();
    drop(reopened);
    let wrong = Binding {
        validator_pubkey_sha3: [3; 32],
        ..binding
    };
    assert!(SlashingProtection::open_bound(&dir, wrong).is_err());
    let other_network = Binding {
        genesis_digest: [4; 32],
        ..binding
    };
    assert!(SlashingProtection::open_bound(&dir, other_network).is_err());
    let reopened = SlashingProtection::open_bound(&dir, binding).unwrap();
    assert_eq!(reopened.watermarks().target_epoch, Some(11));
    drop(reopened);
    fs::remove_dir_all(dir).unwrap();
}
