use super::DOMAIN;
use bloch_pos_committee::transition::{
    native_dex::{self, pool_batch, pool_candidate, pool_wire, State},
    PosTransaction,
};
use bloch_ustav::{
    dex_admission::{Error, PendingBatch},
    dex_journal::{Journal, TailRecovery},
};
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) fn check(anchor: &State, frames: &[&[u8]], final_state: &State) {
    let directory = std::env::temp_dir().join(format!(
        "bloch-admission-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&directory).unwrap();
    let path = directory.join("candidates.log");
    let mut journal = Journal::create(&path, anchor.clone(), 3).unwrap();
    let parent = journal.checkpoint();
    let initial_file = fs::read(&path).unwrap();
    assert!(PendingBatch::new(&journal, 3).is_err());
    let mut pending = PendingBatch::new(&journal, 4).unwrap();
    assert!(pending.is_empty());
    assert!(pending.build(&journal, 4).is_err());
    assert!(matches!(
        pending.admit(&journal, &vec![0; pool_batch::MAX_BYTES as usize + 1], 4),
        Err(Error::ResourceLimit)
    ));
    assert!(pending.admit(&journal, frames[1], 4).is_err()); // depends on the first add
    let mut forged = pool_wire::decode(frames[0], &DOMAIN).unwrap();
    if let pool_wire::Request::Add(r) = &mut forged {
        if let PosTransaction::TransferV2 { keys, .. } = &mut r.blch {
            keys[0].signature[0] ^= 1;
        }
    }
    assert!(pending
        .admit(&journal, &pool_wire::encode(&forged, &DOMAIN).unwrap(), 4)
        .is_err());
    let mut wrong_domain = frames[0].to_vec();
    wrong_domain[10] ^= 1;
    assert!(pending.admit(&journal, &wrong_domain, 4).is_err());
    let mut expired = PendingBatch::new(&journal, 101).unwrap();
    assert!(expired.admit(&journal, frames[0], 101).is_err());
    assert!(expired.is_empty());
    assert!(pending.is_empty());
    assert_eq!(pending.wire_bytes(), 0);
    assert_eq!(journal.checkpoint(), parent);
    assert_eq!(fs::read(&path).unwrap(), initial_file);

    pending
        .admit_from_reader(
            &journal,
            &mut std::io::Cursor::new(frames[0]),
            Some(frames[0].len() as u64),
            4,
        )
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending.wire_bytes(), frames[0].len() as u64);
    assert!(matches!(
        pending.admit(&journal, frames[0], 4),
        Err(Error::Duplicate)
    ));
    let first_candidate = pending.build(&journal, 4).unwrap();
    assert!(matches!(
        pending.admit_from_reader(&journal, &mut NoBody, Some(pool_batch::MAX_BYTES), 4),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        pending.admit_from_reader(
            &journal,
            &mut std::io::Cursor::new(&frames[1][..20]),
            Some(frames[1].len() as u64),
            4
        ),
        Err(Error::LengthMismatch)
    ));
    let mut broken = BrokenBody { first: true };
    assert!(matches!(
        pending.admit_from_reader(&journal, &mut broken, None, 4),
        Err(Error::Io(_))
    ));
    assert_eq!(pending.len(), 1);
    assert_eq!(pending.wire_bytes(), frames[0].len() as u64);
    assert_eq!(journal.checkpoint(), parent);
    assert_eq!(fs::read(&path).unwrap(), initial_file);
    assert_eq!(pending.build(&journal, 4).unwrap(), first_candidate);

    assert!(pending.admit(&journal, &frames[1][..20], 4).is_err());
    assert_eq!(pending.len(), 1);
    assert_eq!(pending.build(&journal, 4).unwrap(), first_candidate);
    pending
        .admit_from_reader(&journal, &mut std::io::Cursor::new(frames[1]), None, 4)
        .unwrap();
    let two_candidate = pending.build(&journal, 4).unwrap();
    let mut forged = pool_wire::decode(frames[2], &DOMAIN).unwrap();
    if let pool_wire::Request::Remove(r) = &mut forged {
        r.native.witnesses.owners[0][0] ^= 1;
    }
    assert!(matches!(
        pending.admit(&journal, &pool_wire::encode(&forged, &DOMAIN).unwrap(), 4),
        Err(Error::Batch(pool_batch::Error::Operation { index: 2, .. }))
    ));
    assert_eq!(pending.len(), 2);
    assert_eq!(pending.build(&journal, 4).unwrap(), two_candidate);
    let preview = pending
        .admit_from_reader(
            &journal,
            &mut std::io::Cursor::new(frames[2]),
            Some(frames[2].len() as u64),
            4,
        )
        .unwrap();
    assert_eq!(preview.post_root, final_state.state_root());
    assert_eq!(pending.len(), 3);
    assert_eq!(
        pending.wire_bytes(),
        frames.iter().map(|f| f.len() as u64).sum::<u64>()
    );
    assert_eq!(journal.checkpoint(), parent);
    assert_eq!(journal.state().fee_escrow(), anchor.fee_escrow());
    assert_eq!(fs::read(&path).unwrap(), initial_file);

    // Editing a local prefix must preserve dependency order and exact accounting.
    let mut editable = PendingBatch::new(&journal, 4).unwrap();
    for frame in frames {
        editable.admit(&journal, frame, 4).unwrap();
    }
    let full_candidate = editable.build(&journal, 4).unwrap();
    let full_bytes = editable.wire_bytes();
    assert!(matches!(
        editable.retain_prefix(&journal, usize::MAX, 4),
        Err(Error::InvalidPrefix)
    ));
    assert_eq!(editable.wire_bytes(), full_bytes);
    assert_eq!(editable.build(&journal, 4).unwrap(), full_candidate);
    editable.retain_prefix(&journal, frames.len(), 4).unwrap();
    assert_eq!(editable.build(&journal, 4).unwrap(), full_candidate);
    editable.retain_prefix(&journal, 1, 4).unwrap();
    assert_eq!(editable.wire_bytes(), frames[0].len() as u64);
    assert_eq!(editable.build(&journal, 4).unwrap(), first_candidate);
    // The removed redemption cannot skip its removed dependency.
    assert!(editable.admit(&journal, frames[2], 4).is_err());
    assert_eq!(editable.len(), 1);
    for frame in &frames[1..] {
        editable.admit(&journal, frame, 4).unwrap();
    }
    assert_eq!(editable.build(&journal, 4).unwrap(), full_candidate);
    editable.retain_prefix(&journal, 0, 6).unwrap();
    assert!(editable.is_empty());
    assert_eq!(editable.wire_bytes(), 0);
    assert_eq!(editable.height(), 6);
    assert!(!editable.is_closed());
    assert!(matches!(
        editable.retain_prefix(&journal, 0, 5),
        Err(Error::HeightRegression)
    ));
    assert!(editable.build(&journal, 6).is_err());
    editable.admit(&journal, frames[0], 6).unwrap();
    assert!(matches!(
        editable.retain_prefix(&journal, 2, 7),
        Err(Error::InvalidPrefix)
    ));
    assert_eq!(editable.height(), 7);
    assert_eq!(editable.len(), 1);
    assert_eq!(journal.checkpoint(), parent);
    assert_eq!(fs::read(&path).unwrap(), initial_file);

    // Neither an equal-height foreign root nor an equal-root foreign height fits.
    let other_path = directory.join("other.log");
    let other = Journal::create(&other_path, final_state.clone(), 3).unwrap();
    assert!(matches!(pending.build(&other, 4), Err(Error::StaleParent)));
    assert!(matches!(
        editable.retain_prefix(&other, 0, 7),
        Err(Error::StaleParent)
    ));
    assert_eq!(editable.len(), 1);
    drop(other);
    fs::remove_file(&other_path).unwrap();
    let other = Journal::create(&other_path, anchor.clone(), 2).unwrap();
    assert!(matches!(pending.build(&other, 4), Err(Error::StaleParent)));
    drop(other);
    fs::remove_file(&other_path).unwrap();
    // Previously admitted signatures must not be checked at the old height.
    let mut timed_out = PendingBatch::new(&journal, 4).unwrap();
    for frame in frames {
        timed_out.admit(&journal, frame, 4).unwrap();
    }
    assert!(matches!(
        timed_out.commit(&mut journal, 101),
        Err(Error::Candidate(pool_candidate::Error::Batch(
            pool_batch::Error::Operation {
                index: 0,
                source: pool_wire::Error::Joint(native_dex::Error::Native(
                    bloch_euvm::ustav::gateway::pools::Error::Amm(
                        bloch_euvm::ustav::amm::Error::Expired
                    )
                )),
            }
        )))
    ));
    assert_eq!(timed_out.len(), frames.len());
    assert_eq!(timed_out.height(), 101);
    assert!(!timed_out.is_closed());
    assert!(matches!(
        timed_out.commit(&mut journal, 4),
        Err(Error::HeightRegression)
    ));
    assert!(matches!(
        timed_out.build(&journal, 100),
        Err(Error::HeightRegression)
    ));
    assert!(matches!(
        timed_out.admit(&journal, frames[0], 4),
        Err(Error::HeightRegression)
    ));
    assert_eq!(journal.checkpoint(), parent);
    assert_eq!(fs::read(&path).unwrap(), initial_file);
    timed_out.retain_prefix(&journal, 0, 101).unwrap();
    assert!(timed_out.is_empty());
    assert_eq!(timed_out.wire_bytes(), 0);
    assert!(matches!(
        timed_out.admit(&journal, frames[0], 4),
        Err(Error::HeightRegression)
    ));
    assert!(timed_out.admit(&journal, frames[0], 101).is_err());
    assert!(timed_out.is_empty());
    // A malformed operation cannot roll back the last trusted host height either.
    let mut failed_input = PendingBatch::new(&journal, 4).unwrap();
    failed_input.admit(&journal, frames[0], 4).unwrap();
    assert!(failed_input.admit(&journal, &[], 6).is_err());
    assert_eq!(failed_input.height(), 6);
    assert_eq!(failed_input.len(), 1);
    assert!(matches!(
        failed_input.build(&journal, 5),
        Err(Error::HeightRegression)
    ));
    failed_input.build(&journal, 6).unwrap();
    // An unexpired delayed batch must execute using the new height.
    pending.build(&journal, 5).unwrap();
    assert_eq!(pending.height(), 5);
    let mut competing = PendingBatch::new(&journal, 4).unwrap();
    competing.admit(&journal, frames[0], 4).unwrap();
    let committed = pending.commit(&mut journal, 5).unwrap();
    assert_eq!(committed.height, 5);
    assert_eq!(journal.checkpoint().height, 5);
    assert_eq!(committed.post_root, preview.post_root);
    assert_eq!(committed.charge, preview.charge);
    assert_eq!(journal.state().base(), final_state.base());
    assert_eq!(
        journal.state().native().snapshot(),
        final_state.native().snapshot()
    );
    assert_eq!(journal.state().fee_escrow(), final_state.fee_escrow());
    assert!(pending.is_closed());
    assert!(pending.is_empty());
    assert_eq!(pending.wire_bytes(), 0);
    let durable = fs::read(&path).unwrap();
    assert!(matches!(
        pending.retain_prefix(&journal, 0, 5),
        Err(Error::Closed)
    ));
    assert!(matches!(
        competing.retain_prefix(&journal, 0, 5),
        Err(Error::StaleParent)
    ));
    assert_eq!(competing.len(), 1);
    assert!(durable.len() > initial_file.len());
    assert!(matches!(
        pending.commit(&mut journal, 4),
        Err(Error::Closed)
    ));
    assert!(matches!(
        pending.admit(&journal, frames[0], 4),
        Err(Error::Closed)
    ));
    assert!(matches!(
        competing.commit(&mut journal, 4),
        Err(Error::StaleParent)
    ));
    assert_eq!(competing.len(), 1);
    assert_eq!(fs::read(&path).unwrap(), durable);
    assert!(matches!(
        pending.admit_from_reader(&journal, &mut NoBody, None, 5),
        Err(Error::Closed)
    ));
    assert!(matches!(
        competing.admit_from_reader(&journal, &mut NoBody, None, 5),
        Err(Error::StaleParent)
    ));
    let tip = journal.checkpoint();
    drop(journal);
    let reopened = Journal::open(&path, anchor.clone(), 3, tip, TailRecovery::Reject).unwrap();
    assert_eq!(reopened.state().state_root(), final_state.state_root());
    drop(reopened);
    fs::remove_file(&path).unwrap();
    fs::remove_dir(&directory).unwrap();
}

struct NoBody;
impl std::io::Read for NoBody {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        panic!("rejected request must not read its body")
    }
}
struct BrokenBody {
    first: bool,
}
impl std::io::Read for BrokenBody {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.first {
            self.first = false;
            out[0] = 7;
            Ok(1)
        } else {
            Err(std::io::ErrorKind::TimedOut.into())
        }
    }
}
