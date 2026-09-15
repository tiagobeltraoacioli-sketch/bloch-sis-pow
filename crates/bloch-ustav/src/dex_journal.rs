//! Durable candidate replay for an explicitly enabled local DEX host.
//! No live block integration or authority to derive checkpoints from this log.
use crate::{BlochVerifier, Verifier};
use bloch_pos_committee::{
    transition::native_dex::{pool_batch, pool_candidate, State},
    SignatureVerifier,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

const MAGIC: &[u8; 8] = b"BLCHDJ01";
const HEADER_BYTES: u64 = 48; // magic, anchor height, anchor combined state root
pub const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RECORDS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    pub root: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailRecovery {
    Reject,
    DiscardIncomplete,
}
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Locked,
    InvalidFile,
    InvalidHeader,
    WrongAnchor,
    WrongHead,
    InvalidLength,
    ResourceLimit,
    NonIncreasingHeight,
    Poisoned,
    Incomplete { offset: u64 },
    Candidate(pool_candidate::Error),
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

struct BaseVerifier;
impl SignatureVerifier for BaseVerifier {
    fn verify_with_key(&self, key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        BlochVerifier.verify_pq(root, key, signature)
    }
}

/// Owns the exclusive file lock and the only mutable host state.
/// File paths/directories must be controlled by the operator, not RPC clients.
pub struct Journal {
    file: File,
    state: State,
    head: Checkpoint,
    length: u64,
    records: usize,
    poisoned: bool,
}
impl Journal {
    /// Create a new log from an independently authenticated anchor.
    pub fn create(path: &Path, state: State, height: u64) -> Result<Self, Error> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.try_lock().map_err(|_| Error::Locked)?;
        let head = Checkpoint {
            height,
            root: state.state_root(),
        };
        file.write_all(MAGIC)?;
        file.write_all(&height.to_le_bytes())?;
        file.write_all(&head.root)?;
        file.sync_all()?;
        // Persist creation of the directory entry as well as the file contents.
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent)?.sync_all()?;
        Ok(Self {
            file,
            state,
            head,
            length: HEADER_BYTES,
            records: 0,
            poisoned: false,
        })
    }

    /// Replay with real PQ verification and require an independently trusted tip.
    /// Recovery may discard only a physically incomplete final record, and only
    /// after the complete replayed prefix matches the trusted expected head.
    pub fn open(
        path: &Path,
        anchor: State,
        anchor_height: u64,
        expected_head: Checkpoint,
        recovery: TailRecovery,
    ) -> Result<Self, Error> {
        if !std::fs::symlink_metadata(path)?.file_type().is_file() {
            return Err(Error::InvalidFile);
        }
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        file.try_lock().map_err(|_| Error::Locked)?;
        let length = file.metadata()?.len();
        if length > MAX_JOURNAL_BYTES {
            return Err(Error::ResourceLimit);
        }
        if length < HEADER_BYTES {
            return Err(Error::InvalidHeader);
        }
        let mut header = [0; HEADER_BYTES as usize];
        file.read_exact(&mut header)?;
        if &header[..8] != MAGIC {
            return Err(Error::InvalidHeader);
        }
        if header[8..16] != anchor_height.to_le_bytes() || header[16..48] != anchor.state_root() {
            return Err(Error::WrongAnchor);
        }
        let mut journal = Self {
            file,
            head: Checkpoint {
                height: anchor_height,
                root: anchor.state_root(),
            },
            state: anchor,
            length: HEADER_BYTES,
            records: 0,
            poisoned: false,
        };
        let mut incomplete = false;
        while journal.length < length {
            if journal.records == MAX_RECORDS {
                return Err(Error::ResourceLimit);
            }
            let remaining = length - journal.length;
            if remaining < 4 {
                incomplete = true;
                break;
            }
            let mut encoded_length = [0; 4];
            journal.file.read_exact(&mut encoded_length)?;
            let count = u32::from_le_bytes(encoded_length) as usize;
            if count == 0 || count > pool_candidate::MAX_ENCODED_BYTES {
                return Err(Error::InvalidLength);
            }
            if count as u64 > remaining - 4 {
                incomplete = true;
                break;
            }
            let mut candidate = vec![0; count];
            journal.file.read_exact(&mut candidate)?;
            let height = candidate_height(&candidate)?;
            if height <= journal.head.height {
                return Err(Error::NonIncreasingHeight);
            }
            let result = pool_candidate::apply(
                &mut journal.state,
                &candidate,
                height,
                &BaseVerifier,
                &BlochVerifier,
            )
            .map_err(Error::Candidate)?;
            journal.head = Checkpoint {
                height,
                root: result.post_root,
            };
            journal.length += 4 + count as u64;
            journal.records += 1;
        }
        if incomplete && recovery == TailRecovery::Reject {
            return Err(Error::Incomplete {
                offset: journal.length,
            });
        }
        if journal.head != expected_head {
            return Err(Error::WrongHead);
        }
        if incomplete {
            journal.file.set_len(journal.length)?;
            journal.file.sync_all()?;
        }
        journal.file.seek(SeekFrom::Start(journal.length))?;
        Ok(journal)
    }

    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn checkpoint(&self) -> Checkpoint {
        self.head
    }

    /// The host supplies the authenticated candidate height. Successful return
    /// follows fsync; any write/fsync failure poisons this handle until reopen.
    pub fn append(&mut self, candidate: &[u8], height: u64) -> Result<pool_batch::Outcome, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if height <= self.head.height {
            return Err(Error::NonIncreasingHeight);
        }
        if candidate.len() > pool_candidate::MAX_ENCODED_BYTES || self.records == MAX_RECORDS {
            return Err(Error::ResourceLimit);
        }
        let next_length = self
            .length
            .checked_add(4 + candidate.len() as u64)
            .filter(|n| *n <= MAX_JOURNAL_BYTES)
            .ok_or(Error::ResourceLimit)?;
        let mut staged = self.state.clone();
        let result = pool_candidate::apply(
            &mut staged,
            candidate,
            height,
            &BaseVerifier,
            &BlochVerifier,
        )
        .map_err(Error::Candidate)?;
        persist_record(&mut self.file, candidate, &mut self.poisoned)?;
        self.state = staged;
        self.head = Checkpoint {
            height,
            root: result.post_root,
        };
        self.length = next_length;
        self.records += 1;
        Ok(result)
    }
}

// The candidate decoder rechecks magic, version, domain, context and all roots.
// The replayed final height/root must match the separately trusted checkpoint.
fn candidate_height(bytes: &[u8]) -> Result<u64, Error> {
    let value = bytes.get(74..82).ok_or(Error::InvalidLength)?;
    Ok(u64::from_le_bytes(
        value.try_into().map_err(|_| Error::InvalidLength)?,
    ))
}

trait Durable: Write {
    fn sync(&mut self) -> io::Result<()>;
}
impl Durable for File {
    fn sync(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}
fn persist_record(
    writer: &mut impl Durable,
    candidate: &[u8],
    poisoned: &mut bool,
) -> Result<(), Error> {
    if *poisoned {
        return Err(Error::Poisoned);
    }
    let write = (|| -> io::Result<()> {
        writer.write_all(&(candidate.len() as u32).to_le_bytes())?;
        writer.write_all(candidate)?;
        writer.sync()
    })();
    if let Err(error) = write {
        *poisoned = true;
        return Err(Error::Io(error));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct FaultyWriter {
        bytes: Vec<u8>,
        remaining: usize,
        fail_sync: bool,
    }
    impl Write for FaultyWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::other("injected write failure"));
            }
            let count = bytes.len().min(self.remaining);
            self.bytes.extend_from_slice(&bytes[..count]);
            self.remaining -= count;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Durable for FaultyWriter {
        fn sync(&mut self) -> io::Result<()> {
            if self.fail_sync {
                Err(io::Error::other("injected sync failure"))
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn every_partial_write_failure_poisons_and_prevents_further_appends() {
        let payload = [42; 16];
        for remaining in 0..20 {
            let mut writer = FaultyWriter {
                bytes: vec![],
                remaining,
                fail_sync: false,
            };
            let mut poisoned = false;
            assert!(matches!(
                persist_record(&mut writer, &payload, &mut poisoned),
                Err(Error::Io(_))
            ));
            assert!(poisoned);
            let before = writer.bytes.clone();
            writer.remaining = 100;
            assert!(matches!(
                persist_record(&mut writer, &payload, &mut poisoned),
                Err(Error::Poisoned)
            ));
            assert_eq!(writer.bytes, before);
        }
    }
    #[test]
    fn complete_write_followed_by_sync_failure_remains_unconfirmed_and_poisoned() {
        let mut writer = FaultyWriter {
            bytes: vec![],
            remaining: 100,
            fail_sync: true,
        };
        let mut poisoned = false;
        assert!(matches!(
            persist_record(&mut writer, &[7; 8], &mut poisoned),
            Err(Error::Io(_))
        ));
        assert_eq!(writer.bytes.len(), 12);
        assert!(poisoned);
    }
    #[test]
    fn durable_record_has_exact_length_prefix_and_payload() {
        let mut writer = FaultyWriter {
            bytes: vec![],
            remaining: 100,
            fail_sync: false,
        };
        let mut poisoned = false;
        persist_record(&mut writer, &[1, 2, 3], &mut poisoned).unwrap();
        assert_eq!(writer.bytes, [3, 0, 0, 0, 1, 2, 3]);
        assert!(!poisoned);
    }
}
