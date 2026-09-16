//! Optional derived sidecar, validated only against fully replayed canonical
//! state. The block log remains authoritative; this is not fast-sync, native
//! bootstrap, finality authentication or a substitute for base-state replay.
use super::Store;
use bloch_pos_committee::transition::native_dex::snapshot_wire::MAX_SNAPSHOT_BYTES;
use bloch_pos_committee::{interfaces::StateReader, transition::CommittedState, SignatureVerifier};
use sha3::{Digest, Sha3_256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

const MAGIC: &[u8; 8] = b"BPOSNAT1";
const HEADER_BYTES: usize = 8 + 4 + 32 + 32 + 32 + 8 + 4 + 32;
const FILE_NAME: &str = "native-component.bin";
static SERIAL: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Binding {
    genesis: [u8; 32],
    head: [u8; 32],
    root: [u8; 32],
    slot: u64,
}
impl Binding {
    fn from_state(genesis: [u8; 32], state: &CommittedState) -> Self {
        Self {
            genesis,
            head: *state.head().as_bytes(),
            root: state.state_root(),
            slot: state.slot(),
        }
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn digest(header: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(b"BLOCH-NATIVE-SIDECAR-v1");
    hash.update(header);
    hash.update(payload);
    hash.finalize().into()
}
fn write_record(dir: &Path, binding: Binding, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_SNAPSHOT_BYTES {
        return Err(invalid("native snapshot exceeds limit"));
    }
    let mut header = Vec::with_capacity(HEADER_BYTES);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&1u32.to_le_bytes());
    header.extend_from_slice(&binding.genesis);
    header.extend_from_slice(&binding.head);
    header.extend_from_slice(&binding.root);
    header.extend_from_slice(&binding.slot.to_le_bytes());
    header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    let checksum = digest(&header, payload);
    header.extend_from_slice(&checksum);
    let path = dir.join(format!(
        ".native-component.{}.{}.tmp",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(&path)?;
    let outcome = (|| {
        file.write_all(&header)?;
        file.write_all(payload)?;
        file.sync_all()?;
        fs::rename(&path, dir.join(FILE_NAME))?;
        #[cfg(unix)]
        File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(&path);
    }
    outcome
}
fn read_record(dir: &Path) -> io::Result<Option<(Binding, Vec<u8>)>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let mut file = match options.open(dir.join(FILE_NAME)) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() < HEADER_BYTES as u64
        || metadata.len() > (HEADER_BYTES + MAX_SNAPSHOT_BYTES) as u64
    {
        return Err(invalid("invalid native snapshot file size/type"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(invalid("native snapshot has multiple links"));
        }
    }
    let mut header = [0u8; HEADER_BYTES];
    file.read_exact(&mut header)?;
    if &header[..8] != MAGIC || header[8..12] != 1u32.to_le_bytes() {
        return Err(invalid("native snapshot schema mismatch"));
    }
    let binding = Binding {
        genesis: header[12..44]
            .try_into()
            .map_err(|_| invalid("native genesis"))?,
        head: header[44..76]
            .try_into()
            .map_err(|_| invalid("native head"))?,
        root: header[76..108]
            .try_into()
            .map_err(|_| invalid("native root"))?,
        slot: u64::from_le_bytes(
            header[108..116]
                .try_into()
                .map_err(|_| invalid("native slot"))?,
        ),
    };
    let len = u32::from_le_bytes(
        header[116..120]
            .try_into()
            .map_err(|_| invalid("native length"))?,
    ) as usize;
    if len > MAX_SNAPSHOT_BYTES || metadata.len() != (HEADER_BYTES + len) as u64 {
        return Err(invalid("native snapshot length mismatch"));
    }
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(len)
        .map_err(|_| invalid("native snapshot allocation limit"))?;
    file.take((len as u64) + 1).read_to_end(&mut payload)?;
    if payload.len() != len || digest(&header[..120], &payload) != header[120..152] {
        return Err(invalid("native snapshot checksum mismatch"));
    }
    Ok(Some((binding, payload)))
}

impl Store {
    /// Call only after the corresponding block log append/rewrite is durable.
    /// The existing Store owns the exclusive directory lock for this write.
    pub fn save_native_component(&self, state: &CommittedState) -> io::Result<()> {
        let payload = state
            .native_component_snapshot_bytes()
            .map_err(|e| invalid(&format!("native snapshot encode: {e:?}")))?;
        write_record(
            &self.dir,
            Binding::from_state(self.genesis_digest, state),
            payload.as_deref().unwrap_or(&[]),
        )
    }

    /// Validate against complete replay before restoring anything. A stale
    /// checkpoint is an ordinary cache miss (log fsync precedes sidecar fsync).
    /// Invalid same-head data is an error; it cannot supply a new trusted root.
    pub fn restore_native_component(
        &self,
        replayed: &CommittedState,
        verifier: &dyn SignatureVerifier,
    ) -> io::Result<Option<CommittedState>> {
        let Some((binding, payload)) = read_record(&self.dir)? else {
            return Ok(None);
        };
        let expected = Binding::from_state(self.genesis_digest, replayed);
        if binding.genesis != expected.genesis {
            return Err(invalid("native snapshot belongs to another genesis"));
        }
        if binding.head != expected.head {
            return Ok(None);
        }
        if binding.slot != expected.slot {
            return Err(invalid("native snapshot contradicts replayed head slot"));
        }
        if binding.root != expected.root {
            return Err(invalid("native snapshot contradicts replayed state root"));
        }
        if payload.is_empty() {
            if replayed
                .native_component_snapshot_bytes()
                .map_err(|_| invalid("native replay export failed"))?
                .is_some()
            {
                return Err(invalid("native snapshot lost its component"));
            }
            return Ok(None);
        }
        replayed
            .with_restored_native_component(&payload, verifier)
            .map(Some)
            .map_err(|e| invalid(&format!("native snapshot restore: {e:?}")))
    }
}

#[cfg(test)]
#[path = "native_snapshot_tests.rs"]
mod tests;
