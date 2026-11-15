// SPDX-License-Identifier: AGPL-3.0-or-later

//! `--security-events <path>`: a bounded JSON-lines security event log.
//!
//! - One JSON object per line, schema `bloch-sentinel-event/1` (see
//!   docs/SENTINEL-HOOKS.md).
//! - Size-bounded: when the file would pass [`MAX_FILE_BYTES`] it is renamed
//!   to `<path>.1` (replacing the previous one) and a new file is started, so
//!   the log never takes more than twice that on disk.
//! - Rate-bounded per event type ([`PER_TYPE_PER_MINUTE`]); what is dropped
//!   is counted and reported by `getsecuritystatus`.
//! - Never blocks the caller: lines go through a bounded queue to one writer
//!   thread; a full queue drops the line and counts it.
//! - Carries no secrets by construction: callers pass classified reasons,
//!   public roots, addresses and counters, never key material, paths to key
//!   files, or raw error strings.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::rpc::Json;

pub(crate) const SCHEMA: &str = "bloch-sentinel-event/1";
pub(crate) const MAX_FILE_BYTES: u64 = 8 << 20;
pub(crate) const PER_TYPE_PER_MINUTE: u32 = 60;
const QUEUE_DEPTH: usize = 1024;

#[derive(Debug, Default)]
pub(crate) struct EventStats {
    pub(crate) emitted: AtomicU64,
    pub(crate) written: AtomicU64,
    pub(crate) dropped_rate: AtomicU64,
    pub(crate) dropped_queue: AtomicU64,
    pub(crate) write_errors: AtomicU64,
    pub(crate) rotations: AtomicU64,
}

/// The file half: append, rotate at a size bound. Synchronous; used by the
/// writer thread and directly by tests.
pub(crate) struct EventFile {
    path: PathBuf,
    file: File,
    size: u64,
    max_bytes: u64,
}

fn open_append(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

impl EventFile {
    pub(crate) fn open(path: &Path, max_bytes: u64) -> std::io::Result<Self> {
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if !meta.file_type().is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{} exists and is not a regular file", path.display()),
                ));
            }
        }
        let file = open_append(path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(EventFile { path: path.to_path_buf(), file, size, max_bytes: max_bytes.max(1024) })
    }

    fn rotated_path(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".1");
        PathBuf::from(p)
    }

    /// Append one line (a trailing newline is added). Rotates first when the
    /// line would push the file past its bound.
    pub(crate) fn write_line(&mut self, line: &str, stats: &EventStats) -> std::io::Result<()> {
        let len = line.len() as u64 + 1;
        if self.size > 0 && self.size.saturating_add(len) > self.max_bytes {
            self.file.flush()?;
            std::fs::rename(&self.path, self.rotated_path())?;
            self.file = open_append(&self.path)?;
            self.size = 0;
            stats.rotations.fetch_add(1, Ordering::Relaxed);
        }
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        self.file.write_all(&buf)?;
        self.size = self.size.saturating_add(len);
        Ok(())
    }
}

struct RateLimiter {
    windows: HashMap<&'static str, (Instant, u32)>,
}

impl RateLimiter {
    fn admit(&mut self, kind: &'static str, now: Instant) -> bool {
        let slot = self.windows.entry(kind).or_insert((now, 0));
        if now.saturating_duration_since(slot.0) >= Duration::from_secs(60) {
            *slot = (now, 0);
        }
        if slot.1 >= PER_TYPE_PER_MINUTE {
            return false;
        }
        slot.1 += 1;
        true
    }
}

/// The emitting half. Cheap to call from any thread, including the
/// consensus thread: formatting plus one `try_send`.
pub(crate) struct EventSink {
    tx: Option<SyncSender<String>>,
    pub(crate) stats: Arc<EventStats>,
    limiter: Mutex<RateLimiter>,
    seq: AtomicU64,
    /// Test sinks keep their lines here instead of writing a file.
    #[cfg(test)]
    pub(crate) captured: Mutex<Vec<String>>,
}

impl EventSink {
    /// Open `path` now (so a bad path stops the boot) and start the writer.
    pub(crate) fn start(path: &Path) -> std::io::Result<Self> {
        let mut file = EventFile::open(path, MAX_FILE_BYTES)?;
        let stats = Arc::new(EventStats::default());
        let (tx, rx) = mpsc::sync_channel::<String>(QUEUE_DEPTH);
        let writer_stats = stats.clone();
        std::thread::Builder::new().name("sentinel-events".into()).spawn(move || {
            for line in rx {
                match file.write_line(&line, &writer_stats) {
                    Ok(()) => writer_stats.written.fetch_add(1, Ordering::Relaxed),
                    Err(_) => writer_stats.write_errors.fetch_add(1, Ordering::Relaxed),
                };
            }
        })?;
        Ok(Self::with_sender(Some(tx), stats))
    }

    fn with_sender(tx: Option<SyncSender<String>>, stats: Arc<EventStats>) -> Self {
        EventSink {
            tx,
            stats,
            limiter: Mutex::new(RateLimiter { windows: HashMap::new() }),
            seq: AtomicU64::new(0),
            #[cfg(test)]
            captured: Mutex::new(Vec::new()),
        }
    }

    #[cfg(test)]
    pub(crate) fn capture() -> Self {
        Self::with_sender(None, Arc::new(EventStats::default()))
    }

    /// Emit one event of type `kind` with `fields`. Never blocks.
    pub(crate) fn emit(&self, kind: &'static str, fields: Vec<(&str, Json)>) {
        let now = Instant::now();
        let admitted = match self.limiter.lock() {
            Ok(mut l) => l.admit(kind, now),
            Err(p) => p.into_inner().admit(kind, now),
        };
        if !admitted {
            self.stats.dropped_rate.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let mut obj: Vec<(String, Json)> = vec![
            ("schema".into(), Json::s(SCHEMA)),
            ("seq".into(), Json::u(seq)),
            ("ts_ms".into(), Json::u(super::unix_ms())),
            ("type".into(), Json::s(kind)),
        ];
        obj.extend(fields.into_iter().map(|(k, v)| (k.to_string(), v)));
        let line = Json::Obj(obj).to_string();
        self.stats.emitted.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        if self.tx.is_none() {
            if let Ok(mut c) = self.captured.lock() {
                c.push(line);
            }
            return;
        }
        if let Some(tx) = &self.tx {
            match tx.try_send(line) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                    self.stats.dropped_queue.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    pub(crate) fn stats_json(&self) -> Json {
        let s = &self.stats;
        Json::obj(vec![
            ("enabled", Json::Bool(true)),
            ("emitted", Json::u(s.emitted.load(Ordering::Relaxed))),
            ("written", Json::u(s.written.load(Ordering::Relaxed))),
            ("dropped_rate_limited", Json::u(s.dropped_rate.load(Ordering::Relaxed))),
            ("dropped_queue_full", Json::u(s.dropped_queue.load(Ordering::Relaxed))),
            ("write_errors", Json::u(s.write_errors.load(Ordering::Relaxed))),
            ("rotations", Json::u(s.rotations.load(Ordering::Relaxed))),
            ("max_file_bytes", Json::u(MAX_FILE_BYTES)),
            ("per_type_per_minute", Json::u(u64::from(PER_TYPE_PER_MINUTE))),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bloch-sentinel-ev-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn file_rotates_and_stays_bounded() {
        let dir = scratch("rotate");
        let path = dir.join("events.jsonl");
        let stats = EventStats::default();
        let mut f = EventFile::open(&path, 1024).unwrap();
        let line = "x".repeat(100);
        for _ in 0..100 {
            f.write_line(&line, &stats).unwrap();
        }
        let main = std::fs::metadata(&path).unwrap().len();
        let rotated = std::fs::metadata(dir.join("events.jsonl.1")).unwrap().len();
        assert!(main <= 1024 && rotated <= 1024, "{main} {rotated}");
        assert!(stats.rotations.load(Ordering::Relaxed) >= 9);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_a_non_regular_path() {
        let dir = scratch("nonreg");
        assert!(EventFile::open(&dir, 1024).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn events_are_json_lines_and_rate_limited_per_type() {
        let sink = EventSink::capture();
        for _ in 0..(PER_TYPE_PER_MINUTE + 10) {
            sink.emit("ban_applied", vec![("range", Json::s("192.0.2.0/24"))]);
        }
        sink.emit("admin_command", vec![]);
        let lines = sink.captured.lock().unwrap().clone();
        assert_eq!(lines.len() as u32, PER_TYPE_PER_MINUTE + 1);
        assert_eq!(sink.stats.dropped_rate.load(Ordering::Relaxed), 10);
        let first = crate::rpc::parse_json(&lines[0]).unwrap();
        assert_eq!(first.get("schema").and_then(Json::as_str), Some(SCHEMA));
        assert_eq!(first.get("type").and_then(Json::as_str), Some("ban_applied"));
        assert!(first.get("ts_ms").and_then(Json::as_u64).is_some());
        assert!(lines.iter().all(|l| !l.contains('\n')));
    }

    #[test]
    fn the_writer_thread_appends_lines() {
        let dir = scratch("writer");
        let path = dir.join("ev.jsonl");
        let sink = EventSink::start(&path).unwrap();
        sink.emit("doppelganger_detected", vec![("validator", Json::u(3))]);
        let deadline = Instant::now() + Duration::from_secs(5);
        while sink.stats.written.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with('\n'));
        assert!(text.contains("\"doppelganger_detected\""));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
