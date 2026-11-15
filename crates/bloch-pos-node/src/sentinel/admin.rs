// SPDX-License-Identifier: AGPL-3.0-or-later

//! `--admin-socket <path>`: the Sentinel's only write surface.
//!
//! A unix stream socket, mode 0600, owned by the node's user, speaking
//! line-delimited JSON. Exactly three commands exist and nothing else is
//! reachable through it — no restart, no reject-root, no key operation:
//!
//! ```text
//! {"cmd":"peer.ban","addr":"192.0.2.7","ttl_secs":600,"reason":"flood"}
//! {"cmd":"peer.ban","cidr":"192.0.2.0/24","ttl_secs":600,"reason":"flood"}
//! {"cmd":"peer.unban","cidr":"192.0.2.0/24"}
//! {"cmd":"peer.bans"}
//! ```
//!
//! Every answer is one JSON line with `"ok": true|false`. Every command,
//! accepted or refused, is logged and emitted as an `admin_command` event.
//! All bounds live in [`super::bans`].
//!
//! The socket refuses to be created in a world- or group-writable directory, or over
//! an existing path that is not a socket, and a connecting process whose uid
//! is not the node's (or root's) is answered with nothing and closed.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::cidr::Cidr;
use super::Sentinel;
use crate::rpc::Json;

const MAX_LINE_BYTES: usize = 4096;
const MAX_COMMANDS_PER_CONNECTION: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_LIFETIME: Duration = Duration::from_secs(30);

pub(crate) const COMMANDS: &[&str] = &["peer.ban", "peer.unban", "peer.bans"];

/// Check `path` is a safe place for the socket, removing a stale socket we
/// own. Separate from [`bind`] so the refusals are testable.
pub(crate) fn check_path(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    let shown = path.display();
    if path.as_os_str().is_empty() {
        return Err("--admin-socket: empty path".into());
    }
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    let dir = std::fs::metadata(&parent)
        .map_err(|e| format!("--admin-socket {shown}: its directory {} is not usable: {e}", parent.display()))?;
    if !dir.is_dir() {
        return Err(format!("--admin-socket {shown}: {} is not a directory", parent.display()));
    }
    let dir_mode = dir.permissions().mode();
    if dir_mode & 0o002 != 0 {
        return Err(format!(
            "--admin-socket {shown}: refusing a world-writable directory ({}); use a directory only the node user can write",
            parent.display()
        ));
    }
    // Review R-05: whoever can write the directory can replace the socket.
    if dir_mode & 0o020 != 0 {
        return Err(format!(
            "--admin-socket {shown}: refusing a group-writable directory ({}); use a directory only the node user can write",
            parent.display()
        ));
    }
    let me = unsafe { libc::geteuid() };
    if dir.uid() != me && dir.uid() != 0 {
        return Err(format!(
            "--admin-socket {shown}: directory {} is owned by uid {}, not by the node user ({me}) or root",
            parent.display(),
            dir.uid()
        ));
    }
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("--admin-socket {shown}: {e}")),
        Ok(meta) if meta.file_type().is_socket() => {
            if meta.uid() != me {
                return Err(format!("--admin-socket {shown}: an existing socket there belongs to uid {}", meta.uid()));
            }
            // A socket of ours left by a previous run: nobody is listening on
            // it (the data-dir lock guarantees one node per data dir, and a
            // live listener would answer a connect).
            if UnixStream::connect(path).is_ok() {
                return Err(format!("--admin-socket {shown}: another process is listening on it"));
            }
            std::fs::remove_file(path).map_err(|e| format!("--admin-socket {shown}: cannot remove stale socket: {e}"))
        }
        Ok(_) => Err(format!("--admin-socket {shown}: path exists and is not a socket; refusing to replace it")),
    }
}

/// Create the socket and make it 0600, then verify.
///
/// No `umask` here: it is process-wide, and narrowing it even briefly would
/// leak into whatever another thread creates meanwhile. Between `bind` and
/// `chmod` the socket has the process's ordinary creation mode; that window
/// is covered twice over: [`check_path`] has already refused a directory
/// anyone else can write, and [`serve`] refuses every client whose uid is
/// not the node's or root's, whatever the file mode says.
pub(crate) fn bind(path: &Path) -> Result<UnixListener, String> {
    use std::os::unix::fs::PermissionsExt;
    check_path(path)?;
    let bound = UnixListener::bind(path);
    let listener = bound.map_err(|e| format!("--admin-socket {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("--admin-socket {}: chmod 0600: {e}", path.display()))?;
    let mode = std::fs::metadata(path).map_err(|e| format!("--admin-socket {}: {e}", path.display()))?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!("--admin-socket {}: mode {:o} is not owner-only", path.display(), mode & 0o777));
    }
    Ok(listener)
}

/// The uid of the process on the other end, where the platform says.
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len)
        };
        if rc == 0 { Some(cred.uid) } else { None }
    }
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if rc == 0 { Some(uid) } else { None }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        let _ = fd;
        None
    }
}

/// Accept loop. One connection at a time, each bounded in lines, bytes and
/// lifetime, so a stuck client cannot hold the socket for long and nothing
/// here can grow.
pub(crate) fn serve(listener: UnixListener, sentinel: Arc<Sentinel>) {
    let me = unsafe { libc::geteuid() };
    for conn in listener.incoming() {
        let Ok(stream) = conn else {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        };
        match peer_uid(&stream) {
            Some(uid) if uid == me || uid == 0 => {}
            other => {
                eprintln!("sentinel: admin socket connection from uid {other:?} refused");
                continue;
            }
        }
        handle_connection(stream, &sentinel);
    }
}

/// Read one `\n`-terminated line into `pending`, never past `deadline`.
/// `Ok(Some(line))` (without the newline), `Ok(None)` when the line is
/// longer than [`MAX_LINE_BYTES`], `Err` on EOF, timeout or I/O error.
///
/// Review R-05: every `read` gets the time that is LEFT, so a client that
/// trickles a byte at a time cannot stretch a connection past its lifetime.
fn read_line_until(stream: &mut UnixStream, pending: &mut Vec<u8>, deadline: Instant) -> std::io::Result<Option<Vec<u8>>> {
    loop {
        if let Some(at) = pending.iter().position(|b| *b == b'\n') {
            let mut line: Vec<u8> = pending.drain(..=at).collect();
            line.pop();
            return Ok(if line.len() > MAX_LINE_BYTES { None } else { Some(line) });
        }
        if pending.len() > MAX_LINE_BYTES {
            return Ok(None);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        stream.set_read_timeout(Some(left.min(IO_TIMEOUT)))?;
        let mut buf = [0u8; 1024];
        match stream.read(&mut buf)? {
            0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            n => pending.extend_from_slice(buf.get(..n).unwrap_or(&[])),
        }
    }
}

fn handle_connection(stream: UnixStream, sentinel: &Sentinel) {
    handle_connection_within(stream, sentinel, CONNECTION_LIFETIME)
}

pub(crate) fn handle_connection_within(mut stream: UnixStream, sentinel: &Sentinel, lifetime: Duration) {
    let deadline = Instant::now() + lifetime;
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let mut pending = Vec::new();
    for _ in 0..MAX_COMMANDS_PER_CONNECTION {
        let (answer, close) = match read_line_until(&mut stream, &mut pending, deadline) {
            Err(_) => return,
            Ok(None) => (error_json(None, &format!("line longer than {MAX_LINE_BYTES} bytes")), true),
            Ok(Some(line)) => match std::str::from_utf8(&line) {
                Ok(text) if text.trim().is_empty() => continue,
                Ok(text) => (handle_line(sentinel, text), false),
                Err(_) => (error_json(None, "line is not UTF-8"), false),
            },
        };
        let mut text = answer.to_string();
        text.push('\n');
        if stream.write_all(text.as_bytes()).is_err() || close {
            return;
        }
    }
}

fn error_json(id: Option<Json>, msg: &str) -> Json {
    let mut f = vec![("ok", Json::Bool(false)), ("error", Json::s(msg))];
    if let Some(id) = id {
        f.push(("id", id));
    }
    Json::obj(f)
}

fn range_of(req: &Json) -> Result<Cidr, String> {
    match (req.get("addr"), req.get("cidr")) {
        (Some(_), Some(_)) => Err("give `addr` or `cidr`, not both".into()),
        (Some(a), None) => {
            let a = a.as_str().ok_or("`addr` must be a string")?;
            if a.contains('/') {
                return Err("`addr` is one address; use `cidr` for a range".into());
            }
            Cidr::parse(a)
        }
        (None, Some(c)) => Cidr::parse(c.as_str().ok_or("`cidr` must be a string")?),
        (None, None) => Err("missing `addr` or `cidr`".into()),
    }
}

/// One command line in, one answer out. Logged and evented either way.
pub(crate) fn handle_line(sentinel: &Sentinel, line: &str) -> Json {
    sentinel.note_admin_command();
    let parsed = crate::rpc::parse_json(line.trim());
    let (cmd, id, outcome) = match &parsed {
        Err(e) => ("invalid".to_string(), None, Err(format!("not JSON: {e}"))),
        Ok(req) => {
            let id = req.get("id").filter(|v| matches!(v, Json::Num(_) | Json::Str(_))).cloned();
            let cmd = req.get("cmd").and_then(Json::as_str).unwrap_or("").to_string();
            let outcome = match cmd.as_str() {
                "peer.ban" => (|| -> Result<Json, String> {
                    let range = range_of(req)?;
                    let ttl = req.get("ttl_secs").and_then(Json::as_u64).ok_or("missing or invalid `ttl_secs`")?;
                    let reason = match req.get("reason") {
                        None | Some(Json::Null) => "",
                        Some(r) => r.as_str().ok_or("`reason` must be a string")?,
                    };
                    let (ban, disconnected) = sentinel.ban(range, ttl, reason)?;
                    Ok(Json::obj(vec![
                        ("range", Json::s(ban.range.to_string())),
                        ("ttl_secs", Json::u(ban.ttl_secs)),
                        ("reason", Json::s(ban.reason)),
                        ("disconnected", Json::u(disconnected as u64)),
                    ]))
                })(),
                "peer.unban" => range_of(req).map(|range| {
                    let removed = sentinel.unban(range).is_some();
                    Json::obj(vec![("range", Json::s(range.to_string())), ("removed", Json::Bool(removed))])
                }),
                "peer.bans" => Ok(sentinel.bans_json(Instant::now())),
                "" => Err("missing `cmd`".into()),
                _ => Err(format!("unknown command; the admin socket accepts only {}", COMMANDS.join(", "))),
            };
            (cmd, id, outcome)
        }
    };
    let cmd_shown: String = if COMMANDS.contains(&cmd.as_str()) { cmd.clone() } else { "unknown".into() };
    let ok = outcome.is_ok();
    match &outcome {
        Ok(_) => println!("sentinel: admin command {cmd_shown}: ok"),
        Err(e) => eprintln!("sentinel: admin command {cmd_shown}: refused: {e}"),
    }
    let mut fields = vec![("cmd", Json::s(cmd_shown)), ("ok", Json::Bool(ok))];
    if let Ok(Some(range)) = parsed.as_ref().map(|r| range_of(r).ok()) {
        fields.push(("range", Json::s(range.to_string())));
    }
    if let Err(e) = &outcome {
        fields.push(("error", Json::s(e.clone())));
    }
    sentinel.emit("admin_command", fields);
    match outcome {
        Ok(result) => {
            let mut f = vec![("ok", Json::Bool(true)), ("result", result)];
            if let Some(id) = id {
                f.push(("id", id));
            }
            Json::obj(f)
        }
        Err(e) => error_json(id, &e),
    }
}
