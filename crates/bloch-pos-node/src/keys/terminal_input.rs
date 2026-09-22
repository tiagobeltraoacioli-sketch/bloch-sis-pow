//! Interactive secret input for the single-threaded CLI startup path only.
//!
//! This must run before creating threads: pthread_sigmask changes this thread's
//! mask, and another thread could otherwise receive a process-directed signal.
//! No process-wide signal disposition is installed or replaced.
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use zeroize::Zeroizing;

const INTERRUPTS: [libc::c_int; 7] = [
    libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT,
    libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU,
];

struct SignalMask {
    saved: libc::sigset_t,
    newly_actionable: [bool; 7],
}
impl SignalMask {
    fn block() -> io::Result<Self> {
        // SAFETY: each libc call receives valid storage for the exact type.
        let mut signals: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut saved: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigemptyset(&mut signals); }
        for signal in INTERRUPTS {
            unsafe { libc::sigaddset(&mut signals, signal); }
        }
        let result = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &signals, &mut saved) };
        if result != 0 { return Err(io::Error::from_raw_os_error(result)); }
        // Establish the guard immediately: every error below must restore the
        // caller's signal mask before returning.
        let mut guard = Self { saved, newly_actionable: [false; 7] };
        for (index, signal) in INTERRUPTS.into_iter().enumerate() {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(signal, std::ptr::null(), &mut action) } != 0 {
                let error = io::Error::last_os_error();
                return Err(io::Error::new(
                    error.kind(),
                    format!("cannot inspect disposition for signal {signal}: {error}"),
                ));
            }
            guard.newly_actionable[index] = action.sa_sigaction != libc::SIG_IGN
                && unsafe { libc::sigismember(&guard.saved, signal) } == 0;
        }
        Ok(guard)
    }
    fn interrupted(&self) -> io::Result<bool> {
        let mut pending: libc::sigset_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigpending(&mut pending) } != 0 { return Err(io::Error::last_os_error()); }
        Ok(INTERRUPTS.iter().zip(self.newly_actionable).any(|(signal, actionable)| {
            actionable && unsafe { libc::sigismember(&pending, *signal) } == 1
        }))
    }
}
impl Drop for SignalMask {
    fn drop(&mut self) {
        // The terminal guard is dropped/restored before this guard. Releasing
        // a pending signal now preserves its original disposition and mask.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.saved, std::ptr::null_mut()); }
    }
}

struct Restore { fd: libc::c_int, saved: libc::termios, active: bool }
impl Restore {
    fn restore(&mut self) -> io::Result<()> {
        if unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for Restore {
    fn drop(&mut self) { if self.active { let _ = self.restore(); } }
}

pub(super) fn read_passphrase(prompt: &str) -> io::Result<Zeroizing<String>> {
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return Err(io::Error::new(io::ErrorKind::Unsupported,
            "stdin is not a terminal; supply the passphrase with --passphrase-file <0600 file>"));
    }
    // Declared first so every return/error restores the terminal before
    // releasing signals. Preserve signals that the caller already blocked.
    let signals = SignalMask::block()?;
    // Use one descriptor for terminal control and input. Reopening /dev/tty
    // read-only makes tcsetattr fail on Darwin, while a separate terminal can
    // create a control/read split. Duplicating stdin preserves its access mode
    // without borrowing Rust's buffered global stdin.
    let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    // SAFETY: fcntl returned a new owned descriptor, transferred to File.
    let mut input = unsafe { File::from_raw_fd(fd) };
    let fd = input.as_raw_fd();
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut term) } != 0 { return Err(io::Error::last_os_error()); }
    let mut restore = Restore { fd, saved: term, active: true };
    term.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &term) } != 0 { return Err(io::Error::last_os_error()); }
    let mut err = io::stderr();
    err.write_all(prompt.as_bytes())?;
    err.flush()?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(4096));
    let mut byte = Zeroizing::new([0u8; 1]);
    let read = (|| -> io::Result<()> {
        loop {
            if signals.interrupted()? {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "passphrase entry interrupted; retry the command"));
            }
            // macOS poll(2) can report POLLNVAL for /dev/tty despite a
            // valid descriptor. select supports the controlling terminal.
            if fd < 0 || fd as usize >= libc::FD_SETSIZE {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "terminal descriptor exceeds select capacity"));
            }
            let mut readable: libc::fd_set = unsafe { std::mem::zeroed() };
            unsafe { libc::FD_ZERO(&mut readable); libc::FD_SET(fd, &mut readable); }
            let mut timeout = libc::timeval { tv_sec: 0, tv_usec: 100_000 };
            let result = unsafe { libc::select(fd.saturating_add(1), &mut readable,
                std::ptr::null_mut(), std::ptr::null_mut(), &mut timeout) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted { continue; }
                return Err(error);
            }
            if result == 0 { continue; }
            match input.read(&mut byte[..]) {
                Ok(0) => break,
                Ok(_) if byte[0] == b'\n' => break,
                Ok(_) => {
                    if bytes.len() >= 4096 { return Err(io::Error::new(io::ErrorKind::InvalidInput, "passphrase exceeds 4096 bytes")); }
                    bytes.push(byte[0]);
                }
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    })();
    restore.restore()?;
    let _ = err.write_all(b"\n");
    // Drop sensitive input before unmasking a signal that may terminate us.
    if let Err(error) = read {
        drop(bytes);
        drop(byte);
        drop(restore);
        drop(input);
        drop(signals);
        return Err(error);
    }
    let mut line = Zeroizing::new(std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "passphrase is not UTF-8"))?.to_owned());
    while line.ends_with('\n') || line.ends_with('\r') { line.pop(); }
    if line.is_empty() { return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty passphrase")); }
    Ok(line)
}
