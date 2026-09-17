// SPDX-License-Identifier: AGPL-3.0-or-later
//! Socket timeouts measured against one absolute deadline, not renewed by progress.
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Instant;

pub(crate) struct DeadlineStream<'a> {
    stream: &'a TcpStream,
    deadline: Instant,
}

impl<'a> DeadlineStream<'a> {
    pub(crate) fn new(stream: &'a TcpStream, deadline: Instant) -> Self {
        Self { stream, deadline }
    }
    fn remaining(&self) -> io::Result<std::time::Duration> {
        self.deadline.checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "connection deadline exceeded"))
    }
}

impl Read for DeadlineStream<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer)
    }
}

impl Write for DeadlineStream<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}
