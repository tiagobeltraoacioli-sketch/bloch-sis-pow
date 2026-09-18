// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded diagnostics only: never participates in validation or peer scoring.
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const BURST: u64 = 8;
const WINDOW: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
pub(crate) enum Class { Block, Attestation, Transaction, Sync, Connection }
impl Class {
    fn label(self) -> &'static str {
        match self {
            Self::Block => "block", Self::Attestation => "attestation",
            Self::Transaction => "transaction", Self::Sync => "sync", Self::Connection => "connection",
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Window { start: Option<Instant>, emitted: u64, suppressed: u64 }

#[derive(Default)]
struct Logger {
    windows: Mutex<[Window; 5]>,
    suppressed: AtomicU64,
}
impl Logger {
    fn emit_at(&self, class: Class, now: Instant, output: impl FnOnce(u64)) {
        let permit = {
            let mut windows = self.windows.lock().unwrap_or_else(|p| p.into_inner());
            // Exhaustive matching ties every class to one fixed window; adding
            // a class requires explicitly choosing its storage here.
            let [block, attestation, transaction, sync, connection] = &mut *windows;
            let window = match class {
                Class::Block => block, Class::Attestation => attestation,
                Class::Transaction => transaction, Class::Sync => sync, Class::Connection => connection,
            };
            let reset = window.start.is_none_or(|start| now.checked_duration_since(start).is_some_and(|age| age >= WINDOW));
            let previous = if reset {
                let previous = window.suppressed;
                *window = Window { start: Some(now), ..Window::default() };
                previous
            } else { 0 };
            if window.emitted < BURST {
                window.emitted = window.emitted.saturating_add(1);
                Some(previous)
            } else {
                window.suppressed = window.suppressed.saturating_add(1);
                let _ = self.suppressed.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| Some(n.saturating_add(1)));
                None
            }
        };
        // Never hold the admission lock during potentially blocking stderr IO.
        if let Some(suppressed) = permit { output(suppressed); }
    }
}

fn logger() -> &'static Logger {
    static LOGGER: OnceLock<Logger> = OnceLock::new();
    LOGGER.get_or_init(Logger::default)
}

pub(crate) fn emit(class: Class, output: impl FnOnce()) {
    logger().emit_at(class, Instant::now(), |suppressed| {
        if suppressed != 0 {
            let _ = writeln!(std::io::stderr(), "rejection-log: suppressed {suppressed} {} diagnostics in the preceding window", class.label());
        }
        output();
    });
}

/// Cumulative exact suppressed calls (saturates at u64::MAX); reads never reset it.
pub(crate) fn suppressed_total() -> u64 { logger().suppressed.load(Ordering::Relaxed) }

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn rejection_logging_burst_counts_every_suppression_and_recovers() {
        let logger = Logger::default();
        let now = Instant::now();
        let emitted = Cell::new(0);
        for _ in 0..100 {
            logger.emit_at(Class::Block, now, |summary| {
                assert_eq!(summary, 0);
                emitted.set(emitted.get() + 1);
            });
        }
        assert_eq!(emitted.get(), BURST);
        assert_eq!(logger.suppressed.load(Ordering::Relaxed), 100 - BURST);
        // An independent fixed class retains its diagnostic allowance.
        logger.emit_at(Class::Attestation, now, |_| emitted.set(emitted.get() + 1));
        assert_eq!(emitted.get(), BURST + 1);
        logger.emit_at(Class::Block, now + WINDOW, |summary| assert_eq!(summary, 100 - BURST));
        logger.emit_at(Class::Block, now + WINDOW, |summary| assert_eq!(summary, 0));
        assert_eq!(logger.suppressed.load(Ordering::Relaxed), 100 - BURST);
        assert_eq!(logger.suppressed.load(Ordering::Relaxed), 100 - BURST, "scraping never resets the counter");
    }

    #[test]
    fn rejection_logging_does_not_format_suppressed_events_or_renew_on_progress() {
        let logger = Logger::default();
        let now = Instant::now();
        for _ in 0..BURST { logger.emit_at(Class::Sync, now, |_| {}); }
        for second in 1..10 {
            logger.emit_at(Class::Sync, now + Duration::from_secs(second), |_| panic!("suppressed formatting ran"));
        }
        logger.emit_at(Class::Sync, now + WINDOW, |summary| assert_eq!(summary, 9));
        assert_eq!(logger.suppressed.load(Ordering::Relaxed), 9);
    }
}
