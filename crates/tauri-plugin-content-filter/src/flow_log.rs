//! Reading flow records back from the extension.
//!
//! The extension runs as **root**, launched by `nesessionmanager`; this app runs as the console
//! user. They share no memory, no XPC channel, and — importantly — no App Group container:
//! `containerURLForSecurityApplicationGroupIdentifier` resolves relative to the caller's home
//! directory, so the extension's group container is under `/var/root/…` and the app's is under
//! `~/…`. They are different directories and the app cannot read root's, so the obvious
//! "extension writes a file, app tails it" design does not work between these two processes.
//!
//! The unified log has none of those problems. The extension already emits there for debugging,
//! `log stream` needs no elevated privileges to read public messages, and using it here means the
//! UI and Console.app read the *same source* — so "the UI shows nothing" and "Console shows
//! nothing" can never disagree while diagnosing a silent filter.
//!
//! Implementation: spawn `log stream`, parse each line for the marker defined in `filter-types`,
//! and push decoded records into a bounded ring buffer the UI polls.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use filter_types::{FlowRecord, LOG_SUBSYSTEM};

/// How many records to retain. Bounded because this is a live tail of every connection on the
/// machine: on a busy network an unbounded buffer is a memory leak with extra steps.
const CAPACITY: usize = 500;

/// Ring buffer of recently observed flows, plus a lifetime counter.
#[derive(Default)]
pub struct FlowBuffer {
    records: Vec<FlowRecord>,
    /// Total ever seen, not just those still buffered. This is the number that answers "is the
    /// provider receiving anything at all?", which stays meaningful after the ring has wrapped.
    total: usize,
}

impl FlowBuffer {
    fn push(&mut self, record: FlowRecord) {
        self.total = self.total.saturating_add(1);
        if self.records.len() == CAPACITY {
            self.records.remove(0);
        }
        self.records.push(record);
    }

    /// The most recent `limit` records, newest first.
    pub fn recent(&self, limit: usize) -> Vec<FlowRecord> {
        self.records.iter().rev().take(limit).cloned().collect()
    }

    pub fn total(&self) -> usize {
        self.total
    }
}

/// A running `log stream` tail. Dropping this kills the child process.
pub struct FlowTail {
    child: Child,
}

impl Drop for FlowTail {
    fn drop(&mut self) {
        // `log stream` runs until killed; without this it would outlive the app.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start tailing the extension's log output into `buffer`.
///
/// Returns a handle that must be kept alive; dropping it stops the tail.
pub fn start(buffer: Arc<Mutex<FlowBuffer>>) -> Result<FlowTail, String> {
    // Filtering by subsystem keeps this to our own messages. `--style compact` keeps one message
    // per line, which is what the line-oriented parse below assumes.
    let predicate = format!("subsystem == \"{LOG_SUBSYSTEM}\"");

    let mut child = Command::new("/usr/bin/log")
        .args(["stream", "--style", "compact", "--predicate", &predicate])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start `log stream`: {e}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "log stream produced no stdout".to_owned())?;

    std::thread::Builder::new()
        .name("flow-log-tail".into())
        .spawn(move || {
            for line in BufReader::new(stdout).lines() {
                // A non-UTF-8 or otherwise unreadable line is skipped rather than ending the
                // tail: one malformed message must not stop flow collection for the session.
                let Ok(line) = line else { continue };
                if let Some(record) = FlowRecord::decode(&line) {
                    if let Ok(mut buf) = buffer.lock() {
                        buf.push(record);
                    }
                }
            }
        })
        .map_err(|e| format!("could not spawn the log-tail thread: {e}"))?;

    Ok(FlowTail { child })
}

#[cfg(test)]
mod tests {
    use super::*;
    use filter_types::{AddressFamily, TransportProtocol, Verdict};

    fn rec(port: u16) -> FlowRecord {
        FlowRecord {
            ts_ms: 0,
            family: AddressFamily::V4,
            protocol: TransportProtocol::Tcp,
            remote_host: Some("192.0.2.1".into()),
            remote_port: Some(port),
            hostname: None,
            url_host: None,
            source_app: None,
            verdict: Verdict::Allow,
        }
    }

    #[test]
    fn recent_returns_newest_first() {
        let mut b = FlowBuffer::default();
        b.push(rec(1));
        b.push(rec(2));
        b.push(rec(3));
        let got: Vec<_> = b.recent(2).iter().map(|r| r.remote_port.unwrap()).collect();
        assert_eq!(got, vec![3, 2]);
    }

    #[test]
    fn buffer_is_bounded_but_the_total_keeps_counting() {
        let mut b = FlowBuffer::default();
        for i in 0..(CAPACITY + 50) {
            b.push(rec(i as u16));
        }
        assert_eq!(b.records.len(), CAPACITY, "ring must not grow past capacity");
        assert_eq!(b.total(), CAPACITY + 50, "total counts everything ever seen");
    }

    #[test]
    fn oldest_records_are_the_ones_dropped() {
        let mut b = FlowBuffer::default();
        for i in 0..(CAPACITY + 1) {
            b.push(rec(i as u16));
        }
        let oldest_kept = b.records.first().unwrap().remote_port.unwrap();
        assert_eq!(oldest_kept, 1, "record 0 should have been evicted");
    }

    #[test]
    fn recent_handles_a_limit_larger_than_the_buffer() {
        let mut b = FlowBuffer::default();
        b.push(rec(7));
        assert_eq!(b.recent(100).len(), 1);
    }
}
