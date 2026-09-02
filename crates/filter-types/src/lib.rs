//! Types shared between the content-filter Tauri plugin and its frontend.
//!
//! These cross the Tauri command boundary (`#[tauri::command]` return types), which is why they
//! live in their own crate with a serde derive rather than directly in
//! `tauri-plugin-content-filter`: `tauri::generate_handler!` needs `Serialize` on every command's
//! return type, and keeping that requirement visible in one small, dependency-light crate makes
//! it easy to see what actually crosses the boundary.
//!
//! Flow records do **not** cross this boundary any more. Earlier, this crate also defined the
//! `FLOW1 {json}` line format the extension emitted over the unified log and the app tailed back
//! with `log stream`, to feed a live table in the app window. That table is gone — flows are read
//! from a terminal now, with `make logs` — so that wire format,
//! and the crate's reason for being shared with `filter-sysext`, went with it. See
//! `crates/filter-sysext/src/flow.rs` for the extension-side equivalent, which has no need to be
//! shared or serializable.
//!
//! [`TestConnectResult`] and [`tcp_probe`] are the odd one out: they hold no NetworkExtension
//! state at all. They exist so the app can *demonstrate* the allowlist from its own UI — a
//! plain `std::net::TcpStream` connect, attributable straight to this app's own process,
//! independent of any Apple framework. That independence is also why the probe lives here
//! rather than in `tauri-plugin-content-filter`: it needs to work identically whether or not
//! the macOS-only half of that plugin is even compiled in, which is exactly this crate's job
//! for `ActivationState` / `FilterStatus` already.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Where the system extension stands, as reported to the UI.
///
/// `NeedsUserApproval` and `NeedsReboot` are separate states on purpose — both are non-terminal,
/// and collapsing either into success is how an extension that never actually runs gets reported
/// as working.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum ActivationState {
    /// No activation has been attempted this session.
    #[default]
    Idle,
    /// Request submitted, waiting on the framework.
    Pending,
    /// Waiting for the user in System Settings.
    NeedsUserApproval,
    /// Activated and running.
    Active,
    /// The request succeeded but macOS staged the extension instead of activating it, because a
    /// different version is already installed and a running provider is never hot-swapped. The
    /// old version keeps running until a reboot.
    ///
    /// This is the condition that let 15 stale copies accumulate on the dev machine with none
    /// ever active. Reporting it as success is precisely the bug; it gets its own state.
    NeedsReboot,
    Failed(String),
}

/// Combined status for the UI: is the extension installed, and is the filter switched on?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterStatus {
    pub activation: ActivationState,
    /// `NEFilterManager.sharedManager.isEnabled` — whether a filter configuration is enabled.
    /// Independent of [`Self::activation`]: this can be true while no provider is running, which
    /// is exactly what "shows up in System Settings but never filters" looks like.
    pub enabled: bool,
}

/// Outcome of a [`tcp_probe`] call — the test-connect button's result.
///
/// Three states rather than a bool-or-error: a `Blocked` connection (refused, or the network
/// simply going quiet) and a `TimedOut` one usually mean the same thing in practice under this
/// filter (`dropVerdict()` does not send an RST, so a client tends to see a hang, not a refusal),
/// but keeping them distinct means a real DNS failure or an actually-unreachable host is not
/// silently reported as "the filter dropped it".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum TestConnectResult {
    /// The TCP handshake completed.
    Reachable,
    /// The OS reported a definite failure before the timeout (connection refused, no route, DNS
    /// failure). Carries the OS's own error text.
    Blocked(String),
    /// No definite answer arrived within the timeout. Under this filter's `dropVerdict()` this is
    /// the *expected* shape of "blocked" for TCP, since a dropped flow is not actively refused.
    TimedOut,
}

/// How long to wait for a connection before calling it blocked. Generous enough that a slow but
/// genuinely reachable host does not read as a false block, short enough that the test panel does
/// not feel hung.
pub const TEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Attempt a raw TCP connect to `host:port` and classify the outcome.
///
/// Deliberately not TLS, not HTTP — a bare socket connect is the simplest possible flow to
/// attribute, and it is also the shape of flow that carries **no hostname** at `handleNewFlow:`
/// time (see `crates/filter-sysext/src/rules.rs`'s module doc on the `ip` matcher), which makes
/// this the right tool for proving that matcher rather than only the webview's hostname-carrying
/// fetches.
///
/// Blocking: run this off the main thread (`spawn_blocking` in the Tauri command that calls it).
pub fn tcp_probe(host: &str, port: u16) -> TestConnectResult {
    let addr = match (host, port).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => return TestConnectResult::Blocked(format!("{host} resolved to no address")),
        },
        Err(e) => return TestConnectResult::Blocked(format!("could not resolve {host}: {e}")),
    };

    match TcpStream::connect_timeout(&addr, TEST_CONNECT_TIMEOUT) {
        Ok(_) => TestConnectResult::Reachable,
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => TestConnectResult::TimedOut,
        Err(e) => TestConnectResult::Blocked(e.to_string()),
    }
}

#[cfg(test)]
mod tcp_probe_tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn reaches_a_real_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(tcp_probe("127.0.0.1", port), TestConnectResult::Reachable);
    }

    #[test]
    fn reports_a_definite_refusal_as_blocked_not_timed_out() {
        // Binding and immediately dropping frees the port but leaves nothing listening, so the OS
        // answers with a prompt, definite RST rather than silence.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        match tcp_probe("127.0.0.1", port) {
            TestConnectResult::Blocked(_) => {}
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn an_unresolvable_host_is_reported_as_blocked() {
        match tcp_probe("this-host-should-not-resolve.invalid", 443) {
            TestConnectResult::Blocked(_) => {}
            other => panic!("expected Blocked, got {other:?}"),
        }
    }
}
