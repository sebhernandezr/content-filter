//! Types shared between the content-filter system extension and the container app.
//!
//! The two processes are not related at runtime: the extension runs as **root**, launched by
//! `nesessionmanager`; the app runs as the console user. They communicate in one direction only,
//! through the **unified log** — the extension emits one line per flow with `os_log`, and the app
//! reads those lines back by tailing `log stream`.
//!
//! That makes the log line a wire format, and this crate is its single definition. Both sides
//! depend on this crate so the encoder and the decoder cannot drift apart.
//!
//! Why the unified log rather than a file in the shared App Group container: the extension is
//! root, so `containerURLForSecurityApplicationGroupIdentifier` resolves under `/var/root/…`,
//! while the app's resolves under `~/…`. They are two different directories and the app cannot
//! read root's. The unified log has no such split, needs no XPC and no sandbox exception, and it
//! means the UI and Console.app are reading the *same source* — so "the UI shows nothing" and
//! "Console shows nothing" can never disagree while debugging.

use serde::{Deserialize, Serialize};

/// Prefix marking a log line as a machine-readable flow record.
///
/// The extension emits `FLOW1 {json}`. The app scans `log stream` output for this marker and
/// parses what follows. The trailing digit is a format version: bump it if [`FlowRecord`] ever
/// changes shape incompatibly, so an old extension and a new app fail loudly instead of silently
/// mis-parsing.
pub const FLOW_MARKER: &str = "FLOW1 ";

/// The os_log subsystem both sides agree on. The app builds its `log stream` predicate from this,
/// and the extension creates its log handle with it.
pub const LOG_SUBSYSTEM: &str = "com.digiexam.macos.NetworkExtensions";

/// os_log category for per-flow records.
pub const LOG_CATEGORY_FLOW: &str = "flow";

/// os_log category for provider lifecycle events (start/stop).
pub const LOG_CATEGORY_LIFECYCLE: &str = "lifecycle";

/// One network flow, as observed by `handleNewFlow:`.
///
/// Almost every field is optional, and that is not defensiveness — it reflects what the
/// NetworkExtension framework actually guarantees at the moment the flow is first seen. See
/// [`FlowRecord::remote_host`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowRecord {
    /// Milliseconds since the Unix epoch, taken when the flow was observed.
    pub ts_ms: u64,

    /// IPv4 / IPv6, from `NEFilterSocketFlow.socketFamily`.
    pub family: AddressFamily,

    /// TCP / UDP, from `NEFilterSocketFlow.socketProtocol`.
    pub protocol: TransportProtocol,

    /// Remote hostname or IP literal.
    ///
    /// `None` is normal, not an error. Apple's header for `NEFilterSocketFlow.remoteEndpoint`
    /// states: *"This endpoint object may be nil when `[NEFilterDataProvider handleNewFlow:]` is
    /// invoked and if so will be populated upon receiving network data."* So for a genuine share
    /// of flows the destination simply is not known yet at the moment we are asked for a verdict.
    /// Such records are still emitted — dropping them would make normal framework behaviour look
    /// like a hole in our filter.
    pub remote_host: Option<String>,

    /// Remote port. `None` for the same reason as [`Self::remote_host`].
    pub remote_port: Option<u16>,

    /// `NEFilterSocketFlow.remoteHostname`, populated only for Network.framework / NSURLSession
    /// flows. When present it is a real hostname; [`Self::remote_host`] may be only an IP literal.
    pub hostname: Option<String>,

    /// `NEFilterFlow.URL.host`, populated for WebKit-originated flows.
    pub url_host: Option<String>,

    /// Bundle identifier of the originating app.
    ///
    /// Always `None` in this MVP: attribution is behind a compile-time flag
    /// (`crates/filter-sysext/src/attribution.rs`). See that module for what enabling it costs.
    pub source_app: Option<String>,

    /// What we told the framework to do. Always [`Verdict::Allow`] in this observe-only build.
    pub verdict: Verdict,
}

impl FlowRecord {
    /// Encode as a single log line: `FLOW1 {json}`.
    pub fn encode(&self) -> String {
        // serde_json on a struct of plain scalars cannot fail; a corrupt line would be worse than
        // a placeholder, so degrade rather than panic inside a privileged root process.
        match serde_json::to_string(self) {
            Ok(json) => format!("{FLOW_MARKER}{json}"),
            Err(e) => format!("{FLOW_MARKER}{{\"encode_error\":\"{e}\"}}"),
        }
    }

    /// Recover a record from a log line, or `None` if the line is not a flow record.
    ///
    /// Takes the whole message because `log stream` output carries its own prefixes; this scans
    /// for the marker rather than requiring the line to start with it.
    pub fn decode(line: &str) -> Option<Self> {
        let idx = line.find(FLOW_MARKER)?;
        let json = &line[idx + FLOW_MARKER.len()..];
        serde_json::from_str(json).ok()
    }

    /// The best available name for the destination, preferring real hostnames over IP literals.
    pub fn best_destination(&self) -> Option<&str> {
        self.url_host
            .as_deref()
            .or(self.hostname.as_deref())
            .or(self.remote_host.as_deref())
    }
}

/// IP address family, from `socketFamily` (`AF_INET` / `AF_INET6` in `<sys/socket.h>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressFamily {
    V4,
    V6,
    /// Anything else, carrying the raw `AF_*` value so an unexpected family is visible in the log
    /// rather than silently flattened.
    Other(i32),
}

impl AddressFamily {
    pub const AF_INET: i32 = 2;
    pub const AF_INET6: i32 = 30;

    pub fn from_raw(v: i32) -> Self {
        match v {
            Self::AF_INET => Self::V4,
            Self::AF_INET6 => Self::V6,
            other => Self::Other(other),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::V4 => "IPv4".into(),
            Self::V6 => "IPv6".into(),
            Self::Other(v) => format!("AF({v})"),
        }
    }
}

/// Transport protocol, from `socketProtocol` (`IPPROTO_*` in `<netinet/in.h>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Other(i32),
}

impl TransportProtocol {
    pub const IPPROTO_TCP: i32 = 6;
    pub const IPPROTO_UDP: i32 = 17;

    pub fn from_raw(v: i32) -> Self {
        match v {
            Self::IPPROTO_TCP => Self::Tcp,
            Self::IPPROTO_UDP => Self::Udp,
            other => Self::Other(other),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Tcp => "TCP".into(),
            Self::Udp => "UDP".into(),
            Self::Other(v) => format!("proto({v})"),
        }
    }
}

/// The verdict returned to the framework.
///
/// `Drop` exists so the UI and log format do not need changing when enforcement lands, but this
/// build never produces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Allow,
    Drop,
}

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
    /// Flow records buffered since the app started.
    pub flows_seen: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FlowRecord {
        FlowRecord {
            ts_ms: 1_700_000_000_000,
            family: AddressFamily::V6,
            protocol: TransportProtocol::Tcp,
            remote_host: Some("2606:4700::1".into()),
            remote_port: Some(443),
            hostname: Some("example.com".into()),
            url_host: None,
            source_app: None,
            verdict: Verdict::Allow,
        }
    }

    #[test]
    fn round_trips_through_a_log_line() {
        let rec = sample();
        assert_eq!(FlowRecord::decode(&rec.encode()), Some(rec));
    }

    #[test]
    fn decodes_when_the_marker_is_mid_line() {
        // `log stream` prefixes every message with timestamp, process and subsystem.
        let rec = sample();
        let line = format!("2026-08-31 10:00:00.123 Df filter[123:456] [flow] {}", rec.encode());
        assert_eq!(FlowRecord::decode(&line), Some(rec));
    }

    #[test]
    fn ignores_lines_that_are_not_flow_records() {
        assert_eq!(FlowRecord::decode("startFilterWithCompletionHandler:"), None);
        assert_eq!(FlowRecord::decode(""), None);
    }

    #[test]
    fn survives_a_truncated_record() {
        // log truncation must not take the whole tail down.
        assert_eq!(FlowRecord::decode("FLOW1 {\"ts_ms\":170000"), None);
    }

    #[test]
    fn families_and_protocols_map_from_raw_values() {
        assert_eq!(AddressFamily::from_raw(2), AddressFamily::V4);
        assert_eq!(AddressFamily::from_raw(30), AddressFamily::V6);
        assert_eq!(AddressFamily::from_raw(1), AddressFamily::Other(1));
        assert_eq!(TransportProtocol::from_raw(6), TransportProtocol::Tcp);
        assert_eq!(TransportProtocol::from_raw(17), TransportProtocol::Udp);
        assert_eq!(TransportProtocol::from_raw(1), TransportProtocol::Other(1));
    }

    #[test]
    fn destination_prefers_hostname_over_ip_literal() {
        let rec = sample();
        assert_eq!(rec.best_destination(), Some("example.com"));

        let ip_only = FlowRecord { hostname: None, ..sample() };
        assert_eq!(ip_only.best_destination(), Some("2606:4700::1"));

        let pending = FlowRecord { hostname: None, remote_host: None, ..sample() };
        assert_eq!(pending.best_destination(), None);
    }

    #[test]
    fn a_flow_with_no_endpoint_yet_still_encodes() {
        // The documented "remoteEndpoint may be nil at handleNewFlow: time" case.
        let pending = FlowRecord {
            remote_host: None,
            remote_port: None,
            hostname: None,
            ..sample()
        };
        assert_eq!(FlowRecord::decode(&pending.encode()), Some(pending));
    }
}
