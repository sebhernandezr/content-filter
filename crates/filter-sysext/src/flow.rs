//! Turning an `NEFilterFlow` into a [`FlowInfo`], and that into a readable log line.
//!
//! Everything the ticket asks to observe — remote host and port, transport protocol, IPv4 vs
//! IPv6 — comes from `NEFilterSocketFlow`, which is the concrete subclass we get when the filter
//! is configured with `filterSockets = true`. Source-app identity comes from
//! [`crate::attribution`], which is where the actual work (and the actual trust decision) lives;
//! this module just carries the result alongside everything else `rules::decide` needs.
//!
//! `FlowInfo` used to be `filter_types::FlowRecord`, serialized as `FLOW1 {json}` and shipped to
//! the container app over the unified log so a UI table could render it. There is no UI table any
//! more — the terminal, via `make logs`, is the intended way to watch flows — so this is a
//! plain struct with no serde derives, and it doubles as the input to [`crate::rules::decide`].

use std::time::{SystemTime, UNIX_EPOCH};

use objc2::rc::Retained;
#[allow(deprecated)] // see remote_endpoint_parts
use objc2_network_extension::NWHostEndpoint;
use objc2_network_extension::{NEFilterFlow, NEFilterSocketFlow};

use crate::attribution::{self, AppId};
use crate::rules::Action;

/// IP address family, from `socketFamily` (`AF_INET` / `AF_INET6` in `<sys/socket.h>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// One network flow, as observed by `handleNewFlow:`.
///
/// Almost every field is optional, and that is not defensiveness — it reflects what the
/// NetworkExtension framework actually guarantees at the moment the flow is first seen. See
/// [`FlowInfo::best_destination`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowInfo {
    /// Milliseconds since the Unix epoch, taken when the flow was observed.
    pub ts_ms: u64,

    pub family: AddressFamily,
    pub protocol: TransportProtocol,

    /// Remote hostname or IP literal.
    ///
    /// `None` is normal, not an error. Apple's header for `NEFilterSocketFlow.remoteEndpoint`
    /// states: *"This endpoint object may be nil when `[NEFilterDataProvider handleNewFlow:]` is
    /// invoked and if so will be populated upon receiving network data."* So for a genuine share
    /// of flows the destination simply is not known yet at the moment we are asked for a verdict.
    pub remote_host: Option<String>,

    /// Remote port. `None` for the same reason as [`Self::remote_host`].
    pub remote_port: Option<u16>,

    /// `NEFilterSocketFlow.remoteHostname`, populated only for Network.framework / NSURLSession
    /// flows. When present it is a real hostname; [`Self::remote_host`] may be only an IP literal.
    pub hostname: Option<String>,

    /// `NEFilterFlow.URL.host`, populated for WebKit-originated flows.
    pub url_host: Option<String>,

    /// The app that opened this flow — `None` when neither the framework's identifier nor the
    /// executable path could name it. See [`crate::attribution`], including what it deliberately
    /// does not verify.
    pub app: Option<AppId>,

    /// PID of the originating process, for the log only. Independent of [`Self::app`] on purpose:
    /// it can be checked against reality with `ps -p <pid>` without trusting our identification.
    pub pid: Option<i32>,
}

impl FlowInfo {
    /// The best available name for the destination, preferring real hostnames over IP literals.
    /// This is also what [`crate::rules::Rule`] host matchers compare against.
    pub fn best_destination(&self) -> Option<&str> {
        self.url_host
            .as_deref()
            .or(self.hostname.as_deref())
            .or(self.remote_host.as_deref())
    }

    /// One human-readable line, fixed column order so a terminal tail scans easily:
    ///
    /// ```text
    /// allow TCP  IPv4 93.184.216.34:443 host=example.com  app=com.digiexam.macos.NetworkExtensions(id) pid=3312
    /// drop  TCP  IPv4 93.184.216.34:443 host=example.com  app=/usr/bin/curl(path) pid=4711
    /// drop  UDP  IPv6 (endpoint not yet known)            app=<none> pid=-
    /// ```
    ///
    /// `(endpoint not yet known)` is deliberate wording: it must not read as the filter missing
    /// traffic when the framework simply has not populated the endpoint yet. The `app=` column is
    /// what makes "same destination, different verdict per app" legible in the log rather than
    /// just in the eventual pass/fail of a connection; its `(id)` / `(path)` suffix says which
    /// source named it, so a rule written against the wrong form is visible rather than silent.
    pub fn log_line(&self, action: Action) -> String {
        let proto = self.protocol.label();
        let family = self.family.label();
        let endpoint = match (&self.remote_host, self.remote_port) {
            (Some(host), Some(port)) => {
                let mut s = format!("{host}:{port}");
                if let Some(dest) = self.best_destination() {
                    if dest != host {
                        s.push_str(&format!(" host={dest}"));
                    }
                }
                s
            }
            _ => "(endpoint not yet known)".to_owned(),
        };
        let pid = match self.pid {
            Some(pid) => pid.to_string(),
            None => "-".to_owned(),
        };
        format!(
            "{:<5} {proto:<4} {family:<4} {endpoint}  app={} pid={pid}",
            action.label(),
            self.app_label(),
        )
    }

    /// The `app=` column's value. `<none>` when neither attribution source could name the process
    /// — distinct from a name, and worth reading alongside `pid=`, which is populated whenever the
    /// flow carried an audit token at all.
    fn app_label(&self) -> String {
        match &self.app {
            Some(app) => app.log_label(),
            None => "<none>".to_owned(),
        }
    }
}

/// Build a [`FlowInfo`] for `flow`.
///
/// Never fails and never panics: this runs on the framework's callback path for every connection
/// on the machine, inside a privileged process. A missing field becomes `None`, not an error.
pub fn info_for(flow: &NEFilterFlow) -> FlowInfo {
    let socket = socket_flow(flow);

    // socketFamily/socketProtocol are plain C ints and are populated at handleNewFlow: time.
    // Absent a socket flow at all (which should not happen with filterSockets = true) the raw
    // values stay 0 and surface as Other(0) rather than being guessed at.
    let (family, protocol) = match socket.as_ref() {
        // SAFETY: reading declared properties on a live framework object.
        Some(s) => unsafe {
            (
                AddressFamily::from_raw(s.socketFamily()),
                TransportProtocol::from_raw(s.socketProtocol()),
            )
        },
        None => (AddressFamily::Other(0), TransportProtocol::Other(0)),
    };

    let (remote_host, remote_port) = socket
        .as_ref()
        .and_then(|s| remote_endpoint_parts(s))
        .unwrap_or((None, None));

    // remoteHostname is non-nil only for Network.framework / NSURLSession flows, where it is a
    // real hostname rather than the IP literal remote_host may hold.
    let hostname = socket
        .as_ref()
        // SAFETY: declared property; returns nil for flows that carry no hostname.
        .and_then(|s| unsafe { s.remoteHostname() })
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());

    // WebKit-originated flows carry the request URL.
    // SAFETY: declared property on NEFilterFlow; nil for non-URL flows.
    let url_host = unsafe { flow.URL() }
        .and_then(|u| u.host())
        .map(|h| h.to_string())
        .filter(|s| !s.is_empty());

    FlowInfo {
        ts_ms: now_ms(),
        family,
        protocol,
        remote_host,
        remote_port,
        hostname,
        url_host,
        app: attribution::identify(flow),
        pid: attribution::pid_for(flow),
    }
}

/// Split `remoteEndpoint` into host and port.
///
/// Returns `(None, None)` when the endpoint is nil — which Apple documents as normal at
/// `handleNewFlow:` time: *"This endpoint object may be nil when [NEFilterDataProvider
/// handleNewFlow:] is invoked and if so will be populated upon receiving network data."* A record
/// is still emitted for these flows so that normal framework behaviour cannot be mistaken for the
/// filter missing traffic.
///
/// `NWHostEndpoint` is deprecated in favour of Network.framework's `nw_endpoint_t`, but
/// `NEFilterSocketFlow.remoteEndpoint` is still typed as `NWEndpoint` and the flow exposes no
/// non-deprecated accessor. The allow is scoped to this one function rather than the crate, so
/// that a deprecation elsewhere that *can* be acted on still surfaces as a warning.
#[allow(deprecated)]
fn remote_endpoint_parts(socket: &NEFilterSocketFlow) -> Option<(Option<String>, Option<u16>)> {
    // SAFETY: declared property; explicitly nullable, hence the Option.
    let endpoint = unsafe { socket.remoteEndpoint() }?;
    let host_endpoint = endpoint.downcast::<NWHostEndpoint>().ok()?;

    // SAFETY: NWHostEndpoint declares both as non-null NSString.
    let hostname = unsafe { host_endpoint.hostname() }.to_string();
    let port = unsafe { host_endpoint.port() }.to_string();

    Some((
        Some(hostname).filter(|s| !s.is_empty()),
        port.parse::<u16>().ok(),
    ))
}

/// Downcast to the socket-flow subclass, if this flow really is one.
fn socket_flow(flow: &NEFilterFlow) -> Option<Retained<NEFilterSocketFlow>> {
    // SAFETY: the framework holds a reference to `flow` for the duration of the callback, so
    // retaining it here mirrors an ownership that is already valid. `downcast` needs an owned
    // Retained, and it verifies the real runtime class before succeeding.
    let retained: Retained<NEFilterFlow> =
        unsafe { Retained::retain(flow as *const NEFilterFlow as *mut NEFilterFlow) }?;
    retained.downcast::<NEFilterSocketFlow>().ok()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FlowInfo {
        FlowInfo {
            ts_ms: 1_700_000_000_000,
            family: AddressFamily::V6,
            protocol: TransportProtocol::Tcp,
            remote_host: Some("2606:4700::1".into()),
            remote_port: Some(443),
            hostname: Some("example.com".into()),
            url_host: None,
            app: None,
            pid: None,
        }
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

        let ip_only = FlowInfo { hostname: None, ..sample() };
        assert_eq!(ip_only.best_destination(), Some("2606:4700::1"));

        let pending = FlowInfo { hostname: None, remote_host: None, ..sample() };
        assert_eq!(pending.best_destination(), None);
    }

    #[test]
    fn log_line_includes_hostname_alongside_the_ip() {
        let line = sample().log_line(Action::Allow);
        assert!(line.starts_with("allow"), "{line}");
        assert!(line.contains("2606:4700::1"), "{line}");
        assert!(line.contains(":443"), "{line}");
        assert!(line.contains("host=example.com"), "{line}");
    }

    #[test]
    fn log_line_for_a_pending_endpoint_reads_as_pending_not_missing() {
        // The documented "remoteEndpoint may be nil at handleNewFlow: time" case must not be
        // mistaken, from the log alone, for the filter dropping traffic it should have seen.
        let pending = FlowInfo {
            remote_host: None,
            remote_port: None,
            hostname: None,
            ..sample()
        };
        let line = pending.log_line(Action::Allow);
        assert!(line.contains("endpoint not yet known"), "{line}");
    }

    #[test]
    fn log_line_shows_the_drop_action() {
        let line = sample().log_line(Action::Drop);
        assert!(line.starts_with("drop"), "{line}");
    }

    #[test]
    fn log_line_marks_an_unnamed_flow_as_none() {
        let line = sample().log_line(Action::Drop);
        assert!(line.contains("app=<none>"), "{line}");
        assert!(line.contains("pid=-"), "a flow with no token shows no pid: {line}");
    }

    #[test]
    fn log_line_shows_the_app_name_and_which_source_named_it() {
        let by_id = FlowInfo {
            app: Some(AppId {
                name: "com.digiexam.macos.NetworkExtensions".into(),
                source: "id",
            }),
            pid: Some(3312),
            ..sample()
        }
        .log_line(Action::Allow);
        assert!(by_id.contains("app=com.digiexam.macos.NetworkExtensions(id)"), "{by_id}");
        assert!(by_id.contains("pid=3312"), "{by_id}");

        // The path form is what a raw-socket client like curl produces, and a rule written
        // against the identifier form would silently never match it — hence the suffix.
        let by_path = FlowInfo {
            app: Some(AppId { name: "/usr/bin/curl".into(), source: "path" }),
            pid: Some(4711),
            ..sample()
        }
        .log_line(Action::Drop);
        assert!(by_path.contains("app=/usr/bin/curl(path)"), "{by_path}");
    }
}
