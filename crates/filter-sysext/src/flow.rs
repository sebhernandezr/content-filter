//! Turning an `NEFilterFlow` into a [`FlowRecord`].
//!
//! Everything the ticket asks to observe — remote host and port, transport protocol, IPv4 vs
//! IPv6 — comes from `NEFilterSocketFlow`, which is the concrete subclass we get when the filter
//! is configured with `filterSockets = true`.

use std::time::{SystemTime, UNIX_EPOCH};

use filter_types::{AddressFamily, FlowRecord, TransportProtocol, Verdict};
use objc2::rc::Retained;
#[allow(deprecated)] // see remote_endpoint_parts
use objc2_network_extension::NWHostEndpoint;
use objc2_network_extension::{NEFilterFlow, NEFilterSocketFlow};

use crate::attribution;

/// Build a record for `flow`.
///
/// Never fails and never panics: this runs on the framework's callback path for every connection
/// on the machine, inside a privileged process. A missing field becomes `None`, not an error.
pub fn record_for(flow: &NEFilterFlow) -> FlowRecord {
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

    FlowRecord {
        ts_ms: now_ms(),
        family,
        protocol,
        remote_host,
        remote_port,
        hostname,
        url_host,
        source_app: attribution::source_bundle_id(flow),
        // Observe-only build: the verdict is a constant. Enforcement replaces this in the
        // follow-up ticket, which is the only line here that should need to change.
        verdict: Verdict::Allow,
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
