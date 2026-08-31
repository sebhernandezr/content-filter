//! Tauri plugin driving the Digiexam content-filter system extension.
//!
//! # The two-step model, and why it matters
//!
//! Getting flows requires **two independent things**, and the whole point of separating them in
//! this API is that they fail separately:
//!
//! 1. **Activation** ([`sysext`]) — `OSSystemExtensionRequest` installs the extension and gets it
//!    approved by the user. Reported by [`filter_types::ActivationState`].
//! 2. **Enabling** ([`filter_manager`]) — saving an enabled `NEFilterManager` configuration is
//!    what actually launches the provider process.
//!
//! Step 2 succeeding while step 1 has not really finished is the failure this project was built
//! to make impossible to miss: the configuration appears in System Settings → Network, the app
//! reports "enabled", and no provider process exists to receive a single flow.

#[cfg(target_os = "macos")]
mod commands;
#[cfg(target_os = "macos")]
mod filter_manager;
#[cfg(target_os = "macos")]
mod flow_log;
#[cfg(target_os = "macos")]
mod sysext;

#[cfg(not(target_os = "macos"))]
mod unsupported;

use std::sync::{Arc, Mutex};

use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

/// Plugin-wide state, reachable from commands via `app.state::<FilterState>()`.
#[derive(Default)]
pub struct FilterState {
    /// Buffered flow records, filled by the `log stream` tail.
    #[cfg(target_os = "macos")]
    pub flows: Arc<Mutex<flow_log::FlowBuffer>>,
    /// The running tail. Held so it is not dropped (which would kill the child process).
    #[cfg(target_os = "macos")]
    pub tail: Mutex<Option<flow_log::FlowTail>>,
    /// Last activation outcome, so the UI can show it without re-submitting a request.
    pub activation: Mutex<filter_types::ActivationState>,
}

impl FilterState {
    fn new() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            flows: Arc::new(Mutex::new(flow_log::FlowBuffer::default())),
            #[cfg(target_os = "macos")]
            tail: Mutex::new(None),
            activation: Mutex::new(filter_types::ActivationState::Idle),
        }
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("content-filter")
        .invoke_handler(tauri::generate_handler![
            commands::activate_extension,
            commands::enable_filter,
            commands::disable_filter,
            commands::remove_filter,
            commands::filter_status,
            commands::recent_flows,
        ])
        .setup(|app, _api| {
            app.manage(FilterState::new());

            // Start tailing immediately, not on first enable. Records emitted between the
            // provider starting and the user opening the flow view would otherwise be lost, and
            // an empty view would be ambiguous between "no flows" and "not listening yet".
            #[cfg(target_os = "macos")]
            {
                let state = app.state::<FilterState>();
                match flow_log::start(state.flows.clone()) {
                    Ok(tail) => *state.tail.lock().unwrap() = Some(tail),
                    // Non-fatal: the filter still works, only the in-app flow view is blind.
                    // Console.app remains available, which is the point of using os_log.
                    Err(e) => eprintln!("[content-filter] flow log tail unavailable: {e}"),
                }
            }
            Ok(())
        })
        .build()
}

#[cfg(not(target_os = "macos"))]
use unsupported as commands;
