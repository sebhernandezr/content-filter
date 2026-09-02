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
//!
//! Flow records themselves are not part of this plugin: watch them in a terminal with
//! `make logs`, not in the app window.

#[cfg(target_os = "macos")]
mod commands;
#[cfg(target_os = "macos")]
mod filter_manager;
#[cfg(target_os = "macos")]
mod sysext;

#[cfg(not(target_os = "macos"))]
mod unsupported;

use std::sync::Mutex;

use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

/// Plugin-wide state, reachable from commands via `app.state::<FilterState>()`.
#[derive(Default)]
pub struct FilterState {
    /// Last activation outcome, so the UI can show it without re-submitting a request.
    pub activation: Mutex<filter_types::ActivationState>,
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("content-filter")
        .invoke_handler(tauri::generate_handler![
            commands::activate_extension,
            commands::enable_filter,
            commands::disable_filter,
            commands::remove_filter,
            commands::filter_status,
            commands::test_connect,
        ])
        .setup(|app, _api| {
            app.manage(FilterState::default());
            Ok(())
        })
        .build()
}

#[cfg(not(target_os = "macos"))]
use unsupported as commands;
