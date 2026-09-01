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
//! from a terminal now, with `make logs-flows` — so that wire format,
//! and the crate's reason for being shared with `filter-sysext`, went with it. See
//! `crates/filter-sysext/src/flow.rs` for the extension-side equivalent, which has no need to be
//! shared or serializable.

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
