//! Stubs for non-macOS targets.
//!
//! NetworkExtension and SystemExtensions are Apple-only. These exist so the container app still
//! builds and the frontend can be developed on Linux or Windows; every command reports clearly
//! that the platform is unsupported rather than silently doing nothing.
//!
//! `test_connect` is the one exception: a bare TCP connect has nothing to do with
//! NetworkExtension, so it works for real here too, which is what lets the test panel be
//! developed on this platform as well.

use filter_types::{FilterStatus, TestConnectResult};
use tauri::{AppHandle, Runtime};

const MSG: &str = "the content filter is only available on macOS";

#[tauri::command]
pub(crate) async fn activate_extension<R: Runtime>(_app: AppHandle<R>) -> Result<(), String> {
    Err(MSG.into())
}

#[tauri::command]
pub(crate) async fn enable_filter<R: Runtime>(_app: AppHandle<R>) -> Result<FilterStatus, String> {
    Err(MSG.into())
}

#[tauri::command]
pub(crate) async fn disable_filter<R: Runtime>(_app: AppHandle<R>) -> Result<FilterStatus, String> {
    Err(MSG.into())
}

#[tauri::command]
pub(crate) async fn remove_filter<R: Runtime>(_app: AppHandle<R>) -> Result<FilterStatus, String> {
    Err(MSG.into())
}

#[tauri::command]
pub(crate) async fn filter_status<R: Runtime>(_app: AppHandle<R>) -> Result<FilterStatus, String> {
    Err(MSG.into())
}

#[tauri::command]
pub(crate) async fn test_connect(host: String, port: u16) -> Result<TestConnectResult, String> {
    tauri::async_runtime::spawn_blocking(move || filter_types::tcp_probe(&host, port))
        .await
        .map_err(|e| format!("background task failed: {e}"))
}
