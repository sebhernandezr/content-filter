//! Stubs for non-macOS targets.
//!
//! NetworkExtension and SystemExtensions are Apple-only. These exist so the container app still
//! builds and the frontend can be developed on Linux or Windows; every command reports clearly
//! that the platform is unsupported rather than silently doing nothing.

use filter_types::{FilterStatus, FlowRecord};
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
pub(crate) async fn recent_flows<R: Runtime>(
    _app: AppHandle<R>,
    _limit: Option<usize>,
) -> Result<Vec<FlowRecord>, String> {
    Ok(Vec::new())
}
