//! Tauri commands exposed to the frontend.
//!
//! Every command that touches an Apple framework runs on a blocking thread pool via
//! `spawn_blocking`. This is not incidental: [`crate::sysext`] and [`crate::filter_manager`]
//! dispatch their work onto the **main queue** and then block waiting on a channel, so calling
//! them from the main thread would deadlock against the very run loop that has to service the
//! completion handlers.

use filter_types::{ActivationState, FilterStatus};
use tauri::{AppHandle, Manager, Runtime};

use crate::{filter_manager, sysext, FilterState};

type CmdResult<T> = Result<T, String>;

/// Run `f` off the main thread and flatten the join error.
async fn blocking<T, F>(f: F) -> CmdResult<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("background task failed: {e}"))
}

/// Install and activate the system extension, prompting the user for approval if needed.
///
/// Safe to call repeatedly: once approved, subsequent calls complete immediately.
#[tauri::command]
pub(crate) async fn activate_extension<R: Runtime>(app: AppHandle<R>) -> CmdResult<ActivationState> {
    let state = blocking(|| sysext::activate(filter_manager::FILTER_SYSEXT_ID)).await?;
    *app.state::<FilterState>().activation.lock().unwrap() = state.clone();
    Ok(state)
}

/// Activate the extension if necessary, then enable the filter.
///
/// Activation comes first and its result gates the enable: enabling a filter whose provider is
/// only staged produces a configuration that shows up in System Settings and filters nothing,
/// which is the exact failure this project exists to avoid. If the extension needs approval or a
/// reboot, that is reported and the enable is not attempted.
#[tauri::command]
pub(crate) async fn enable_filter<R: Runtime>(app: AppHandle<R>) -> CmdResult<FilterStatus> {
    let activation = blocking(|| sysext::activate(filter_manager::FILTER_SYSEXT_ID)).await?;
    *app.state::<FilterState>().activation.lock().unwrap() = activation.clone();

    match &activation {
        ActivationState::Active => {}
        ActivationState::NeedsUserApproval => {
            return Err("Approve the extension in System Settings → General → Login Items & \
                        Extensions → Network Extensions, then try again."
                .into())
        }
        ActivationState::NeedsReboot => {
            return Err("A different version of the extension is still running. Restart the Mac, \
                        then enable the filter again."
                .into())
        }
        ActivationState::Failed(e) => return Err(e.clone()),
        other => return Err(format!("extension not ready: {other:?}")),
    }

    blocking(filter_manager::enable).await??;
    status_now(&app).await
}

/// Turn the filter off, leaving its configuration in System Settings.
#[tauri::command]
pub(crate) async fn disable_filter<R: Runtime>(app: AppHandle<R>) -> CmdResult<FilterStatus> {
    blocking(filter_manager::disable).await??;
    status_now(&app).await
}

/// Remove the filter configuration entirely, and deactivate the extension.
#[tauri::command]
pub(crate) async fn remove_filter<R: Runtime>(app: AppHandle<R>) -> CmdResult<FilterStatus> {
    blocking(filter_manager::remove).await??;
    let activation = blocking(|| sysext::deactivate(filter_manager::FILTER_SYSEXT_ID)).await?;
    *app.state::<FilterState>().activation.lock().unwrap() = activation;
    status_now(&app).await
}

/// Current filter status.
#[tauri::command]
pub(crate) async fn filter_status<R: Runtime>(app: AppHandle<R>) -> CmdResult<FilterStatus> {
    status_now(&app).await
}

/// Read the live status: configuration state from NEFilterManager, activation state from what we
/// last observed.
async fn status_now<R: Runtime>(app: &AppHandle<R>) -> CmdResult<FilterStatus> {
    let enabled = blocking(filter_manager::is_enabled).await??;
    let state = app.state::<FilterState>();
    let activation = state.activation.lock().unwrap().clone();
    Ok(FilterStatus { activation, enabled })
}
