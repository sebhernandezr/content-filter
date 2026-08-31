//! Filter configuration via `NEFilterManager`.
//!
//! `NEFilterManager.sharedManager` is a singleton: one filter configuration per app. Saving an
//! enabled configuration is what actually causes macOS to launch the provider process, which is
//! why the extension being *activated* is necessary but not sufficient for flows to arrive.
//!
//! Every call follows the same shape: dispatch onto the main queue, run a nested
//! `loadFromPreferences` → mutate → `saveToPreferences` chain inside completion blocks, and have
//! the calling worker thread wait on a channel. The nesting is not stylistic — the completion
//! handlers fire on the main queue and `NEFilterManager` is not `Send`, so the whole chain has to
//! stay on that queue.

use std::sync::mpsc::channel;
use std::time::Duration;

use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2_foundation::{NSError, NSString};
use objc2_network_extension::{NEFilterManager, NEFilterProviderConfiguration};

/// Bundle identifier of the content-filter system extension. Must match `SYSEXT_ID` in
/// `macos/identity.sh` and the `CFBundleIdentifier` in `macos/sysext/Info.plist`.
pub const FILTER_SYSEXT_ID: &str = "com.digiexam.macos.NetworkExtensions.ContentFilter";

/// Description shown in System Settings → Network → Filters.
const FILTER_DESCRIPTION: &str = "Digiexam Content Filter";

fn err_str(e: *mut NSError) -> String {
    // SAFETY: only called with a non-null NSError* handed to us by the framework.
    unsafe { (*e).localizedDescription().to_string() }
}

/// Enable the filter, creating or updating the configuration as needed.
///
/// This is the call that starts the provider process. Must be called off the main thread.
pub fn enable() -> Result<(), String> {
    let (tx, rx) = channel::<Result<(), String>>();

    DispatchQueue::main().exec_async(move || {
        // SAFETY: singleton accessor.
        let manager = unsafe { NEFilterManager::sharedManager() };
        let mgr = manager.clone();

        let load_block = RcBlock::new(move |err: *mut NSError| {
            if !err.is_null() {
                let _ = tx.send(Err(format!("loadFromPreferences failed: {}", err_str(err))));
                return;
            }

            // SAFETY: constructing and populating a configuration object, then handing it to the
            // manager, all on the main queue as the API requires.
            unsafe {
                let config = NEFilterProviderConfiguration::new();

                // Socket-level filtering: covers all TCP and UDP, IPv4 and IPv6. This is what
                // causes flows to be delivered as NEFilterSocketFlow, which is where the family,
                // protocol and remote endpoint we log come from.
                config.setFilterSockets(true);
                // Packet-level filtering is a different, heavier provider mode and is not what
                // this filter is. Explicit rather than relying on the default.
                config.setFilterPackets(false);

                // Names the extension that provides the filter. Without this macOS has a
                // configuration but no provider to run.
                config.setFilterDataProviderBundleIdentifier(Some(&NSString::from_str(
                    FILTER_SYSEXT_ID,
                )));

                // No vendorConfiguration is set: the observe-only build has no policy to pass.
                // The allowlist lands here in the enforcement follow-up.

                mgr.setProviderConfiguration(Some(&config));
                mgr.setLocalizedDescription(Some(&NSString::from_str(FILTER_DESCRIPTION)));
                mgr.setEnabled(true);
            }

            let tx_save = tx.clone();
            let save_block = RcBlock::new(move |save_err: *mut NSError| {
                if !save_err.is_null() {
                    let _ = tx_save.send(Err(format!(
                        "saveToPreferences failed: {}",
                        err_str(save_err)
                    )));
                    return;
                }
                let _ = tx_save.send(Ok(()));
            });
            // SAFETY: save with a completion block that lives as long as the call needs it.
            unsafe { mgr.saveToPreferencesWithCompletionHandler(&save_block) };
        });

        // SAFETY: load with a completion block; the manager is the main-queue singleton.
        unsafe { manager.loadFromPreferencesWithCompletionHandler(&load_block) };
    });

    // Generous: the first save can prompt for an admin password to install the configuration.
    rx.recv_timeout(Duration::from_secs(60))
        .map_err(|_| "enabling the filter timed out".to_owned())?
}

/// Disable the filter, keeping its configuration in System Settings.
///
/// The provider is stopped (its `stopFilterWithReason:` runs). Must be called off the main thread.
pub fn disable() -> Result<(), String> {
    mutate_and_save(|manager| {
        // SAFETY: setter on the main-queue singleton.
        unsafe { manager.setEnabled(false) };
    })
}

/// Remove the configuration entirely from System Settings.
pub fn remove() -> Result<(), String> {
    let (tx, rx) = channel::<Result<(), String>>();

    DispatchQueue::main().exec_async(move || {
        let manager = unsafe { NEFilterManager::sharedManager() };
        let mgr = manager.clone();
        let load_block = RcBlock::new(move |err: *mut NSError| {
            if !err.is_null() {
                let _ = tx.send(Err(format!("loadFromPreferences failed: {}", err_str(err))));
                return;
            }
            let tx_rm = tx.clone();
            let rm_block = RcBlock::new(move |rm_err: *mut NSError| {
                if !rm_err.is_null() {
                    let _ = tx_rm.send(Err(format!(
                        "removeFromPreferences failed: {}",
                        err_str(rm_err)
                    )));
                    return;
                }
                let _ = tx_rm.send(Ok(()));
            });
            // SAFETY: remove with a completion block.
            unsafe { mgr.removeFromPreferencesWithCompletionHandler(&rm_block) };
        });
        unsafe { manager.loadFromPreferencesWithCompletionHandler(&load_block) };
    });

    rx.recv_timeout(Duration::from_secs(30))
        .map_err(|_| "removing the filter timed out".to_owned())?
}

/// Whether a filter configuration is currently enabled.
///
/// Note what this does and does not tell you: it reflects the saved *configuration*, not whether
/// a provider process is running. It can report `true` while the extension is staged and inert —
/// which is precisely the state that reads as "it's in System Settings but nothing is filtered".
/// Pair it with the activation state before concluding the filter works.
pub fn is_enabled() -> Result<bool, String> {
    let (tx, rx) = channel::<Result<bool, String>>();

    DispatchQueue::main().exec_async(move || {
        let manager = unsafe { NEFilterManager::sharedManager() };
        let mgr = manager.clone();
        let load_block = RcBlock::new(move |err: *mut NSError| {
            if !err.is_null() {
                let _ = tx.send(Err(format!("loadFromPreferences failed: {}", err_str(err))));
                return;
            }
            // SAFETY: property read on the main-queue singleton.
            let _ = tx.send(Ok(unsafe { mgr.isEnabled() }));
        });
        unsafe { manager.loadFromPreferencesWithCompletionHandler(&load_block) };
    });

    rx.recv_timeout(Duration::from_secs(15))
        .map_err(|_| "reading filter status timed out".to_owned())?
}

/// Shared load → mutate → save chain for the simple cases.
fn mutate_and_save<F>(mutate: F) -> Result<(), String>
where
    F: Fn(&NEFilterManager) + Send + 'static,
{
    let (tx, rx) = channel::<Result<(), String>>();

    DispatchQueue::main().exec_async(move || {
        let manager = unsafe { NEFilterManager::sharedManager() };
        let mgr = manager.clone();
        let load_block = RcBlock::new(move |err: *mut NSError| {
            if !err.is_null() {
                let _ = tx.send(Err(format!("loadFromPreferences failed: {}", err_str(err))));
                return;
            }
            mutate(&mgr);
            let tx_save = tx.clone();
            let save_block = RcBlock::new(move |save_err: *mut NSError| {
                if !save_err.is_null() {
                    let _ = tx_save.send(Err(format!(
                        "saveToPreferences failed: {}",
                        err_str(save_err)
                    )));
                    return;
                }
                let _ = tx_save.send(Ok(()));
            });
            unsafe { mgr.saveToPreferencesWithCompletionHandler(&save_block) };
        });
        unsafe { manager.loadFromPreferencesWithCompletionHandler(&load_block) };
    });

    rx.recv_timeout(Duration::from_secs(30))
        .map_err(|_| "saving filter preferences timed out".to_owned())?
}
