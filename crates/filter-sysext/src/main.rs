//! `digiexam-content-filter` — the NEFilterDataProvider **system extension**.
//!
//! This binary is the executable inside
//! `com.digiexam.macos.NetworkExtensions.ContentFilter.systemextension`. It does exactly three
//! things and deliberately nothing else: register the provider class with the ObjC runtime,
//! declare itself a system-extension provider, and then park on the main dispatch queue so the
//! framework can call into [`provider::FilterProvider`].
//!
//! There is no filtering logic here, and none in the provider either — this is the observe-only
//! MVP. Every flow is logged and allowed.
//!
//! # Watching it work
//!
//! ```text
//! log stream --predicate 'subsystem == "com.digiexam.macos.NetworkExtensions"' --info
//! ```
//!
//! # Lifecycle
//!
//! Nothing here runs until the container app has (1) activated the extension via
//! `OSSystemExtensionRequest` and (2) enabled a filter configuration through `NEFilterManager`.
//! Activation alone does not start this process — that distinction is what makes an extension
//! appear in System Settings while never seeing a single flow.

mod attribution;
mod flow;
mod logging;
mod provider;

use objc2::ClassType;
use objc2_network_extension::NEProvider;

unsafe extern "C" {
    /// `dispatch_main()` — the C equivalent of Swift's `dispatchMain()`. Never returns.
    fn dispatch_main() -> !;
}

fn main() {
    logging::lifecycle("main: content-filter extension starting");

    // Force a static reference to the class so the linker cannot dead-strip it, and so it is
    // registered with the ObjC runtime before startSystemExtensionMode looks it up.
    //
    // This is load-bearing and its absence fails silently: the extension would start, the
    // framework would find no class registered for `com.apple.networkextension.filter-data`, and
    // handleNewFlow: would never be called.
    let class = provider::FilterProvider::class();
    logging::lifecycle(&format!(
        "main: registered provider class '{}' (must match NEProviderClasses in Info.plist)",
        class.name().to_str().unwrap_or("<non-utf8>"),
    ));

    // Tells the NetworkExtension framework that this process is a system-extension provider.
    // Equivalent to Swift's `NEProvider.startSystemExtensionMode()`.
    // SAFETY: called exactly once, from main, before the dispatch main queue is entered.
    unsafe { NEProvider::startSystemExtensionMode() };
    logging::lifecycle("main: startSystemExtensionMode() returned; parking on the main queue");

    // Park forever. The framework services provider callbacks on this queue; returning from main
    // would terminate the extension.
    // SAFETY: dispatch_main never returns and takes no arguments.
    unsafe { dispatch_main() }
}
