//! System-extension activation via `OSSystemExtensionRequest`.
//!
//! Activation is what installs the extension and gets it approved by the user. It is a **separate
//! step** from enabling the filter (see [`crate::filter_manager`]), and conflating the two is how
//! an extension ends up visible in System Settings while no provider process ever runs.

use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use filter_types::ActivationState;
use objc2::rc::Retained;
use objc2::runtime::{NSObject, ProtocolObject};
use objc2::{define_class, msg_send, AllocAnyThread, DefinedClass};
use objc2_foundation::{NSError, NSObjectProtocol, NSString};
use objc2_system_extensions::{
    OSSystemExtensionManager, OSSystemExtensionProperties, OSSystemExtensionReplacementAction,
    OSSystemExtensionRequest, OSSystemExtensionRequestDelegate, OSSystemExtensionRequestResult,
};

/// How long to wait for a terminal delegate callback.
///
/// Generous, because the window includes the user walking to System Settings and approving the
/// extension. A timeout is not a failure of the request: the request stays live on Apple's side,
/// and a later call will complete immediately once approval has happened.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(180);

struct ActIvars {
    tx: Sender<ActivationState>,
    kind: RequestKind,
}

define_class!(
    // SAFETY: a plain NSObject subclass with no subclassing requirements and no Drop.
    #[unsafe(super(NSObject))]
    #[name = "DigiexamSysExtDelegate"]
    #[ivars = ActIvars]
    struct ActDelegate;

    unsafe impl NSObjectProtocol for ActDelegate {}

    // SAFETY: these are the OSSystemExtensionRequestDelegate methods with their declared
    // signatures. Callbacks arrive on the queue given to the request (the main queue); each one
    // just forwards a state onto the channel, which is cheap and non-blocking.
    unsafe impl OSSystemExtensionRequestDelegate for ActDelegate {
        /// An older copy is already installed. Replace it with the one we ship.
        #[unsafe(method(request:actionForReplacingExtension:withExtension:))]
        fn action_for_replacing(
            &self,
            _request: &OSSystemExtensionRequest,
            _existing: &OSSystemExtensionProperties,
            _replacement: &OSSystemExtensionProperties,
        ) -> OSSystemExtensionReplacementAction {
            OSSystemExtensionReplacementAction::Replace
        }

        /// The request is parked until the user approves in System Settings. Not terminal: we
        /// report the state so the UI can tell the user where to click, and keep waiting.
        #[unsafe(method(requestNeedsUserApproval:))]
        fn needs_user_approval(&self, _request: &OSSystemExtensionRequest) {
            let _ = self.ivars().tx.send(ActivationState::NeedsUserApproval);
        }

        #[unsafe(method(request:didFinishWithResult:))]
        fn did_finish(
            &self,
            _request: &OSSystemExtensionRequest,
            result: OSSystemExtensionRequestResult,
        ) {
            // `WillCompleteAfterReboot` means the extension was only STAGED. macOS never
            // hot-swaps a running provider, so when the installed copy has a different
            // CFBundleVersion the old one keeps running and the new one waits for a reboot.
            //
            // Reporting this as success is exactly the bug that let 15 stale copies accumulate on
            // the dev machine with none ever active, while the app cheerfully claimed the filter
            // was installed. It gets its own state, and the UI says so.
            //
            // A finished-without-reboot result means different things for the two request kinds:
            // for Activate it means the extension is now Active, but for Deactivate it means the
            // extension is gone, i.e. Idle. Reporting Active here regardless of kind was the bug
            // that left the UI stuck on "activated and running" after a successful removal, since
            // that (wrong) state got cached and nothing but an app restart re-derived the truth.
            let state = if result == OSSystemExtensionRequestResult::WillCompleteAfterReboot {
                ActivationState::NeedsReboot
            } else {
                match self.ivars().kind {
                    RequestKind::Activate => ActivationState::Active,
                    RequestKind::Deactivate => ActivationState::Idle,
                }
            };
            let _ = self.ivars().tx.send(state);
        }

        #[unsafe(method(request:didFailWithError:))]
        fn did_fail(&self, _request: &OSSystemExtensionRequest, error: &NSError) {
            let _ = self.ivars().tx.send(ActivationState::Failed(format!(
                "activation failed: {} (code {})",
                error.localizedDescription(),
                error.code(),
            )));
        }
    }
);

impl ActDelegate {
    fn new(tx: Sender<ActivationState>, kind: RequestKind) -> Retained<Self> {
        let this = Self::alloc().set_ivars(ActIvars { tx, kind });
        // SAFETY: NSObject's designated initializer.
        unsafe { msg_send![super(this), init] }
    }
}

/// Ask macOS to activate the embedded system extension.
///
/// Must be called **off** the main thread: delegate callbacks are delivered on the main queue, so
/// this thread waits on a channel while the app's run loop services them. Calling it from the
/// main thread deadlocks.
///
/// Requirements that are easy to miss and fail opaquely:
/// - the calling app needs `com.apple.developer.system-extension.install`
/// - the `.app` must live in `/Applications`; anywhere else fails with
///   `OSSystemExtensionErrorUnsupportedParentBundleLocation`
pub fn activate(bundle_id: &str) -> ActivationState {
    submit(bundle_id, RequestKind::Activate)
}

/// Ask macOS to deactivate (uninstall) the extension.
pub fn deactivate(bundle_id: &str) -> ActivationState {
    submit(bundle_id, RequestKind::Deactivate)
}

#[derive(Clone, Copy)]
enum RequestKind {
    Activate,
    Deactivate,
}

fn submit(bundle_id: &str, kind: RequestKind) -> ActivationState {
    let (tx, rx) = channel::<ActivationState>();
    let delegate = ActDelegate::new(tx, kind);
    let ident = NSString::from_str(bundle_id);
    let queue = dispatch2::DispatchQueue::main();

    // SAFETY: the standard SystemExtensions activation API; `queue` is the main queue and
    // `ident` outlives the call.
    let request = unsafe {
        match kind {
            RequestKind::Activate => {
                OSSystemExtensionRequest::activationRequestForExtension_queue(&ident, queue)
            }
            RequestKind::Deactivate => {
                OSSystemExtensionRequest::deactivationRequestForExtension_queue(&ident, queue)
            }
        }
    };

    // SAFETY: the delegate is a valid object conforming to the protocol, kept alive below.
    unsafe { request.setDelegate(Some(ProtocolObject::from_ref(&*delegate))) };

    // SAFETY: singleton accessor; submitting a well-formed request.
    let manager = unsafe { OSSystemExtensionManager::sharedManager() };
    unsafe { manager.submitRequest(&request) };

    // `requestNeedsUserApproval:` is not terminal, so keep receiving until a terminal state
    // arrives or the window closes. Reporting the last non-terminal state on timeout is what
    // lets the UI say "still waiting for your approval" rather than a bare timeout.
    let mut last = ActivationState::Pending;
    let deadline = std::time::Instant::now() + APPROVAL_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            // Active/NeedsReboot/Idle are all terminal — Idle is what a successful Deactivate
            // sends (see did_finish above). Missing it here was the bug: it fell into the
            // catch-all "keep waiting" arm below (meant only for NeedsUserApproval), so a
            // successful removal blocked this call for the full APPROVAL_TIMEOUT instead of
            // returning immediately.
            Ok(
                state @ (ActivationState::Active
                | ActivationState::NeedsReboot
                | ActivationState::Idle),
            ) => {
                last = state;
                break;
            }
            Ok(state @ ActivationState::Failed(_)) => {
                last = state;
                break;
            }
            Ok(state) => last = state, // NeedsUserApproval: keep waiting
            Err(_) => break,
        }
    }

    // `request` and `delegate` are held on this frame for the whole wait on purpose: dropping the
    // request cancels a still-pending approval.
    drop(request);
    drop(delegate);

    if matches!(last, ActivationState::NeedsUserApproval | ActivationState::Pending) {
        return ActivationState::NeedsUserApproval;
    }
    last
}
