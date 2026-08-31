//! `FilterProvider` — the `NEFilterDataProvider` subclass the NetworkExtension framework
//! instantiates inside this extension.
//!
//! The class is registered with the ObjC runtime under the name `FilterProvider`, which must
//! match the value of `NEProviderClasses[com.apple.networkextension.filter-data]` in
//! `macos/sysext/Info.plist`. If those two strings drift, the extension launches and starts
//! normally and `handleNewFlow:` is simply never called — indistinguishable, from the outside,
//! from a filter that does not work.

use block2::DynBlock;
use objc2::rc::Retained;
use objc2::{define_class, AnyThread};
use objc2_foundation::{NSError, NSObjectProtocol};
use objc2_network_extension::{
    NEFilterDataProvider, NEFilterFlow, NEFilterNewFlowVerdict, NEProviderStopReason,
};

use crate::{flow, logging};

define_class!(
    // SAFETY:
    // - NEFilterDataProvider imposes no additional subclassing requirements beyond overriding
    //   the lifecycle methods, which we do below.
    // - This class implements no Drop.
    #[unsafe(super = NEFilterDataProvider)]
    #[thread_kind = AnyThread]
    #[name = "FilterProvider"]
    pub struct FilterProvider;

    // SAFETY: NSObjectProtocol carries no safety requirements of its own, and the method bodies
    // below are safe. objc2 permits method definitions in any impl block within define_class!.
    unsafe impl NSObjectProtocol for FilterProvider {
        /// `-[NEFilterDataProvider startFilterWithCompletionHandler:]`
        ///
        /// Reports success and does nothing else — deliberately.
        ///
        /// It is tempting to apply `NEFilterSettings` here. We do not, because the framework
        /// default is already exactly what an observe-only build wants. Apple's header for
        /// `-[NEFilterSettings initWithRules:defaultAction:]` states: *"The default defaultAction
        /// is NEFilterActionFilterData"*, and `NEFilterActionFilterData` means "call this
        /// provider's handleNewFlow: method with the flow". So with no settings applied at all,
        /// every flow is delivered to us.
        ///
        /// Calling `applySettings:` would therefore add no capability and one failure mode: if
        /// the call fails or the settings are mis-shaped, flow delivery stops silently, which is
        /// precisely the symptom this MVP exists to rule out. Rules become worthwhile in the
        /// enforcement follow-up, as a performance filter so the provider is not consulted for
        /// traffic it will always allow.
        #[unsafe(method(startFilterWithCompletionHandler:))]
        fn start_filter(&self, completion_handler: &DynBlock<dyn Fn(*mut NSError)>) {
            logging::lifecycle(
                "startFilter: provider started (observe-only build: every flow is allowed). \
                 No NEFilterSettings applied — the framework default action is already FilterData.",
            );
            // nil error == started successfully. Until this is called the framework considers the
            // filter to be still starting and delivers nothing.
            completion_handler.call((std::ptr::null_mut(),));
        }

        /// `-[NEFilterDataProvider stopFilterWithReason:completionHandler:]`
        ///
        /// The reason code is worth logging verbatim: it distinguishes a clean user-initiated
        /// disable from the provider being torn down because the configuration was removed, the
        /// extension was replaced, or something failed.
        #[unsafe(method(stopFilterWithReason:completionHandler:))]
        fn stop_filter(
            &self,
            reason: NEProviderStopReason,
            completion_handler: &DynBlock<dyn Fn()>,
        ) {
            logging::lifecycle(&format!(
                "stopFilter: reason={} ({})",
                reason.0,
                stop_reason_label(reason),
            ));
            completion_handler.call(());
        }

        /// `-[NEFilterDataProvider handleNewFlow:]`
        ///
        /// Called once per new flow, concurrently, on the framework's queue. Logs the flow and
        /// allows it.
        ///
        /// `method_id` rather than `method` is required: this returns a retained object, and the
        /// plain `method` form would demand `Retained<NEFilterNewFlowVerdict>: Encode`, which
        /// does not (and should not) exist.
        #[unsafe(method_id(handleNewFlow:))]
        fn handle_new_flow(&self, flow: &NEFilterFlow) -> Retained<NEFilterNewFlowVerdict> {
            logging::flow(&flow::record_for(flow));

            // The entire enforcement decision for this ticket. The follow-up replaces this single
            // expression; everything around it — extraction, logging, the wire format — stays.
            // SAFETY: a framework class method returning an autoreleased verdict singleton.
            unsafe { NEFilterNewFlowVerdict::allowVerdict() }
        }
    }
);

/// Human-readable name for an `NEProviderStopReason`, so the log says why rather than just a
/// number. Unknown values are still printed numerically by the caller.
fn stop_reason_label(reason: NEProviderStopReason) -> &'static str {
    match reason.0 {
        0 => "None",
        1 => "UserInitiated",
        2 => "ProviderFailed",
        3 => "NoNetworkAvailable",
        4 => "UnrecoverableNetworkChange",
        5 => "ProviderDisabled",
        6 => "AuthenticationCanceled",
        7 => "ConfigurationFailed",
        8 => "IdleTimeout",
        9 => "ConfigurationDisabled",
        10 => "ConfigurationRemoved",
        11 => "Superseded",
        12 => "UserLogout",
        13 => "UserSwitch",
        14 => "ConnectionFailed",
        15 => "Sleep",
        16 => "AppUpdate",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_reasons_are_named() {
        assert_eq!(stop_reason_label(NEProviderStopReason(1)), "UserInitiated");
        assert_eq!(stop_reason_label(NEProviderStopReason(10)), "ConfigurationRemoved");
        assert_eq!(stop_reason_label(NEProviderStopReason(999)), "unknown");
    }
}
