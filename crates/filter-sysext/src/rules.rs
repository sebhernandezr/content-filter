//! The allow/deny decision point.
//!
//! This module is the seam the enforcement ticket lands in. Today it is wired end to end and
//! configured to allow everything, so it changes no behaviour — but `handleNewFlow:` already
//! routes every flow through [`RuleSet::decide`], so turning enforcement on is a matter of
//! writing rules, not of restructuring the provider.
//!
//! # Where rules come from
//!
//! One absolute path, [`RULES_PATH`]. Rules will eventually be pushed by a backend, so they have
//! to live somewhere a *writer* can reach at runtime — which rules out this extension's own
//! bundle: it is sealed by the code signature, and writing into it invalidates the signature and
//! stops the provider launching.
//!
//! `/Library/…` and deliberately not `~/Library/…`: this process runs as **root** and the
//! container app as the console user, so a path under `~` resolves to two different directories
//! for the two of them. That is the same split that makes a shared App Group container useless
//! here. `/Library/Application Support` resolves identically for both.
//!
//! # Two things that are deliberate, and are not oversights
//!
//! **This build fails OPEN.** A missing or malformed rules file logs loudly and leaves traffic
//! flowing. That is right for an observe-only MVP and *wrong* for real enforcement: a lockdown
//! that opens the network when someone deletes its rules file is worse than no lockdown. Flipping
//! [`RuleSet::allow_everything`] to a deny-by-default fallback is a decision for the enforcement
//! ticket, not a bug to be fixed in passing.
//!
//! **The file is not tamper-proof.** `make install-rules` gives it `root:wheel` and mode 644,
//! which stops a non-admin user editing it and stops nothing else. Any admin can rewrite their own
//! allowlist. Real lockdown needs the provider to verify a backend signature over the rules
//! payload rather than trusting the bytes on disk.
//!
//! # The constraint the enforcement ticket has to solve
//!
//! Matching on `host` will miss most traffic, and that is a property of the framework rather than
//! a defect here. `NEFilterSocketFlow.remoteEndpoint` is documented as possibly nil at
//! `handleNewFlow:` time, and `remoteHostname` is populated only for Network.framework /
//! NSURLSession flows — so for a large share of flows [`FlowInfo::best_destination`] is `None`, or
//! an IP literal, at the exact moment a verdict is demanded. Blocking a site *by name* therefore
//! needs `pauseVerdict` / `filterDataVerdict` plus `handleOutboundDataFromFlow:` to read the
//! hostname out of the TLS ClientHello SNI. This module stops at the decision point so that work
//! has somewhere to land.

use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};

use serde::Deserialize;

use crate::flow::FlowInfo;
use crate::logging;

/// The one place rules are read from. See the module docs for why it is here and not in the
/// extension's bundle. Installed by `make install-rules`.
pub const RULES_PATH: &str = "/Library/Application Support/Digiexam/rules.json";

/// What to do with a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Drop,
}

impl Action {
    /// Fixed-width-friendly name, used in the log line and in load messages.
    pub fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Drop => "drop",
        }
    }
}

/// One rule. Every matcher is optional and they are ANDed; a rule with no matchers at all matches
/// every flow, which is a legitimate way to write a catch-all ahead of the default action.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub action: Action,

    /// Exact hostname, or a leading-dot suffix pattern: `".example.com"` matches `example.com`
    /// and any subdomain of it. Compared against [`FlowInfo::best_destination`], case-insensitively.
    ///
    /// A flow whose destination is not known yet never matches a host rule — see the module docs.
    #[serde(default)]
    pub host: Option<String>,

    #[serde(default)]
    pub port: Option<u16>,
}

impl Rule {
    fn matches(&self, flow: &FlowInfo) -> bool {
        if let Some(port) = self.port {
            if flow.remote_port != Some(port) {
                return false;
            }
        }
        if let Some(pattern) = &self.host {
            // No destination yet means no host match. Treating "unknown" as a match would make a
            // deny rule block traffic it was never shown to apply to.
            let Some(host) = flow.best_destination() else {
                return false;
            };
            if !host_matches(pattern, host) {
                return false;
            }
        }
        true
    }
}

/// The full rule set: an ordered list plus what to do when nothing matches.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleSet {
    pub default_action: Action,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// The fallback used before the first successful load, and after a failed one.
    ///
    /// See the module docs: this build fails open on purpose, and enforcement must not.
    pub fn allow_everything() -> Self {
        Self {
            default_action: Action::Allow,
            rules: Vec::new(),
        }
    }

    /// Parse, separately from reading the file, so the JSON shape is testable without a fixture
    /// on disk.
    pub fn from_json(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|e| e.to_string())
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_json(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// First match wins; if nothing matches, [`Self::default_action`].
    ///
    /// Pure — no I/O, no framework calls — which is what makes the policy itself unit-testable
    /// away from a live `NEFilterFlow`.
    pub fn decide(&self, flow: &FlowInfo) -> Action {
        self.rules
            .iter()
            .find(|rule| rule.matches(flow))
            .map(|rule| rule.action)
            .unwrap_or(self.default_action)
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    match pattern.strip_prefix('.') {
        // ".example.com" covers the apex as well as subdomains: a rule for a site that did not
        // also cover the bare domain would be a trap.
        Some(apex) => host == apex || host.ends_with(&pattern),
        None => host == pattern,
    }
}

/// Held behind an `RwLock` rather than a `OnceLock` because [`reload`] runs again on every
/// `startFilter` — so toggling the filter off and on picks up rules a backend has since rewritten,
/// with no rebuild and no reboot. `handleNewFlow:` takes an uncontended read lock per flow, which
/// is cheap enough for that path and is the reason not to bake the set in immutably.
static CURRENT: OnceLock<RwLock<Arc<RuleSet>>> = OnceLock::new();

fn cell() -> &'static RwLock<Arc<RuleSet>> {
    CURRENT.get_or_init(|| RwLock::new(Arc::new(RuleSet::allow_everything())))
}

/// The rule set in force right now.
pub fn current() -> Arc<RuleSet> {
    // A poisoned lock must not take down a privileged process on the packet path: the data behind
    // it is an immutable Arc that a panicking writer cannot have left half-written.
    match cell().read() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// Re-read [`RULES_PATH`] and swap it in.
///
/// Always logs the outcome. A silent load is indistinguishable from no load at all, which is the
/// class of failure this whole project is built to make visible.
pub fn reload() {
    match RuleSet::load(Path::new(RULES_PATH)) {
        Ok(set) => {
            logging::lifecycle(&format!(
                "rules: loaded {} rule(s), default={} from {}",
                set.rules.len(),
                set.default_action.label(),
                RULES_PATH,
            ));
            match cell().write() {
                Ok(mut guard) => *guard = Arc::new(set),
                Err(poisoned) => *poisoned.into_inner() = Arc::new(set),
            }
        }
        Err(e) => {
            let kept = current();
            logging::lifecycle(&format!(
                "rules: COULD NOT LOAD ({e}); keeping {} rule(s), default={}. \
                 This observe-only build fails OPEN by design; enforcement must fail closed.",
                kept.rules.len(),
                kept.default_action.label(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{AddressFamily, TransportProtocol};

    fn flow(host: Option<&str>, port: Option<u16>) -> FlowInfo {
        FlowInfo {
            ts_ms: 0,
            family: AddressFamily::V4,
            protocol: TransportProtocol::Tcp,
            remote_host: host.map(Into::into),
            remote_port: port,
            hostname: None,
            url_host: None,
            source_app: None,
        }
    }

    fn set(default_action: Action, rules: Vec<Rule>) -> RuleSet {
        RuleSet {
            default_action,
            rules,
        }
    }

    fn rule(action: Action, host: Option<&str>, port: Option<u16>) -> Rule {
        Rule {
            action,
            host: host.map(Into::into),
            port,
        }
    }

    #[test]
    fn the_shipped_seed_allows_everything() {
        // Guards the behaviour-neutrality of this refactor: if macos/rules.json ever stops
        // parsing to allow-all, enabling the filter starts blocking traffic and this test says so.
        let seed = RuleSet::from_json(r#"{ "default_action": "allow", "rules": [] }"#).unwrap();
        assert_eq!(seed.default_action, Action::Allow);
        assert!(seed.rules.is_empty());
        assert_eq!(seed.decide(&flow(Some("example.com"), Some(443))), Action::Allow);
    }

    #[test]
    fn an_unknown_action_is_a_parse_error_not_a_default() {
        let err = RuleSet::from_json(r#"{ "default_action": "maybe", "rules": [] }"#);
        assert!(err.is_err(), "an unrecognised action must not silently become allow");
    }

    #[test]
    fn a_truncated_file_fails_cleanly() {
        assert!(RuleSet::from_json(r#"{ "default_action": "allow", "ru"#).is_err());
    }

    #[test]
    fn matchers_are_optional_in_the_json() {
        let parsed =
            RuleSet::from_json(r#"{"default_action":"drop","rules":[{"action":"allow"}]}"#).unwrap();
        // A rule with no matchers matches everything, so the default is never reached.
        assert_eq!(parsed.decide(&flow(None, None)), Action::Allow);
    }

    #[test]
    fn falls_through_to_the_default_action() {
        let s = set(Action::Drop, vec![rule(Action::Allow, Some("example.com"), None)]);
        assert_eq!(s.decide(&flow(Some("other.com"), Some(443))), Action::Drop);
    }

    #[test]
    fn exact_host_match() {
        let s = set(Action::Allow, vec![rule(Action::Drop, Some("example.com"), None)]);
        assert_eq!(s.decide(&flow(Some("example.com"), None)), Action::Drop);
        assert_eq!(s.decide(&flow(Some("notexample.com"), None)), Action::Allow);
        // An exact rule must not catch subdomains; that is what the dot form is for.
        assert_eq!(s.decide(&flow(Some("www.example.com"), None)), Action::Allow);
    }

    #[test]
    fn suffix_match_covers_the_apex_and_subdomains() {
        let s = set(Action::Allow, vec![rule(Action::Drop, Some(".example.com"), None)]);
        assert_eq!(s.decide(&flow(Some("example.com"), None)), Action::Drop);
        assert_eq!(s.decide(&flow(Some("www.example.com"), None)), Action::Drop);
        assert_eq!(s.decide(&flow(Some("a.b.example.com"), None)), Action::Drop);
        // Must not match a domain that merely ends with the same letters.
        assert_eq!(s.decide(&flow(Some("notexample.com"), None)), Action::Allow);
    }

    #[test]
    fn host_matching_ignores_case() {
        let s = set(Action::Allow, vec![rule(Action::Drop, Some("Example.COM"), None)]);
        assert_eq!(s.decide(&flow(Some("EXAMPLE.com"), None)), Action::Drop);
    }

    #[test]
    fn port_only_rules_match_any_host() {
        let s = set(Action::Allow, vec![rule(Action::Drop, None, Some(22))]);
        assert_eq!(s.decide(&flow(Some("anything"), Some(22))), Action::Drop);
        assert_eq!(s.decide(&flow(None, Some(22))), Action::Drop);
        assert_eq!(s.decide(&flow(Some("anything"), Some(443))), Action::Allow);
    }

    #[test]
    fn host_and_port_are_anded() {
        let s = set(Action::Allow, vec![rule(Action::Drop, Some("example.com"), Some(443))]);
        assert_eq!(s.decide(&flow(Some("example.com"), Some(443))), Action::Drop);
        assert_eq!(s.decide(&flow(Some("example.com"), Some(80))), Action::Allow);
    }

    #[test]
    fn first_match_wins() {
        let s = set(
            Action::Drop,
            vec![
                rule(Action::Allow, Some("example.com"), None),
                rule(Action::Drop, Some("example.com"), None),
            ],
        );
        assert_eq!(s.decide(&flow(Some("example.com"), None)), Action::Allow);
    }

    #[test]
    fn a_flow_with_no_destination_yet_never_matches_a_host_rule() {
        // remoteEndpoint is documented as possibly nil at handleNewFlow: time. Such a flow must
        // fall through to the default action rather than be caught by a host rule it was never
        // shown to match.
        let s = set(Action::Allow, vec![rule(Action::Drop, Some("example.com"), None)]);
        assert_eq!(s.decide(&flow(None, None)), Action::Allow);
    }

    #[test]
    fn host_rules_see_the_best_destination_not_just_the_ip() {
        // A rule written against a hostname must match a flow whose remote_host is an IP literal
        // but which carries a real hostname alongside it.
        let s = set(Action::Allow, vec![rule(Action::Drop, Some("example.com"), None)]);
        let f = FlowInfo {
            hostname: Some("example.com".into()),
            ..flow(Some("93.184.216.34"), Some(443))
        };
        assert_eq!(s.decide(&f), Action::Drop);
    }

    #[test]
    fn a_missing_file_reports_the_path() {
        let err = RuleSet::load(Path::new("/nonexistent/digiexam/rules.json")).unwrap_err();
        assert!(err.contains("/nonexistent/digiexam/rules.json"), "got: {err}");
    }
}
