//! The allow/deny decision point — now an allowlist keyed on **(source app, destination)**.
//!
//! `handleNewFlow:` routes every flow through [`RuleSet::decide`]. The MVP this seam serves is
//! four provable statements: one named app can reach one named destination; nothing else can
//! reach that destination; that app cannot reach anything else; and both IPv4 and IPv6 are
//! covered. The first two require the rule key to include *who is asking*, which is why
//! [`Rule::app`] exists. See [`crate::attribution`] for where that name comes from — and, just
//! as importantly, for what it does not prove.
//!
//! # Where rules come from
//!
//! One absolute path, [`RULES_PATH`]. Rules are expected to eventually come from a backend, so
//! they have to live somewhere a *writer* can reach at runtime — which rules out this extension's
//! own bundle: it is sealed by the code signature, and writing into it invalidates the signature
//! and stops the provider launching.
//!
//! `/Library/…` and deliberately not `~/Library/…`: this process runs as **root** and the
//! container app as the console user, so a path under `~` resolves to two different directories
//! for the two of them. That is the same split that makes a shared App Group container useless
//! here. `/Library/Application Support` resolves identically for both.
//!
//! # This is an allowlist: `default_action` is `drop`
//!
//! A flow that matches nothing — including one this process could not identify at all — is
//! refused. That is what makes "Digiexam cannot reach anything outside the allowlist" true by
//! construction rather than by hoping every dangerous case was enumerated: an `app` or `host`
//! matcher that cannot be evaluated (no attribution, no name yet) simply does not match, and the
//! flow falls through to `default_action`.
//!
//! One direct consequence: **DNS and DHCP must be explicitly allowed**, or nothing on the machine
//! resolves a name at all and no host-based rule can ever fire. See `macos/rules.json`'s seed
//! rules for port 53/67. A blanket DNS allowance is itself a coarse channel — a real product
//! would pin the resolver — and that is a follow-up, not a gap in this change.
//!
//! # `deny_unknown_fields`, deliberately
//!
//! In a denylist a typo in a matcher only weakens one rule. In an allowlist a matcher that fails
//! to parse as intended (`"hosts"` instead of `"host"`, say) becomes a matcher with **no**
//! condition on that field — which matches *more*, not less, and can silently open the network.
//! [`Rule`] therefore rejects unknown fields outright; [`reload`] already keeps the previously
//! loaded set and logs loudly on any parse failure, so a bad edit degrades to "nothing changed"
//! rather than "quietly permissive".
//!
//! # The escape hatch for nameless flows: `ip`
//!
//! A raw `TcpStream::connect` — which is exactly how this project's own test-connect button
//! reaches the network — carries no hostname anywhere the framework hands us at `handleNewFlow:`
//! time. [`Rule::ip`] matches the literal remote address instead, so an app can still be admitted
//! to a specific destination even when no name is available for it to be checked against.
//!
//! # This build still fails OPEN on a load failure
//!
//! [`RuleSet::allow_everything`] remains the pre-first-load and load-failure fallback, unchanged
//! from the observe-only build. That is a statement about *ops resilience to a bad push*, not
//! about the policy direction: as soon as any rules file loads successfully, that file's own
//! `default_action` — `drop`, in the shipped allowlist — governs every flow. Making the ops
//! fallback itself fail closed is a real hardening step but a distinct one from this pivot, and is
//! not made here.

use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};

use serde::Deserialize;

use crate::flow::{AddressFamily, FlowInfo, TransportProtocol};
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

/// `family` matcher values. A separate type from [`AddressFamily`] because a rule can only ever
/// *ask for* v4 or v6 — there is no useful way to write a rule targeting `AddressFamily::Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum FamilyMatch {
    #[serde(rename = "v4")]
    V4,
    #[serde(rename = "v6")]
    V6,
}

impl FamilyMatch {
    fn matches(self, family: AddressFamily) -> bool {
        matches!(
            (self, family),
            (Self::V4, AddressFamily::V4) | (Self::V6, AddressFamily::V6)
        )
    }
}

/// `protocol` matcher values. Same reasoning as [`FamilyMatch`]: a rule targets TCP or UDP, never
/// the `Other(_)` escape hatch [`TransportProtocol`] itself carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolMatch {
    Tcp,
    Udp,
}

impl ProtocolMatch {
    fn matches(self, protocol: TransportProtocol) -> bool {
        matches!(
            (self, protocol),
            (Self::Tcp, TransportProtocol::Tcp) | (Self::Udp, TransportProtocol::Udp)
        )
    }
}

/// One rule. Every matcher is optional and they are ANDed; a rule with no matchers at all matches
/// every flow, which is a legitimate way to write a catch-all ahead of the default action (the
/// DNS/DHCP seed rules are exactly this, minus the destination matchers).
///
/// `deny_unknown_fields` is deliberate — see the module docs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub action: Action,

    /// The app that must have opened the flow, matched against `AppId::name` — either an
    /// application identifier (`com.digiexam.macos.NetworkExtensions`) or an executable path
    /// (`/usr/bin/curl`), whichever [`crate::attribution`] was able to resolve. The `app=` column
    /// in the flow log prints the exact string to write here, with an `(id)` / `(path)` suffix
    /// saying which form it is; a rule written in the wrong form simply never matches.
    ///
    /// A flow that could not be named never matches this, so it falls through to
    /// `default_action` — `drop`, in an allowlist.
    #[serde(default)]
    pub app: Option<String>,

    /// Exact hostname, or a leading-dot suffix pattern: `".example.com"` matches `example.com`
    /// and any subdomain of it. Compared against [`FlowInfo::best_destination`], case-insensitively.
    ///
    /// A flow whose destination is not known yet never matches a host rule — see the module docs.
    #[serde(default)]
    pub host: Option<String>,

    /// Exact literal match against [`FlowInfo::remote_host`] — the escape hatch for a flow that
    /// carries an address but no name at all. Not a CIDR range: written as a plain string so it
    /// covers both IPv4 and IPv6 literals with the same field.
    #[serde(default)]
    pub ip: Option<String>,

    #[serde(default)]
    pub port: Option<u16>,

    #[serde(default)]
    pub protocol: Option<ProtocolMatch>,

    #[serde(default)]
    pub family: Option<FamilyMatch>,

    /// Ignored by matching entirely; exists so `rules.json` can document *why* a rule exists
    /// (see the DNS/DHCP seed rules) without that text needing to live in a separate file.
    #[serde(default)]
    #[allow(dead_code)]
    pub comment: Option<String>,
}

impl Rule {
    fn matches(&self, flow: &FlowInfo) -> bool {
        if let Some(wanted) = &self.app {
            match &flow.app {
                Some(app) if app.name == *wanted => {}
                _ => return false,
            }
        }
        if let Some(pattern) = &self.host {
            // No destination yet means no host match. Treating "unknown" as a match would make a
            // deny rule block traffic it was never shown to apply to — and, in this allowlist,
            // would make an *allow* rule wrongly admit traffic it was never shown to apply to.
            let Some(host) = flow.best_destination() else {
                return false;
            };
            if !host_matches(pattern, host) {
                return false;
            }
        }
        if let Some(wanted_ip) = &self.ip {
            match flow.remote_host.as_deref() {
                Some(host) if host.eq_ignore_ascii_case(wanted_ip) => {}
                _ => return false,
            }
        }
        if let Some(port) = self.port {
            if flow.remote_port != Some(port) {
                return false;
            }
        }
        if let Some(protocol) = self.protocol {
            if !protocol.matches(flow.protocol) {
                return false;
            }
        }
        if let Some(family) = self.family {
            if !family.matches(flow.family) {
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
    /// The fallback used before the first successful load, and after a failed one. See the
    /// module docs' "This build still fails OPEN on a load failure" section for what this does
    /// and does not mean for the shipped policy.
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
                 This fallback fails OPEN by design — see rules.rs's module doc.",
                kept.rules.len(),
                kept.default_action.label(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::AppId;
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
            app: None,
            pid: None,
        }
    }

    fn flow_from(app: &str, host: Option<&str>) -> FlowInfo {
        FlowInfo {
            app: Some(AppId { name: app.into(), source: "id" }),
            ..flow(host, Some(443))
        }
    }

    fn set(default_action: Action, rules: Vec<Rule>) -> RuleSet {
        RuleSet { default_action, rules }
    }

    /// A rule with only the fields relevant to a given test filled in; everything else `None`.
    fn rule(action: Action) -> Rule {
        Rule {
            action,
            app: None,
            host: None,
            ip: None,
            port: None,
            protocol: None,
            family: None,
            comment: None,
        }
    }

    #[test]
    fn the_shipped_seed_denies_by_default() {
        // Guards the direction of this pivot: the allowlist MVP fails closed, not open.
        let seed = RuleSet::from_json(r#"{ "default_action": "drop", "rules": [] }"#).unwrap();
        assert_eq!(seed.default_action, Action::Drop);
        assert!(seed.rules.is_empty());
        assert_eq!(seed.decide(&flow(Some("example.com"), Some(443))), Action::Drop);
    }

    #[test]
    fn an_unknown_action_is_a_parse_error_not_a_default() {
        let err = RuleSet::from_json(r#"{ "default_action": "maybe", "rules": [] }"#);
        assert!(err.is_err(), "an unrecognised action must not silently become allow");
    }

    #[test]
    fn an_unknown_field_fails_the_parse_rather_than_being_ignored() {
        // The whole point of deny_unknown_fields: a typo like "hosts" for "host" must not parse
        // into a matcher with no host condition, which would silently widen the allowlist.
        let err = RuleSet::from_json(
            r#"{"default_action":"drop","rules":[{"action":"allow","hosts":"example.com"}]}"#,
        );
        assert!(err.is_err(), "an unknown field must fail to parse");
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
        let s = set(Action::Drop, vec![Rule { host: Some("example.com".into()), ..rule(Action::Allow) }]);
        assert_eq!(s.decide(&flow(Some("other.com"), Some(443))), Action::Drop);
    }

    #[test]
    fn exact_host_match() {
        let s = set(Action::Allow, vec![Rule { host: Some("example.com".into()), ..rule(Action::Drop) }]);
        assert_eq!(s.decide(&flow(Some("example.com"), None)), Action::Drop);
        assert_eq!(s.decide(&flow(Some("notexample.com"), None)), Action::Allow);
        // An exact rule must not catch subdomains; that is what the dot form is for.
        assert_eq!(s.decide(&flow(Some("www.example.com"), None)), Action::Allow);
    }

    #[test]
    fn suffix_match_covers_the_apex_and_subdomains() {
        let s = set(Action::Allow, vec![Rule { host: Some(".example.com".into()), ..rule(Action::Drop) }]);
        assert_eq!(s.decide(&flow(Some("example.com"), None)), Action::Drop);
        assert_eq!(s.decide(&flow(Some("www.example.com"), None)), Action::Drop);
        assert_eq!(s.decide(&flow(Some("a.b.example.com"), None)), Action::Drop);
        // Must not match a domain that merely ends with the same letters.
        assert_eq!(s.decide(&flow(Some("notexample.com"), None)), Action::Allow);
    }

    #[test]
    fn host_matching_ignores_case() {
        let s = set(Action::Allow, vec![Rule { host: Some("Example.COM".into()), ..rule(Action::Drop) }]);
        assert_eq!(s.decide(&flow(Some("EXAMPLE.com"), None)), Action::Drop);
    }

    #[test]
    fn port_only_rules_match_any_host() {
        let s = set(Action::Allow, vec![Rule { port: Some(22), ..rule(Action::Drop) }]);
        assert_eq!(s.decide(&flow(Some("anything"), Some(22))), Action::Drop);
        assert_eq!(s.decide(&flow(None, Some(22))), Action::Drop);
        assert_eq!(s.decide(&flow(Some("anything"), Some(443))), Action::Allow);
    }

    #[test]
    fn host_and_port_are_anded() {
        let s = set(
            Action::Allow,
            vec![Rule { host: Some("example.com".into()), port: Some(443), ..rule(Action::Drop) }],
        );
        assert_eq!(s.decide(&flow(Some("example.com"), Some(443))), Action::Drop);
        assert_eq!(s.decide(&flow(Some("example.com"), Some(80))), Action::Allow);
    }

    #[test]
    fn first_match_wins() {
        let s = set(
            Action::Drop,
            vec![
                Rule { host: Some("example.com".into()), ..rule(Action::Allow) },
                Rule { host: Some("example.com".into()), ..rule(Action::Drop) },
            ],
        );
        assert_eq!(s.decide(&flow(Some("example.com"), None)), Action::Allow);
    }

    #[test]
    fn a_flow_with_no_destination_yet_never_matches_a_host_rule() {
        // remoteEndpoint is documented as possibly nil at handleNewFlow: time. Such a flow must
        // fall through to the default action rather than be caught by a host rule it was never
        // shown to match.
        let s = set(Action::Allow, vec![Rule { host: Some("example.com".into()), ..rule(Action::Drop) }]);
        assert_eq!(s.decide(&flow(None, None)), Action::Allow);
    }

    #[test]
    fn host_rules_see_the_best_destination_not_just_the_ip() {
        // A rule written against a hostname must match a flow whose remote_host is an IP literal
        // but which carries a real hostname alongside it.
        let s = set(Action::Allow, vec![Rule { host: Some("example.com".into()), ..rule(Action::Drop) }]);
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

    // ── app ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn app_matcher_requires_a_named_flow() {
        let s = set(
            Action::Drop,
            vec![Rule { app: Some("com.digiexam.macos.NetworkExtensions".into()), ..rule(Action::Allow) }],
        );
        // A flow attribution could not name falls through to the default — which, in an
        // allowlist, means it is refused rather than quietly admitted.
        assert_eq!(s.decide(&flow(None, None)), Action::Drop);
        assert_eq!(
            s.decide(&flow_from("com.digiexam.macos.NetworkExtensions", None)),
            Action::Allow
        );
    }

    #[test]
    fn app_matcher_rejects_a_different_app() {
        let s = set(
            Action::Drop,
            vec![Rule { app: Some("com.digiexam.macos.NetworkExtensions".into()), ..rule(Action::Allow) }],
        );
        assert_eq!(s.decide(&flow_from("com.apple.Safari", None)), Action::Drop);
    }

    #[test]
    fn app_matcher_compares_the_whole_name_not_a_prefix() {
        // A near-miss must not match: "…NetworkExtensions.ContentFilter" is a different process
        // from "…NetworkExtensions", and prefix matching here would admit the wrong one.
        let s = set(
            Action::Drop,
            vec![Rule { app: Some("com.digiexam.macos.NetworkExtensions".into()), ..rule(Action::Allow) }],
        );
        assert_eq!(
            s.decide(&flow_from("com.digiexam.macos.NetworkExtensions.ContentFilter", None)),
            Action::Drop
        );
    }

    #[test]
    fn app_matcher_works_for_a_path_named_flow() {
        // Raw-socket clients are named by executable path, so a rule can be written that way too.
        let s = set(Action::Drop, vec![Rule { app: Some("/usr/bin/curl".into()), ..rule(Action::Allow) }]);
        let curl = FlowInfo {
            app: Some(AppId { name: "/usr/bin/curl".into(), source: "path" }),
            ..flow(None, None)
        };
        assert_eq!(s.decide(&curl), Action::Allow);
    }

    #[test]
    fn app_and_host_together_key_the_rule_on_both() {
        // The crux of the allowlist: same destination, different verdict depending on who asked.
        let s = set(
            Action::Drop,
            vec![Rule {
                app: Some("com.digiexam.macos.NetworkExtensions".into()),
                host: Some(".digiexam.com".into()),
                ..rule(Action::Allow)
            }],
        );
        assert_eq!(
            s.decide(&flow_from("com.digiexam.macos.NetworkExtensions", Some("exam.digiexam.com"))),
            Action::Allow
        );
        assert_eq!(
            s.decide(&flow_from("com.apple.Safari", Some("exam.digiexam.com"))),
            Action::Drop,
            "same destination, different app"
        );
        assert_eq!(
            s.decide(&flow_from("com.digiexam.macos.NetworkExtensions", Some("google.com"))),
            Action::Drop,
            "same app, different destination"
        );
    }

    // ── ip / family / protocol ───────────────────────────────────────────────────────────────

    #[test]
    fn ip_matcher_is_an_exact_literal_match() {
        let s = set(Action::Drop, vec![Rule { ip: Some("93.184.216.34".into()), ..rule(Action::Allow) }]);
        assert_eq!(s.decide(&flow(Some("93.184.216.34"), None)), Action::Allow);
        assert_eq!(s.decide(&flow(Some("93.184.216.35"), None)), Action::Drop);
        assert_eq!(s.decide(&flow(None, None)), Action::Drop, "no address at all must not match");
    }

    #[test]
    fn ip_matcher_works_for_ipv6_literals_too() {
        let s = set(Action::Drop, vec![Rule { ip: Some("2606:4700::1".into()), ..rule(Action::Allow) }]);
        assert_eq!(s.decide(&flow(Some("2606:4700::1"), None)), Action::Allow);
    }

    #[test]
    fn family_matcher_distinguishes_v4_from_v6() {
        let v6_only = set(Action::Allow, vec![Rule { family: Some(FamilyMatch::V6), ..rule(Action::Drop) }]);
        assert_eq!(v6_only.decide(&FlowInfo { family: AddressFamily::V6, ..flow(None, None) }), Action::Drop);
        assert_eq!(v6_only.decide(&FlowInfo { family: AddressFamily::V4, ..flow(None, None) }), Action::Allow);
    }

    #[test]
    fn family_matcher_never_matches_an_unrecognised_family() {
        let v4_only = set(Action::Allow, vec![Rule { family: Some(FamilyMatch::V4), ..rule(Action::Drop) }]);
        let weird = FlowInfo { family: AddressFamily::Other(0), ..flow(None, None) };
        assert_eq!(v4_only.decide(&weird), Action::Allow, "an unrecognised family falls through, it doesn't match either side");
    }

    #[test]
    fn protocol_matcher_distinguishes_tcp_from_udp() {
        let udp_only = set(Action::Allow, vec![Rule { protocol: Some(ProtocolMatch::Udp), ..rule(Action::Drop) }]);
        assert_eq!(udp_only.decide(&FlowInfo { protocol: TransportProtocol::Udp, ..flow(None, None) }), Action::Drop);
        assert_eq!(udp_only.decide(&FlowInfo { protocol: TransportProtocol::Tcp, ..flow(None, None) }), Action::Allow);
    }

    #[test]
    fn a_quic_style_udp_443_block_does_not_touch_tcp_443() {
        // The concrete case from the seed rules: block UDP/443 (QUIC) without touching ordinary
        // TLS-over-TCP on the same port.
        let s = set(
            Action::Allow,
            vec![Rule { protocol: Some(ProtocolMatch::Udp), port: Some(443), ..rule(Action::Drop) }],
        );
        assert_eq!(
            s.decide(&FlowInfo { protocol: TransportProtocol::Udp, ..flow(None, Some(443)) }),
            Action::Drop
        );
        assert_eq!(
            s.decide(&FlowInfo { protocol: TransportProtocol::Tcp, ..flow(None, Some(443)) }),
            Action::Allow
        );
    }
}
