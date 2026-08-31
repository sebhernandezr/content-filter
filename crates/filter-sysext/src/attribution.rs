//! Source-app attribution — resolving which application opened a flow.
//!
//! **Off by default in this MVP.** Flip [`LOG_SOURCE_APP`] to `true` to enable it; the rest of
//! the pipeline (the `source_app` field, the log format, the UI column) is already wired, so this
//! is genuinely a one-line change.
//!
//! # What enabling it actually involves
//!
//! `NEFilterFlow.sourceAppIdentifier` is **iOS-only** and always nil here. On macOS the flow
//! instead carries audit tokens:
//!
//! - `sourceAppAuditToken` — the application that owns the connection.
//! - `sourceProcessAuditToken` — the process that actually opened the socket. These differ when a
//!   system process acts on an app's behalf: WebKit apps make their connections through
//!   `com.apple.WebKit.Networking`, so attributing browser traffic needs both.
//!
//! An `audit_token_t` is `struct { unsigned int val[8]; }`, and the PID lives at `val[5]` —
//! byte offset 20. It has to be read at that offset by hand because `audit_token_to_pid()`, while
//! still declared in `<bsm/libbsm.h>`, is no longer exported by libSystem on current macOS.
//!
//! Turning a PID into a bundle identifier then has two options, and the obvious one is the wrong
//! one:
//!
//! - `NSRunningApplication::runningApplicationWithProcessIdentifier` is a single call, but it
//!   only sees **GUI applications**. It returns nil for `curl`, for daemons, and for helper
//!   processes, and it is unreliable when called from a non-GUI root process such as this one.
//! - `SecCodeCopyGuestWithAttributes` with `kSecGuestAttributeAudit`, followed by
//!   `SecCodeCopySigningInformation` → `kSecCodeInfoIdentifier`, works for **every** process,
//!   needs no GUI session, and returns the signing identifier rather than a best guess. It costs
//!   Security.framework FFI and a little more code.
//!
//! The enforcement follow-up has to identify `curl` and daemons, which `NSRunningApplication`
//! structurally cannot do — so when this is switched on, it should be built on `SecCode`, not on
//! AppKit. That is why this module ships as a stub rather than as the easy-but-lossy version:
//! a half-working attribution that silently returns `None` for every non-GUI process is worse
//! than a clearly absent one.

use objc2_network_extension::NEFilterFlow;

/// Whether to attempt source-app attribution for each flow.
///
/// Kept `false` for the observe-only MVP. Attribution is not needed to prove that flows reach
/// `handleNewFlow:`, and every extra framework call on this path is a call that can fail or
/// block inside a privileged process on the critical path of every connection on the machine.
pub const LOG_SOURCE_APP: bool = false;

/// Bundle identifier of the app that opened `flow`, or `None`.
///
/// Always `None` while [`LOG_SOURCE_APP`] is `false`. `filter_types::FlowRecord::source_app`
/// carries the result.
pub fn source_bundle_id(_flow: &NEFilterFlow) -> Option<String> {
    if !LOG_SOURCE_APP {
        return None;
    }
    // Implement with SecCodeCopyGuestWithAttributes when this is enabled — see the module docs
    // for why NSRunningApplication is not the right primitive here.
    None
}

/// Extract the PID from a serialized `audit_token_t`.
///
/// Kept (and tested) even while attribution is off, because the layout assumption — PID at
/// `val[5]`, little-endian, byte offset 20 — is the one piece of this that is easy to get subtly
/// wrong and impossible to notice: a wrong offset yields a plausible-looking PID that resolves to
/// the wrong app, or to nothing.
#[allow(dead_code)]
pub fn pid_from_audit_token(token: &[u8]) -> Option<i32> {
    if token.len() < 32 {
        return None;
    }
    let pid = i32::from_le_bytes([token[20], token[21], token[22], token[23]]);
    (pid > 0).then_some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 32-byte audit token with `pid` in val[5].
    fn token_with_pid(pid: u32) -> Vec<u8> {
        let mut t = vec![0u8; 32];
        t[20..24].copy_from_slice(&pid.to_le_bytes());
        t
    }

    #[test]
    fn reads_the_pid_from_val5() {
        assert_eq!(pid_from_audit_token(&token_with_pid(4321)), Some(4321));
    }

    #[test]
    fn rejects_a_short_token() {
        assert_eq!(pid_from_audit_token(&[0u8; 16]), None);
    }

    #[test]
    fn rejects_a_zero_pid() {
        // All-zero is what an uninitialised or unavailable token looks like; it must not be
        // reported as pid 0 (the kernel).
        assert_eq!(pid_from_audit_token(&[0u8; 32]), None);
    }

    #[test]
    fn ignores_other_fields_of_the_token() {
        let mut t = token_with_pid(99);
        t[0..4].copy_from_slice(&7u32.to_le_bytes()); // val[0], the auid
        t[24..28].copy_from_slice(&5u32.to_le_bytes()); // val[6]
        assert_eq!(pid_from_audit_token(&t), Some(99));
    }

    #[test]
    fn attribution_is_off_in_this_build() {
        // Guards the MVP scope decision: if this flips, the UI column and the log format need a
        // matching review, and this test is the reminder.
        assert!(!LOG_SOURCE_APP);
    }
}
