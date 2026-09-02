//! Source-app attribution — which application opened a flow.
//!
//! The NetworkExtension framework already answers this, and cheaply. Two sources, tried in order:
//!
//! 1. `NEFilterFlow.sourceAppIdentifier` — a plain string identifying the source application.
//! 2. `proc_pidpath_audittoken` on the flow's audit token — the executable's path on disk.
//!
//! The second exists because the first is documented as possibly nil, and because command-line
//! tools and daemons (`curl`, helper processes) are not "applications" in the sense the first one
//! means. Between them, every process on the machine ends up with a name.
//!
//! # Which audit token
//!
//! `NEFilterFlow` carries two:
//!
//! - `sourceAppAuditToken` — the application that owns the connection.
//! - `sourceProcessAuditToken` — the process that actually opened the socket. These differ when a
//!   system process acts on an app's behalf: WebKit apps make their connections through
//!   `com.apple.WebKit.Networking`, so using the *process* token first would attribute Safari's
//!   traffic and this app's own webview traffic to the same identity — which would make "Safari
//!   cannot reach it, Digiexam can" unprovable. The app token is tried first for exactly that
//!   reason; the process token is only a fallback for flows carrying no app token at all.
//!
//! `proc_pidpath_audittoken` takes the token rather than a pid on purpose: no pid to extract, and
//! no pid-reuse race to reason about.
//!
//! # What this deliberately does NOT do
//!
//! **This is not a code-signature check.** It reports the identity the OS associates with the
//! process; it does not verify that the process's signature is intact or that it was signed by
//! any particular team. A determined user could ship a binary claiming Digiexam's identifier and
//! this would report it as Digiexam.
//!
//! That is a real gap for exam lockdown, and it is a **known, deliberate deferral** rather than an
//! oversight. An earlier version of this module did verify signatures, via
//! `SecCodeCopyGuestWithAttributes` -> `SecCodeCheckValidity` -> `SecCodeCopySigningInformation`.
//! It was removed because it failed — silently and identically for every process, since that code
//! discarded every `OSStatus` — and because nothing in the current requirements asks for spoofing
//! resistance. When it comes back it should come back on its own terms: one call at a time, each
//! with the flags that call actually documents, and with the `OSStatus` logged rather than thrown
//! away.

use objc2_network_extension::NEFilterFlow;

// Linked from libSystem, which every Mach-O binary already links against — no build.rs change
// and no crate dependency needed.
unsafe extern "C" {
    /// `proc_pidpath_audittoken(audit_token_t *, void *, uint32_t) -> int` from `<libproc.h>`,
    /// available since macOS 11. Returns the number of bytes written, or <= 0 on failure.
    fn proc_pidpath_audittoken(
        audittoken: *const u8,
        buffer: *mut u8,
        buffersize: u32,
    ) -> std::ffi::c_int;
}

/// `PROC_PIDPATHINFO_MAXSIZE` from `<sys/proc_info.h>` — 4 * `MAXPATHLEN`. The call fails rather
/// than truncating when the buffer is smaller, so this must not be trimmed to something that
/// merely looks reasonable.
const PROC_PIDPATHINFO_MAXSIZE: usize = 4 * 1024;

/// A serialized `audit_token_t` is `struct { unsigned int val[8]; }` — 8 x u32.
const AUDIT_TOKEN_LEN: usize = 32;

/// The name of the app that opened a flow, and where that name came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppId {
    /// Either an application identifier (`com.digiexam.macos.NetworkExtensions`) or an executable
    /// path (`/usr/bin/curl`), depending on [`Self::source`]. This is what an `app` rule in
    /// `rules.json` is compared against, so the log has to show it verbatim.
    pub name: String,
    /// `"id"` or `"path"`. Rendered in the log line so which of the two sources answered is never
    /// a guess — a rule written against the wrong form is otherwise invisible.
    pub source: &'static str,
}

impl AppId {
    /// `name(source)`, as it appears in the `app=` column.
    pub fn log_label(&self) -> String {
        format!("{}({})", self.name, self.source)
    }
}

/// Identify the app that opened `flow`, or `None` if neither source could name it.
pub fn identify(flow: &NEFilterFlow) -> Option<AppId> {
    // SAFETY: declared property on a live framework object; explicitly nullable.
    let identifier = unsafe { flow.sourceAppIdentifier() }
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());

    if let Some(name) = identifier {
        return Some(AppId { name, source: "id" });
    }

    let token = source_audit_token(flow)?;
    let name = path_for_audit_token(&token)?;
    Some(AppId { name, source: "path" })
}

/// Prefer the app's own audit token; fall back to the process token only when the app token is
/// unavailable. See the module doc for why this order, not the reverse, is what makes attribution
/// meaningful for WebKit-based apps.
fn source_audit_token(flow: &NEFilterFlow) -> Option<Vec<u8>> {
    // SAFETY: declared properties on a live framework object; both explicitly nullable.
    let data = unsafe { flow.sourceAppAuditToken() }
        .or_else(|| unsafe { flow.sourceProcessAuditToken() })?;
    let bytes = data.to_vec();
    (bytes.len() >= AUDIT_TOKEN_LEN).then_some(bytes)
}

/// Executable path for the process identified by `token`.
fn path_for_audit_token(token: &[u8]) -> Option<String> {
    if token.len() < AUDIT_TOKEN_LEN {
        return None;
    }
    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];

    // SAFETY: `token` is at least a full audit_token_t (checked above) and `buf` is a writable
    // allocation of exactly the length passed; the call writes at most `buffersize` bytes.
    let written =
        unsafe { proc_pidpath_audittoken(token.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if written <= 0 {
        return None;
    }

    buf.truncate(written as usize);
    // The kernel writes a NUL-terminated C string and reports the length without the terminator,
    // but tolerate one anyway rather than letting a stray NUL into a rule comparison.
    while buf.last() == Some(&0) {
        buf.pop();
    }
    String::from_utf8(buf).ok().filter(|s| !s.is_empty())
}

/// Extract the PID from a serialized `audit_token_t`. `val[5]`, byte offset 20, little-endian.
///
/// Used only for the `pid=` log column — identification itself goes through the audit token
/// directly. It earns its place there because a pid is the one thing that can be checked against
/// reality (`ps -p <pid>`) without trusting anything else in this module.
pub fn pid_from_audit_token(token: &[u8]) -> Option<i32> {
    if token.len() < AUDIT_TOKEN_LEN {
        return None;
    }
    let pid = i32::from_le_bytes([token[20], token[21], token[22], token[23]]);
    (pid > 0).then_some(pid)
}

/// The PID behind `flow`, for logging. `None` when the flow carries no audit token.
pub fn pid_for(flow: &NEFilterFlow) -> Option<i32> {
    pid_from_audit_token(&source_audit_token(flow)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 32-byte audit token with `pid` in val[5].
    fn token_with_pid(pid: u32) -> Vec<u8> {
        let mut t = vec![0u8; AUDIT_TOKEN_LEN];
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
        t[24..28].copy_from_slice(&5u32.to_le_bytes()); // val[6], the asid
        assert_eq!(pid_from_audit_token(&t), Some(99));
    }

    #[test]
    fn a_short_token_is_never_handed_to_proc_pidpath() {
        // Guards the length check in front of the FFI call: proc_pidpath_audittoken reads a full
        // audit_token_t, so a short buffer would be an out-of-bounds read, not a graceful failure.
        assert_eq!(path_for_audit_token(&[0u8; 16]), None);
    }

    #[test]
    fn resolves_the_path_of_this_very_process() {
        // The one part of this module testable for real: ask the kernel for our own path via our
        // own audit token, and check it against what the test binary knows itself to be. This is
        // what proves the FFI declaration and the buffer handling are right.
        let mut token = [0u8; AUDIT_TOKEN_LEN];
        // SAFETY: writing our own task's audit token into a correctly sized buffer.
        if !unsafe { self_audit_token(&mut token) } {
            // Not fatal: if the audit token cannot be read in this environment there is nothing
            // meaningful to check, and failing here would be a false alarm.
            return;
        }
        let path = path_for_audit_token(&token).expect("our own path should resolve");
        let expected = std::env::current_exe().unwrap();
        assert_eq!(path, expected.to_string_lossy(), "should resolve to this test binary");
    }

    /// `task_info(mach_task_self(), TASK_AUDIT_TOKEN, ...)` — test-only, to obtain a real token to
    /// feed the function under test rather than a synthetic one.
    unsafe fn self_audit_token(out: &mut [u8; AUDIT_TOKEN_LEN]) -> bool {
        const TASK_AUDIT_TOKEN: u32 = 15;
        unsafe extern "C" {
            fn mach_task_self() -> u32;
            fn task_info(
                target_task: u32,
                flavor: u32,
                task_info_out: *mut u8,
                task_info_count: *mut u32,
            ) -> i32;
        }
        // The count is in 32-bit words, not bytes.
        let mut count = (AUDIT_TOKEN_LEN / 4) as u32;
        let kr = unsafe {
            task_info(mach_task_self(), TASK_AUDIT_TOKEN, out.as_mut_ptr(), &mut count)
        };
        kr == 0
    }

    #[test]
    fn log_label_shows_the_source() {
        let by_id = AppId { name: "com.digiexam.macos.NetworkExtensions".into(), source: "id" };
        assert_eq!(by_id.log_label(), "com.digiexam.macos.NetworkExtensions(id)");

        let by_path = AppId { name: "/usr/bin/curl".into(), source: "path" };
        assert_eq!(by_path.log_label(), "/usr/bin/curl(path)");
    }
}
