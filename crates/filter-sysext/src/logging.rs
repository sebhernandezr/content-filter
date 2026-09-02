//! Unified-log output for the extension.
//!
//! `eprintln!` alone is not reliable inside a NetworkExtension provider — the process is launched
//! by `nesessionmanager` and its stderr generally goes nowhere you can see. `os_log` is what
//! actually surfaces, in Console.app and `log stream`, and it is also what `make logs` filters
//! on.
//!
//! Read this extension's output with:
//!
//! ```text
//! log stream --predicate 'subsystem == "com.digiexam.macos.NetworkExtensions"' --info
//! ```

use std::ffi::{c_char, c_void, CString};
use std::sync::OnceLock;

// Provided by oslog_shim.c (built by build.rs). `os_log` itself is a macro in <os/log.h> and has
// no exported symbol to link against, so the shim calls it from C on our behalf.
unsafe extern "C" {
    /// Wraps `os_log_create(subsystem, category) -> os_log_t`.
    fn digiexam_log_create(subsystem: *const c_char, category: *const c_char) -> *mut c_void;
    /// Wraps `os_log(log, "%{public}s", msg)` at the default level.
    fn digiexam_log_public_str(log: *mut c_void, msg: *const c_char);
}

/// The os_log subsystem this extension logs under. `make logs` builds its predicate from the
/// same string (see the Makefile's `SUBSYSTEM` variable) — they must agree or `make logs` goes
/// silently empty.
const LOG_SUBSYSTEM: &str = "com.digiexam.macos.NetworkExtensions";

/// Category for provider lifecycle events (start/stop/rules loaded).
const LOG_CATEGORY_LIFECYCLE: &str = "lifecycle";
/// Category for per-flow lines. Kept separate from lifecycle so a `log show`/`log stream`
/// predicate can filter on it directly, and so `make logs` can render it as the `flow` flag
/// distinct from `life`.
const LOG_CATEGORY_FLOW: &str = "flow";

/// `os_log_t` handles are immortal for the life of the process, so they are created once and
/// reused. Stored as raw pointers; they are never dereferenced by us, only handed back to os_log.
struct LogHandle(*mut c_void);
// SAFETY: os_log_t is documented as safe to use from any thread, and we only ever pass the
// pointer back into os_log. handleNewFlow: is called concurrently, so this bound is required.
unsafe impl Sync for LogHandle {}
unsafe impl Send for LogHandle {}

fn handle(category: &str, cell: &'static OnceLock<LogHandle>) -> *mut c_void {
    cell.get_or_init(|| {
        let sub = CString::new(LOG_SUBSYSTEM).expect("subsystem has no interior NUL");
        let cat = CString::new(category).expect("category has no interior NUL");
        // SAFETY: both arguments are valid NUL-terminated C strings that outlive the call.
        LogHandle(unsafe { digiexam_log_create(sub.as_ptr(), cat.as_ptr()) })
    })
    .0
}

/// Write `msg` to the unified log under `category`.
///
/// The shim formats with `%{public}s`; see `oslog_shim.c` for why the `public` qualifier is not
/// optional.
fn emit(category: &str, cell: &'static OnceLock<LogHandle>, msg: &str) {
    // A NUL inside the message would truncate it; replace rather than drop the record.
    let sanitized = msg.replace('\0', "\u{fffd}");
    let Ok(cs) = CString::new(sanitized) else { return };
    // SAFETY: `handle` returns a valid os_log_t, and `cs` is NUL-terminated and outlives the call.
    unsafe { digiexam_log_public_str(handle(category, cell), cs.as_ptr()) };

    // Mirrored to stderr so the binary is also debuggable when run directly from a terminal
    // (which is how you check that it at least starts, outside the NE host).
    eprintln!("{msg}");
}

static LIFECYCLE: OnceLock<LogHandle> = OnceLock::new();
static FLOW: OnceLock<LogHandle> = OnceLock::new();

/// Log a provider lifecycle event (start, stop, class registration, rules load).
pub fn lifecycle(msg: &str) {
    emit(LOG_CATEGORY_LIFECYCLE, &LIFECYCLE, msg);
}

/// Log one already-formatted flow line. See `flow::FlowInfo::log_line`.
pub fn flow(line: &str) {
    emit(LOG_CATEGORY_FLOW, &FLOW, line);
}
