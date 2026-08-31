/*
 * Thin C shim over the unified logging API.
 *
 * `os_log()` and friends are MACROS in <os/log.h>, not exported functions — libsystem_trace only
 * exports `_os_log_impl`, which takes a hand-serialized argument buffer whose layout is a private
 * implementation detail. Encoding that buffer from Rust is possible but is exactly the kind of
 * thing that fails silently at runtime, in the one component whose entire job is diagnosability.
 *
 * So the macro gets called from C, where it is meant to be called, and Rust calls these two
 * ordinary functions instead. Built by build.rs via the `cc` crate; build-time only.
 */

#include <os/log.h>

os_log_t digiexam_log_create(const char *subsystem, const char *category) {
    return os_log_create(subsystem, category);
}

/*
 * Log `msg` at the DEFAULT level.
 *
 * Two things here are load-bearing:
 *
 *   %{public}s  — os_log redacts dynamic strings as "<private>" unless explicitly marked public.
 *                 Without this qualifier every flow record would reach Console.app, and the
 *                 container app's log tail, as literally nothing.
 *
 *   default level — OS_LOG_TYPE_DEFAULT messages are captured and shown by a bare `log stream`.
 *                 os_log_info/os_log_debug would require callers to remember `--info`/`--debug`,
 *                 and would be dropped from the persisted store.
 */
void digiexam_log_public_str(os_log_t log, const char *msg) {
    os_log(log, "%{public}s", msg);
}
