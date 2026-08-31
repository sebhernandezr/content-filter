# Architecture & Implementation Guide

This document explains how the Digiexam macOS Content Filter works end-to-end: how it's built, installed, and captures network data.

## Overview

The content filter is a **system-wide network monitoring tool** built as a macOS **system extension** (not an app extension). It observes every network connection on the machine and logs the details, without blocking anything (the "observe-only MVP" — enforcement is planned for a follow-up).

Two main components:
1. **The System Extension** (`crates/filter-sysext/`) — a privileged process running as `root` that intercepts network flows
2. **The Container App** (`app/`) — a Tauri app running as the console user that controls the extension and displays logs

## The Two-Step Model (Critical)

**This is the core insight that shaped the entire design.** Getting network flows requires two completely independent things to succeed, and they fail independently:

### Step 1: Activation
```
Container App
    ↓ invoke OSSystemExtensionRequest
System Integrity Protection / macOS Gatekeeper
    ↓ (user approves in System Settings)
System Extension installed & verified
    ↓ (ActivationState changes)
```
- File: `crates/tauri-plugin-content-filter/src/sysext.rs`
- Result: The extension is installed on disk, digitally signed, and verified by the OS
- **Does NOT start the filter yet** — just installs it
- User approval can take 180 seconds (timeout in sysext.rs)

### Step 2: Enabling the Filter
```
Container App
    ↓ invoke NEFilterManager.saveToPreferences()
macOS Network Extension framework
    ↓ (spawns the provider process)
System Extension binary starts
    ↓ (enters dispatch_main, parks on main queue)
handleNewFlow: callback is now live
```
- File: `crates/tauri-plugin-content-filter/src/filter_manager.rs`
- Result: Flows are now being logged
- **Step 2 can succeed even if Step 1 failed silently** — this was the bug the previous attempt got stuck in

**Why separate them?** Because the previous codebase did step 2 without verifying step 1, and ended up with 15 staged extension copies, none of them actually running, while the UI claimed success. This design forces the failure to be visible: the UI shows activation state and configuration state as two separate rows. `ActivationState::NeedsReboot` (meaning the extension is staged but not active) never collapses into success.

## Architecture Layers

### Layer 1: System Extension (Filter Provider)

**What it does:** Receives every new network connection on the machine and logs it.

**Files:**
- `crates/filter-sysext/src/main.rs` — entry point: registers the provider class, calls `NEProvider.startSystemExtensionMode()`, parks forever
- `crates/filter-sysext/src/provider.rs` — `FilterProvider` class (ObjC, via objc2): implements three lifecycle methods
  - `startFilter()` — called when NEFilterManager enables the filter; logs that it started
  - `stopFilter()` — called when the filter is disabled or configuration is removed; logs the reason code
  - `handleNewFlow()` — **the hot path**: called once per new connection (concurrently, from the framework's queue); extracts flow details and logs them
- `crates/filter-sysext/src/flow.rs` — `record_for()`: turns a raw `NEFilterFlow` into a `FlowRecord` struct with fields like remote IP, port, hostname (if available), resolved domain (if WebKit), source app
- `crates/filter-sysext/src/logging.rs` — logs to the unified log system (`os_log`) under subsystem `com.digiexam.macos.NetworkExtensions`
- `crates/filter-sysext/src/attribution.rs` — source app identification (which bundle ID made the connection)

**Runs as:** `root` (required by the NetworkExtension framework)

**Lifecycle:**
1. Spawned by macOS only after the container app calls `NEFilterManager.saveToPreferences()`
2. Immediately calls `startFilter()` to report readiness
3. Waits on `dispatch_main()` — parks forever, processing `handleNewFlow()` callbacks from the framework
4. When the filter is disabled, `stopFilter()` is called and the process exits (or remains idle until re-enabled)

**Important:** The provider itself does **not** decide allow/block — it only logs. The default framework action is `NEFilterActionFilterData` (deliver every flow), and the provider returns `allowVerdict()` unconditionally (line 94 of provider.rs has a comment saying "this expression is replaced in the enforcement ticket").

### Layer 2: Unified Log (Inter-Process Communication)

The extension (running as root) and the app (running as console user) cannot share a writable file — their home directories are different (`/var/root/…` vs `~/…`). Instead, they communicate via the **unified log** (`os_log`).

**How it works:**
1. Extension writes log lines to the unified log with subsystem `com.digiexam.macos.NetworkExtensions`
2. Container app runs `log stream --predicate 'subsystem == "com.digiexam.macos.NetworkExtensions"' --info` as a child process
3. App captures each line and parses it into a `FlowRecord`
4. Records are buffered in memory in a circular ring buffer

**Files:**
- `crates/filter-sysext/src/logging.rs` — writes: `os_log` calls using `os_log` crate
- `crates/tauri-plugin-content-filter/src/flow_log.rs` — reads: spawns `log stream` subprocess, captures output, parses into `FlowRecord` structs, maintains ring buffer
- `crates/filter-types/src/lib.rs` — defines `FlowRecord` struct and the log line format: `FLOW1 {json}` (the prefix allows both reader and writer to agree on format even if they diverge)

### Layer 3: Container App & Tauri Plugin

The container app is a minimal Tauri app (Rust backend + TypeScript frontend) that:
1. Drives extension activation (calling `OSSystemExtensionRequest`)
2. Enables/disables the filter configuration (calling `NEFilterManager`)
3. Reads the unified log and buffers flow records
4. Exposes commands to the UI

**Backend (Rust):**
- `crates/tauri-plugin-content-filter/src/lib.rs` — Tauri plugin initialization; manages `FilterState` (shared state for activation, flows, log tail)
- `crates/tauri-plugin-content-filter/src/commands.rs` — Tauri commands (invoked by frontend):
  - `enable_filter()` — activate + enable in one call
  - `disable_filter()` — disable the filter config
  - `remove_filter()` — remove config + deactivate extension
  - `filter_status()` — query current state
  - `recent_flows()` — fetch buffered flow records
- `crates/tauri-plugin-content-filter/src/sysext.rs` — `OSSystemExtensionRequest` API wrapper; submits activation/deactivation requests and waits for callbacks
- `crates/tauri-plugin-content-filter/src/filter_manager.rs` — `NEFilterManager` API wrapper; enables/disables/removes filter config

All blocking APIs are called on a thread pool (not the main thread), because they dispatch to the main queue and wait for callbacks — calling from main would deadlock (the dispatch queue can't service callbacks while the main thread is blocked in the same API).

**Frontend (TypeScript):**
- `app/src/main.ts` — minimal UI with four buttons (Enable, Disable, Remove, Status) and a table of recent flows
- `app/src/style.css` — styling
- Calls backend commands via Tauri's `invoke()` API
- Polls status every 500ms so the UI stays in sync with macOS state

## Build Pipeline

**Entry point:** `Makefile`

```
make check        ← Run this first
  → scripts/check-signing.sh
      ✓ Verify Developer ID cert exists in keychain
      ✓ Verify provisioning profiles exist and embed the cert
      ✓ Verify entitlements files are well-formed
      ✓ Verify SIP status (informs the user if dev mode is unavailable)

make build        ← Full signed app with extension embedded
  → scripts/assemble-sysext.sh
      ✓ Cargo build filter-sysext (Rust → binary)
      ✓ Create universal binary (lipo: arm64 + x86_64)
      ✓ Substitute placeholders into Info.plist.in → Info.plist
      ✓ Embed provisioning profile into .systemextension
      ✓ Sign .systemextension with developer cert + extension-specific entitlements
      ✓ Verify signature

  → Tauri build (npm run tauri build --target universal-apple-darwin)
      ✓ TypeScript frontend build
      ✓ Cargo build app and plugin (Rust backend)
      ✓ Create .app bundle
      ✓ Tauri signs the app (but NOT with --deep, to avoid re-signing the embedded sysext)
  
  → scripts/build-app.sh
      ✓ Copy Tauri's .app from target/ to dist/
      ✓ Embed the signed .systemextension into Contents/Library/SystemExtensions/
      ✓ Embed app provisioning profile into Contents/embedded.provisionprofile
      ✓ Sign the outer app (without --deep) with app-specific entitlements
      ✓ Verify both app and embedded extension are validly signed
      ✓ Verify both are universal (arm64 + x86_64)
      ✓ Verify embedded extension's provider class symbol is present
      ✓ Verify entitlements on both bundles

make install      ← Copy to /Applications and launch
  → make build (dependency)
  → notarize (submit dist/Digiexam.app to Apple)
      ✓ Staple the notarization ticket to the app
      ✓ Verify staple success
  → cp dist/Digiexam.app /Applications/
  → open /Applications/Digiexam.app
```

**Why this order matters:**
1. Inner bundle (sysext) signs first, with its own entitlements
2. Outer bundle (app) signs second, without `--deep` (to avoid re-signing the inner bundle with the wrong entitlements)
3. Profile embedding must happen before signing (the signature seals the profile into CodeResources)
4. Notarization is required to pass sysextd's validation (unnotarized bundles fail activation with OSSystemExtensionErrorCodeSignatureInvalid)

## Installation & Activation Flow

When the user clicks "Enable" in the UI:

```
User clicks Enable in UI
    ↓
frontend invokes plugin:content-filter|enable_filter
    ↓ (commands.rs)
Backend: call sysext::activate()
    ↓
submit OSSystemExtensionRequest (activation request, not deactivation)
    ↓
macOS shows approval dialog in System Settings
    ↓
User approves (or time out after 180s)
    ↓ (callback: did_finish, see sysext.rs)
Backend: ActivationState = Active (or NeedsReboot if the extension was staged)
    ↓
Backend: call filter_manager::enable()
    ↓
NEFilterManager.saveToPreferences(configuration)
    ↓
Framework spawns system extension process
    ↓
Extension: main() → register provider class → startSystemExtensionMode() → dispatch_main()
    ↓
Extension: startFilter() callback is called by framework
    ↓
Extension: parked, waiting for handleNewFlow() callbacks
    ↓
Backend: query filter_status() to report "enabled"
    ↓
UI: display "activated and running" + "enabled"
```

**Remove flow:**
```
User clicks Remove
    ↓
Backend: call filter_manager::remove()
    ↓
NEFilterManager.removeConfigurationForBundle() (removes the configuration, kills the provider)
    ↓
Backend: call sysext::deactivate()
    ↓
submit OSSystemExtensionRequest (deactivation request)
    ↓ (callback: did_finish)
Backend: ActivationState = Idle (not Active)
    ↓
UI: display "not activated"
```

## How Network Capture Works

### The Socket-Level View

The filter intercepts at the **socket layer**, not the HTTP layer. This means:

- **One `FlowRecord` per connection opening**, not per HTTP request
- **No request/response data**, only connection metadata: source app, destination IP, destination port, protocol (TCP/UDP), address family (IPv4/IPv6)
- **Limited hostname visibility:**
  - `url_host` — populated **only** for WebKit flows (Safari, WKWebView). This is the actual URL hostname from the request.
  - `hostname` — populated **only** for Network.framework/NSURLSession flows (Apple's high-level networking APIs)
  - `remote_host` — always populated with the destination IP from the socket

### Real-World Example: Chrome navigating to digiexam.com

Chrome has its own network stack (not WebKit, not NSURLSession). When you navigate to `digiexam.com`:

1. Chrome's internal DNS resolver resolves `digiexam.com` → an IP (e.g., `198.51.100.42`)
2. Chrome opens a socket to that IP
3. Filter's `handleNewFlow()` is called with the socket
4. The flow record gets:
   - `remote_host` = `"198.51.100.42"` (the IP)
   - `remote_port` = `443` (HTTPS)
   - `hostname` = `null` (Chrome doesn't use NSURLSession)
   - `url_host` = `null` (not a WebKit flow)
   - `source_app` = `"com.google.Chrome"` (from Mach-O loader inspection)
   - `verdict` = `Allow` (unconditionally)

**To capture the hostname for non-Apple-networking apps, you'd need to:**
- Parse TLS ClientHello SNI (Server Name Indication) from the raw bytes
- Implement `handleInboundDataFromFlow:` and `handleOutboundDataFromFlow:` callbacks
- This is content inspection, not just socket metadata
- Planned as a follow-up ticket if needed

### Safari navigating to digiexam.com

Safari uses WebKit, which is built on Network.framework. The flow record gets:
- `url_host` = `"digiexam.com"` (directly from the URL)
- Much more useful for domain-level filtering

## Provisioning, Signing & Entitlements

See [docs/signing.md](signing.md) for the detailed explanation. Quick version:

- Developer ID certificate must be embedded in **both** provisioning profiles
- Both profiles must be copied into the bundles **before signing** (signing seals them into CodeResources)
- The app is signed without `--deep` to avoid re-signing the embedded extension with the wrong entitlements
- Notarization is required (sysextd validates against Apple's infrastructure)
- SIP is on, so developer mode is unavailable — profiles are required from day one, not just for distribution

## File & Data Flow

```
FlowRecord is born:
  NEFilterFlow (framework object)
  → flow::record_for() extracts fields
  → serializes to JSON
  → logged to os_log via logging::flow()

FlowRecord is read:
  log stream subprocess captures the line
  → flow_log.rs parses JSON
  → inserts into circular ring buffer
  → frontend polls filter_status() / recent_flows()
  → JavaScript renders into <table>
```

## State Machine (ActivationState)

```
Idle
  ↓ (user clicks Enable)
Pending
  ↓ (framework processes request)
NeedsUserApproval (if user hasn't approved yet)
  ↓ (user approves in System Settings)
Active (extension is running)
  or
NeedsReboot (extension was staged, not activated)
  or
Failed(string) (something went wrong)
```

The UI reports `Idle` when no activation has been attempted, and always shows the raw state — never collapses `NeedsReboot` into success, because that was the exact failure mode that let stale copies accumulate before.

## Key Files by Purpose

| Purpose | File |
|---------|------|
| Build scripts | `scripts/check-signing.sh`, `scripts/assemble-sysext.sh`, `scripts/build-app.sh` |
| Identifiers & versions | `macos/identity.sh` (single source of truth) |
| Extension activation | `crates/tauri-plugin-content-filter/src/sysext.rs` |
| Filter enable/disable | `crates/tauri-plugin-content-filter/src/filter_manager.rs` |
| Network capture | `crates/filter-sysext/src/provider.rs` (callback), `flow.rs` (extraction) |
| Data logging | `crates/filter-sysext/src/logging.rs` (write), `flow_log.rs` (read) |
| Wire format | `crates/filter-types/src/lib.rs` |
| UI commands | `crates/tauri-plugin-content-filter/src/commands.rs` |
| UI rendering | `app/src/main.ts` |

## Common Pitfalls

1. **CFBundleVersion:** Bumping it makes macOS stage the extension instead of activating it. Keep it stable in `macos/identity.sh`.
2. **App location:** Activation fails with `UnsupportedParentBundleLocation` if the app is anywhere but `/Applications`.
3. **Signing order:** Sign the extension before embedding, then sign the app without `--deep`.
4. **XML comments:** No `--` inside entitlements XML comments (illegal XML; `plutil -lint` won't catch it, but `make check` will).
5. **Thread safety:** Blocking APIs must run off the main thread to avoid deadlocking on dispatch callbacks.
6. **Notarization:** Unnotarized local builds fail sysextd validation with OSSystemExtensionErrorCodeSignatureInvalid.

## Testing & Validation

- `make status` — what's installed and running (via `systemextensionsctl list` and `pgrep`)
- `make logs` — tail the unified log in real time
- `make logs-flows` — tail only flow records
- `make test` — Rust test suite (17 tests)
- UI manually: enable → check logs → disable → remove

See [docs/validation.md](validation.md) for the full checklist.
