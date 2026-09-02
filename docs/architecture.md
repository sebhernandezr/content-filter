# Architecture & Implementation Guide

This document explains how the Digiexam macOS Content Filter works end-to-end: how it's built, installed, and captures network data.

## Overview

The content filter is a macOS **system extension** (not an app extension) that decides, per connection, whether to let traffic through. The decision is a **per-app allowlist**: a rule can require both a destination *and* the identity of the app that opened the connection, so "only Digiexam may reach this host" is expressible as a rule. See "Rules and Enforcement" below for the model, where that identity comes from, and what it is and is not worth.

Two main components:
1. **The System Extension** (`crates/filter-sysext/`) — a privileged process running as `root` that intercepts network flows
2. **The Container App** (`app/`) — a Tauri app running as the console user that controls the extension. It does not display flows; watch those in a terminal with `make logs-flows`.

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
- Result: Flows are now being observed and decided on
- **Step 2 can succeed even if Step 1 failed silently** — this was the bug the previous attempt got stuck in

**Why separate them?** Because the previous codebase did step 2 without verifying step 1, and ended up with 15 staged extension copies, none of them actually running, while the UI claimed success. This design forces the failure to be visible: the UI shows activation state and configuration state as two separate rows. `ActivationState::NeedsReboot` (meaning the extension is staged but not active) never collapses into success.

## Architecture Layers

### Layer 1: System Extension (Filter Provider)

**What it does:** Receives every new network connection on the machine, decides what to do with it, and logs the outcome.

**Files:**
- `crates/filter-sysext/src/main.rs` — entry point: loads rules once, registers the provider class, calls `NEProvider.startSystemExtensionMode()`, parks forever
- `crates/filter-sysext/src/provider.rs` — `FilterProvider` class (ObjC, via objc2): implements three lifecycle methods
  - `startFilter()` — called when NEFilterManager enables the filter; **reloads rules from disk** (so toggling the filter off and on picks up a rules file a backend has since rewritten, no rebuild or reboot needed), then logs that it started
  - `stopFilter()` — called when the filter is disabled or configuration is removed; logs the reason code
  - `handleNewFlow()` — **the hot path**: called once per new connection (concurrently, from the framework's queue); extracts flow details, asks `rules::decide()` for a verdict, logs the outcome, returns `allowVerdict()` or `dropVerdict()`
- `crates/filter-sysext/src/flow.rs` — `info_for()`: turns a raw `NEFilterFlow` into a `FlowInfo` struct with fields like remote IP, port, hostname (if available), resolved domain (if WebKit), the caller's `AppId`, and its pid; `FlowInfo::log_line()` renders one human-readable log line, including the `app=` and `pid=` columns
- `crates/filter-sysext/src/rules.rs` — the allowlist: `RuleSet::decide()` matches a `FlowInfo` against an ordered list of rules (app/host/ip/port/protocol/family) and falls back to `default_action`; see "Rules and Enforcement" below
- `crates/filter-sysext/src/logging.rs` — logs to the unified log system (`os_log`) under subsystem `com.digiexam.macos.NetworkExtensions`
- `crates/filter-sysext/src/attribution.rs` — names the app that opened a flow, from `sourceAppIdentifier` or the executable path behind the flow's audit token; deliberately *not* a signature check — see "Rules and Enforcement" below

**Runs as:** `root` (required by the NetworkExtension framework)

**Lifecycle:**
1. Spawned by macOS only after the container app calls `NEFilterManager.saveToPreferences()`
2. Immediately calls `startFilter()`, which reloads rules and reports readiness
3. Waits on `dispatch_main()` — parks forever, processing `handleNewFlow()` callbacks from the framework
4. When the filter is disabled, `stopFilter()` is called and the process exits (or remains idle until re-enabled)

**The decision itself:** the default framework action is `NEFilterActionFilterData` (deliver every flow to `handleNewFlow:`); no `NEFilterSettings` are applied because that default already does what's needed. What `handleNewFlow:` returns is now `rules::current().decide(&info)` — see "Rules and Enforcement".

### Layer 2: Watching Flows

There is no IPC channel for flow data — no shared file, no App Group, no log-parsing pipeline into the app. The extension writes one readable line per flow to the unified log (`os_log`, subsystem `com.digiexam.macos.NetworkExtensions`, category `flow`), and you read it directly with a terminal:

```
make logs-flows
```

which runs `log stream --predicate 'subsystem == "..." AND category == "flow"'`. This *is* the intended way to observe traffic — not a debugging fallback for a UI that used to exist. A prior version of this project tailed that same log stream from the container app, parsed it into structs, and rendered a live table; that machinery (`filter-types::FlowRecord`, `flow_log.rs`, the frontend table) has been removed because a terminal already does the job.

### Layer 3: Container App & Tauri Plugin

The container app is a minimal Tauri app (Rust backend + TypeScript frontend) that:
1. Drives extension activation (calling `OSSystemExtensionRequest`)
2. Enables/disables the filter configuration (calling `NEFilterManager`)
3. Exposes commands to the UI

**Backend (Rust):**
- `crates/tauri-plugin-content-filter/src/lib.rs` — Tauri plugin initialization; manages `FilterState` (last observed activation state)
- `crates/tauri-plugin-content-filter/src/commands.rs` — Tauri commands (invoked by frontend):
  - `enable_filter()` — activate + enable in one call
  - `disable_filter()` — disable the filter config
  - `remove_filter()` — remove config + deactivate extension
  - `filter_status()` — query current state
  - `test_connect()` — raw TCP connect to a given host:port, for demonstrating the allowlist from the UI (`filter_types::tcp_probe`)
- `crates/tauri-plugin-content-filter/src/sysext.rs` — `OSSystemExtensionRequest` API wrapper; submits activation/deactivation requests and waits for callbacks
- `crates/tauri-plugin-content-filter/src/filter_manager.rs` — `NEFilterManager` API wrapper; enables/disables/removes filter config
- `crates/filter-types/src/lib.rs` — `ActivationState` / `FilterStatus` cross the Tauri command boundary; `TestConnectResult` / `tcp_probe()` implement the test-connect command for real, and are platform-independent so they also back the non-macOS stub build

All blocking APIs are called on a thread pool (not the main thread), because they dispatch to the main queue and wait for callbacks — calling from main would deadlock (the dispatch queue can't service callbacks while the main thread is blocked in the same API).

**Frontend (TypeScript):**
- `app/src/main.ts` — minimal UI: three buttons (Enable, Disable, Remove), two status rows
  (Extension, Configuration), and a test panel with two ways to probe the allowlist — a
  webview `fetch()` (carries a hostname, exercises the `host` matcher) and a `test_connect`
  call (a bare socket, carries no hostname, exercises the `ip` matcher). No flow table — see
  Layer 2.
- `app/src/style.css` — styling
- Calls backend commands via Tauri's `invoke()` API
- Polls status every 2s so the UI stays in sync with macOS state

## Rules and Enforcement

This is a **per-app allowlist**: `default_action` in the shipped seed is `drop`, and rules say what is
permitted. Four things have to be provable for the MVP: one named app reaches one named
destination; nothing else reaches it; that app reaches nothing else; and both IPv4 and IPv6 are
covered. The first two require the rule key to include *who is asking*, not just *where to* — see
"Why attribution has to be verified, not just read" below.

Rules live in one file, read at a fixed path: `/Library/Application Support/Digiexam/rules.json`. Not inside the extension's own bundle — the bundle is sealed by the code signature, and rules need to be writable at runtime so a backend can push updates without a rebuild. Not under either process's home directory — the extension runs as `root` and the app as the console user, so `~/…` resolves to two different places for the two of them, the same split that rules out a shared App Group container.

```json
{
  "default_action": "drop",
  "rules": [
    { "action": "allow", "port": 53, "comment": "DNS — nothing resolves without it" },
    { "action": "allow", "protocol": "udp", "port": 67, "comment": "DHCP" },
    {
      "action": "allow",
      "app": "com.digiexam.macos.NetworkExtensions",
      "host": ".example.com",
      "comment": "the one allowed destination, only for Digiexam"
    }
  ]
}
```

Every matcher is optional and they are ANDed; a rule with none matches every flow (that is what the
DNS/DHCP seed rules are). Rules are evaluated in order; the first match wins; no match falls through
to `default_action`.

| matcher | matches against | notes |
|---|---|---|
| `app` | `AppId.name` | an application identifier or an executable path, whichever the OS reported — see below |
| `host` | `FlowInfo::best_destination()` | exact, or a leading-dot suffix (`.example.com` covers the apex and every subdomain) |
| `ip` | `FlowInfo.remote_host` | exact literal only, no CIDR; the escape hatch for a flow that carries an address but no name — see below |
| `port` | `FlowInfo.remote_port` | |
| `protocol` | `tcp` / `udp` | |
| `family` | `v4` / `v6` | |

**Why DNS and DHCP have to be allowed explicitly:** `default_action: drop` blocks everything not
matched, including the resolver. Without the port-53 rule, nothing on the machine resolves a
hostname at all, and no `host` rule can ever fire — the allowlist would appear to block *everything*,
not just what it was meant to. A blanket DNS allowance is itself a coarse channel (any process can
tunnel data through it); a real product would pin the resolver instead. That is a follow-up, not
solved here.

**Where the app name comes from, and what it is worth.**
`crates/filter-sysext/src/attribution.rs` tries two sources in order:
`NEFilterFlow.sourceAppIdentifier` (a plain string the framework supplies), and failing that
`proc_pidpath_audittoken` on the flow's audit token (the executable's path on disk). The audit
token used is `sourceAppAuditToken` in preference to `sourceProcessAuditToken`: WebKit apps make
their connections through `com.apple.WebKit.Networking`, so the process token would give Safari and
this app's own webview the *same* identity and make "Safari cannot, Digiexam can" unprovable.

Because the two sources produce different *forms* of name, the flow log tags each with `(id)` or
`(path)`, and a rule has to be written in the matching form — a rule written the wrong way round
simply never matches, which the suffix makes visible instead of silent.

**This is not a code-signature check**, and that is a deliberate, documented deferral. The name is
what the OS associates with the process; nothing here verifies that the process's signature is
intact or that it was signed by a particular team, so a binary claiming Digiexam's identifier would
be reported as Digiexam. An earlier revision did verify signatures via `SecCodeCheckValidity`; it
was removed because it failed silently for every process (the code discarded every `OSStatus`) and
because spoofing resistance is not among the current requirements. Re-adding it is real hardening
work for a later ticket — see `attribution.rs`'s module doc, which records the terms it should come
back on.

**The escape hatch for nameless flows: `ip`.** A raw `TcpStream::connect` (exactly what the app's
own "Test TCP connect" button does) carries no hostname anywhere the framework hands the filter at
`handleNewFlow:` time — see the socket-level view below. `ip` matches the literal remote address
instead, so an app can still be admitted to a destination it reaches without a name attached.

`make install-rules` (a dependency of `make install`) copies `macos/rules.json` to the runtime path
with `root:wheel` ownership and mode 644 — sudo is required because `/Library/Application Support`
is admin-owned. That ownership stops a non-admin user from editing it and stops nothing else; it is
not tamper-proof against an admin. Real lockdown will need the provider to verify a backend
signature over the rules payload rather than trust the bytes on disk as-is.

**The ops fallback still fails open, deliberately kept separate from the policy pivot.** A missing
or unparseable rules file logs the failure loudly and keeps whatever rule set was last loaded
successfully (or allow-everything, before any load has succeeded). That is a statement about
resilience to a bad push, not about the shipped policy: as soon as any file loads, *its*
`default_action` — `drop` here — governs every flow. Making that ops fallback itself fail closed is
real hardening, and a distinct decision from this pivot; `rules.rs`'s module doc flags it explicitly
so it is not mistaken for an oversight.

**The constraint this model does not solve:** matching on `host` misses a flow at the moment a
verdict is required whenever `remoteEndpoint` is nil or `remoteHostname` is unset — see the
Chrome example below. The `ip` matcher covers the *known-destination* case; it does not recover a
name the framework never handed over. Reading a name off the wire (the TLS ClientHello SNI, via
`pauseVerdict` / `filterDataVerdict` and `handleOutboundDataFromFlow:`) would close more of that
gap and is a real follow-up, but it was set aside for this MVP once the policy became fail-closed:
an allowlist already refuses anything it cannot positively identify, which is the property that
made SNI parsing non-essential for *this* ticket.

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

- **One `FlowInfo` per connection opening**, not per HTTP request
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
4. The flow gets:
   - `remote_host` = `"198.51.100.42"` (the IP)
   - `remote_port` = `443` (HTTPS)
   - `hostname` = `null` (Chrome doesn't use NSURLSession)
   - `url_host` = `null` (not a WebKit flow)
   - `app` — **is** populated: attribution reads `sourceAppAuditToken` regardless of which
     networking stack the app uses, so Chrome still gets named even though no hostname is
     available. Attribution and hostname visibility are independent axes.
5. `rules::decide()` sees `best_destination() == None` (no `hostname`, no `url_host`, only the raw
   `remote_host` IP), so any `host` rule is skipped for this flow regardless of `app`. It falls
   through to `default_action` — `drop`, with the shipped seed — unless a rule matches on `ip`
   instead of `host`, which is exactly the case that matcher exists for.

**A name is recoverable in principle** by parsing the TLS ClientHello SNI out of the flow's raw
outbound bytes (`pauseVerdict` / `filterDataVerdict` plus `handleOutboundDataFromFlow:`). Not
implemented here — see "The constraint this model does not solve" above for why an allowlist made
this less urgent than it would be for a denylist.

### Safari navigating to digiexam.com

Safari uses WebKit, which is built on Network.framework. The flow gets:
- `url_host` = `"digiexam.com"` (directly from the URL) — `best_destination()` now returns a real
  name, so a `host` rule can match
- `app` resolves the same way as Chrome's, via the audit token — but WebKit-originated traffic
  (Safari, and this project's own webview) is attributed to `com.apple.WebKit.Networking` via
  `sourceProcessAuditToken` if `sourceAppAuditToken` were ever absent. Attribution prefers the
  *app* token specifically to avoid that collapse — see `attribution.rs`'s module doc — which is
  what keeps "Safari cannot reach it, Digiexam can" provable even though both go through WebKit.

## Provisioning, Signing & Entitlements

See [docs/signing.md](signing.md) for the detailed explanation. Quick version:

- Developer ID certificate must be embedded in **both** provisioning profiles
- Both profiles must be copied into the bundles **before signing** (signing seals them into CodeResources)
- The app is signed without `--deep` to avoid re-signing the embedded extension with the wrong entitlements
- Notarization is required (sysextd validates against Apple's infrastructure)
- SIP is on, so developer mode is unavailable — profiles are required from day one, not just for distribution

## File & Data Flow

```
FlowInfo is born:
  NEFilterFlow (framework object)
  → flow::info_for() extracts fields
  → rules::current().decide(&info) picks Allow or Drop
  → info.log_line(action) renders one readable line
  → logged to os_log via logging::flow()

FlowInfo is read:
  a terminal, via `make logs-flows`
  (no IPC, no ring buffer, no UI table — see Layer 2 above)
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
| App attribution | `crates/filter-sysext/src/attribution.rs` (sourceAppIdentifier / proc_pidpath) |
| Allowlist decision | `crates/filter-sysext/src/rules.rs` |
| Data logging | `crates/filter-sysext/src/logging.rs`; read it with `make logs-flows` |
| Tauri command types | `crates/filter-types/src/lib.rs` |
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
- `make logs-flows` — tail only flow records; this is the primary way to watch traffic
- `make test` — Rust test suite
- UI manually: enable → watch `make logs-flows` → disable → remove

See [docs/validation.md](validation.md) for the full checklist.
