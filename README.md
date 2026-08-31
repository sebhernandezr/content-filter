# Digiexam macOS Content Filter

A system-wide network content filter for macOS: an `NEFilterDataProvider` packaged as a
**system extension**, written in Rust, driven by a Tauri container app.

> **This is the observe-only MVP.** Every network flow on the machine is logged and
> **allowed**. Nothing is blocked. The allow/block logic and the allowlist are the next
> ticket — they replace one expression in
> [`crates/filter-sysext/src/provider.rs`](crates/filter-sysext/src/provider.rs).

## Quick start

```bash
make check      # signing preflight — run this first, and whenever signing misbehaves
make build      # signed Digiexam.app with the extension embedded
make install    # copy to /Applications and launch (sysexts ONLY activate from there)
make logs       # watch the extension's output
make status     # what macOS actually has installed and running
```

Then follow [docs/validation.md](docs/validation.md).

## Layout

```
crates/filter-sysext/     the .systemextension executable (own cargo workspace)
crates/filter-types/      the flow-log wire format, shared by extension and app
crates/tauri-plugin-content-filter/
                          activation, NEFilterManager control, log tail, Tauri commands
app/                      Tauri container app + minimal frontend
macos/                    entitlements, sysext Info.plist template, identity.sh
scripts/                  check-signing / assemble-sysext / build-app
docs/                     signing.md, validation.md
```

## How it fits together

Two **independent** things must both succeed before a single flow is observed, and the
whole design keeps them visibly separate because they fail separately:

1. **Activation** — `OSSystemExtensionRequest` installs the extension and gets user
   approval. → `crates/tauri-plugin-content-filter/src/sysext.rs`
2. **Enabling** — saving an enabled `NEFilterManager` configuration is what actually
   launches the provider process. → `filter_manager.rs`

Step 2 can succeed while step 1 has not really finished. That produces a filter that is
visible in System Settings → Network and observes nothing — which is exactly the state the
previous attempt was stuck in, with 15 staged extension copies and none ever active. The UI
reports activation and configuration as two separate rows for this reason, and
`ActivationState::NeedsReboot` is never collapsed into success.

Flow records travel from the extension to the app over the **unified log**, not a shared
App Group container: the extension runs as `root` and the app as the console user, so their
group containers are different directories (`/var/root/…` vs `~/…`) and the app cannot read
the extension's. `crates/filter-types/src/lib.rs` defines the log line format both sides
use; `flow_log.rs` tails it with `log stream`.

## Things that will cost you a day if you forget

| | |
|---|---|
| **Keep `CFBundleVersion` stable** | Bumping it makes macOS *stage* the extension instead of activating it, keeping the old one running until a reboot. Declared once in [`macos/identity.sh`](macos/identity.sh). |
| **The app must be in `/Applications`** | Activation fails anywhere else with `UnsupportedParentBundleLocation`. |
| **Sign the extension before embedding it** | And sign the app **without** `--deep`, or the extension gets the app's entitlements and stops launching. |
| **No `--` inside entitlements XML comments** | Illegal XML; codesign rejects the whole file. `plutil -lint` will not warn you. `make check` does. |
| **SIP is on, so developer mode is unavailable** | Provisioning profiles are required from day one; notarization is not, for local testing. |

Details and the reasoning behind each: [docs/signing.md](docs/signing.md).

## Requirements

macOS 12.0+ · Rust 1.97 with the `aarch64-apple-darwin` and `x86_64-apple-darwin` targets
(pinned in `rust-toolchain.toml`) · Node 20+ · a Developer ID Application certificate and
the two provisioning profiles (`make check` verifies all of it).

Builds universal (arm64 + x86_64) by default.
