# Digiexam macOS Content Filter

A system-wide network content filter for macOS: an `NEFilterDataProvider` packaged as a
**system extension**, written in Rust, driven by a Tauri container app.

> **This is the per-app allowlist MVP.** Every flow is decided by
> [`crates/filter-sysext/src/rules.rs`](crates/filter-sysext/src/rules.rs) against
> `rules.json`, keyed on **both** the destination and the app that asked. The shipped seed
> permits DNS/DHCP plus one app reaching one destination; everything else is dropped by
> default. See "Rules and Enforcement" in [docs/architecture.md](docs/architecture.md) for the
> model and its known limits — including that the app name is not signature-verified.

## Quick start

```bash
make check      # signing preflight — run this first, and whenever signing misbehaves
make build      # signed Digiexam.app with the extension embedded
make install    # copy to /Applications, install rules.json, and launch (sysexts ONLY
                # activate from /Applications)
make logs       # watch the extension's output — this is how you see traffic; there is no UI table
make status     # what macOS actually has installed and running
```

Then follow [docs/validation.md](docs/validation.md).

## Layout

```
crates/filter-sysext/     the .systemextension executable (own cargo workspace);
                          flow.rs + attribution.rs + rules.rs is where flows are read,
                          attributed to an app, and decided
crates/filter-types/      status types + the test-connect probe, shared across the Tauri
                          command boundary
crates/tauri-plugin-content-filter/
                          activation, NEFilterManager control, Tauri commands
app/                      Tauri container app + minimal frontend (enable/disable, allowlist
                          test panel, no flow table)
macos/                    entitlements, sysext Info.plist template, identity.sh, rules.json seed
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

Flows are watched with `make logs`, which tails the extension's unified-log output — there is no
UI table and no IPC channel for flow data. Every logged line names the app
that opened the flow and its pid, from `sourceAppIdentifier` or the executable path behind the
flow's audit token (see `crates/filter-sysext/src/attribution.rs`). That name is what an `app`
rule matches on; it is what the OS reports for the process, not a code-signature check, which
that module's doc records as a deliberate deferral.

Rules are read from `/Users/Shared/Digiexam/rules.json`, not from the
extension's own bundle: the extension runs as `root` and the app as the console user, so a
path under either one's home directory would resolve to two different places for the two of
them (the same split that rules out a shared App Group container here), and the bundle itself
is sealed by the code signature — writable rules need to live outside it. `/Users/Shared`
resolves identically for both and needs no sudo to write into. See
`crates/filter-sysext/src/rules.rs`.

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
