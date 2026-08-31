# MVP validation checklist

Manual, on a real Mac. The MVP is proven when every box is ticked.

The goal is narrow: **flows reach `handleNewFlow:` and are visible.** Nothing is blocked —
the verdict is a hard-coded allow.

---

## Step 0 — reboot first (required)

At time of writing this machine has **15 staged copies** of the extension from the previous
attempt, all `[terminated waiting to uninstall on reboot]`, none `enabled` or `active`:

```bash
make status
```

macOS only clears those on boot. **Reboot before anything else**, then confirm:

```bash
systemextensionsctl list | grep ContentFilter    # expect no output
```

Testing before this reboot means testing against whatever stale binary macOS still has
loaded, which is how the original problem went undiagnosed.

---

## Build and install

| # | Check | Command | Pass |
|---|---|---|---|
| 1 | Signing preflight | `make check` | "Signing preflight passed" |
| 2 | Extension entitlements | `codesign -d --entitlements - --xml dist/*.systemextension \| plutil -p -` | shows `content-filter-provider-systemextension` and the `.ContentFilter` app-id |
| 3 | Universal slices | build output line `app arch: … sysext arch: …` | both show `x86_64 arm64` |
| 4 | App signature | `codesign --verify --deep --strict --verbose=2 dist/Digiexam.app` | valid on disk; satisfies its Designated Requirement |
| 5 | Install location | `make install` | app launches from `/Applications` |

Steps 1–4 are all automated inside `make build` and fail the build if violated.

---

## Activation

| # | Check | How | Pass |
|---|---|---|---|
| 6 | Approval prompt | Click **Enable filter** | macOS prompts; UI shows "waiting for approval in System Settings" |
| 7 | Approve | System Settings → General → Login Items & Extensions → Network Extensions | toggle Digiexam on |
| 8 | **Activation** | `make status` | exactly **one** entry, with **both** `enabled` and `active` flags set |
| 9 | Provider process | `make status` | a process for the extension exists, owned by `root` |

**Item 8 is the one that has never passed.** Blank `enabled`/`active` columns mean the
extension is installed but not running — the state the previous attempt was stuck in.

If the UI says *"staged — restart the Mac to activate"*, `CFBundleVersion` changed relative
to what is installed. Reboot and re-check; if that happens on an unchanged build, something
is bumping the version and that is a bug.

---

## Flows

Open a log tail in a second terminal and leave it running:

```bash
make logs
```

| # | Check | How | Pass |
|---|---|---|---|
| 10 | `start_filter` fires | after enabling | `startFilter: provider started (observe-only build…)` |
| 11 | Flows arrive | browse in Safari | `FLOW1 {…}` lines appear |
| 12 | Digiexam's own traffic | any request from the app | the app's own flows appear |
| 13 | IPv4 | `curl -4 https://example.com` | a record with `"family":"V4"` |
| 14 | IPv6 | `curl -6 https://ipv6.google.com` | a record with `"family":"V6"` |
| 15 | TCP | browsing | `"protocol":"Tcp"` |
| 16 | UDP | `dig @8.8.8.8 example.com` | `"protocol":"Udp"` |
| 17 | Ports and hosts | any of the above | `remote_host` and `remote_port` populated |
| 18 | **Nothing is blocked** | browse normally throughout | no connection failures anywhere on the machine |
| 19 | UI shows flows | app window | table fills within ~1s; "Flows seen" climbs |

On item 17: some records legitimately show `"remote_host":null` and
`(not yet known)` in the UI. Apple documents `remoteEndpoint` as possibly nil at
`handleNewFlow:` time, populated only once data flows. That is normal, not a gap.

Only flow records for `curl` are worth grepping directly:

```bash
make logs-flows
```

---

## Lifecycle

| # | Check | How | Pass |
|---|---|---|---|
| 20 | Disable | click **Disable** | `stopFilter: reason=…` logged; UI shows "disabled" |
| 21 | Re-enable | click **Enable filter** | `startFilter` again, **no** second approval prompt |
| 22 | Remove | click **Remove** | configuration gone from System Settings → Network |
| 23 | **No version churn** | `make build && make install` without touching `BUNDLE_VERSION`, then re-enable | still exactly one entry, still `active`, **no reboot needed** |

**Item 23 is the regression test for the original defect.** If a plain rebuild forces a
reboot, `CFBundleVersion` is moving when it should not.

---

## Open questions to settle during validation

- **Intel.** Everything is built universal and item 3 proves both slices exist, but items
  5–23 will only have been exercised on Apple Silicon. Decide whether Intel validation is
  required for this ticket or is follow-up scope.
- **"Digiexam's own traffic"** (item 12) — is that this container app, or a separate
  existing Digiexam exam client with its own bundle ID? Doesn't change MVP code; determines
  whether the enforcement allowlist keys on one bundle ID or several.
- **Source-app attribution** is off (`LOG_SOURCE_APP` in
  `crates/filter-sysext/src/attribution.rs`). If the flow log turns out to be hard to
  interpret without knowing which app opened each connection, that is the signal to turn it
  on — via `SecCode`, not `NSRunningApplication`; see that module's docs.

---

## When something is wrong

| Symptom | First thing to check |
|---|---|
| Filter shows in System Settings, no flows | `make status` — is anything `active`? This is *the* classic failure. |
| Nothing in `make logs` at all | Is the provider process running? Does the Info.plist class match `#[name=…]`? `assemble-sysext.sh` asserts this. |
| Activation fails immediately | Is the app in `/Applications`? |
| App launches then dies, or won't launch | AMFI 163: `make check`, and see [signing.md](signing.md). |
| "staged — restart the Mac" | `CFBundleVersion` changed; see [`macos/identity.sh`](../macos/identity.sh). |
