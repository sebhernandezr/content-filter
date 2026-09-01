# MVP validation checklist

Manual, on a real Mac. The MVP is proven when every box is ticked.

The goal is narrow: **flows reach `handleNewFlow:` and are visible in a terminal.** Nothing is
blocked with the shipped `rules.json` — its `default_action` is `allow` — but the verdict now
comes from `rules::decide()` (`crates/filter-sysext/src/rules.rs`), not a hard-coded constant, so
this checklist also proves that seam is wired (see the rules step under Flows below).

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
| 5a | Rules installed | `ls -l "/Library/Application Support/Digiexam/rules.json"` | exists, owned `root:wheel`, mode `644` (installed by `make install-rules`, a dependency of `make install`) |

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
| 10a | Rules loaded | after enabling | `rules: loaded 0 rule(s), default=allow from /Library/Application Support/Digiexam/rules.json` |
| 10 | `start_filter` fires | after enabling | `startFilter: provider started` |
| 11 | Flows arrive | browse in Safari | `allow …` lines appear |
| 12 | Digiexam's own traffic | any request from the app | the app's own flows appear |
| 13 | IPv4 | `curl -4 https://example.com` | a line showing `IPv4` |
| 14 | IPv6 | `curl -6 https://ipv6.google.com` | a line showing `IPv6` |
| 15 | TCP | browsing | a line showing `TCP` |
| 16 | UDP | `dig @8.8.8.8 example.com` | a line showing `UDP` |
| 17 | Ports and hosts | any of the above | host and port shown, e.g. `93.184.216.34:443 host=example.com` |
| 18 | **Nothing is blocked** | browse normally throughout | no connection failures anywhere on the machine; every logged line starts `allow` |

On item 17: some lines legitimately read `(endpoint not yet known)` instead of a host and port.
Apple documents `remoteEndpoint` as possibly nil at `handleNewFlow:` time, populated only once
data flows. That is normal, not a gap.

Only flow lines are worth grepping directly:

```bash
make logs-flows
```

### Rules smoke test — proves the seam is wired, not just written

No rebuild needed; this is the point.

| # | Check | How | Pass |
|---|---|---|---|
| 19a | Deny takes effect | `sudo` edit `/Library/Application Support/Digiexam/rules.json` to `{"default_action":"drop","rules":[]}`, then click **Disable** then **Enable filter** in the app | `make logs` shows the reload line with `default=drop`; `make logs-flows` shows `drop …` lines; browsing actually fails |
| 19b | Revert | change the file back to `{"default_action":"allow","rules":[]}`, disable/enable again | reload line shows `default=allow`; browsing works again |
| 19c | Fail-open on a bad file | `sudo mv` the file aside, disable/enable | `make logs` shows a `rules: COULD NOT LOAD` line; traffic still flows (fails open, as documented in `rules.rs`) — then restore the file and disable/enable once more |

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
| Every flow reads `drop`, unexpectedly | Check `/Library/Application Support/Digiexam/rules.json` — `default_action` may have been left at `drop` from an earlier test. |
| Activation fails immediately | Is the app in `/Applications`? |
| App launches then dies, or won't launch | AMFI 163: `make check`, and see [signing.md](signing.md). |
| "staged — restart the Mac" | `CFBundleVersion` changed; see [`macos/identity.sh`](../macos/identity.sh). |
