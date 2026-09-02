# MVP validation checklist

Manual, on a real Mac. The MVP is proven when every box is ticked.

The goal is four provable statements, in this order because each depends on the one before it:

1. Digiexam can reach one explicitly allowed destination.
2. Safari, Chrome, or anything else **cannot** reach that same destination.
3. Digiexam **cannot** reach anything outside the allowlist.
4. IPv4 and IPv6 traffic are both filtered.

The verdict comes from `rules::decide()` (`crates/filter-sysext/src/rules.rs`) against
`/Users/Shared/Digiexam/rules.json`, keyed on **both** destination and the app that
opened the flow (`crates/filter-sysext/src/attribution.rs`). Note what is *not* claimed: the app
name is what the OS reports, not a signature check, so this checklist proves the allowlist works —
not that it resists a deliberately spoofed binary. That hardening is a separate, tracked follow-up.

---

## Step 0 — reboot first, if stale copies are staged

```bash
make status
```

macOS only clears `[terminated waiting to uninstall on reboot]` copies on boot. If any are listed,
**reboot before anything else**, then confirm:

```bash
systemextensionsctl list | grep ContentFilter    # expect no output
```

Testing before this reboot means testing against whatever stale binary macOS still has loaded.

---

## Build and install

| # | Check | Command | Pass |
|---|---|---|---|
| 1 | Signing preflight | `make check` | "Signing preflight passed" (now also lints `macos/rules.json`) |
| 2 | Extension entitlements | `codesign -d --entitlements - --xml dist/*.systemextension \| plutil -p -` | shows `content-filter-provider-systemextension` and the `.ContentFilter` app-id |
| 3 | Universal slices | build output line `app arch: … sysext arch: …` | both show `x86_64 arm64` |
| 4 | App signature | `codesign --verify --deep --strict --verbose=2 dist/Digiexam.app` | valid on disk; satisfies its Designated Requirement |
| 5 | Install location | `make install` | app launches from `/Applications` |
| 5a | Rules installed | `ls -l "/Users/Shared/Digiexam/rules.json"` | exists (seeded by `make install-rules`, a dependency of `make install`, only if not already present) |
| 5b | Rules content | `cat "/Users/Shared/Digiexam/rules.json"` | `default_action` is `"drop"`; a DNS rule on port 53; an allow rule naming `com.digiexam.macos.NetworkExtensions` (adjust to whatever the log's `app=` column shows for the app — see below) |

Steps 1–4 are all automated inside `make build` and fail the build if violated.

Before testing, edit the seed allow rule's `host` in `macos/rules.json` (and re-run
`make install-rules`) to point at whatever destination you're demonstrating against — the shipped
seed uses `.example.com` as a reachable default.

---

## Activation

| # | Check | How | Pass |
|---|---|---|---|
| 6 | Approval prompt | Click **Enable filter** | macOS prompts; UI shows "waiting for approval in System Settings" |
| 7 | Approve | System Settings → General → Login Items & Extensions → Network Extensions | toggle Digiexam on |
| 8 | **Activation** | `make status` | exactly **one** entry, with **both** `enabled` and `active` flags set |
| 9 | Provider process | `make status` | a process for the extension exists, owned by `root` |

If the UI says *"staged — restart the Mac to activate"*, `CFBundleVersion` changed relative to
what is installed. Reboot and re-check; if that happens on an unchanged build, something is
bumping the version and that is a bug.

---

## The four requirements

Open a log tail in a second terminal and leave it running:

```bash
make logs-flows
```

Every line ends in `app=…(source) pid=…`. The `(id)` suffix means the name came from
`sourceAppIdentifier`; `(path)` means it came from the executable path behind the flow's audit
token. A `(path)` flow can only be named in a rule by its path.

An `(id)` name is `<team-identifier>.<bundle-identifier>`, and the team half is often empty — a
leading `.` is normal. **The same app appears under two of these**: with the team prefix for the
sockets it opens itself, without it for the ones its webview opens for it. So **write `(id)` rules
as the plain bundle identifier** (`com.digiexam.macos.NetworkExtensions`), which covers both; the
verbatim string also works but pins one of the two.

`app=<none>` means neither source could name the process. `pid=` is populated whenever the flow
carried an audit token at all, and can be checked against `ps -p <pid>` independently of whether
our naming worked.

### 1 — Digiexam reaches the allowed destination

| # | Check | How | Pass |
|---|---|---|---|
| 10 | Rules loaded | after enabling | `rules: loaded 3 rule(s), default=drop from /Users/Shared/Digiexam/rules.json` |
| 11 | Webview fetch | in the app, "Test webview fetch" against the allowed host | panel shows `reachable`; log shows `allow … host=<allowed> app=.com.digiexam.macos.NetworkExtensions(id)` — note the leading dot, this is the webview's report |
| 12 | TCP connect | in the app, "Test TCP connect" against the same host | panel shows `reachable`; log shows `allow` with `app=<team>.com.digiexam.macos.NetworkExtensions(id)` — the *same* app as item 11, reported with its team prefix |

If 12 shows `drop` while 11 shows `allow`, the seed's `host` rule matched but the destination has
no IP-literal rule — expected unless you added one; the `ip` matcher exists for exactly this case.

### 2 — Nobody else reaches it

| # | Check | How | Pass |
|---|---|---|---|
| 13 | Safari | browse to the allowed host | fails; log shows `drop … host=<allowed>` with Safari's own `app=` (identifier or path form) |
| 14 | Chrome | same host, in Chrome if installed | fails; log shows `drop` with Chrome's own `app=` |
| 15 | curl | `curl -v --no-keepalive https://<allowed host>` | fails; log shows `drop` with `app=/usr/bin/curl(path)` or similar |

Item 13 is the one that most directly depends on attribution being correct: Safari and this
project's own webview both ride WebKit, and if `app=` ever showed the *same* name for both, this
requirement would be unprovable. `attribution.rs` prefers `sourceAppAuditToken` over
`sourceProcessAuditToken` precisely to keep them distinct — if this item fails with both showing
`com.apple.WebKit.Networking`, that preference is the thing to look at.

### 3 — Digiexam reaches nothing else

| # | Check | How | Pass |
|---|---|---|---|
| 16 | Different host, webview fetch | point the test panel at e.g. `google.com` | panel shows `blocked` or `timed out`; log shows `drop` with Digiexam's own `app=` |
| 17 | Different host, TCP connect | same, via "Test TCP connect" | same result |

This is the pair that proves the rule is keyed on **both** app and destination: item 11 and item 16
show the identical app with opposite verdicts, differing only in where it's connecting to.

### 4 — Both address families are filtered

| # | Check | How | Pass |
|---|---|---|---|
| 18 | IPv4 | `curl -4 https://example.com` | log line shows `IPv4` |
| 19 | IPv6 | `curl -6 https://ipv6.google.com` | log line shows `IPv6` |
| 20 | Family-specific rule | add `{ "action": "drop", "family": "v6" }` ahead of the allow rule in `rules.json`, `make install-rules`, disable/enable | v6 traffic to the allowed host now drops; v4 to the same host still allows | 

Revert the family rule afterward.

On any of the above: a line reading `(endpoint not yet known)` instead of a host and port is
normal, not a gap — Apple documents `remoteEndpoint` as possibly nil at `handleNewFlow:` time,
populated only once data actually flows.

### Not covered: spoofing

There is deliberately **no** spoofing check in this MVP. `attribution.rs` reports the identity the
OS associates with the process and does not verify its code signature, so a binary claiming
Digiexam's identifier would be admitted by an `app` rule. This is a known gap for exam lockdown,
recorded in that module's doc, and closing it is a separate ticket — not something this checklist
should imply is already handled.

### Resilience checks (ops fallback, unrelated to the four requirements)

| # | Check | How | Pass |
|---|---|---|---|
| 22 | Fail-open on a bad file | `sudo mv` the installed `rules.json` aside, disable/enable | `make logs` shows `rules: COULD NOT LOAD`; traffic flows unfiltered (documented fail-open fallback — see `rules.rs`'s module doc); then restore the file and disable/enable again |
| 23 | Unknown field rejected | `sudo` add a typo'd key (e.g. `"hosts"` instead of `"host"`) to a rule, disable/enable | load fails loudly (`deny_unknown_fields`); the *previous* rule set stays in force rather than a widened one taking effect |

---

## Lifecycle

| # | Check | How | Pass |
|---|---|---|---|
| 24 | Disable | click **Disable** | `stopFilter: reason=…` logged; UI shows "disabled"; network returns to normal |
| 25 | Re-enable | click **Enable filter** | `startFilter` again (which reloads rules), **no** second approval prompt |
| 26 | Remove | click **Remove** | configuration gone from System Settings → Network |
| 27 | **No version churn** | `make build && make install` without touching `BUNDLE_VERSION`, then re-enable | still exactly one entry, still `active`, **no reboot needed** |

**Item 27 is the regression test for the original defect.** If a plain rebuild forces a reboot,
`CFBundleVersion` is moving when it should not.

---

## Open questions to settle during validation

- **Intel.** Everything is built universal and item 3 (Build and install) proves both slices
  exist, but the rest of this checklist will only have been exercised on Apple Silicon. Decide
  whether Intel validation is required for this ticket or is follow-up scope.
- **"Digiexam's traffic"** in this checklist means the container app (`Digiexam.app`) itself, via
  its test panel — not a separate exam client. If a real exam client with its own bundle ID and
  team exists, its identifier belongs in `rules.json`'s `app` field alongside or instead of the
  container app's.
- **DNS is allowed for everyone**, not just Digiexam (see the port-53 seed rule) — a real product
  would pin the resolver rather than leaving that channel open to every process. Not solved here.
- **Hostname-carrying flows only.** A `host` rule can only fire once a name reaches
  `handleNewFlow:` — see "The constraint this model does not solve" in
  [docs/architecture.md](architecture.md). The `ip` matcher is the mitigation shipped for this
  MVP; SNI parsing is the deferred, more complete one.

---

## When something is wrong

| Symptom | First thing to check |
|---|---|
| Filter shows in System Settings, no flows | `make status` — is anything `active`? This is *the* classic failure. |
| Nothing in `make logs` at all | Is the provider process running? Does the Info.plist class match `#[name=…]`? `assemble-sysext.sh` asserts this. |
| Digiexam's own allowed request is blocked | Compare the rule's `app` against the log's `app=` column. An `(id)` rule never matches a `(path)`-named flow or vice versa. For `(id)`, prefer the plain bundle identifier over the verbatim string: the verbatim form carries a `<team>.` prefix that differs between the app's own sockets and its webview's, so pinning it covers only half the app's traffic. Also confirm the flow has a `host=` at all; if not, match on `ip` instead. |
| Everything reads `drop`, including DNS | Confirm the port-53 seed rule is still present in the installed `rules.json` — without it nothing resolves and every host rule is unreachable. |
| Every flow reads `drop`, unexpectedly | Check `/Users/Shared/Digiexam/rules.json` — `default_action` may have been left at `drop` from an earlier family/protocol test that wasn't reverted. |
| Activation fails immediately | Is the app in `/Applications`? |
| App launches then dies, or won't launch | AMFI 163: `make check`, and see [signing.md](signing.md). |
| "staged — restart the Mac" | `CFBundleVersion` changed; see [`macos/identity.sh`](../macos/identity.sh). |
