# Signing, entitlements and provisioning profiles

Everything Xcode normally hides, written down. If signing breaks, start with
`./scripts/check-signing.sh` — it checks every claim on this page against reality.

## The mental model

Three things are easy to conflate. They are not the same:

| Thing | What it is | Where it physically lives |
|---|---|---|
| **Entitlements** | A plist of capabilities you *claim* | A file on disk at build time. **Baked into the code signature.** Never a file inside the bundle. |
| **Provisioning profile** | Apple's countersigned permission slip: your team may claim those entitlements, and here are the exact certs allowed to sign | A file **copied into the bundle** at `Contents/embedded.provisionprofile` |
| **Signing certificate** | Your identity | The keychain |

At launch AMFI requires that the **entitlements in the signature are a subset of the
entitlements in the embedded profile**, and that the **signing cert is one of the profile's
`DeveloperCertificates`**. Violate either and the binary signs, verifies and notarizes
perfectly, then refuses to spawn — reported as an opaque "Launch failed", AMFI error 163,
with no mention of signing anywhere.

`assert_profile_matches` in [`scripts/lib-signing.sh`](../scripts/lib-signing.sh) exists to
turn that into a build error instead.

## What this project has

| | Value |
|---|---|
| Team ID | `73T9H7VE4P` (DigiExam Solutions Sweden AB) |
| Signing cert | one Developer ID Application, `5E4B69C0B26D76ABC446DBF644CA12A514726F16` |
| App bundle ID | `com.digiexam.macos.NetworkExtensions` |
| Extension bundle ID | `com.digiexam.macos.NetworkExtensions.ContentFilter` |
| App Group | `group.com.digiexam.macos.NetworkExtensions` |
| App profile | "Digiexam macOS App", expires 2044-08-26 |
| Extension profile | "Digiexam macOS ContentFilter", expires 2044-08-26 |

All of it is declared once in [`macos/identity.sh`](../macos/identity.sh).

The extension's bundle ID **must be prefixed by the app's** — that is a macOS requirement,
not a convention.

## Entitlements

Files: [`macos/entitlements/app.entitlements`](../macos/entitlements/app.entitlements) and
[`sysext.entitlements`](../macos/entitlements/sysext.entitlements). Neither is copied into a
bundle; both reach their bundle only through `codesign --entitlements`.

Read back what actually landed:

```bash
codesign -d --entitlements - --xml dist/Digiexam.app | plutil -p -
```

### How the two differ

| Key | App | Extension | Why |
|---|---|---|---|
| `com.apple.application-identifier` | `…NetworkExtensions` | `…NetworkExtensions.ContentFilter` | Each must match its **own** profile. Crossing them is a silent AMFI failure. |
| `com.apple.developer.team-identifier` | ✅ | ✅ | |
| `com.apple.developer.networking.networkextension` | ✅ | ✅ | App drives `NEFilterManager`; extension *is* the provider. |
| `com.apple.developer.system-extension.install` | ✅ | ❌ | The right to *install* belongs to the installer. |
| `com.apple.security.application-groups` | ✅ | ✅ | Must match exactly. |
| `com.apple.security.app-sandbox` | ❌ | ❌ | Optional for system extensions. Off for the MVP; see the file's own comment. |

### Three traps

**1. `com.apple.application-identifier` is load-bearing and easy to lose.**
`xcodebuild` injects it automatically; **`codesign` does not**. Without it,
`nesessionmanager` refuses the app's control channel to the NE plugin — and it fails
*looking like success*: `saveToPreferences` returns OK, the filter appears in System
Settings, and nothing ever happens.

**2. The entitlement is `content-filter-provider-systemextension`,** not the plain
`content-filter-provider`. The plain form is for *app* extensions. Our profiles authorise
only the `-systemextension` variants, so the plain form is an entitlement in the signature
that the profile lacks → AMFI 163.

**3. XML comments must not contain a doubled hyphen.** It is illegal XML, and codesign's
parser rejects the whole file:

```
Failed to parse entitlements: AMFIUnserializeXML: syntax error near line 8
```

`plutil -lint` accepts the file anyway, so it will not warn you. This is very easy to
reintroduce by writing a codesign flag in a comment. `check-signing.sh` guards against it.

## Provisioning profiles

**Committed to this repo** at `macos/profiles/app.provisionprofile` and
`macos/profiles/sysext.provisionprofile`. They're not secret — no private key, just Apple's
countersigned statement of which certs and entitlements this app-id may use — so every
developer on the team builds straight off a `git clone`, no personal Xcode account or
profile-store setup required. Only the Developer ID Application **certificate + private
key** (the actual signing identity, in the keychain) stays per-machine.

`assemble-sysext.sh` and `build-app.sh` read those two files directly by fixed path and
copy them into **each** bundle at a fixed filename:

```
dist/Digiexam.app/Contents/embedded.provisionprofile                      <- macos/profiles/app.provisionprofile
dist/Digiexam.app/Contents/Library/SystemExtensions/
    com.digiexam.macos.NetworkExtensions.ContentFilter.systemextension/
        Contents/embedded.provisionprofile                               <- macos/profiles/sysext.provisionprofile
```

**Copy the profile in before `codesign` runs on that bundle.** Signing seals `Contents/`
into `CodeResources`; a profile added afterwards invalidates the signature.

Inspect one with `security cms -D -i <file> | plutil -p -`.

### Refreshing them (rotation, renaming, a new entitlement)

Whoever has developer-portal access:

1. Regenerate the profile(s) in the portal and download the `.provisionprofile` file(s) —
   they land in `~/Downloads` by default.
2. Run `./scripts/import-profiles.sh`. It finds them by their portal **Name** (the
   `APP_PROFILE_NAME`/`SYSEXT_PROFILE_NAME` in [`macos/identity.sh`](../macos/identity.sh)),
   copies them into `macos/profiles/`, and strips the `com.apple.quarantine` xattr a
   browser download carries (see the note below — leaving it in breaks activation).
3. `./scripts/check-signing.sh` to confirm they match your signing cert, then commit them
   and let the rest of the team `git pull`.

## Are profiles required for local dev testing?

**Yes. From day one.** There are two ways macOS will load a system extension, and only one
is open to us.

**Path A — developer mode.** `systemextensionsctl developer on` relaxes signing checks. On
this machine:

```
$ systemextensionsctl developer
At this time, this tool cannot be used if System Integrity Protection is enabled.
$ csrutil status
System Integrity Protection status: enabled.
```

It requires disabling SIP from recovery. **This path is closed.**

**Path B — Developer ID signed with an embedded profile.** Ours. Notarization is **not**
required for local testing: a locally built, Developer ID-signed, profile-embedded
extension with no quarantine attribute activates on the build machine.

That last clause bit us once: a `.provisionprofile` downloaded via browser carries
`com.apple.quarantine`, and a plain `cp` preserves xattrs — so the flag rode into
`Contents/embedded.provisionprofile` inside the sealed bundle and activation failed with
`OSSystemExtensionErrorCodeSignatureInvalid` (code 8), even though `codesign --verify
--deep --strict` passed clean (xattrs aren't sealed into the CDHash, so verify can't see
this). Both `embed_profile()` in [`scripts/lib-signing.sh`](../scripts/lib-signing.sh) and
`scripts/import-profiles.sh` now strip it automatically — but if activation ever throws
code 8 again with everything else checking out, `xattr -lr dist/Digiexam.app | grep
quarantine` is the first thing to run.

| | Local dev? | Distribution? |
|---|---|---|
| Developer ID cert | ✅ | ✅ |
| Embedded profiles | ✅ | ✅ |
| Correct entitlements | ✅ | ✅ |
| Hardened runtime (`--options runtime`) | ✅ | ✅ |
| Notarization | ❌ | ✅ |
| Stapling | ❌ | ✅ |
| DMG | ❌ | ✅ |

## Signing order

Inner bundle first, always:

1. `assemble-sysext.sh` — build, lipo, write `Info.plist`, embed the **extension's**
   profile, `codesign` with the **extension's** entitlements.
2. `build-app.sh` — Tauri build, copy the signed extension into
   `Contents/Library/SystemExtensions/`, embed the **app's** profile, `codesign` the app
   with the **app's** entitlements — **without `--deep`**.

`--deep` would re-sign the embedded extension with the *app's* entitlements, which the
extension's profile does not authorise. It would verify locally and fail to activate.

## Two hard requirements that fail opaquely

- **The `.app` must be in `/Applications`.** Activating from `dist/`, `~/Downloads`, or a
  mounted DMG fails with `OSSystemExtensionErrorUnsupportedParentBundleLocation`. Use
  `make install`.
- **Keep `CFBundleVersion` stable across rebuilds.** See
  [`macos/identity.sh`](../macos/identity.sh) — this is the single most expensive mistake
  available in this project, and it is documented at length there.

## Relationship to the old build script

[`scripts/reference/build-tauri-dmg.sh`](../scripts/reference/build-tauri-dmg.sh) is the
previous product build script, kept **verbatim**. It is the spec for the distribution
ticket, not dead weight — two parts in particular should be reused rather than rewritten:

- **`notarize()` (lines 192–245)** submits and polls as *separate* steps, with submit
  retries. `notarytool submit --wait` has been observed dying with `Bus error: 10` *after*
  a successful upload, taking the submission id with it and forcing a full rebuild while
  Apple was still processing the upload happily.
- **The DMG layout (lines 345–411)**, including the committed `.DS_Store` template that
  lets styling work headlessly without Finder automation.

What was **not** carried over, and why: the `xcodebuild` archive path (replaced by
`assemble-sysext.sh`), and `CURRENT_PROJECT_VERSION="$(date +%s)"` at line 304, which is
the defect that produced 15 staged extensions and zero active ones.
