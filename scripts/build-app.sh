#!/usr/bin/env bash
# Build the complete, signed Digiexam.app with the content-filter system extension embedded.
#
# Adapted from the previous product build script (scripts/reference/build-tauri-dmg.sh), keeping
# its steps 2, 3, 4, 5 and 8 — Tauri build, embed, re-sign, notarize+staple, verify — and dropping
# the parts this MVP does not need (the DMG: you install a local .app here, not a disk image).
#
# Notarization is NOT optional, even for local testing on this machine. It looks like it should
# be — Developer ID cert, embedded profile, `codesign --verify --deep --strict` all pass clean —
# but activation still fails with OSSystemExtensionErrorCodeSignatureInvalid (8). The unified log
# (`log show`, process sysextd) names the real reason:
#
#   sysextd: (Security) [com.apple.securityd:SecError] Error checking with notarization daemon: 3
#   sysextd: bundle code signature is not valid - does not satisfy requirement: -67050
#
# sysextd calls out to the notarization daemon as part of validating the staged extension,
# independent of `codesign --verify` — an unnotarized bundle fails that call and gets uninstalled
# before it ever activates. Confirmed empirically 2026-08-31: notarizing + stapling is what fixed
# it, nothing else did.
#
# The submit/poll split in notarize() below is copied near-verbatim from the reference script; it
# exists because `notarytool submit --wait` has crashed after a successful upload and lost the
# submission id.
#
# Order matters and is not negotiable: the inner .systemextension must be fully signed BEFORE it
# is copied in, and the outer app is then signed shallowly (no deep flag) so that it seals the
# inner bundle's existing signature into its CodeResources.
#
# Env:
#   SIGN_IDENTITY     override the signing cert; auto-detected otherwise
#   SKIP_TIMESTAMP=1  sign without a secure timestamp (offline iteration only)
#   SKIP_FRONTEND=1   reuse the existing app/dist (skips npm build)
#   SKIP_NOTARIZE=1   build signed-but-unnotarized — activation WILL fail with code 8; only for
#                     iterating on something that doesn't need activation (e.g. a UI-only change)
#   NOTARY_PROFILE    a `xcrun notarytool store-credentials` keychain profile name
#   AC_USERNAME / AC_PASSWORD   Apple ID + app-specific password, used if NOTARY_PROFILE is unset
#   NOTARY_TIMEOUT    seconds to wait for a verdict (default 1800)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

# shellcheck source=../macos/identity.sh
source "$ROOT/macos/identity.sh"
# shellcheck source=./lib-signing.sh
source "$ROOT/scripts/lib-signing.sh"

log() { printf '\033[36m[build]\033[0m %s\n' "$*" >&2; }

# Submit `$1` for notarization and wait for a verdict — submitting and polling as SEPARATE steps,
# ported from scripts/reference/build-tauri-dmg.sh's notarize(). `notarytool submit --wait` does
# both in one process, so a crash in its polling loop takes the submission id with it and forces a
# full rebuild even though Apple is still processing the upload happily. Polling separately means a
# crash costs a poll, not the whole submission — and on timeout the id is printed so the wait can
# be resumed by hand instead of resubmitting.
notarize() {
  local path="$1" name id status deadline tries=0
  name="$(basename "$path")"
  while :; do
    id="$(xcrun notarytool submit "$path" "${NOTARY_ARGS[@]}" --no-wait --output-format json \
          | plutil -extract id raw -o - - 2>/dev/null)" || true
    [[ -n "$id" && "$id" != "null" ]] && break
    tries=$((tries + 1))
    if (( tries >= NOTARY_SUBMIT_TRIES )); then
      echo "notarytool submit produced no submission id for $name after $tries attempt(s)" >&2
      return 1
    fi
    echo "  submit attempt $tries for $name failed (transient?); retrying in 20s" >&2
    sleep 20
  done
  log "submitted $name -> $id (polling, up to ${NOTARY_TIMEOUT}s)"
  deadline=$(( $(date +%s) + NOTARY_TIMEOUT ))
  while :; do
    status="$(xcrun notarytool info "$id" "${NOTARY_ARGS[@]}" --output-format json 2>/dev/null \
              | plutil -extract status raw -o - - 2>/dev/null || true)"
    case "$status" in
      Accepted)
        log "notarization accepted: $name ($id)"
        return 0
        ;;
      Invalid | Rejected)
        echo "notarization $status for $name ($id) — log follows:" >&2
        xcrun notarytool log "$id" "${NOTARY_ARGS[@]}" >&2 || true
        return 1
        ;;
    esac
    if (( $(date +%s) >= deadline )); then
      echo "notarization of $name still '${status:-unknown}' after ${NOTARY_TIMEOUT}s." >&2
      echo "  It is probably still progressing — resume without rebuilding:" >&2
      echo "  xcrun notarytool info $id ${NOTARY_ARGS[*]}" >&2
      return 1
    fi
    sleep 15
  done
}

OUT="$ROOT/dist"
APP="$OUT/$PRODUCT_NAME.app"
SYSEXT_BUNDLE="$OUT/$SYSEXT_ID.systemextension"

# ── 1. Preflight ────────────────────────────────────────────────────────────────────────────
# Cheap, and it turns every signing misconfiguration into a clear message here rather than an
# artifact that verifies perfectly and then refuses to launch or activate.
log "signing preflight"
"$ROOT/scripts/check-signing.sh" >/dev/null || { "$ROOT/scripts/check-signing.sh"; exit 1; }

SIGN_SHA1="$(resolve_sign_identity)"
export SIGN_SHA1
log "signing identity: $SIGN_SHA1"

TS=(--timestamp)
[[ "${SKIP_TIMESTAMP:-0}" == "1" ]] && TS=(--timestamp=none)

# Resolve notarization credentials now, before the expensive Tauri build, so a missing-creds
# mistake fails in seconds rather than after a multi-minute compile.
if [[ "${SKIP_NOTARIZE:-0}" != "1" ]]; then
  if [[ -n "${NOTARY_PROFILE:-}" ]]; then
    NOTARY_ARGS=(--keychain-profile "$NOTARY_PROFILE")
  elif [[ -n "${AC_USERNAME:-}" && -n "${AC_PASSWORD:-}" ]]; then
    NOTARY_ARGS=(--apple-id "$AC_USERNAME" --password "$AC_PASSWORD" --team-id "$TEAM_ID")
  else
    echo "no notary creds: set NOTARY_PROFILE, or AC_USERNAME+AC_PASSWORD, or SKIP_NOTARIZE=1" >&2
    echo "  (SKIP_NOTARIZE=1 produces a build that will fail to activate — see this script's" >&2
    echo "  header comment for why notarization is not optional here)" >&2
    exit 1
  fi
  NOTARY_TIMEOUT="${NOTARY_TIMEOUT:-1800}"
  NOTARY_SUBMIT_TRIES="${NOTARY_SUBMIT_TRIES:-3}"
fi

# ── 2. System extension ─────────────────────────────────────────────────────────────────────
log "building + signing the system extension"
"$ROOT/scripts/assemble-sysext.sh" >/dev/null
[[ -d "$SYSEXT_BUNDLE" ]] || { echo "assemble-sysext.sh produced no bundle" >&2; exit 1; }

# ── 3. Container app ────────────────────────────────────────────────────────────────────────
# Universal: both slices, lipo'd by Tauri. `universal-apple-darwin` is not a rustup target — it
# requires aarch64-apple-darwin and x86_64-apple-darwin to be installed, which rust-toolchain.toml
# guarantees.
log "building the Tauri app (universal)"
BUILD_ARGS=(--target universal-apple-darwin)
[[ "${SKIP_FRONTEND:-0}" == "1" ]] && BUILD_ARGS+=(--no-bundle)

( cd "$ROOT/app" && APPLE_SIGNING_IDENTITY="$SIGN_SHA1" npm run tauri build -- "${BUILD_ARGS[@]}" )

TARGET_DIR="$(cargo metadata --format-version 1 --no-deps \
  | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
TAURI_APP="$TARGET_DIR/universal-apple-darwin/release/bundle/macos/$PRODUCT_NAME.app"
[[ -d "$TAURI_APP" ]] || { echo "tauri build did not produce $TAURI_APP" >&2; exit 1; }

rm -rf "$APP"
cp -R "$TAURI_APP" "$APP"
log "staged $APP"

# ── 4. Embed ────────────────────────────────────────────────────────────────────────────────
# The sysext goes in Contents/Library/SystemExtensions/; the app's own provisioning profile goes
# in Contents/embedded.provisionprofile. Both must be in place before the app is signed, because
# signing seals Contents/ into CodeResources.
log "embedding the system extension and the app provisioning profile"
mkdir -p "$APP/Contents/Library/SystemExtensions"
cp -R "$SYSEXT_BUNDLE" "$APP/Contents/Library/SystemExtensions/"

APP_PROFILE="$ROOT/macos/profiles/app.provisionprofile"
assert_profile_matches "$APP_PROFILE" "$APP_PROFILE_NAME"
embed_profile "$APP_PROFILE" "$APP"

# ── 5. Sign the outer app ───────────────────────────────────────────────────────────────────
# No deep flag: the embedded extension already carries its own signature with its own
# entitlements and its own profile. Signing deeply here would re-sign it with the APP's
# entitlements, which the sysext's profile does not authorise — and the result would install and
# then refuse to launch.
log "signing $PRODUCT_NAME.app"
codesign --force --options runtime "${TS[@]}" \
         --entitlements "$ROOT/macos/entitlements/app.entitlements" \
         --sign "$SIGN_SHA1" "$APP"

# ── 6. Verify ───────────────────────────────────────────────────────────────────────────────
log "verifying"
codesign --verify --deep --strict --verbose=2 "$APP"

EMBEDDED="$APP/Contents/Library/SystemExtensions/$SYSEXT_ID.systemextension"
[[ -d "$EMBEDDED" ]] || { echo "the system extension is not in the final app" >&2; exit 1; }
codesign --verify --strict "$EMBEDDED"

# The two bundles must carry DIFFERENT application-identifiers, each matching its own profile.
# Getting these crossed is a silent AMFI failure, so it is asserted rather than assumed.
app_id="$(codesign -d --entitlements - --xml "$APP" 2>/dev/null | plutil -p - \
  | sed -n 's/.*"com\.apple\.application-identifier" => "\([^"]*\)".*/\1/p')"
ext_id="$(codesign -d --entitlements - --xml "$EMBEDDED" 2>/dev/null | plutil -p - \
  | sed -n 's/.*"com\.apple\.application-identifier" => "\([^"]*\)".*/\1/p')"
[[ "$app_id" == "$TEAM_ID.$APP_ID" ]] \
  || { echo "app signed with application-identifier '$app_id', expected '$TEAM_ID.$APP_ID'" >&2; exit 1; }
[[ "$ext_id" == "$TEAM_ID.$SYSEXT_ID" ]] \
  || { echo "sysext signed with application-identifier '$ext_id', expected '$TEAM_ID.$SYSEXT_ID'" >&2; exit 1; }

# Read the executable name from the plist rather than assuming it matches the product name:
# Tauri names the binary after the cargo package, not after productName.
APP_EXE="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Contents/Info.plist")"
APP_ARCHS="$(lipo -archs "$APP/Contents/MacOS/$APP_EXE")"
EXT_ARCHS="$(lipo -archs "$EMBEDDED/Contents/MacOS/$SYSEXT_ID")"

# A universal app carrying a single-arch extension loads fine on the build machine and fails on
# the other architecture, at activation time, with nothing in the build log to explain it.
for want in arm64 x86_64; do
  grep -qw "$want" <<<"$APP_ARCHS" || { echo "app is missing the $want slice ($APP_ARCHS)" >&2; exit 1; }
  grep -qw "$want" <<<"$EXT_ARCHS" || { echo "sysext is missing the $want slice ($EXT_ARCHS)" >&2; exit 1; }
done

log "app  entitlement id: $app_id"
log "ext  entitlement id: $ext_id"
log "app  arch: $APP_ARCHS   sysext arch: $EXT_ARCHS"
log "sysext version: $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$EMBEDDED/Contents/Info.plist")"

# ── 7. Notarize + staple ────────────────────────────────────────────────────────────────────
# Required for activation on this machine, not just distribution — see the header comment. The
# notarization ticket covers every Mach-O in the submitted zip, embedded extension included, so
# only the outer .app is submitted and stapled.
if [[ "${SKIP_NOTARIZE:-0}" != "1" ]]; then
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/digiexam-notarize.XXXXXX")"
  trap 'rm -rf "$WORK"' EXIT
  log "notarizing $PRODUCT_NAME.app"
  ditto -c -k --keepParent "$APP" "$WORK/app.zip"
  notarize "$WORK/app.zip"
  xcrun stapler staple "$APP"
  xcrun stapler validate "$APP"
else
  log "SKIP_NOTARIZE=1: built signed-but-unnotarized — activation will fail with code 8"
fi

echo
log "built $APP"
log "NOTE: system extensions only activate from /Applications. Run 'make install'."
