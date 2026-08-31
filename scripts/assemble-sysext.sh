#!/usr/bin/env bash
# Build, assemble and sign the .systemextension bundle.
#
# This replaces the xcodegen + `xcodebuild archive` step from the previous build script
# (scripts/reference/build-tauri-dmg.sh lines 269-308). Xcode used to do all of this invisibly;
# without it, every part has to be explicit — which is the point, because the naming rules below
# are enforced silently by sysextd and produce no diagnostic when broken.
#
# Output: dist/<SYSEXT_ID>.systemextension, signed and ready to embed in the container app.
#
# Env:
#   SIGN_IDENTITY   override the signing cert (SHA-1 or display name); auto-detected otherwise
#   SKIP_TIMESTAMP=1  sign with --timestamp=none for offline iteration (NOT for distribution:
#                     a signature without a secure timestamp stops verifying when the cert expires)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

# shellcheck source=../macos/identity.sh
source "$ROOT/macos/identity.sh"
# shellcheck source=./lib-signing.sh
source "$ROOT/scripts/lib-signing.sh"

log() { printf '[sysext] %s\n' "$*" >&2; }

CRATE="$ROOT/crates/filter-sysext"
BIN_NAME="digiexam-content-filter"
OUT="$ROOT/dist"
BUNDLE="$OUT/$SYSEXT_ID.systemextension"

# ── 1. Build both architectures ─────────────────────────────────────────────────────────────
# A universal extension is required because the .app it lives in is universal: a sysext whose
# executable lacks the host's architecture cannot be loaded, and the failure appears at
# activation time, not at build time.
log "building $BIN_NAME for arm64 and x86_64"
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  ( cd "$CRATE" && cargo build --release --target "$target" )
done

# Ask cargo where its output actually is rather than assuming a layout — this crate is its own
# workspace, so its target dir is NOT the repo-root one.
TARGET_DIR="$(cd "$CRATE" && cargo metadata --format-version 1 --no-deps \
  | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"

ARM="$TARGET_DIR/aarch64-apple-darwin/release/$BIN_NAME"
X86="$TARGET_DIR/x86_64-apple-darwin/release/$BIN_NAME"
[[ -f "$ARM" ]] || { echo "missing arm64 build: $ARM" >&2; exit 1; }
[[ -f "$X86" ]] || { echo "missing x86_64 build: $X86" >&2; exit 1; }

# ── 2. Assemble the bundle ──────────────────────────────────────────────────────────────────
# Three naming rules, all enforced by sysextd, none of which produce a useful error when broken:
#   - the bundle directory must be   <CFBundleIdentifier>.systemextension
#   - the executable must be named   <CFBundleIdentifier>   (not the cargo binary name)
#   - CFBundlePackageType must be    SYSX
log "assembling $(basename "$BUNDLE")"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS"

lipo -create -output "$BUNDLE/Contents/MacOS/$SYSEXT_ID" "$ARM" "$X86"
chmod +x "$BUNDLE/Contents/MacOS/$SYSEXT_ID"
log "universal executable: $(lipo -archs "$BUNDLE/Contents/MacOS/$SYSEXT_ID")"

# Substitute the template. There is no Xcode here, so Xcode-style $(VAR) would be written into
# the plist verbatim; these @@TOKEN@@s are ours and the lint below proves none survived.
sed -e "s|@@SYSEXT_ID@@|$SYSEXT_ID|g" \
    -e "s|@@SYSEXT_DISPLAY_NAME@@|$SYSEXT_DISPLAY_NAME|g" \
    -e "s|@@SYSEXT_USAGE_DESCRIPTION@@|$SYSEXT_USAGE_DESCRIPTION|g" \
    -e "s|@@MARKETING_VERSION@@|$MARKETING_VERSION|g" \
    -e "s|@@BUNDLE_VERSION@@|$BUNDLE_VERSION|g" \
    "$ROOT/macos/sysext/Info.plist.in" > "$BUNDLE/Contents/Info.plist"

if grep -q '@@' "$BUNDLE/Contents/Info.plist"; then
  echo "ERROR: un-substituted @@TOKEN@@ left in Info.plist:" >&2
  grep -n '@@' "$BUNDLE/Contents/Info.plist" >&2
  exit 1
fi
plutil -lint "$BUNDLE/Contents/Info.plist" >/dev/null

# The Info.plist names the ObjC class the framework will look up. If it does not match the
# `#[name = "..."]` on the define_class! in provider.rs, the extension starts and handleNewFlow:
# is never called — a failure that looks exactly like "the filter does not work". Cheap to check.
WANT_CLASS="$(/usr/libexec/PlistBuddy -c \
  'Print :NetworkExtension:NEProviderClasses:com.apple.networkextension.filter-data' \
  "$BUNDLE/Contents/Info.plist" 2>/dev/null || echo "")"
# NOTE: counted into a variable rather than piped into `grep -q`. Under `set -o pipefail`,
# `grep -q` exits at the first match, `strings` then dies of SIGPIPE, and the pipeline reports
# failure even though the string was found — an intermittent build break that depends purely on
# which process wins the race. `grep -c` consumes all input, so there is no signal to race with.
CLASS_HITS="$(strings -a "$BUNDLE/Contents/MacOS/$SYSEXT_ID" | grep -cx "$WANT_CLASS" || true)"
if [[ -n "$WANT_CLASS" && "${CLASS_HITS:-0}" -eq 0 ]]; then
  echo "ERROR: Info.plist expects provider class '$WANT_CLASS' but that symbol is not in the" >&2
  echo "       binary. The extension would start and handleNewFlow: would never be called." >&2
  echo "       Check #[name = ...] on the define_class! in crates/filter-sysext/src/provider.rs." >&2
  exit 1
fi
log "provider class '$WANT_CLASS' present in the binary ($CLASS_HITS slice(s))"

# ── 3. Embed the provisioning profile ───────────────────────────────────────────────────────
# Must happen BEFORE codesign: the signature seals Contents/ into CodeResources, so a profile
# copied in afterwards invalidates it.
SIGN_SHA1="$(resolve_sign_identity || true)"
[[ -n "$SIGN_SHA1" ]] || { echo "no Developer ID Application cert for $TEAM_ID" >&2; exit 1; }
export SIGN_SHA1

SYSEXT_PROFILE="$ROOT/macos/profiles/sysext.provisionprofile"
assert_profile_matches "$SYSEXT_PROFILE" "$SYSEXT_PROFILE_NAME"
embed_profile "$SYSEXT_PROFILE" "$BUNDLE"
log "embedded $(basename "$SYSEXT_PROFILE")"

# ── 4. Sign ─────────────────────────────────────────────────────────────────────────────────
# Inner bundle first, with its OWN entitlements and its OWN profile. The container app is signed
# later, without --deep, and seals this already-signed bundle into its CodeResources.
TS=(--timestamp)
[[ "${SKIP_TIMESTAMP:-0}" == "1" ]] && TS=(--timestamp=none)

log "signing with $SIGN_SHA1"
codesign --force --options runtime "${TS[@]}" \
         --entitlements "$ROOT/macos/entitlements/sysext.entitlements" \
         --sign "$SIGN_SHA1" "$BUNDLE"

codesign --verify --strict --verbose=2 "$BUNDLE"

log "done -> $BUNDLE"
log "entitlements now in the signature:"
codesign -d --entitlements - --xml "$BUNDLE" 2>/dev/null | plutil -p - | sed 's/^/         /' >&2
