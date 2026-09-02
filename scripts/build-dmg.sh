#!/usr/bin/env bash
# Wrap the already-built, signed, notarized Digiexam.app (from `make build`) in a plain
# drag-to-Applications DMG, for manual installs and sharing outside this machine.
#
# The .app is not copied into /Applications here — system extensions only activate from
# /Applications (see the comment on `install` in the Makefile), so a DMG can never do that part;
# it just gets the .app to another machine, where `make install` or a manual drag takes over.
#
# The DMG is signed but NOT separately notarized/stapled: the .app inside already carries its own
# notarization staple (from scripts/build-app.sh), and that's what Gatekeeper checks when the app
# is launched. Notarizing the DMG container too would just be another Apple round-trip with no
# practical benefit for a manually-shared build.
#
# No branding (background image / volume icon) — this repo carries none, unlike
# scripts/reference/build-tauri-dmg.sh's Spark packaging, which is reference-only.
#
# Env:
#   SIGN_IDENTITY   override the signing cert; auto-detected otherwise (same as build-app.sh)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

# shellcheck source=../macos/identity.sh
source "$ROOT/macos/identity.sh"
# shellcheck source=./lib-signing.sh
source "$ROOT/scripts/lib-signing.sh"

log() { printf '\033[36m[dmg]\033[0m %s\n' "$*" >&2; }

OUT="$ROOT/dist"
APP="$OUT/$PRODUCT_NAME.app"
DMG="$OUT/$PRODUCT_NAME.dmg"

[[ -d "$APP" ]] || { echo "no $APP — run 'make build' first" >&2; exit 1; }

SIGN_SHA1="$(resolve_sign_identity)"
export SIGN_SHA1
log "signing identity: $SIGN_SHA1"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/digiexam-dmg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/stage"
mkdir -p "$STAGE"

log "staging drag-to-Applications layout"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"

# A stale mounted volume of the same name would make the new image mount as "$PRODUCT_NAME 1"
# later if anything ever attaches it under that assumption; harmless for `hdiutil create` itself,
# but cheap to clear so a leftover DMG mount from a previous run doesn't linger.
for v in /Volumes/"$PRODUCT_NAME" /Volumes/"$PRODUCT_NAME "[0-9]*; do
  [[ -e "$v" ]] && hdiutil detach "$v" -force >/dev/null 2>&1 || true
done

log "building $DMG"
rm -f "$DMG"
hdiutil create -volname "$PRODUCT_NAME" -srcfolder "$STAGE" -ov -format UDZO -imagekey zlib-level=9 -o "$DMG" >/dev/null

log "signing the DMG"
codesign --force --sign "$SIGN_SHA1" --timestamp "$DMG"

log "verifying"
codesign --verify --verbose=2 "$DMG"

echo
log "built $DMG"
du -sh "$DMG" >&2
