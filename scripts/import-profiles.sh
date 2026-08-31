#!/usr/bin/env bash
# Pull freshly (re-)generated provisioning profiles from $DOWNLOADS_DIR (default ~/Downloads) into
# macos/profiles/, where they are committed to git as the team's shared, canonical copies.
#
# Run this once after regenerating either profile in the developer portal. Everyone else then just
# `git pull` — nobody needs their own copy in an Xcode profile store. See docs/signing.md.
#
# Profiles are matched by their internal "Name" field (macos/identity.sh's APP_PROFILE_NAME /
# SYSEXT_PROFILE_NAME), not by download filename, since a browser may suffix a re-download with
# " (1)" etc.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

# shellcheck source=../macos/identity.sh
source "$ROOT/macos/identity.sh"
# shellcheck source=./lib-signing.sh
source "$ROOT/scripts/lib-signing.sh"

mkdir -p "$ROOT/macos/profiles"

# $1 = profile display name, $2 = human label, $3 = dest filename
import_one() {
  local name="$1" label="$2" dest="$3" src
  src="$(locate_profile_by_name "$name" "$DOWNLOADS_DIR" || true)"
  if [[ -z "$src" ]]; then
    echo "ERROR: no profile named \"$name\" found in $DOWNLOADS_DIR" >&2
    echo "       Regenerate it in the developer portal and download it first." >&2
    exit 1
  fi
  cp "$src" "$ROOT/macos/profiles/$dest"
  # Browser downloads carry com.apple.quarantine; codesign doesn't seal xattrs into the CDHash so
  # it wouldn't break signing, but system extension activation checks for it — see
  # scripts/lib-signing.sh's embed_profile for the full story. Stripped here too, at the source,
  # so a `git diff` never shows it and nobody re-learns this the hard way.
  xattr -d com.apple.quarantine "$ROOT/macos/profiles/$dest" 2>/dev/null || true
  echo "imported $label ($(basename "$src")) -> macos/profiles/$dest"
}

import_one "$APP_PROFILE_NAME"    "container app" "app.provisionprofile"
import_one "$SYSEXT_PROFILE_NAME" "system ext"    "sysext.provisionprofile"

echo
echo "Run scripts/check-signing.sh to verify these match your signing cert, then commit them:"
echo "  git add macos/profiles/*.provisionprofile"
