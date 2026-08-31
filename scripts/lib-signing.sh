# Signing helpers. Sourced, not executed.
#
# Distilled from the previous product build script (preserved verbatim at
# scripts/reference/build-tauri-dmg.sh). The valuable idea there, kept in full:
#
#   A provisioning profile names the EXACT set of certificates it will accept. If you sign with a
#   cert the profile does not embed, the artifact signs and notarizes perfectly and then refuses
#   to launch — AMFI spawn error 163, surfacing as an opaque "Launch failed" with no mention of
#   signing. So the profile/cert relationship is asserted at build time, loudly, rather than
#   discovered on a user's first double-click.
#
# What was simplified: the original intersected keychain certs x app-profile certs x
# sysext-profile certs to disambiguate several same-named "Developer ID Application" certs. This
# keychain holds exactly one, so that search is replaced by a direct lookup plus the assertion
# (which is the part that actually catches the failure). Restore the intersection from the
# reference script if the team ever holds multiple Developer ID certs.

# Where `scripts/import-profiles.sh` looks for freshly downloaded profiles to pull into the repo.
# Not used by the build itself — see macos/profiles/ for that.
DOWNLOADS_DIR="${DOWNLOADS_DIR:-$HOME/Downloads}"

# Every certificate SHA-1 (upper-case, no colons) embedded in provisioning profile $1, one per line.
# A profile is a CMS-signed plist; `security cms -D` decodes it, and DeveloperCertificates is an
# array of DER blobs that openssl fingerprints.
profile_certs() {
  local pl c i=0
  pl="$(security cms -D -i "$1" 2>/dev/null)" || return 0
  while c="$(printf '%s' "$pl" | plutil -extract "DeveloperCertificates.$i" raw -o - - 2>/dev/null \
      | base64 -d 2>/dev/null | openssl x509 -inform DER -noout -fingerprint -sha1 2>/dev/null \
      | sed 's/.*=//; s/://g' | tr '[:lower:]' '[:upper:]')" && [[ -n "$c" ]]; do
    echo "$c"
    i=$((i + 1))
  done
}

# True if provisioning profile $1 embeds the cert whose SHA-1 is $2.
#
# The certificate list is captured before matching rather than piped into `grep -q`. Under
# `set -o pipefail` a `grep -q` that exits at its first match sends SIGPIPE to the producer, and
# the pipeline then reports failure even though the match succeeded — intermittently, depending on
# which process wins the race. Here that would mean spuriously reporting that a perfectly good
# profile does not embed the signing cert, and failing the build.
profile_has_cert() {
  local certs
  certs="$(profile_certs "$1")"
  [[ $'\n'"$certs"$'\n' == *$'\n'"$2"$'\n'* ]]
}

# The value of a top-level key ($2) inside profile $1, e.g. Name or UUID.
profile_key() {
  security cms -D -i "$1" 2>/dev/null | plutil -extract "$2" raw -o - - 2>/dev/null
}

# The application-identifier this profile provisions, e.g.
# `73T9H7VE4P.com.digiexam.macos.NetworkExtensions`.
#
# Read via `plutil -p` + sed rather than `plutil -extract`: the key itself contains dots, which
# plutil keypaths treat as separators with no portable way to escape them.
profile_app_id() {
  security cms -D -i "$1" 2>/dev/null | plutil -p - 2>/dev/null \
    | sed -n 's/.*"com\.apple\.application-identifier" => "\([^"]*\)".*/\1/p' | head -1
}

# The NetworkExtension entitlement values this profile authorises, one per line.
profile_ne_entitlements() {
  security cms -D -i "$1" 2>/dev/null | plutil -p - 2>/dev/null \
    | awk '/"com\.apple\.developer\.networking\.networkextension"/{f=1;next} f&&/\]/{f=0} f' \
    | sed -n 's/.*=> "\([^"]*\)".*/\1/p'
}

# Developer ID Application cert SHA-1s for $TEAM_ID that this keychain can actually sign with.
# `find-identity -v` lists only identities that hold a private key.
keychain_dev_id_certs() {
  security find-identity -v -p codesigning \
    | awk -v t="$TEAM_ID" '/Developer ID Application/ && $0 ~ t {print $2}'
}

# Resolve the signing identity to a canonical SHA-1 and echo it.
#
# Signing by SHA-1 rather than by display name matters: several certs can share the identical
# display string "Developer ID Application: <org> (<TEAM>)", so signing by name means signing with
# "whichever the keychain happens to list first" — which changes silently when an unrelated cert is
# added. Honours a caller-supplied $SIGN_IDENTITY (SHA-1 with or without colons, or a display name).
resolve_sign_identity() {
  local want norm
  want="${SIGN_IDENTITY:-}"
  if [[ -z "$want" ]]; then
    want="$(keychain_dev_id_certs | head -1)"
    [[ -n "$want" ]] || return 1
    echo "$want"
    return 0
  fi
  norm="$(printf '%s' "$want" | tr -d ':' | tr '[:lower:]' '[:upper:]')"
  if [[ "$norm" =~ ^[0-9A-F]{40}$ ]]; then
    echo "$norm"
  else
    security find-identity -v -p codesigning | awk -v n="$want" 'index($0, n) {print $2; exit}'
  fi
}

# Path of the profile in directory $2 whose "Name" is exactly $1, PREFERRING one that embeds the
# signing cert. Selecting purely by name can pick a stale same-named profile carrying a different
# cert, which passes codesign and then fails to spawn; falling back to the first name match lets
# assert_profile_matches turn that into a clear error rather than a mystery.
#
# Only used by scripts/import-profiles.sh, searching $DOWNLOADS_DIR — the build itself reads the
# committed macos/profiles/*.provisionprofile directly, not this lookup.
locate_profile_by_name() {
  local want="$1" dir="$2" f fallback=""
  for f in "$dir"/*.provisionprofile; do
    [[ -f "$f" ]] || continue
    [[ "$(profile_key "$f" Name)" == "$want" ]] || continue
    fallback="${fallback:-$f}"
    if [[ -n "${SIGN_SHA1:-}" ]] && profile_has_cert "$f" "$SIGN_SHA1"; then echo "$f"; return 0; fi
  done
  [[ -n "$fallback" ]] && { echo "$fallback"; return 0; }
  return 1
}

# Fail loudly if profile $1 (labelled $2) does not embed $SIGN_SHA1. An obvious build error beats
# a fully-signed artifact that only fails on first launch.
assert_profile_matches() {
  local path="$1" label="$2"
  [[ -f "$path" ]] || { echo "ERROR: the '$label' provisioning profile was not found: $path" >&2; exit 1; }
  profile_has_cert "$path" "$SIGN_SHA1" && return 0
  {
    echo "ERROR: the '$label' provisioning profile does not embed the signing cert $SIGN_SHA1:"
    echo "         $path"
    echo "       Signing anyway would produce a bundle that verifies and notarizes and then"
    echo "       refuses to launch (AMFI spawn error 163)."
    echo "       That profile accepts: $(profile_certs "$path" | tr '\n' ' ')"
    echo "       This keychain can sign with: $(keychain_dev_id_certs | tr '\n' ' ')"
    echo "       Fix: remove stale same-named profiles from"
    echo "         $PROFILE_STORE"
    echo "       or re-issue the profile against the cert you are signing with."
  } >&2
  exit 1
}

# Copy profile $1 into bundle $2 as Contents/embedded.provisionprofile.
#
# MUST happen before that bundle is codesigned: the signature seals Contents/ into CodeResources,
# so a profile added afterwards invalidates it.
#
# Profiles downloaded from the developer portal via a browser carry com.apple.quarantine. `cp`
# preserves xattrs, so that flag rides along into the bundle. codesign doesn't seal xattrs into
# the CDHash (verify still passes), but system extension activation fails it as
# OSSystemExtensionErrorCodeSignatureInvalid on a machine that can't fall back to notarization —
# see docs/signing.md's "no quarantine attribute" precondition. Strip it here, at the source, so
# no downstream copy (make install's `cp -R` included) can reintroduce it.
embed_profile() {
  local profile="$1" bundle="$2" dest
  mkdir -p "$bundle/Contents"
  dest="$bundle/Contents/embedded.provisionprofile"
  cp "$profile" "$dest"
  xattr -d com.apple.quarantine "$dest" 2>/dev/null || true
}
