#!/usr/bin/env bash
# Signing preflight. Run this before anything else, and any time signing misbehaves.
#
# It answers, without building a single artifact:
#   - which certificate will actually be used to sign
#   - whether both provisioning profiles accept that certificate  (AMFI 163 prevention)
#   - whether each profile provisions the app-id its bundle will claim
#   - whether each profile authorises the entitlements we intend to claim
#   - whether system-extension developer mode is available on this machine
#
# Every one of these is a failure that otherwise surfaces much later, as an artifact that signs
# and verifies perfectly and then refuses to launch or activate.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

# shellcheck source=../macos/identity.sh
source "$ROOT/macos/identity.sh"
# shellcheck source=./lib-signing.sh
source "$ROOT/scripts/lib-signing.sh"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; FAILED=1; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }
FAILED=0

echo "── Signing identity ─────────────────────────────────────────────"
SIGN_SHA1="$(resolve_sign_identity || true)"
if [[ -z "$SIGN_SHA1" ]]; then
  bad "no Developer ID Application certificate for team $TEAM_ID in this keychain"
  echo "     available identities:" >&2
  security find-identity -v -p codesigning >&2 || true
  exit 1
fi
export SIGN_SHA1
ok "signing cert: $SIGN_SHA1"
security find-identity -v -p codesigning | grep -i "$SIGN_SHA1" | sed 's/^/      /'

echo
echo "── Provisioning profiles ────────────────────────────────────────"
echo "   (committed at macos/profiles/ — run scripts/import-profiles.sh to refresh them)"

# $1 = path under macos/profiles, $2 = expected app-id suffix, $3 = human label
check_profile() {
  local path="$ROOT/macos/profiles/$1" expect_id="$2" label="$3" app_id
  if [[ ! -f "$path" ]]; then
    bad "$label: $path not found — run scripts/import-profiles.sh"
    return
  fi
  ok "$label: $(basename "$path")"

  # The assertion that prevents AMFI spawn error 163.
  if profile_has_cert "$path" "$SIGN_SHA1"; then
    ok "  embeds the signing cert"
  else
    bad "  does NOT embed $SIGN_SHA1 — would sign fine and then fail to launch (AMFI 163)"
    echo "       accepts: $(profile_certs "$path" | tr '\n' ' ')" >&2
  fi

  app_id="$(profile_app_id "$path")"
  if [[ "$app_id" == "$TEAM_ID.$expect_id" ]]; then
    ok "  provisions $app_id"
  else
    bad "  provisions '$app_id' but the bundle will claim '$TEAM_ID.$expect_id'"
  fi

  # Captured, not piped into `grep -q` — see profile_has_cert in lib-signing.sh for why.
  local ne; ne="$(profile_ne_entitlements "$path")"
  if [[ $'\n'"$ne"$'\n' == *$'\n'"content-filter-provider-systemextension"$'\n'* ]]; then
    ok "  authorises content-filter-provider-systemextension"
  else
    bad "  does NOT authorise content-filter-provider-systemextension"
    echo "       authorises: $(profile_ne_entitlements "$path" | tr '\n' ' ')" >&2
  fi

  local exp; exp="$(profile_key "$path" ExpirationDate || true)"
  [[ -n "$exp" ]] && ok "  expires $exp"
}

check_profile "app.provisionprofile"    "$APP_ID"    "container app"
echo
check_profile "sysext.provisionprofile" "$SYSEXT_ID" "system ext"

echo
echo "── Entitlements files ───────────────────────────────────────────"
for f in macos/entitlements/app.entitlements macos/entitlements/sysext.entitlements; do
  b="$(basename "$f")"
  if plutil -lint "$f" >/dev/null 2>&1; then ok "$b is a valid plist"; else bad "$b is malformed"; fi

  # A doubled hyphen inside an XML comment is illegal XML. plutil -lint accepts it anyway, but
  # codesign's parser does not: it rejects the entire file with "AMFIUnserializeXML: syntax
  # error near line N" and signs nothing. Easy to reintroduce by writing a codesign flag in a
  # comment, so it is checked here rather than discovered at signing time.
  # Strip the comment delimiters first — they contain a doubled hyphen by definition.
  # `grep -c` rather than `grep -q`, so the producer is never SIGPIPE'd under pipefail.
  if [[ "$(awk '/<!--/,/-->/' "$f" | sed 's/<!--//g; s/-->//g' | grep -c -- '--' || true)" -gt 0 ]]; then
    bad "$b has a doubled hyphen inside an XML comment; codesign will refuse to parse it"
    awk '/<!--/,/-->/' "$f" | sed 's/<!--//g; s/-->//g' | grep -n -- '--' | sed 's/^/       /' >&2
  else
    ok "$b comments are free of doubled hyphens"
  fi
done

echo
echo "── Rules seed ────────────────────────────────────────────────────"
# macos/rules.json is the seed `make install-rules` copies to
# /Library/Application Support/Digiexam/rules.json. It never enters the signed bundle, but a
# malformed seed would only be discovered when the extension logs a load failure at runtime — this
# catches it at preflight instead.
if [[ -f "$ROOT/macos/rules.json" ]]; then
  if /usr/bin/python3 -m json.tool "$ROOT/macos/rules.json" >/dev/null 2>&1; then
    ok "macos/rules.json is valid JSON"
  else
    bad "macos/rules.json is not valid JSON"
  fi
else
  bad "macos/rules.json not found"
fi

echo
echo "── Host capabilities ────────────────────────────────────────────"
# Captured rather than piped: a spurious miss here would wrongly claim SIP is off and tell you
# developer mode is available, which is worse than useless guidance.
SIP_STATUS="$(csrutil status 2>/dev/null || true)"
if [[ "$SIP_STATUS" == *enabled* ]]; then
  warn "SIP is enabled: \`systemextensionsctl developer on\` is unavailable."
  echo "     That is fine — this project always uses the Developer ID + embedded-profile path." >&2
  echo "     Notarization is NOT required for local testing; profiles ARE." >&2
else
  ok "SIP disabled — developer mode is also available"
fi

STAGED="$(systemextensionsctl list 2>/dev/null | grep -c "$SYSEXT_ID" || true)"
if [[ "${STAGED:-0}" -gt 0 ]]; then
  warn "$STAGED existing copies of $SYSEXT_ID are installed or staged."
  systemextensionsctl list 2>/dev/null | grep "$SYSEXT_ID" | sed 's/^/       /' >&2 || true
  echo "     Copies in [terminated waiting to uninstall on reboot] need a REBOOT to clear." >&2
  echo "     Run 'make clean-sysext' for guidance." >&2
fi

echo
if [[ "$FAILED" -eq 0 ]]; then
  printf '\033[32mSigning preflight passed.\033[0m\n'
else
  printf '\033[31mSigning preflight FAILED.\033[0m\n' >&2
  exit 1
fi
