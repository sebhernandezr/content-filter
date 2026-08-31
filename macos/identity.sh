# Single source of truth for every identifier and version in the macOS build.
# Sourced by all of scripts/*.sh. Not executable on its own.
#
# Bundle identifiers are FIXED: they are what the Apple Developer portal App IDs, the App Group,
# and the two provisioning profiles were issued against. Changing one means new portal App IDs
# and new profiles before anything can be signed. Display names, by contrast, are free.

TEAM_ID="73T9H7VE4P"

# Container app. Must equal the profile's com.apple.application-identifier suffix.
APP_ID="com.digiexam.macos.NetworkExtensions"
# System extension. macOS requires this to be prefixed by the container app's identifier.
SYSEXT_ID="com.digiexam.macos.NetworkExtensions.ContentFilter"
# Shared between both entitlements; must match exactly or it is two different containers.
APP_GROUP="group.com.digiexam.macos.NetworkExtensions"

# Provisioning profile display names, as issued by the portal ("Name" key inside the profile).
APP_PROFILE_NAME="Digiexam macOS App"
SYSEXT_PROFILE_NAME="Digiexam macOS ContentFilter"

# User-visible strings. Safe to change at any time.
PRODUCT_NAME="Digiexam"
SYSEXT_DISPLAY_NAME="Digiexam Content Filter"

# Shown in the system activation-approval dialog. Required by sysextd's category property check
# for com.apple.system_extension.network_extension — without it, activation fails with
# OSSystemExtensionErrorCode 9 (validationFailed) regardless of signing/notarization. This is a
# SEPARATE key from the identically-worded one in app/src-tauri/Info.plist: sysextd checks the
# .systemextension bundle's own copy, not the container app's.
SYSEXT_USAGE_DESCRIPTION="Digiexam uses a network content filter to restrict internet access during exams."

# ── Versions ────────────────────────────────────────────────────────────────────────────────
# BUNDLE_VERSION is CFBundleVersion, and it is the reason this file exists.
#
# macOS will not hot-swap a running NetworkExtension provider. When an activation request
# carries a DIFFERENT CFBundleVersion from the copy already installed, sysextd STAGES the new
# one as `terminated_waiting_to_uninstall_on_reboot` and keeps running the old one — so the
# rebuild appears to install and then does nothing until a reboot.
#
# The previous build script set this from `date +%s`, giving every single build a new version.
# The result was 15 staged copies on the dev machine and ZERO ever active: the filter showed up
# in System Settings (that is just the NEFilterManager preference record) while no provider
# process existed to receive a flow.
#
# So: BUMP THIS BY HAND, and only when you actually intend to ship a new extension version.
# Leaving it alone across a rebuild is what makes iteration reboot-free.
MARKETING_VERSION="0.1.0"
BUNDLE_VERSION="1"
