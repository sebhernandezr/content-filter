SHELL := /bin/bash
SYSEXT_ID := com.digiexam.macos.NetworkExtensions.ContentFilter
PRODUCT   := Digiexam
SUBSYSTEM := com.digiexam.macos.NetworkExtensions

.PHONY: help check build sysext install install-rules logs logs-flows test fmt clean clean-sysext status

help:
	@echo "make check         signing preflight (certs, profiles, entitlements)"
	@echo "make sysext        build + sign the .systemextension only"
	@echo "make build         full signed $(PRODUCT).app with the extension embedded"
	@echo "make install       copy to /Applications, install rules.json, and launch"
	@echo "                   (REQUIRED: sysexts only activate from /Applications)"
	@echo "make install-rules install/refresh rules.json under /Library/Application Support"
	@echo "                   (needs sudo — that directory is admin-owned)"
	@echo "make logs          watch traffic: tail the extension's unified log output"
	@echo "make logs-flows    watch traffic: tail flow records only — this is how you see it"
	@echo "make status        what macOS thinks is installed and enabled"
	@echo "make test          run the Rust test suites"
	@echo "make clean-sysext  how to clear staged extension copies"

check:
	@./scripts/check-signing.sh

sysext:
	@./scripts/assemble-sysext.sh

build:
	@./scripts/build-app.sh

# System extensions are refused from anywhere but /Applications: activating from dist/, a
# Downloads folder, or a mounted DMG fails with OSSystemExtensionErrorUnsupportedParentBundleLocation.
install: build install-rules
	@echo "==> installing to /Applications/$(PRODUCT).app"
	@rm -rf "/Applications/$(PRODUCT).app"
	@cp -R "dist/$(PRODUCT).app" /Applications/
	@echo "==> launching"
	@open "/Applications/$(PRODUCT).app"

# The extension reads rules from here at runtime (crates/filter-sysext/src/rules.rs), not from
# its own bundle: the bundle is sealed by the code signature, and rules need to be writable so a
# backend can update them later without a rebuild. Root-owned so non-admin users cannot edit it;
# see rules.rs's module doc for what that protection does and does not buy.
RULES_DIR := /Library/Application Support/Digiexam
install-rules:
	@echo "==> installing rules.json to $(RULES_DIR) (sudo required)"
	@sudo mkdir -p "$(RULES_DIR)"
	@sudo cp macos/rules.json "$(RULES_DIR)/rules.json"
	@sudo chown -R root:wheel "$(RULES_DIR)"
	@sudo chmod 755 "$(RULES_DIR)"
	@sudo chmod 644 "$(RULES_DIR)/rules.json"

logs:
	@echo "==> streaming subsystem $(SUBSYSTEM) (ctrl-c to stop)"
	@log stream --style compact --predicate 'subsystem == "$(SUBSYSTEM)"'

logs-flows:
	@log stream --style compact --predicate 'subsystem == "$(SUBSYSTEM)" AND category == "flow"'

status:
	@echo "── installed system extensions ─────────────────────────────"
	@systemextensionsctl list | grep -E "enabled|$(SYSEXT_ID)" || echo "  none"
	@echo
	@echo "── provider process ────────────────────────────────────────"
	@pgrep -fl "$(SYSEXT_ID)" || echo "  not running"

test:
	@cargo test --workspace
	@cd crates/filter-sysext && cargo test

fmt:
	@cargo fmt --all
	@cd crates/filter-sysext && cargo fmt

# Staged copies pile up when CFBundleVersion changes between builds: macOS never hot-swaps a
# running provider, so the replacement waits for a reboot while the old one keeps running. Keeping
# BUNDLE_VERSION in macos/identity.sh stable across rebuilds is what avoids this entirely.
clean-sysext:
	@echo "Currently installed / staged:"
	@systemextensionsctl list | grep "$(SYSEXT_ID)" || echo "  none"
	@echo
	@echo "Copies marked [terminated waiting to uninstall on reboot] cannot be removed without"
	@echo "a restart — macOS clears them on boot. To remove the active one first:"
	@echo
	@echo "    open /Applications/$(PRODUCT).app   # then press Remove in the UI"
	@echo
	@echo "then reboot. After rebooting, 'make status' should list nothing."

clean:
	@cargo clean
	@cd crates/filter-sysext && cargo clean
	@rm -rf dist app/dist
