SHELL := /bin/bash
SYSEXT_ID := com.digiexam.macos.NetworkExtensions.ContentFilter
PRODUCT   := Digiexam
SUBSYSTEM := com.digiexam.macos.NetworkExtensions

.PHONY: help check build sysext install install-rules rules-force dmg logs test fmt clean clean-sysext status

help:
	@echo "make check         signing preflight (certs, profiles, entitlements)"
	@echo "make sysext        build + sign the .systemextension only"
	@echo "make build         full signed $(PRODUCT).app with the extension embedded"
	@echo "make install       copy to /Applications, seed rules.json if absent, and launch"
	@echo "                   (REQUIRED: sysexts only activate from /Applications)"
	@echo "make dmg           build + wrap $(PRODUCT).app in a signed DMG for manual install/sharing"
	@echo "                   (not a substitute for install: dropping the app from a mounted DMG"
	@echo "                   into /Applications still needs a plain Finder drag, then activation)"
	@echo "make install-rules seed rules.json under /Users/Shared if not already present"
	@echo "                   (no sudo needed; leaves an existing file alone)"
	@echo "make rules-force   overwrite rules.json from macos/rules.json unconditionally"
	@echo "make logs          watch traffic: tail the extension's unified log output — this is how you see it"
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
# backend can update them later without a rebuild. /Users/Shared is already world-writable and
# sticky, so this needs no sudo and no ownership fixup; see rules.rs's module doc for why that's
# an acceptable tradeoff now that rules are headed for a backend-signed payload rather than
# filesystem permissions as the trust boundary.
RULES_DIR  := /Users/Shared/Digiexam
RULES_FILE := $(RULES_DIR)/rules.json

# Seeds the rules file only if it is not already there. `make install` depends on this, so an
# unconditional copy here would silently discard edits made against the live file on every
# rebuild. Use `make rules-force` to deliberately re-seed from macos/rules.json.
install-rules:
	@if [ -f "$(RULES_FILE)" ]; then \
		echo "==> rules.json already present at $(RULES_FILE) — leaving it alone (make rules-force to re-seed)"; \
	else \
		echo "==> seeding rules.json to $(RULES_FILE)"; \
		mkdir -p "$(RULES_DIR)"; \
		cp macos/rules.json "$(RULES_FILE)"; \
	fi

rules-force:
	@echo "==> overwriting $(RULES_FILE) from macos/rules.json"
	@mkdir -p "$(RULES_DIR)"
	@cp macos/rules.json "$(RULES_FILE)"

dmg: build
	@./scripts/build-dmg.sh

logs:
	@echo "==> streaming subsystem $(SUBSYSTEM) (ctrl-c to stop)"
	@log stream --style compact --predicate 'subsystem == "$(SUBSYSTEM)"' | sed -E -l \
		-e '/^(Filtering|Timestamp)/d' \
		-e 's/^[0-9-]+ ([0-9:.]+) +[A-Za-z]+ +[^][]+\[[0-9]+:[0-9a-f]+\] +\[[^]]+:([a-z]+)\] +/\1 \2 /' \
		-e 's/^([0-9:.]+) lifecycle /\1 life /'

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
