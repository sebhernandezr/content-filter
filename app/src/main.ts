/**
 * Minimal UI for the content filter: switch it on and off, and show what state macOS thinks it's
 * in. Flow traffic is watched in a terminal (`make logs-flows`), not here — see rules.rs for why.
 */
import { invoke } from "@tauri-apps/api/core";

/** Mirrors `filter_types::ActivationState`. */
type ActivationState =
  | { state: "idle" }
  | { state: "pending" }
  | { state: "needs_user_approval" }
  | { state: "active" }
  | { state: "needs_reboot" }
  | { state: "failed"; detail: string };

/** Mirrors `filter_types::FilterStatus`. */
interface FilterStatus {
  activation: ActivationState;
  enabled: boolean;
}

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const els = {
  enable: $<HTMLButtonElement>("enable"),
  disable: $<HTMLButtonElement>("disable"),
  remove: $<HTMLButtonElement>("remove"),
  activation: $<HTMLElement>("activation"),
  enabled: $<HTMLElement>("enabled"),
  message: $<HTMLParagraphElement>("message"),
};

function showMessage(text: string, isError = false) {
  els.message.textContent = text;
  els.message.classList.toggle("error", isError);
  els.message.hidden = text === "";
}

/**
 * Render the activation state.
 *
 * `needs_reboot` and `needs_user_approval` are surfaced distinctly and prominently on purpose:
 * both mean the extension is NOT running, and both would otherwise be mistaken for success —
 * the filter's configuration still appears in System Settings either way.
 */
function renderActivation(state: ActivationState) {
  const el = els.activation;
  el.className = "";
  switch (state.state) {
    case "active":
      el.textContent = "activated and running";
      el.className = "state-active";
      break;
    case "needs_user_approval":
      el.textContent = "waiting for approval in System Settings";
      el.className = "state-warn";
      break;
    case "needs_reboot":
      el.textContent = "staged — restart the Mac to activate";
      el.className = "state-warn";
      break;
    case "failed":
      el.textContent = `failed: ${state.detail}`;
      el.className = "state-error";
      break;
    case "pending":
      el.textContent = "activating…";
      break;
    default:
      el.textContent = "not activated";
  }
}

function renderStatus(status: FilterStatus) {
  renderActivation(status.activation);
  els.enabled.textContent = status.enabled ? "enabled" : "disabled";
  els.enabled.className = status.enabled ? "state-active" : "";
}

async function refresh() {
  try {
    const status = await invoke<FilterStatus>("plugin:content-filter|filter_status");
    renderStatus(status);
  } catch (e) {
    // Polling errors are not worth a banner every tick; the status row already shows staleness.
    console.error("refresh failed", e);
  }
}

/** Run a command with the buttons disabled, surfacing any error to the user. */
async function run(command: string, pendingText: string) {
  const buttons = [els.enable, els.disable, els.remove];
  buttons.forEach((b) => (b.disabled = true));
  showMessage(pendingText);
  try {
    const status = await invoke<FilterStatus>(`plugin:content-filter|${command}`);
    renderStatus(status);
    showMessage("");
  } catch (e) {
    showMessage(String(e), true);
  } finally {
    buttons.forEach((b) => (b.disabled = false));
    void refresh();
  }
}

els.enable.addEventListener("click", () =>
  run(
    "enable_filter",
    "Activating the extension and enabling the filter…\n" +
      "If macOS asks you to approve it, do that in System Settings and press Enable again.",
  ),
);
els.disable.addEventListener("click", () => run("disable_filter", "Disabling…"));
els.remove.addEventListener("click", () =>
  run("remove_filter", "Removing the configuration and deactivating the extension…"),
);

void refresh();
// No table to keep fresh any more — flows are watched in a terminal — so a slower poll is enough
// to keep the status rows in sync with macOS.
setInterval(() => void refresh(), 2000);
