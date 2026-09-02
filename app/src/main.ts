/**
 * Minimal UI for the content filter: switch it on and off, show what state macOS thinks it's
 * in, and prove the allowlist with two test flows. Flow traffic itself is watched in a
 * terminal (`make logs-flows`), not here — see rules.rs for why.
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

/** Mirrors `filter_types::TestConnectResult`. */
type TestConnectResult =
  | { state: "reachable" }
  | { state: "blocked"; detail: string }
  | { state: "timed_out" };

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const els = {
  enable: $<HTMLButtonElement>("enable"),
  disable: $<HTMLButtonElement>("disable"),
  remove: $<HTMLButtonElement>("remove"),
  activation: $<HTMLElement>("activation"),
  enabled: $<HTMLElement>("enabled"),
  message: $<HTMLParagraphElement>("message"),
  testHost: $<HTMLInputElement>("test-host"),
  testPort: $<HTMLInputElement>("test-port"),
  testFetch: $<HTMLButtonElement>("test-fetch"),
  testConnect: $<HTMLButtonElement>("test-connect"),
  fetchResult: $<HTMLElement>("fetch-result"),
  connectResult: $<HTMLElement>("connect-result"),
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

/**
 * Render one test-panel outcome. Three states, not a bool, because "blocked" and "timed out" are
 * both failures for the demo but mean different things while debugging a rule: a `dropVerdict()`
 * flow typically times out rather than being actively refused (there is no RST), so a `blocked`
 * result usually means DNS failed or the host genuinely doesn't exist — not that the filter acted.
 */
function renderTestResult(el: HTMLElement, result: TestConnectResult) {
  el.className = "";
  switch (result.state) {
    case "reachable":
      el.textContent = "reachable";
      el.className = "state-active";
      break;
    case "blocked":
      el.textContent = `blocked: ${result.detail}`;
      el.className = "state-error";
      break;
    case "timed_out":
      el.textContent = "timed out (typical shape of a dropped flow)";
      el.className = "state-error";
      break;
  }
}

els.testFetch.addEventListener("click", async () => {
  const host = els.testHost.value.trim();
  const port = els.testPort.value.trim();
  els.testFetch.disabled = true;
  els.fetchResult.textContent = "testing…";
  els.fetchResult.className = "";
  try {
    // A plain webview fetch: goes out through WebKit and carries a hostname, so it exercises the
    // `host` matcher in rules.json rather than the `ip` escape hatch the TCP-connect button below
    // exercises. AbortSignal.timeout matches the server-side TEST_CONNECT_TIMEOUT in spirit; a
    // dropped flow here surfaces as this fetch rejecting, which is reported the same as "blocked".
    await fetch(`https://${host}:${port}/`, { mode: "no-cors", signal: AbortSignal.timeout(5000) });
    renderTestResult(els.fetchResult, { state: "reachable" });
  } catch (e) {
    const timedOut = e instanceof DOMException && e.name === "TimeoutError";
    renderTestResult(
      els.fetchResult,
      timedOut ? { state: "timed_out" } : { state: "blocked", detail: String(e) },
    );
  } finally {
    els.testFetch.disabled = false;
  }
});

els.testConnect.addEventListener("click", async () => {
  const host = els.testHost.value.trim();
  const port = Number(els.testPort.value);
  els.testConnect.disabled = true;
  els.connectResult.textContent = "testing…";
  els.connectResult.className = "";
  try {
    const result = await invoke<TestConnectResult>("plugin:content-filter|test_connect", {
      host,
      port,
    });
    renderTestResult(els.connectResult, result);
  } catch (e) {
    renderTestResult(els.connectResult, { state: "blocked", detail: String(e) });
  } finally {
    els.testConnect.disabled = false;
  }
});

void refresh();
// No table to keep fresh any more — flows are watched in a terminal — so a slower poll is enough
// to keep the status rows in sync with macOS.
setInterval(() => void refresh(), 2000);
