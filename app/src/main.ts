/**
 * Minimal UI for the observe-only content filter.
 *
 * Two jobs, per the MVP scope: switch the filter on and off, and show that flow data is really
 * reaching the app from the extension. Nothing here is meant to be the eventual product UI.
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

/** Mirrors `filter_types::AddressFamily` / `TransportProtocol`. */
type Family = "V4" | "V6" | { Other: number };
type Proto = "Tcp" | "Udp" | { Other: number };

/** Mirrors `filter_types::FlowRecord`. */
interface FlowRecord {
  ts_ms: number;
  family: Family;
  protocol: Proto;
  remote_host: string | null;
  remote_port: number | null;
  hostname: string | null;
  url_host: string | null;
  source_app: string | null;
  verdict: "Allow" | "Drop";
}

/** Mirrors `filter_types::FilterStatus`. */
interface FilterStatus {
  activation: ActivationState;
  enabled: boolean;
  flows_seen: number;
}

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const els = {
  enable: $<HTMLButtonElement>("enable"),
  disable: $<HTMLButtonElement>("disable"),
  remove: $<HTMLButtonElement>("remove"),
  activation: $<HTMLElement>("activation"),
  enabled: $<HTMLElement>("enabled"),
  count: $<HTMLElement>("count"),
  message: $<HTMLParagraphElement>("message"),
  flows: $<HTMLTableElement>("flows"),
  empty: $<HTMLParagraphElement>("empty"),
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
  els.count.textContent = String(status.flows_seen);
}

const label = (v: Family | Proto): string =>
  typeof v === "string" ? v.toUpperCase() : `(${v.Other})`;

const time = (ms: number) =>
  new Date(ms).toLocaleTimeString(undefined, { hour12: false });

function renderFlows(flows: FlowRecord[]) {
  els.flows.hidden = flows.length === 0;
  els.empty.hidden = flows.length > 0;

  const body = els.flows.tBodies[0];
  body.replaceChildren(
    ...flows.map((f) => {
      const tr = document.createElement("tr");
      const dest = f.url_host ?? f.hostname ?? f.remote_host;

      const cells: Array<[string, string]> = [
        [time(f.ts_ms), ""],
        // A null destination is normal, not a bug: Apple documents remoteEndpoint as possibly
        // nil at handleNewFlow: time, populated only once data flows. Shown explicitly so it
        // does not read as the filter missing traffic.
        [dest ?? "(not yet known)", dest ? "dest" : "dest pending"],
        [f.remote_port === null ? "—" : String(f.remote_port), ""],
        [label(f.protocol), ""],
        [f.family === "V4" ? "IPv4" : f.family === "V6" ? "IPv6" : label(f.family), ""],
        [f.verdict, ""],
      ];

      for (const [text, cls] of cells) {
        const td = document.createElement("td");
        td.textContent = text;
        if (cls) td.className = cls;
        tr.appendChild(td);
      }
      return tr;
    }),
  );
}

async function refresh() {
  try {
    const [status, flows] = await Promise.all([
      invoke<FilterStatus>("plugin:content-filter|filter_status"),
      invoke<FlowRecord[]>("plugin:content-filter|recent_flows", { limit: 200 }),
    ]);
    renderStatus(status);
    renderFlows(flows);
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
setInterval(() => void refresh(), 500);
