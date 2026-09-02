import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type ActivationState =
  | { state: "idle" }
  | { state: "pending" }
  | { state: "needs_user_approval" }
  | { state: "active" }
  | { state: "needs_reboot" }
  | { state: "failed"; detail: string };

interface FilterStatus {
  activation: ActivationState;
  enabled: boolean;
}

type TestConnectResult =
  | { state: "reachable" }
  | { state: "blocked"; detail: string }
  | { state: "timed_out" };

function activationText(state: ActivationState): string {
  switch (state.state) {
    case "active":
      return "activated and running";
    case "needs_user_approval":
      return "waiting for approval in System Settings";
    case "needs_reboot":
      return "staged — restart the Mac to activate";
    case "failed":
      return `failed: ${state.detail}`;
    case "pending":
      return "activating…";
    default:
      return "not activated";
  }
}

function testResultText(result: TestConnectResult | "testing" | null): string {
  if (result === null) return "—";
  if (result === "testing") return "testing…";
  switch (result.state) {
    case "reachable":
      return "reachable";
    case "blocked":
      return `blocked: ${result.detail}`;
    case "timed_out":
      return "timed out (typical shape of a dropped flow)";
  }
}

export function App() {
  const [status, setStatus] = useState<FilterStatus | null>(null);
  const [message, setMessage] = useState<{ text: string; isError: boolean } | null>(null);
  const [busy, setBusy] = useState(false);

  const [host, setHost] = useState("digexam.com");
  const [port, setPort] = useState("443");
  const [fetchResult, setFetchResult] = useState<TestConnectResult | "testing" | null>(null);
  const [connectResult, setConnectResult] = useState<TestConnectResult | "testing" | null>(null);
  const [fetchBusy, setFetchBusy] = useState(false);
  const [connectBusy, setConnectBusy] = useState(false);

  async function refresh() {
    try {
      const result = await invoke<FilterStatus>("plugin:content-filter|filter_status");
      setStatus(result);
    } catch (e) {
      console.error("refresh failed", e);
    }
  }

  useEffect(() => {
    void refresh();
    const id = setInterval(() => void refresh(), 2000);
    return () => clearInterval(id);
  }, []);

  async function run(command: string, pendingText: string) {
    setBusy(true);
    setMessage({ text: pendingText, isError: false });
    try {
      const result = await invoke<FilterStatus>(`plugin:content-filter|${command}`);
      setStatus(result);
      setMessage(null);
    } catch (e) {
      setMessage({ text: String(e), isError: true });
    } finally {
      setBusy(false);
      void refresh();
    }
  }

  async function runFetchTest() {
    const trimmedHost = host.trim();
    const trimmedPort = port.trim();
    setFetchBusy(true);
    setFetchResult("testing");
    try {
      await fetch(`https://${trimmedHost}:${trimmedPort}/`, {
        mode: "no-cors",
        signal: AbortSignal.timeout(5000),
      });
      setFetchResult({ state: "reachable" });
    } catch (e) {
      const timedOut = e instanceof DOMException && e.name === "TimeoutError";
      setFetchResult(timedOut ? { state: "timed_out" } : { state: "blocked", detail: String(e) });
    } finally {
      setFetchBusy(false);
    }
  }

  async function runConnectTest() {
    const trimmedHost = host.trim();
    setConnectBusy(true);
    setConnectResult("testing");
    try {
      const result = await invoke<TestConnectResult>("plugin:content-filter|test_connect", {
        host: trimmedHost,
        port: Number(port),
      });
      setConnectResult(result);
    } catch (e) {
      setConnectResult({ state: "blocked", detail: String(e) });
    } finally {
      setConnectBusy(false);
    }
  }

  return (
    <div>
      <header>
        <h1>Content Filter</h1>
      </header>

      <section>
        <div>
          <button type="button" disabled={busy} onClick={() =>
            run(
              "enable_filter",
              "Activating the extension and enabling the filter…"
            )
          }>
            Enable filter
          </button>
          <button type="button" disabled={busy} onClick={() => run("disable_filter", "Disabling…")}>
            Disable
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              run("remove_filter", "Removing the configuration and deactivating the extension…")
            }
          >
            Remove
          </button>
        </div>

        <dl>
          <dt>Extension</dt>
          <dd>{status ? activationText(status.activation) : "—"}</dd>
          <dt>Configuration</dt>
          <dd>{status ? (status.enabled ? "enabled" : "disabled") : "—"}</dd>
        </dl>

        {message &&
          message.text
            .split("\n")
            .map((line, i) => (
              <p key={i} className={message.isError ? "error" : undefined}>
                {line}
              </p>
            ))}
      </section>

      <section>
        <h2>Test</h2>
        <div>
          <label>
            Host
            <input type="text" value={host} onChange={(e) => setHost(e.target.value)} />
          </label>
          <label>
            Port
            <input
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(e) => setPort(e.target.value)}
            />
          </label>
        </div>
        <div>
          <button type="button" disabled={fetchBusy} onClick={() => void runFetchTest()}>
            Test webview fetch
          </button>
          <button type="button" disabled={connectBusy} onClick={() => void runConnectTest()}>
            Test TCP connect
          </button>
        </div>
        <dl>
          <dt>Webview fetch</dt>
          <dd>{testResultText(fetchResult)}</dd>
          <dt>TCP connect</dt>
          <dd>{testResultText(connectResult)}</dd>
        </dl>
      </section>
    </div>
  );
}
