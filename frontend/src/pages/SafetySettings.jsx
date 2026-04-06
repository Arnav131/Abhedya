import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Sidebar from "../components/Sidebar";
import StatusBar from "../components/StatusBar";
import { fetchVaultEntries } from "../utils/vaultCrypto";
import { clearMasterKey } from "../utils/sessionSecrets";
import "./SafetySettings.css";

export default function SafetySettings() {
  const navigate = useNavigate();

  const [entryCount, setEntryCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastChecked, setLastChecked] = useState("");

  const [autoLock, setAutoLock] = useState(true);
  const [biometricHint, setBiometricHint] = useState(false);

  useEffect(() => {
    if (!sessionStorage.getItem("sv_access_token")) {
      navigate("/");
      return;
    }

    verifyBackendConnection();
  }, []);

  async function verifyBackendConnection() {
    setLoading(true);
    setError("");

    try {
      const entries = await fetchVaultEntries();
      setEntryCount(entries.length);
      setLastChecked(new Date().toISOString());
    } catch (err) {
      setError(err.message || "Failed to connect to backend API.");
    } finally {
      setLoading(false);
    }
  }

  const handleLockSession = () => {
    clearMasterKey();
    sessionStorage.removeItem("sv_master_key");
    sessionStorage.removeItem("sv_access_token");
    sessionStorage.removeItem("sv_refresh_token");
    navigate("/");
  };

  const backendHealthy = !loading && !error;

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content settings-page animate-in">
        <header className="settings__header">
          <div>
            <h2>Safety Settings</h2>
            <p className="text-muted">
              Session controls and backend connectivity checks.
            </p>
          </div>
          <button
            className="btn btn-secondary btn-sm"
            onClick={verifyBackendConnection}
            disabled={loading}
          >
            <span className="icon icon-sm">sync</span>
            {loading ? "Checking..." : "Verify Backend Connection"}
          </button>
        </header>

        {error && (
          <div
            style={{
              padding: "10px 14px",
              background: "rgba(255,60,60,0.12)",
              border: "1px solid rgba(255,60,60,0.3)",
              borderRadius: "8px",
              color: "#ff6b6b",
              fontSize: "0.85rem",
              marginBottom: "12px",
            }}
          >
            <span
              className="icon icon-sm"
              style={{ verticalAlign: "middle", marginRight: 6 }}
            >
              error
            </span>
            {error}
          </div>
        )}

        <div className="settings__grid">
          <div className="card">
            <h4 className="settings__title">
              <span className="icon icon-sm">hub</span>
              Backend Status
            </h4>

            <div className="settings__row">
              <span className="text-muted">API Connectivity</span>
              <span
                className={`badge ${backendHealthy ? "badge--green" : "badge--red"}`}
              >
                {loading
                  ? "Checking"
                  : backendHealthy
                    ? "Connected"
                    : "Disconnected"}
              </span>
            </div>

            <div className="settings__row">
              <span className="text-muted">Vault Entries Found</span>
              <span className="mono">{loading ? "..." : entryCount}</span>
            </div>

            <div className="settings__row">
              <span className="text-muted">Last Verified</span>
              <span className="mono">
                {lastChecked
                  ? new Date(lastChecked).toLocaleString()
                  : "Not checked yet"}
              </span>
            </div>
          </div>

          <div className="card">
            <h4 className="settings__title">
              <span className="icon icon-sm">tune</span>
              Local Session Preferences
            </h4>

            <label className="settings__toggle-row">
              <div>
                <span>Auto-Lock on Browser Close</span>
                <p className="text-muted">
                  Clears local keys when this session ends.
                </p>
              </div>
              <input
                type="checkbox"
                checked={autoLock}
                onChange={() => setAutoLock(!autoLock)}
              />
            </label>

            <label className="settings__toggle-row">
              <div>
                <span>Biometric Prompt Hint</span>
                <p className="text-muted">
                  Show unlock hint for devices supporting biometrics.
                </p>
              </div>
              <input
                type="checkbox"
                checked={biometricHint}
                onChange={() => setBiometricHint(!biometricHint)}
              />
            </label>
          </div>

          <div className="card settings__danger">
            <h4 className="settings__title">
              <span className="icon icon-sm">lock</span>
              Session Lockdown
            </h4>
            <p
              className="text-muted"
              style={{ fontSize: "0.85rem", marginBottom: "16px" }}
            >
              Ends the current authenticated session and removes all local
              decryption keys from this browser tab.
            </p>
            <button className="btn btn-danger" onClick={handleLockSession}>
              <span className="icon icon-sm">logout</span>
              Lock and Sign Out
            </button>
          </div>
        </div>

        <StatusBar />
      </main>
    </div>
  );
}
