import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fetchVaultEntries, decryptPayload } from "../utils/vaultCrypto";
import { getMasterKey } from "../utils/sessionSecrets";
import Sidebar from "../components/Sidebar";
import StatusBar from "../components/StatusBar";
import "./MyVault.css";

// Icons mapped by category for visual variety
const categoryIcons = {
  Email: "mail",
  Cloud: "cloud",
  Finance: "account_balance",
  Media: "tv",
  Social: "group",
  Dev: "terminal",
  Other: "key",
};

const DAY_MS = 24 * 60 * 60 * 1000;

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function getPasswordStrength(secret) {
  if (!secret) return 0;

  let score = Math.min(35, secret.length * 2.8);
  if (/[A-Z]/.test(secret)) score += 15;
  if (/[a-z]/.test(secret)) score += 15;
  if (/\d/.test(secret)) score += 15;
  if (/[^A-Za-z0-9]/.test(secret)) score += 20;

  return clamp(Math.round(score), 0, 100);
}

function computeVaultHealth(items) {
  if (!items.length) return 0;

  const total = items.length;
  const decrypted = items.filter((item) => !item.decryptError);
  const decryptedCoverage = Math.round((decrypted.length / total) * 100);

  const avgStrength = decrypted.length
    ? Math.round(
        decrypted.reduce(
          (sum, item) => sum + getPasswordStrength(item.password || ""),
          0,
        ) / decrypted.length,
      )
    : 0;

  const freshCount = items.filter((item) => {
    const t = new Date(item.updated_at || item.created_at).getTime();
    return !Number.isNaN(t) && Date.now() - t <= 30 * DAY_MS;
  }).length;
  const freshness = Math.round((freshCount / total) * 100);

  const composite = Math.round(
    decryptedCoverage * 0.4 + avgStrength * 0.45 + freshness * 0.15,
  );

  return clamp(composite, 0, 100);
}

function formatRelativeTime(timestamp) {
  if (!timestamp) return "just now";

  const time = new Date(timestamp).getTime();
  if (Number.isNaN(time)) return "just now";

  const diffMs = Date.now() - time;
  const minutes = Math.floor(diffMs / 60000);

  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function activateOnKey(event, action) {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    action();
  }
}

export default function MyVault() {
  const navigate = useNavigate();
  const masterPassword = getMasterKey();
  const currentUser = sessionStorage.getItem("sv_username") || "Operator";

  const [vaultItems, setVaultItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [notifOpen, setNotifOpen] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);

  // Redirect if not authenticated
  useEffect(() => {
    if (!sessionStorage.getItem("sv_access_token")) {
      navigate("/");
      return;
    }
    loadVault();
  }, []);

  async function loadVault() {
    setLoading(true);
    setError("");

    if (!masterPassword) {
      setError(
        "Missing master passphrase in this session. Please sign in again.",
      );
      setLoading(false);
      return;
    }

    try {
      const entries = await fetchVaultEntries();

      // Decrypt each entry client-side
      const decrypted = await Promise.all(
        entries.map(async (entry) => {
          try {
            const plain = await decryptPayload(
              entry.ciphertext,
              entry.iv,
              entry.salt,
              masterPassword,
            );
            return {
              id: entry.id,
              label: entry.label,
              ...plain,
              created_at: entry.created_at,
              updated_at: entry.updated_at,
            };
          } catch {
            // Cannot decrypt: item may belong to a different local master passphrase
            return {
              id: entry.id,
              label: entry.label,
              category: "Other",
              decryptError: true,
              created_at: entry.created_at,
              updated_at: entry.updated_at,
            };
          }
        }),
      );

      setVaultItems(decrypted);
    } catch (err) {
      setError(err.message || "Failed to load vault. Please log in again.");
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  const filteredItems = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) return vaultItems;

    return vaultItems.filter((item) => {
      const haystack = [item.label, item.username, item.url, item.category]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return haystack.includes(query);
    });
  }, [searchQuery, vaultItems]);

  const notifications = useMemo(() => {
    return [...vaultItems]
      .sort(
        (a, b) =>
          new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime(),
      )
      .slice(0, 8)
      .map((item) => ({
        id: item.id,
        label: item.label,
        timestamp: item.updated_at || item.created_at,
        detail: item.decryptError
          ? "Locked item detected and cannot be decrypted with this local key."
          : "Credential encrypted and available in your vault.",
      }));
  }, [vaultItems]);

  useEffect(() => {
    const seenAt = Number(
      sessionStorage.getItem("sv_notifications_seen_at") || 0,
    );
    const unread = notifications.filter((note) => {
      const noteTime = new Date(note.timestamp).getTime();
      return !Number.isNaN(noteTime) && noteTime > seenAt;
    }).length;

    setUnreadCount(unread);
  }, [notifications]);

  const toggleNotifications = () => {
    setNotifOpen((prev) => {
      const next = !prev;
      if (next) {
        sessionStorage.setItem("sv_notifications_seen_at", String(Date.now()));
        setUnreadCount(0);
      }
      return next;
    });
  };

  const healthScore = useMemo(
    () => computeVaultHealth(vaultItems),
    [vaultItems],
  );

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content vault-page animate-in">
        {/* Header */}
        <header className="vault__header">
          <div>
            <h2 className="vault__page-title">Dashboard</h2>
            <p className="text-muted vault__page-sub">
              Welcome back, {currentUser}
            </p>
          </div>
          <div className="vault__header-actions">
            <button
              className="btn-icon"
              onClick={() => {
                setSearchOpen((prev) => !prev);
                setNotifOpen(false);
              }}
              aria-label="Toggle search"
            >
              <span className="icon">search</span>
            </button>
            <button
              className="btn-icon vault__notif-btn"
              onClick={toggleNotifications}
              aria-label="Toggle notifications"
            >
              <span className="icon">notifications</span>
              {unreadCount > 0 && (
                <span className="vault__notif-count">
                  {Math.min(unreadCount, 9)}
                </span>
              )}
            </button>
          </div>
        </header>

        {searchOpen && (
          <div className="card vault__search-panel">
            <div className="vault__search-panel-top">
              <h4>Search Your Vault</h4>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setSearchOpen(false)}
              >
                <span className="icon icon-sm">close</span>
                Close
              </button>
            </div>
            <input
              className="input-field"
              placeholder="Search by label, username, URL, category..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              autoFocus
            />
          </div>
        )}

        {notifOpen && (
          <div className="card vault__notif-panel">
            <div className="vault__notif-head">
              <h4>Notifications</h4>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setNotifOpen(false)}
              >
                <span className="icon icon-sm">close</span>
                Close
              </button>
            </div>

            {notifications.length === 0 ? (
              <p className="text-muted" style={{ fontSize: "0.82rem" }}>
                No notification events yet. Add your first credential to
                generate activity.
              </p>
            ) : (
              <div className="vault__notif-list">
                {notifications.map((note) => (
                  <button
                    key={note.id}
                    className="vault__notif-item"
                    onClick={() => {
                      setNotifOpen(false);
                      navigate(`/vault/${note.id}`);
                    }}
                  >
                    <div>
                      <strong>{note.label}</strong>
                      <p className="text-muted">{note.detail}</p>
                    </div>
                    <span className="text-muted vault__notif-time">
                      {formatRelativeTime(note.timestamp)}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Error banner */}
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

        {/* Top summary row */}
        <div className="vault__summary">
          <div className="card vault__health-card">
            <div className="vault__health-top">
              <span className="icon icon-lg text-green">shield</span>
              <span className="vault__health-score text-green">
                {healthScore}%
              </span>
            </div>
            <h4>Security Health</h4>
            <p className="text-muted" style={{ fontSize: "0.82rem" }}>
              {vaultItems.length === 0
                ? "Add your first credential to start protecting your data."
                : healthScore >= 85
                  ? "Your vault posture is strong. Encryption, freshness, and key quality look healthy."
                  : healthScore >= 70
                    ? "Your vault is protected, but some credentials should be strengthened."
                    : "Your vault needs attention. Improve weak credentials and investigate locked entries."}
            </p>
            <div className="progress-bar" style={{ marginTop: "12px" }}>
              <div
                className="progress-bar__fill"
                style={{ width: `${healthScore}%` }}
              ></div>
            </div>
          </div>

          <div
            className="card vault__add-card"
            onClick={() => navigate("/vault/add")}
            onKeyDown={(event) =>
              activateOnKey(event, () => navigate("/vault/add"))
            }
            role="button"
            tabIndex={0}
            aria-label="Add a new vault item"
            style={{ cursor: "pointer" }}
            id="btn-add-item"
          >
            <div className="vault__add-icon">
              <span className="icon icon-xl">add</span>
            </div>
            <h4>Add New Item</h4>
            <p className="text-muted" style={{ fontSize: "0.82rem" }}>
              Securely store a new credential
            </p>
          </div>
        </div>

        {/* Vault Items */}
        <div className="vault__section-header">
          <h3>Your Items</h3>
          <span className="badge badge--green">
            {loading
              ? "..."
              : searchQuery.trim()
                ? `${filteredItems.length}/${vaultItems.length} Shown`
                : `${vaultItems.length} Protected`}
          </span>
        </div>

        {loading ? (
          <div
            style={{
              textAlign: "center",
              padding: "40px",
              color: "var(--text-muted)",
            }}
          >
            <span
              className="icon icon-lg"
              style={{ animation: "spin 1s linear infinite" }}
            >
              sync
            </span>
            <p style={{ marginTop: 12 }}>Decrypting your vault...</p>
          </div>
        ) : vaultItems.length === 0 ? (
          <div
            style={{
              textAlign: "center",
              padding: "40px",
              color: "var(--text-muted)",
            }}
          >
            <span className="icon icon-lg">lock</span>
            <p style={{ marginTop: 12 }}>
              Your vault is empty. Click <strong>"Add New Item"</strong> to test
              the zero-knowledge flow.
            </p>
          </div>
        ) : filteredItems.length === 0 ? (
          <div
            style={{
              textAlign: "center",
              padding: "40px",
              color: "var(--text-muted)",
            }}
          >
            <span className="icon icon-lg">search_off</span>
            <p style={{ marginTop: 12 }}>
              No credentials matched your search. Try a different keyword.
            </p>
          </div>
        ) : (
          <div className="vault__grid">
            {filteredItems.map((item, i) => (
              <div
                key={item.id}
                className="card card--zero-knowledge vault__item"
                style={{ animationDelay: `${i * 80}ms` }}
                onClick={() => navigate(`/vault/${item.id}`)}
                onKeyDown={(event) =>
                  activateOnKey(event, () => navigate(`/vault/${item.id}`))
                }
                role="button"
                tabIndex={0}
                aria-label={`Open credential ${item.label}`}
              >
                <div className="vault__item-header">
                  <div className="vault__item-icon">
                    <span className="icon">
                      {item.decryptError
                        ? "lock"
                        : categoryIcons[item.category] || "key"}
                    </span>
                  </div>
                  <span
                    className={`badge ${item.decryptError ? "badge--red" : "badge--green"}`}
                  >
                    {item.decryptError ? "Locked" : "Decrypted"}
                  </span>
                </div>
                <h4 className="vault__item-name">{item.label}</h4>
                <p className="text-muted vault__item-detail">
                  {item.decryptError
                    ? "Cannot decrypt: wrong master key for this record"
                    : item.username || item.url || "Encrypted credential"}
                </p>
                <div className="vault__item-footer">
                  <span className="vault__item-category text-muted">
                    {item.category || "Credential"}
                  </span>
                  <span className="vault__item-strength text-green">
                    {item.decryptError ? "🔒" : "✓ ZK"}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Encrypted banner */}
        <div className="vault__encrypted-banner">
          <div className="vault__banner-left">
            <span className="icon text-green">lock</span>
            <div>
              <h4>Zero-Knowledge Active</h4>
              <p className="text-muted" style={{ fontSize: "0.82rem" }}>
                All data is encrypted client-side. The server stores only
                ciphertext.
              </p>
            </div>
          </div>
          <span className="badge badge--blue">
            <span className="icon icon-sm">wifi</span> Secure Tunnel
          </span>
        </div>

        <StatusBar />
      </main>
    </div>
  );
}
