import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  fetchVaultEntries,
  decryptPayload,
  fetchHoneypotStatus,
} from "../utils/vaultCrypto";
import { getMasterKey } from "../utils/sessionSecrets";
import Sidebar from "../components/Sidebar";
import StatusBar from "../components/StatusBar";
import AnimatedNumber from "../components/AnimatedNumber";
import RevealText from "../components/RevealText";
import useAnimatedNumber from "../hooks/useAnimatedNumber";
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
const HONEYPOT_ALERT_POLL_MS = 20000;
const DASHBOARD_READ_ALERTS_KEY = "sv_dashboard_read_honeypot_alert_ids";
const MAX_DASHBOARD_READ_ALERTS = 250;

const SNAPSHOT_FILTERS = {
  DECRYPTED: "decrypted",
  WEAK: "weak",
  UPDATED_WEEK: "updated-week",
};

const SNAPSHOT_FILTER_LABELS = {
  [SNAPSHOT_FILTERS.DECRYPTED]: "Decrypted Entries",
  [SNAPSHOT_FILTERS.WEAK]: "Weak Credentials",
  [SNAPSHOT_FILTERS.UPDATED_WEEK]: "Updated This Week",
};

function toEpoch(timestamp) {
  if (!timestamp) return 0;
  const value = new Date(timestamp).getTime();
  return Number.isNaN(value) ? 0 : value;
}

function loadDashboardReadAlertIds() {
  try {
    const raw = sessionStorage.getItem(DASHBOARD_READ_ALERTS_KEY);
    if (!raw) {
      return new Set();
    }

    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return new Set();
    }

    return new Set(parsed.map((value) => String(value)));
  } catch {
    return new Set();
  }
}

function saveDashboardReadAlertIds(readIds) {
  const compact = [...readIds].slice(-MAX_DASHBOARD_READ_ALERTS);
  sessionStorage.setItem(DASHBOARD_READ_ALERTS_KEY, JSON.stringify(compact));
}

function formatHoneypotAlertDetail(alert) {
  const provider = alert.provider ? ` (${alert.provider})` : "";
  const ipPart = alert.triggered_ip ? ` from ${alert.triggered_ip}` : "";
  const timePart = alert.triggered_at
    ? ` at ${new Date(alert.triggered_at).toLocaleString()}`
    : "";

  return `${alert.category}${provider} was triggered${ipPart}${timePart}.`;
}

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

function matchesSnapshotFilter(item, selectedFilter) {
  if (!selectedFilter) {
    return true;
  }

  switch (selectedFilter) {
    case SNAPSHOT_FILTERS.DECRYPTED:
      return !item.decryptError;
    case SNAPSHOT_FILTERS.WEAK:
      return (
        !item.decryptError && getPasswordStrength(item.password || "") < 60
      );
    case SNAPSHOT_FILTERS.UPDATED_WEEK: {
      const time = toEpoch(item.updated_at || item.created_at);
      return time > 0 && Date.now() - time <= 7 * DAY_MS;
    }
    default:
      return true;
  }
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
  const [honeypotAlerts, setHoneypotAlerts] = useState([]);
  const [selectedSnapshotFilter, setSelectedSnapshotFilter] = useState("");
  const [selectedCategoryFilter, setSelectedCategoryFilter] = useState("");

  // Redirect if not authenticated
  useEffect(() => {
    if (!sessionStorage.getItem("sv_access_token")) {
      navigate("/");
      return;
    }
    loadVault();
  }, []);

  useEffect(() => {
    if (!sessionStorage.getItem("sv_access_token")) {
      return undefined;
    }

    let cancelled = false;

    const loadAlerts = async () => {
      try {
        const payload = await fetchHoneypotStatus();
        const entries = Array.isArray(payload?.alerts?.entries)
          ? payload.alerts.entries
          : [];
        const readIds = loadDashboardReadAlertIds();

        const filteredAlerts = entries
          .map((entry) => ({
            id: String(entry?.id || ""),
            category: String(entry?.category || "Unknown"),
            provider: String(entry?.provider || ""),
            triggered_at: entry?.triggered_at || null,
            triggered_ip: entry?.triggered_ip || null,
          }))
          .filter((entry) => entry.id && !readIds.has(entry.id));

        if (!cancelled) {
          setHoneypotAlerts(filteredAlerts);
        }
      } catch {
        // Ignore temporary API failures to keep dashboard usable.
      }
    };

    loadAlerts();
    const intervalId = window.setInterval(loadAlerts, HONEYPOT_ALERT_POLL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
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

    return vaultItems.filter((item) => {
      if (query) {
        const haystack = [item.label, item.username, item.url, item.category]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();

        if (!haystack.includes(query)) {
          return false;
        }
      }

      if (!matchesSnapshotFilter(item, selectedSnapshotFilter)) {
        return false;
      }

      if (selectedCategoryFilter) {
        const itemCategory = item.category || "Other";
        if (itemCategory !== selectedCategoryFilter) {
          return false;
        }
      }

      return true;
    });
  }, [searchQuery, selectedSnapshotFilter, selectedCategoryFilter, vaultItems]);

  const notifications = useMemo(() => {
    const vaultNotifications = [...vaultItems]
      .sort(
        (a, b) =>
          new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime(),
      )
      .slice(0, 8)
      .map((item) => ({
        id: String(item.id),
        type: "vault",
        targetId: item.id,
        label: item.label,
        timestamp: item.updated_at || item.created_at,
        detail: item.decryptError
          ? "Locked item detected and cannot be decrypted with this local key."
          : "Credential encrypted and available in your vault.",
      }));

    const alertNotifications = honeypotAlerts.map((alert) => ({
      id: alert.id,
      type: "alert",
      label: `Honeypot Alert: ${alert.category}`,
      timestamp: alert.triggered_at,
      detail: formatHoneypotAlertDetail(alert),
    }));

    return [...alertNotifications, ...vaultNotifications]
      .sort((a, b) => toEpoch(b.timestamp) - toEpoch(a.timestamp))
      .slice(0, 12);
  }, [vaultItems, honeypotAlerts]);

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

  const handleMarkAlertRead = (alertId) => {
    const normalizedId = String(alertId || "");
    if (!normalizedId) {
      return;
    }

    setHoneypotAlerts((prev) =>
      prev.filter((alert) => alert.id !== normalizedId),
    );

    const readIds = loadDashboardReadAlertIds();
    readIds.add(normalizedId);
    saveDashboardReadAlertIds(readIds);
  };

  const healthScore = useMemo(
    () => computeVaultHealth(vaultItems),
    [vaultItems],
  );

  const vaultInsights = useMemo(() => {
    const total = vaultItems.length;
    const decryptedItems = vaultItems.filter((item) => !item.decryptError);
    const lockedCount = total - decryptedItems.length;

    const weakCount = decryptedItems.filter(
      (item) => getPasswordStrength(item.password || "") < 60,
    ).length;

    const updatedInLastWeek = vaultItems.filter((item) => {
      const time = toEpoch(item.updated_at || item.created_at);
      return time > 0 && Date.now() - time <= 7 * DAY_MS;
    }).length;

    const categoryMap = vaultItems.reduce((acc, item) => {
      const category = item.category || "Other";
      acc[category] = (acc[category] || 0) + 1;
      return acc;
    }, {});

    const categoryPulse = Object.entries(categoryMap)
      .map(([name, count]) => ({
        name,
        count,
        share: total > 0 ? Math.round((count / total) * 100) : 0,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const actionQueue = [];

    if (lockedCount > 0) {
      actionQueue.push(
        "Investigate locked entries and re-authenticate local master key.",
      );
    }

    if (weakCount > 0) {
      actionQueue.push(
        "Strengthen weak credentials to raise your vault resilience score.",
      );
    }

    if (
      total > 0 &&
      updatedInLastWeek < Math.max(1, Math.round(total * 0.35))
    ) {
      actionQueue.push(
        "Rotate stale secrets this week to reduce long-tail exposure.",
      );
    }

    if (!actionQueue.length) {
      actionQueue.push(
        "Defense posture is healthy. Keep weekly scans and regular key rotation active.",
      );
    }

    return {
      total,
      decryptedCount: decryptedItems.length,
      lockedCount,
      weakCount,
      updatedInLastWeek,
      categoryPulse,
      actionQueue,
    };
  }, [vaultItems]);

  const animatedHealthScore = useAnimatedNumber(healthScore, {
    duration: 1100,
    enabled: !loading,
    startValue: 0,
  });

  const animatedFilteredCount = useAnimatedNumber(filteredItems.length, {
    duration: 850,
    enabled: !loading,
    startValue: 0,
  });

  const animatedTotalCount = useAnimatedNumber(vaultItems.length, {
    duration: 950,
    enabled: !loading,
    startValue: 0,
  });

  const animatedUnreadCount = useAnimatedNumber(unreadCount, {
    duration: 650,
    enabled: true,
    startValue: 0,
  });

  const unreadBadgeValue = Math.min(Math.round(animatedUnreadCount), 9);
  const hasSearchQuery = Boolean(searchQuery.trim());
  const hasSelectionFilters = Boolean(
    selectedSnapshotFilter || selectedCategoryFilter,
  );
  const hasActiveFilters = hasSearchQuery || hasSelectionFilters;

  const toggleSnapshotFilter = (filterName) => {
    setSelectedSnapshotFilter((prev) =>
      prev === filterName ? "" : filterName,
    );
  };

  const toggleCategoryFilter = (categoryName) => {
    setSelectedCategoryFilter((prev) =>
      prev === categoryName ? "" : categoryName,
    );
  };

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content vault-page animate-in">
        {/* Header */}
        <header className="vault__header">
          <div>
            <RevealText
              as="h2"
              className="vault__page-title"
              text="Dashboard"
              msPerChar={42}
              initialDelay={80}
            />
            <RevealText
              as="p"
              className="text-muted vault__page-sub"
              text={`Welcome back, ${currentUser}`}
              msPerChar={16}
              initialDelay={180}
            />
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
                <span className="vault__notif-count">{unreadBadgeValue}</span>
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
                No vault events or alerts yet.
              </p>
            ) : (
              <div className="vault__notif-list">
                {notifications.map((note) =>
                  note.type === "alert" ? (
                    <div
                      key={`alert-${note.id}`}
                      className="vault__notif-item vault__notif-item--alert"
                    >
                      <div>
                        <div className="vault__notif-label-row">
                          <strong>{note.label}</strong>
                          <span className="badge badge--red vault__notif-alert-badge">
                            Alert
                          </span>
                        </div>
                        <p className="text-muted">{note.detail}</p>
                      </div>
                      <div className="vault__notif-actions">
                        <span className="text-muted vault__notif-time">
                          {formatRelativeTime(note.timestamp)}
                        </span>
                        <button
                          type="button"
                          className="vault__notif-mark-read"
                          onClick={() => handleMarkAlertRead(note.id)}
                        >
                          Mark as read
                        </button>
                      </div>
                    </div>
                  ) : (
                    <button
                      key={`vault-${note.id}`}
                      className="vault__notif-item"
                      onClick={() => {
                        setNotifOpen(false);
                        navigate(`/vault/${note.targetId}`);
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
                  ),
                )}
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
                <AnimatedNumber
                  target={healthScore}
                  duration={1100}
                  enabled={!loading}
                  suffix="%"
                />
              </span>
            </div>
            <RevealText
              as="h4"
              text="Security Health"
              msPerChar={24}
              initialDelay={220}
            />
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
                style={{ width: `${Math.round(animatedHealthScore)}%` }}
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
            <RevealText
              as="h4"
              text="Add New Item"
              msPerChar={24}
              initialDelay={260}
            />
            <p className="text-muted" style={{ fontSize: "0.82rem" }}>
              Securely store a new credential
            </p>
          </div>
        </div>

        <div className="vault__intel-grid">
          <section className="card vault__intel-card vault__intel-card--span vault__intel-card--snapshot">
            <div className="vault__intel-head">
              <RevealText
                as="h4"
                text="Live Vault Snapshot"
                msPerChar={20}
                initialDelay={180}
              />
              <span className="badge badge--green vault__snapshot-badge">
                <AnimatedNumber
                  target={vaultInsights.updatedInLastWeek}
                  duration={900}
                  enabled={!loading}
                />{" "}
                Updated 7d
              </span>
            </div>

            <div className="vault__intel-metrics">
              <article
                className={`vault__intel-metric ${selectedSnapshotFilter === SNAPSHOT_FILTERS.DECRYPTED ? "vault__intel-metric--active" : ""}`}
                onClick={() => toggleSnapshotFilter(SNAPSHOT_FILTERS.DECRYPTED)}
                onKeyDown={(event) =>
                  activateOnKey(event, () =>
                    toggleSnapshotFilter(SNAPSHOT_FILTERS.DECRYPTED),
                  )
                }
                role="button"
                tabIndex={0}
                aria-pressed={
                  selectedSnapshotFilter === SNAPSHOT_FILTERS.DECRYPTED
                }
              >
                <strong>
                  <AnimatedNumber
                    target={vaultInsights.decryptedCount}
                    duration={900}
                    enabled={!loading}
                  />
                </strong>
                <span className="text-muted">Decrypted Entries</span>
              </article>

              <article
                className={`vault__intel-metric ${selectedSnapshotFilter === SNAPSHOT_FILTERS.WEAK ? "vault__intel-metric--active" : ""}`}
                onClick={() => toggleSnapshotFilter(SNAPSHOT_FILTERS.WEAK)}
                onKeyDown={(event) =>
                  activateOnKey(event, () =>
                    toggleSnapshotFilter(SNAPSHOT_FILTERS.WEAK),
                  )
                }
                role="button"
                tabIndex={0}
                aria-pressed={selectedSnapshotFilter === SNAPSHOT_FILTERS.WEAK}
              >
                <strong>
                  <AnimatedNumber
                    target={vaultInsights.weakCount}
                    duration={900}
                    enabled={!loading}
                  />
                </strong>
                <span className="text-muted">Weak Credentials</span>
              </article>

              <article
                className={`vault__intel-metric ${selectedSnapshotFilter === SNAPSHOT_FILTERS.UPDATED_WEEK ? "vault__intel-metric--active" : ""}`}
                onClick={() =>
                  toggleSnapshotFilter(SNAPSHOT_FILTERS.UPDATED_WEEK)
                }
                onKeyDown={(event) =>
                  activateOnKey(event, () =>
                    toggleSnapshotFilter(SNAPSHOT_FILTERS.UPDATED_WEEK),
                  )
                }
                role="button"
                tabIndex={0}
                aria-pressed={
                  selectedSnapshotFilter === SNAPSHOT_FILTERS.UPDATED_WEEK
                }
              >
                <strong>
                  <AnimatedNumber
                    target={vaultInsights.updatedInLastWeek}
                    duration={900}
                    enabled={!loading}
                  />
                </strong>
                <span className="text-muted">Updated This Week</span>
              </article>
            </div>
          </section>

          <section className="card vault__intel-card">
            <RevealText
              as="h4"
              text="Category"
              msPerChar={20}
              initialDelay={220}
            />

            {vaultInsights.categoryPulse.length === 0 ? (
              <p className="text-muted vault__intel-empty">
                Add credentials to unlock category intelligence.
              </p>
            ) : (
              <div className="vault__category-list">
                {vaultInsights.categoryPulse.map((entry) => (
                  <div
                    key={entry.name}
                    className={`vault__category-row ${selectedCategoryFilter === entry.name ? "vault__category-row--active" : ""}`}
                    onClick={() => toggleCategoryFilter(entry.name)}
                    onKeyDown={(event) =>
                      activateOnKey(event, () =>
                        toggleCategoryFilter(entry.name),
                      )
                    }
                    role="button"
                    tabIndex={0}
                    aria-pressed={selectedCategoryFilter === entry.name}
                  >
                    <div className="vault__category-label">
                      <span className="icon icon-sm">
                        {categoryIcons[entry.name] || "key"}
                      </span>
                      <span>{entry.name}</span>
                    </div>
                    <div className="vault__category-metrics">
                      <span className="mono">{entry.share}%</span>
                      <div className="vault__category-track">
                        <div
                          className="vault__category-fill"
                          style={{ width: `${entry.share}%` }}
                        ></div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="card vault__intel-card">
            <RevealText
              as="h4"
              text="Action Queue"
              msPerChar={20}
              initialDelay={240}
            />
            <ul className="vault__action-list">
              {vaultInsights.actionQueue.map((action) => (
                <li key={action}>
                  <span className="icon icon-sm">task_alt</span>
                  <span>{action}</span>
                </li>
              ))}
            </ul>
          </section>
        </div>

        {/* Vault Items */}
        <div className="vault__section-header">
          <RevealText
            as="h3"
            text="Your Items"
            msPerChar={28}
            initialDelay={280}
          />
          <span className="badge badge--green">
            {loading
              ? "..."
              : hasActiveFilters
                ? `${Math.round(animatedFilteredCount)}/${Math.round(animatedTotalCount)} Shown`
                : `${Math.round(animatedTotalCount)} Protected`}
          </span>
        </div>

        {hasSelectionFilters && (
          <div className="vault__active-filters">
            {selectedSnapshotFilter && (
              <button
                type="button"
                className="vault__active-filter"
                onClick={() => toggleSnapshotFilter(selectedSnapshotFilter)}
              >
                Type: {SNAPSHOT_FILTER_LABELS[selectedSnapshotFilter]}
                <span className="icon icon-sm">close</span>
              </button>
            )}

            {selectedCategoryFilter && (
              <button
                type="button"
                className="vault__active-filter"
                onClick={() => toggleCategoryFilter(selectedCategoryFilter)}
              >
                Category: {selectedCategoryFilter}
                <span className="icon icon-sm">close</span>
              </button>
            )}
          </div>
        )}

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
              {hasSelectionFilters
                ? "No credentials matched the selected filters. Click an active filter again to clear it."
                : "No credentials matched your search. Try a different keyword."}
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
              <RevealText
                as="h4"
                text="Zero-Knowledge Active"
                msPerChar={16}
                initialDelay={120}
              />
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
