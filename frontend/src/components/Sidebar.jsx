import { useEffect } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { clearMasterKey } from "../utils/sessionSecrets";
import { fetchHoneypotStatus } from "../utils/vaultCrypto";
import { useToast } from "./toast/ToastProvider";
import "./Sidebar.css";

const navItems = [
  { path: "/vault", icon: "lock", label: "My Vault" },
  { path: "/security", icon: "shield", label: "Security Health" },
  { path: "/settings", icon: "settings", label: "Safety Settings" },
];

const HONEYPOT_ALERT_POLL_MS = 20000;
const SEEN_ALERTS_KEY = "sv_seen_honeypot_alert_ids";
const MAX_SEEN_ALERTS = 200;

function loadSeenAlertIds() {
  try {
    const raw = sessionStorage.getItem(SEEN_ALERTS_KEY);
    if (!raw) {
      return new Set();
    }
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return new Set();
    }
    return new Set(parsed.map((id) => String(id)));
  } catch {
    return new Set();
  }
}

function saveSeenAlertIds(seenIds) {
  const compact = [...seenIds].slice(-MAX_SEEN_ALERTS);
  sessionStorage.setItem(SEEN_ALERTS_KEY, JSON.stringify(compact));
}

function formatAlertMessage(alert) {
  const providerPart = alert.provider ? ` (${alert.provider})` : "";
  const ipPart = alert.triggered_ip ? ` from ${alert.triggered_ip}` : "";

  let timePart = "";
  if (alert.triggered_at) {
    const parsedTime = new Date(alert.triggered_at);
    if (!Number.isNaN(parsedTime.getTime())) {
      timePart = ` at ${parsedTime.toLocaleString()}`;
    }
  }

  return `${alert.category}${providerPart} was triggered${ipPart}${timePart}.`;
}

export default function Sidebar() {
  const navigate = useNavigate();
  const { showToast } = useToast();
  const currentUser = sessionStorage.getItem("sv_username") || "Operator";
  const initials = currentUser.slice(0, 2).toUpperCase();

  const handleLockAll = () => {
    clearMasterKey();
    sessionStorage.removeItem("sv_master_key");
    sessionStorage.removeItem("sv_access_token");
    sessionStorage.removeItem("sv_refresh_token");
    navigate("/");
  };

  useEffect(() => {
    if (!sessionStorage.getItem("sv_access_token")) {
      return undefined;
    }

    let cancelled = false;

    const checkHoneypotAlerts = async () => {
      try {
        const statusPayload = await fetchHoneypotStatus();
        const entries = statusPayload?.alerts?.entries;

        if (cancelled || !Array.isArray(entries) || entries.length === 0) {
          return;
        }

        const seenIds = loadSeenAlertIds();
        let hasUpdates = false;

        entries.forEach((alert) => {
          const alertId = String(alert?.id || "");
          if (!alertId || seenIds.has(alertId)) {
            return;
          }

          seenIds.add(alertId);
          hasUpdates = true;

          showToast({
            type: "error",
            title: "Honeypot Alert",
            message: formatAlertMessage(alert),
            autoCloseMs: null,
          });
        });

        if (hasUpdates) {
          saveSeenAlertIds(seenIds);
        }
      } catch {
        // Ignore polling errors to avoid noisy UX when endpoint is temporarily unavailable.
      }
    };

    checkHoneypotAlerts();
    const intervalId = window.setInterval(
      checkHoneypotAlerts,
      HONEYPOT_ALERT_POLL_MS,
    );

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [showToast]);

  return (
    <aside className="sidebar">
      <div className="sidebar__header">
        <div className="sidebar__logo">
          <span className="sidebar__logo-icon icon icon-lg">
            enhanced_encryption
          </span>
          <span className="sidebar__logo-text">Abhedya</span>
        </div>
      </div>

      <nav className="sidebar__nav">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              `sidebar__link ${isActive ? "sidebar__link--active" : ""}`
            }
          >
            <span className="icon">{item.icon}</span>
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar__footer">
        <button className="sidebar__lock-btn" onClick={handleLockAll}>
          <span className="icon icon-sm">lock</span>
          <span>Lock All Items</span>
        </button>
        <div className="sidebar__user">
          <div className="sidebar__avatar">{initials || "SV"}</div>
          <div className="sidebar__user-info">
            <span className="sidebar__user-name">{currentUser}</span>
            <span className="sidebar__user-role">Admin Access</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
