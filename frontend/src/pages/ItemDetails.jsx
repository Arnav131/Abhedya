import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import Sidebar from "../components/Sidebar";
import StatusBar from "../components/StatusBar";
import {
  decryptPayload,
  deleteVaultEntry,
  encryptPayload,
  fetchVaultEntry,
  updateVaultEntry,
} from "../utils/vaultCrypto";
import { getMasterKey } from "../utils/sessionSecrets";
import "./ItemDetails.css";

const CATEGORIES = [
  "Email",
  "Cloud",
  "Finance",
  "Media",
  "Social",
  "Dev",
  "Other",
];

const categoryIcons = {
  Email: "mail",
  Cloud: "cloud",
  Finance: "account_balance",
  Media: "tv",
  Social: "group",
  Dev: "terminal",
  Other: "key",
};

const emptyForm = {
  label: "",
  username: "",
  password: "",
  url: "",
  category: "Other",
  notes: "",
};

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";

  return date.toLocaleDateString(undefined, {
    month: "short",
    day: "2-digit",
    year: "numeric",
  });
}

function getStrengthScore(secret) {
  if (!secret) return 0;

  let score = Math.min(35, secret.length * 2.8);
  if (/[A-Z]/.test(secret)) score += 15;
  if (/[a-z]/.test(secret)) score += 15;
  if (/\d/.test(secret)) score += 15;
  if (/[^A-Za-z0-9]/.test(secret)) score += 20;

  return Math.min(100, Math.round(score));
}

export default function ItemDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const masterPassword = getMasterKey();

  const [form, setForm] = useState(emptyForm);
  const [meta, setMeta] = useState({ created_at: "", updated_at: "" });

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState("");

  const [isEditing, setIsEditing] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState("");
  const [autoRotate, setAutoRotate] = useState(true);
  const [breachMonitor, setBreachMonitor] = useState(true);

  useEffect(() => {
    if (!sessionStorage.getItem("sv_access_token")) {
      navigate("/");
      return;
    }

    if (!masterPassword) {
      setLoading(false);
      setError(
        "Missing master passphrase in this session. Please sign in again to decrypt your item.",
      );
      return;
    }

    let cancelled = false;

    async function loadEntry() {
      setLoading(true);
      setError("");

      try {
        const entry = await fetchVaultEntry(id);
        const decrypted = await decryptPayload(
          entry.ciphertext,
          entry.iv,
          entry.salt,
          masterPassword,
        );

        if (cancelled) return;

        setForm({
          label: entry.label || "",
          username: decrypted.username || "",
          password: decrypted.password || "",
          url: decrypted.url || "",
          category: decrypted.category || "Other",
          notes: decrypted.notes || "",
        });
        setMeta({
          created_at: entry.created_at,
          updated_at: entry.updated_at,
        });
      } catch (err) {
        if (cancelled) return;
        setError(err.message || "Failed to load this vault item.");
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadEntry();

    return () => {
      cancelled = true;
    };
  }, [id, masterPassword, navigate]);

  const strength = useMemo(
    () => getStrengthScore(form.password),
    [form.password],
  );
  const serviceIcon = categoryIcons[form.category] || "key";

  const handleChange = (field, value) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleCopy = async (field, value) => {
    if (!value) return;

    try {
      await navigator.clipboard?.writeText(value);
      setCopied(field);
      setTimeout(() => setCopied(""), 1800);
    } catch {
      setError(
        "Clipboard copy failed. Please allow clipboard permission and retry.",
      );
    }
  };

  const handleSave = async () => {
    if (!form.label.trim() || !form.password.trim()) {
      setError("Label and Password are required.");
      return;
    }

    setSaving(true);
    setError("");

    try {
      const payload = {
        username: form.username.trim(),
        password: form.password,
        url: form.url.trim(),
        category: form.category,
        notes: form.notes.trim(),
      };

      const encrypted = await encryptPayload(payload, masterPassword);
      const updated = await updateVaultEntry(id, {
        label: form.label.trim(),
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        salt: encrypted.salt,
      });

      setForm((prev) => ({ ...prev, label: form.label.trim() }));
      setMeta((prev) => ({
        created_at: updated.created_at || prev.created_at,
        updated_at: updated.updated_at || prev.updated_at,
      }));
      setIsEditing(false);
    } catch (err) {
      setError(err.message || "Failed to save item changes.");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!window.confirm(`Delete "${form.label || "this item"}" permanently?`)) {
      return;
    }

    setDeleting(true);
    setError("");

    try {
      await deleteVaultEntry(id);
      navigate("/vault");
    } catch (err) {
      setError(err.message || "Failed to delete this item.");
      setDeleting(false);
    }
  };

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content details-page animate-in">
        <button
          className="details__back btn-ghost"
          onClick={() => navigate("/vault")}
        >
          <span className="icon icon-sm">arrow_back</span>
          Back to Vault
        </button>

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

        {loading ? (
          <div
            style={{
              textAlign: "center",
              padding: "60px",
              color: "var(--text-muted)",
            }}
          >
            <span
              className="icon icon-lg"
              style={{ animation: "spin 1s linear infinite" }}
            >
              sync
            </span>
            <p style={{ marginTop: 12 }}>Decrypting item details...</p>
          </div>
        ) : (
          <>
            <div className="details__header">
              <div className="details__header-left">
                <div className="details__service-icon">
                  <span className="icon icon-lg">{serviceIcon}</span>
                </div>
                <div>
                  <span className="details__label">Credential Detail</span>
                  <h2>{form.label || "Untitled Credential"}</h2>
                </div>
              </div>
              <div className="details__header-actions">
                {isEditing ? (
                  <>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={() => setIsEditing(false)}
                      disabled={saving}
                    >
                      <span className="icon icon-sm">close</span>
                      Cancel
                    </button>
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={handleSave}
                      disabled={saving}
                    >
                      <span className="icon icon-sm">save</span>
                      {saving ? "Saving..." : "Save Changes"}
                    </button>
                  </>
                ) : (
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => setIsEditing(true)}
                  >
                    <span className="icon icon-sm">edit</span>
                    Edit Details
                  </button>
                )}
                <button
                  className="btn btn-danger btn-sm"
                  onClick={handleDelete}
                  disabled={deleting || saving}
                >
                  <span className="icon icon-sm">delete</span>
                  {deleting ? "Deleting..." : "Delete Item"}
                </button>
              </div>
            </div>

            <div className="details__body">
              <div className="details__credentials">
                <div className="card">
                  <h4 className="details__section-title">
                    <span className="icon icon-sm">language</span>
                    Credential Information
                  </h4>

                  <div className="details__field">
                    <label>Label</label>
                    <div className="details__field-row">
                      {isEditing ? (
                        <input
                          className="input-field"
                          value={form.label}
                          onChange={(e) =>
                            handleChange("label", e.target.value)
                          }
                          placeholder="Credential name"
                        />
                      ) : (
                        <span className="mono">{form.label || "-"}</span>
                      )}
                    </div>
                  </div>

                  <div className="details__field">
                    <label>Service URL</label>
                    <div className="details__field-row">
                      {isEditing ? (
                        <input
                          className="input-field"
                          value={form.url}
                          onChange={(e) => handleChange("url", e.target.value)}
                          placeholder="https://..."
                        />
                      ) : (
                        <span className="mono">{form.url || "-"}</span>
                      )}
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => handleCopy("url", form.url)}
                      >
                        <span className="icon icon-sm">
                          {copied === "url" ? "check" : "content_copy"}
                        </span>
                        {copied === "url" ? "Copied" : "Copy"}
                      </button>
                    </div>
                  </div>

                  <div className="details__field">
                    <label>Username</label>
                    <div className="details__field-row">
                      {isEditing ? (
                        <input
                          className="input-field"
                          value={form.username}
                          onChange={(e) =>
                            handleChange("username", e.target.value)
                          }
                          placeholder="user@example.com"
                        />
                      ) : (
                        <span className="mono">{form.username || "-"}</span>
                      )}
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => handleCopy("user", form.username)}
                      >
                        <span className="icon icon-sm">
                          {copied === "user" ? "check" : "content_copy"}
                        </span>
                        {copied === "user" ? "Copied" : "Copy"}
                      </button>
                    </div>
                  </div>

                  <div className="details__field">
                    <label>Password</label>
                    <div className="details__field-row">
                      {isEditing ? (
                        <input
                          className="input-field"
                          type={showPassword ? "text" : "password"}
                          value={form.password}
                          onChange={(e) =>
                            handleChange("password", e.target.value)
                          }
                          placeholder="Enter updated password"
                        />
                      ) : (
                        <span className="mono">
                          {showPassword
                            ? form.password
                            : "\u2022".repeat(form.password.length || 8)}
                        </span>
                      )}
                      <div className="details__field-actions">
                        <button
                          className="btn-icon"
                          onClick={() => setShowPassword(!showPassword)}
                        >
                          <span className="icon icon-sm">
                            {showPassword ? "visibility_off" : "visibility"}
                          </span>
                        </button>
                        <button
                          className="btn btn-ghost btn-sm"
                          onClick={() => handleCopy("pass", form.password)}
                        >
                          <span className="icon icon-sm">
                            {copied === "pass" ? "check" : "content_copy"}
                          </span>
                          {copied === "pass" ? "Copied" : "Copy"}
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="details__field">
                    <label>Category</label>
                    <div className="details__field-row">
                      {isEditing ? (
                        <select
                          className="input-field"
                          value={form.category}
                          onChange={(e) =>
                            handleChange("category", e.target.value)
                          }
                        >
                          {CATEGORIES.map((cat) => (
                            <option key={cat} value={cat}>
                              {cat}
                            </option>
                          ))}
                        </select>
                      ) : (
                        <span className="badge badge--blue">
                          {form.category || "Other"}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="card details__notes">
                  <h4 className="details__section-title">
                    <span className="icon icon-sm">notes</span>
                    Notes
                  </h4>
                  {isEditing ? (
                    <textarea
                      className="input-field"
                      rows={4}
                      value={form.notes}
                      onChange={(e) => handleChange("notes", e.target.value)}
                      placeholder="Optional notes"
                    />
                  ) : (
                    <p className="text-muted">
                      {form.notes || "No notes for this credential."}
                    </p>
                  )}
                </div>
              </div>

              <div className="details__security">
                <div className="card">
                  <h4 className="details__section-title">
                    <span className="icon icon-sm">security</span>
                    Smart Protection
                  </h4>

                  <div className="details__toggle-row">
                    <div>
                      <span className="details__toggle-label">
                        Auto-Rotate Password
                      </span>
                      <span className="text-muted details__toggle-desc">
                        Rotate every 90 days
                      </span>
                    </div>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={autoRotate}
                        onChange={() => setAutoRotate(!autoRotate)}
                      />
                      <span className="toggle__slider"></span>
                    </label>
                  </div>

                  <div className="details__toggle-row">
                    <div>
                      <span className="details__toggle-label">
                        Breach Monitoring
                      </span>
                      <span className="text-muted details__toggle-desc">
                        Scan dark web leaks
                      </span>
                    </div>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={breachMonitor}
                        onChange={() => setBreachMonitor(!breachMonitor)}
                      />
                      <span className="toggle__slider"></span>
                    </label>
                  </div>
                </div>

                <div className="card">
                  <h4 className="details__section-title">
                    <span className="icon icon-sm">analytics</span>
                    Security Assessment
                  </h4>
                  <div className="details__assessment">
                    <div className="details__score">
                      <span className="details__score-value text-green">
                        {strength}%
                      </span>
                      <span
                        className="text-muted"
                        style={{ fontSize: "0.75rem" }}
                      >
                        Strength Score
                      </span>
                    </div>
                    <div className="progress-bar" style={{ height: "6px" }}>
                      <div
                        className="progress-bar__fill"
                        style={{
                          width: `${strength}%`,
                          background:
                            strength >= 90
                              ? "var(--primary-container)"
                              : strength >= 70
                                ? "var(--secondary-container)"
                                : "var(--error)",
                        }}
                      ></div>
                    </div>
                  </div>
                </div>

                <div className="card">
                  <h4 className="details__section-title">
                    <span className="icon icon-sm">info</span>
                    Metadata
                  </h4>
                  <div className="details__meta">
                    <div className="details__meta-row">
                      <span className="text-muted">Last Modified</span>
                      <span className="mono">
                        {formatDate(meta.updated_at)}
                      </span>
                    </div>
                    <div className="details__meta-row">
                      <span className="text-muted">Created</span>
                      <span className="mono">
                        {formatDate(meta.created_at)}
                      </span>
                    </div>
                    <div className="details__meta-row">
                      <span className="text-muted">Category</span>
                      <span className="badge badge--blue">
                        {form.category || "Other"}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        <StatusBar />
      </main>
    </div>
  );
}
