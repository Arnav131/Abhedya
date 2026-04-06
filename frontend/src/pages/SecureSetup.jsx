import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { registerUser, loginUser } from "../utils/vaultCrypto";
import { setMasterKey } from "../utils/sessionSecrets";
import { useToast } from "../components/toast/ToastProvider";
import "./SecureSetup.css";

export default function SecureSetup() {
  const navigate = useNavigate();
  const { showToast } = useToast();
  const [isLogin, setIsLogin] = useState(false);

  // Form fields
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [showPass, setShowPass] = useState(false);

  // Status
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [step] = useState(2);

  const getStrength = () => {
    const len = passphrase.length;
    if (len === 0) return { level: 0, label: "Enter Passphrase", color: "" };
    if (len < 6) return { level: 1, label: "Weak Shield", color: "weak" };
    if (len < 10)
      return { level: 2, label: "Moderate Shield", color: "moderate" };
    if (len < 16) return { level: 3, label: "Strong Shield", color: "strong" };
    return { level: 4, label: "Maximum Fortification", color: "max" };
  };

  const strength = getStrength();
  const progressPercent =
    passphrase.length > 0 ? Math.min(95, 40 + passphrase.length * 3) : 0;
  const isSubmitDisabled =
    loading || !username.trim() || (!isLogin && strength.level < 2);

  const handleSubmit = async () => {
    setError("");
    setLoading(true);

    try {
      if (!isLogin) {
        // Register first
        if (!username.trim() || !email.trim()) {
          throw new Error("Please fill in all fields.");
        }
        await registerUser(username.trim(), email.trim(), passphrase);
        showToast({
          type: "success",
          title: "Registration Successful",
          message: "Your account has been created.",
          autoCloseMs: 3500,
        });
      }

      // Login (both flows end here)
      const tokens = await loginUser(username.trim(), passphrase);

      // Store JWT + master password in sessionStorage (never persisted to disk)
      sessionStorage.setItem("sv_access_token", tokens.access);
      sessionStorage.setItem("sv_refresh_token", tokens.refresh);
      setMasterKey(passphrase);
      sessionStorage.setItem("sv_username", username.trim());

      showToast({
        type: "success",
        title: "Login Successful",
        message: `Welcome back, ${username.trim()}!`,
        autoCloseMs: 2800,
      });

      // Navigate to vault
      navigate("/vault");
    } catch (err) {
      let msg = err.message;
      try {
        const parsed = JSON.parse(msg);
        // Extract first error from Django response
        const firstKey = Object.keys(parsed)[0];
        msg = Array.isArray(parsed[firstKey])
          ? parsed[firstKey][0]
          : parsed[firstKey];
      } catch (_) {
        /* use raw msg */
      }
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="setup">
      {/* Background ambient effects */}
      <div className="setup__ambient">
        <div className="setup__ambient-orb setup__ambient-orb--green"></div>
        <div className="setup__ambient-orb setup__ambient-orb--blue"></div>
      </div>

      <div className="setup__container animate-in">
        {/* Left narrative panel */}
        <div className="setup__narrative">
          <div className="setup__step-badge">
            <span className="icon icon-sm">security</span>
            Onboarding Step {String(step).padStart(2, "0")}
          </div>

          <h1 className="setup__title">
            {isLogin ? (
              <>
                Unlock Your
                <br />
                <span className="text-green">Private Sanctuary</span>
              </>
            ) : (
              <>
                Crafting Your
                <br />
                <span className="text-green">Private Sanctuary</span>
              </>
            )}
          </h1>

          <p className="setup__subtitle">
            {isLogin
              ? "Enter your master credentials to decrypt and access your vault."
              : "We're setting up a master key that only you will ever hold. This ensures your data remains invisible to everyone else, including us."}
          </p>

          <div className="setup__features">
            <div className="setup__feature">
              <div className="setup__feature-icon">
                <span className="icon">verified_user</span>
              </div>
              <div>
                <h4>Advanced Shielding</h4>
                <p className="text-muted">
                  Your key is hardened against intrusions.
                </p>
              </div>
            </div>
            <div className="setup__feature">
              <div className="setup__feature-icon setup__feature-icon--blue">
                <span className="icon">visibility_off</span>
              </div>
              <div>
                <h4>Total Privacy</h4>
                <p className="text-muted">
                  Silent protection that never sleeps.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Setup card */}
        <div className="setup__card">
          <div className="setup__card-header">
            <span className="icon text-green">enhanced_encryption</span>
            <span className="setup__card-title">
              {isLogin ? "Vault Unlock" : "Vault Configuration"}
            </span>
          </div>

          {/* Progress */}
          {!isLogin && (
            <div className="setup__progress">
              <div className="setup__progress-header">
                <span className="setup__progress-label">
                  Securing your vault
                </span>
                <span className="setup__progress-value text-green">
                  {progressPercent}%
                </span>
              </div>
              <div className="progress-bar">
                <div
                  className="progress-bar__fill"
                  style={{ width: `${progressPercent}%` }}
                ></div>
              </div>
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
                marginBottom: "8px",
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

          {/* Username input */}
          <div className="input-group">
            <label>Username</label>
            <input
              type="text"
              className="input-field"
              placeholder="Choose a username..."
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              id="input-username"
            />
          </div>

          {/* Email input — only for registration */}
          {!isLogin && (
            <div className="input-group">
              <label>Email Address</label>
              <input
                type="email"
                className="input-field"
                placeholder="your@email.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                id="input-email"
              />
            </div>
          )}

          {/* Passphrase input */}
          <div className="input-group">
            <label>Master Passphrase</label>
            <div className="setup__input-wrap">
              <input
                type={showPass ? "text" : "password"}
                className="input-field"
                placeholder="Enter a strong, memorable passphrase..."
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                id="input-passphrase"
              />
              <button
                className="setup__toggle-vis"
                onClick={() => setShowPass(!showPass)}
                type="button"
              >
                <span className="icon icon-sm">
                  {showPass ? "visibility_off" : "visibility"}
                </span>
              </button>
            </div>
          </div>

          {/* Strength meter */}
          <div className="setup__strength">
            <div className="strength-meter">
              {[1, 2, 3, 4].map((i) => (
                <div
                  key={i}
                  className={`strength-meter__bar ${i <= strength.level ? `active ${strength.color}` : ""}`}
                ></div>
              ))}
            </div>
            {strength.level > 0 && (
              <span
                className={`setup__strength-label badge badge--${strength.level >= 3 ? "green" : strength.level >= 2 ? "blue" : "red"}`}
              >
                <span className="icon icon-sm">shield</span>
                {strength.label}
              </span>
            )}
          </div>

          {/* Tip */}
          <div className="setup__tip">
            <span className="icon icon-sm">tips_and_updates</span>
            <p>
              <strong>Tip:</strong> Use a memorable sentence or a combination of
              four random words. This makes it easy for you to remember but
              impossible for others to guess.
            </p>
          </div>

          {/* Actions */}
          <div className="setup__actions">
            <button
              className="btn btn-primary setup__cta"
              disabled={isSubmitDisabled}
              onClick={handleSubmit}
              id="btn-submit"
            >
              {loading ? (
                <>
                  <span
                    className="icon icon-sm"
                    style={{ animation: "spin 1s linear infinite" }}
                  >
                    sync
                  </span>
                  {isLogin ? "Decrypting..." : "Securing..."}
                </>
              ) : (
                <>
                  <span className="icon icon-sm">
                    {isLogin ? "lock_open" : "lock"}
                  </span>
                  {isLogin ? "Unlock My Vault" : "Secure My Vault"}
                </>
              )}
            </button>
            <p className="setup__login-link text-muted">
              {isLogin ? (
                <>
                  Need a vault?{" "}
                  <a
                    href="#"
                    onClick={(e) => {
                      e.preventDefault();
                      setIsLogin(false);
                      setError("");
                    }}
                  >
                    Create one here
                  </a>
                </>
              ) : (
                <>
                  Already have a vault?{" "}
                  <a
                    href="#"
                    onClick={(e) => {
                      e.preventDefault();
                      setIsLogin(true);
                      setError("");
                    }}
                  >
                    Sign in here
                  </a>
                </>
              )}
            </p>
          </div>
        </div>
      </div>

      {/* Bottom status */}
      <div className="setup__bottom-status">
        <span className="status-bar__dot"></span>
        <span className="status-bar__text">No Data Leaves Your Device</span>
        <span className="status-bar__text" style={{ marginLeft: "auto" }}>
          <span className="icon icon-sm">access_time</span> Last Secured Just
          Now
        </span>
      </div>
    </div>
  );
}
