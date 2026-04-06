"""
Abhedya — Honeypot Breach Alert API
======================================
Standalone SMTP alert service for the Honeypot Deception Engine.

When a fake (decoy) password stored alongside a user's real encrypted
password is found in a breach database, it means an attacker has
accessed the vault database.  This module sends an immediate Gmail
SMTP alert to the affected user.

Architecture
------------
This module is a **standalone API** — it does NOT import Django models,
views, or signals.  The backend team will call these functions from
their own views / signals / celery tasks.

How it works
------------
1.  Backend detects that a honeypot decoy password has been breached.
2.  Backend calls ``send_breach_alert()`` with user details + breach info.
3.  This module composes a professional HTML email and sends it via
    Gmail SMTP (TLS on port 587).
4.  Returns a structured result dict so the backend can log/audit.

Configuration (environment variables)
--------------------------------------
    SMTP_HOST           — SMTP server      (default: smtp.gmail.com)
    SMTP_PORT           — SMTP port         (default: 587)
    SMTP_EMAIL          — sender email      (Gmail address)
    SMTP_PASSWORD       — sender password   (Gmail App Password*)
    SMTP_FROM_NAME      — display name      (default: Abhedya Security)
    SMTP_USE_TLS        — use STARTTLS      (default: True)
    SMTP_TIMEOUT        — connection timeout (default: 30s)
    ALERT_RATE_LIMIT    — max alerts/user/hr (default: 5)

    * For Gmail, you MUST use an App Password (not your regular password).
      Enable 2-Step Verification → generate an App Password at
      https://myaccount.google.com/apppasswords

Usage (for backend developers)
-------------------------------
    from ai_engine.honeypot_alert_api import send_breach_alert, send_batch_alerts

    # --- Single alert ---
    result = send_breach_alert(
        recipient_email="user@example.com",
        recipient_name="Arnav",
        breach_details={
            "honeypot_id": "a1b2c3d4-...",
            "category": "decoy_password",
            "provider": "vault",
            "triggered_at": "2026-04-07T01:30:00Z",
            "triggered_ip": "203.0.113.42",
            "severity": "critical",
        },
    )
    # result → {"success": True, "message_id": "...", ...}

    # --- Batch alerts ---
    results = send_batch_alerts([
        {
            "recipient_email": "user1@example.com",
            "recipient_name": "User One",
            "breach_details": {...},
        },
        ...
    ])
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import smtplib
import ssl
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Logging — NEVER emit user PII or credentials
# ---------------------------------------------------------------------------
logger = logging.getLogger("abhedya.honeypot.alert")
logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Configuration — read from env vars (backend can override via args)
# ---------------------------------------------------------------------------

def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _env_int(key: str, default: int = 0) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except (TypeError, ValueError):
        return default


def _env_bool(key: str, default: bool = True) -> bool:
    val = os.environ.get(key, "").lower()
    if val in ("false", "0", "no", "off"):
        return False
    if val in ("true", "1", "yes", "on"):
        return True
    return default


# SMTP defaults (Gmail)
SMTP_HOST: str = _env("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT: int = _env_int("SMTP_PORT", 587)
SMTP_EMAIL: str = _env("SMTP_EMAIL", "")
SMTP_PASSWORD: str = _env("SMTP_PASSWORD", "")
SMTP_FROM_NAME: str = _env("SMTP_FROM_NAME", "Abhedya Security")
SMTP_USE_TLS: bool = _env_bool("SMTP_USE_TLS", True)
SMTP_TIMEOUT: int = _env_int("SMTP_TIMEOUT", 30)

# Alert rate limiting (per-user, in-memory)
ALERT_RATE_LIMIT: int = _env_int("ALERT_RATE_LIMIT", 5)  # max alerts per user per hour

# Retry configuration
MAX_RETRIES: int = 3
RETRY_BACKOFF: float = 2.0  # seconds, doubled on each retry


# ============================================================================
#  1. RATE LIMITER (in-memory, per-process)
# ============================================================================

class _RateLimiter:
    """Simple in-memory sliding-window rate limiter.

    Tracks alert timestamps per user email hash (never stores raw emails).
    Window: 1 hour.  Max alerts per window: ALERT_RATE_LIMIT.
    """

    WINDOW_SECONDS = 3600  # 1 hour

    def __init__(self) -> None:
        self._timestamps: Dict[str, List[float]] = defaultdict(list)

    def _user_key(self, email: str) -> str:
        """Hash the email so we never store PII in memory."""
        return hashlib.sha256(email.lower().encode()).hexdigest()[:16]

    def is_allowed(self, email: str) -> bool:
        """Check if sending another alert to this user is allowed."""
        key = self._user_key(email)
        now = time.time()
        cutoff = now - self.WINDOW_SECONDS

        # Prune old timestamps
        self._timestamps[key] = [
            ts for ts in self._timestamps[key] if ts > cutoff
        ]

        return len(self._timestamps[key]) < ALERT_RATE_LIMIT

    def record(self, email: str) -> None:
        """Record that an alert was sent."""
        key = self._user_key(email)
        self._timestamps[key].append(time.time())

    def remaining(self, email: str) -> int:
        """Return how many more alerts can be sent in the current window."""
        key = self._user_key(email)
        now = time.time()
        cutoff = now - self.WINDOW_SECONDS
        self._timestamps[key] = [
            ts for ts in self._timestamps[key] if ts > cutoff
        ]
        return max(0, ALERT_RATE_LIMIT - len(self._timestamps[key]))


_rate_limiter = _RateLimiter()


# ============================================================================
#  2. HTML EMAIL TEMPLATE
# ============================================================================

def _build_alert_html(
    recipient_name: str,
    breach_details: Dict[str, Any],
    alert_id: str,
) -> str:
    """Build a professional, responsive HTML breach alert email.

    The email uses inline CSS for maximum compatibility across email
    clients (Gmail, Outlook, Apple Mail, etc.).
    """
    severity = str(breach_details.get("severity", "critical")).upper()
    category = str(breach_details.get("category", "unknown")).replace("_", " ").title()
    provider = str(breach_details.get("provider", "—"))
    honeypot_id = str(breach_details.get("honeypot_id", "—"))
    triggered_at = str(breach_details.get("triggered_at", "Unknown"))
    triggered_ip = str(breach_details.get("triggered_ip", "Unknown"))

    severity_color = {
        "CRITICAL": "#DC2626",
        "HIGH": "#EA580C",
        "MEDIUM": "#D97706",
        "LOW": "#2563EB",
    }.get(severity, "#DC2626")

    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Alert — Abhedya</title>
</head>
<body style="margin:0; padding:0; background-color:#0F172A; font-family:'Segoe UI',Roboto,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#0F172A; padding:40px 20px;">
    <tr>
      <td align="center">
        <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="background-color:#1E293B; border-radius:16px; overflow:hidden; box-shadow:0 25px 50px rgba(0,0,0,0.5);">

          <!-- HEADER -->
          <tr>
            <td style="background:linear-gradient(135deg, {severity_color}, #7C3AED); padding:32px 40px; text-align:center;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="text-align:center;">
                    <div style="font-size:48px; margin-bottom:8px;">🚨</div>
                    <h1 style="margin:0; color:#FFFFFF; font-size:24px; font-weight:700; letter-spacing:0.5px;">
                      SECURITY BREACH DETECTED
                    </h1>
                    <p style="margin:8px 0 0; color:rgba(255,255,255,0.85); font-size:14px;">
                      Honeypot Canary Trap Triggered
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- SEVERITY BADGE -->
          <tr>
            <td style="padding:24px 40px 0;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="text-align:center;">
                    <span style="display:inline-block; background:{severity_color}; color:#FFF; font-size:12px; font-weight:700; padding:6px 20px; border-radius:100px; letter-spacing:1.5px; text-transform:uppercase;">
                      ⚠ {severity} SEVERITY
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- GREETING -->
          <tr>
            <td style="padding:24px 40px 0;">
              <p style="margin:0; color:#E2E8F0; font-size:16px; line-height:1.6;">
                Hello <strong style="color:#FFFFFF;">{recipient_name}</strong>,
              </p>
              <p style="margin:12px 0 0; color:#94A3B8; font-size:15px; line-height:1.7;">
                Our honeypot defense system has detected a <strong style="color:{severity_color};">breach</strong>
                involving your account. A decoy credential planted in our vault was found compromised,
                which indicates unauthorized access to the database.
              </p>
            </td>
          </tr>

          <!-- BREACH DETAILS TABLE -->
          <tr>
            <td style="padding:24px 40px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0F172A; border-radius:12px; border:1px solid #334155;">
                <tr>
                  <td style="padding:20px 24px 8px;">
                    <p style="margin:0; color:#64748B; font-size:11px; font-weight:700; letter-spacing:1.5px; text-transform:uppercase;">
                      BREACH DETAILS
                    </p>
                  </td>
                </tr>
                <tr>
                  <td style="padding:0 24px;">
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="padding:12px 0; border-bottom:1px solid #1E293B;">
                          <span style="color:#64748B; font-size:13px;">Alert ID</span><br>
                          <span style="color:#E2E8F0; font-size:14px; font-family:monospace;">{alert_id}</span>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:12px 0; border-bottom:1px solid #1E293B;">
                          <span style="color:#64748B; font-size:13px;">Honeypot ID</span><br>
                          <span style="color:#E2E8F0; font-size:14px; font-family:monospace;">{honeypot_id}</span>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:12px 0; border-bottom:1px solid #1E293B;">
                          <span style="color:#64748B; font-size:13px;">Credential Type</span><br>
                          <span style="color:#F8FAFC; font-size:14px; font-weight:600;">{category}</span>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:12px 0; border-bottom:1px solid #1E293B;">
                          <span style="color:#64748B; font-size:13px;">Provider</span><br>
                          <span style="color:#E2E8F0; font-size:14px;">{provider}</span>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:12px 0; border-bottom:1px solid #1E293B;">
                          <span style="color:#64748B; font-size:13px;">Detected At</span><br>
                          <span style="color:#E2E8F0; font-size:14px;">{triggered_at}</span>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:12px 0;">
                          <span style="color:#64748B; font-size:13px;">Source IP</span><br>
                          <span style="color:{severity_color}; font-size:14px; font-weight:600; font-family:monospace;">{triggered_ip}</span>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr><td style="padding:0 0 16px;"></td></tr>
              </table>
            </td>
          </tr>

          <!-- ACTION STEPS -->
          <tr>
            <td style="padding:0 40px 24px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:linear-gradient(135deg, rgba(220,38,38,0.1), rgba(124,58,237,0.1)); border-radius:12px; border:1px solid #7C3AED33;">
                <tr>
                  <td style="padding:20px 24px 8px;">
                    <p style="margin:0; color:#A78BFA; font-size:11px; font-weight:700; letter-spacing:1.5px; text-transform:uppercase;">
                      🔐 RECOMMENDED ACTIONS
                    </p>
                  </td>
                </tr>
                <tr>
                  <td style="padding:8px 24px 20px;">
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="padding:8px 0; color:#CBD5E1; font-size:14px; line-height:1.6;">
                          <strong style="color:#F8FAFC;">1.</strong> Change your master password immediately
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:8px 0; color:#CBD5E1; font-size:14px; line-height:1.6;">
                          <strong style="color:#F8FAFC;">2.</strong> Rotate all stored credentials in your vault
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:8px 0; color:#CBD5E1; font-size:14px; line-height:1.6;">
                          <strong style="color:#F8FAFC;">3.</strong> Enable two-factor authentication if not already active
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:8px 0; color:#CBD5E1; font-size:14px; line-height:1.6;">
                          <strong style="color:#F8FAFC;">4.</strong> Review active sessions and revoke unrecognized devices
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:8px 0; color:#CBD5E1; font-size:14px; line-height:1.6;">
                          <strong style="color:#F8FAFC;">5.</strong> Regenerate your honeypot traps from the dashboard
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- INFO BOX -->
          <tr>
            <td style="padding:0 40px 32px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0F172A; border-radius:12px; border:1px solid #334155;">
                <tr>
                  <td style="padding:16px 24px;">
                    <p style="margin:0; color:#64748B; font-size:13px; line-height:1.7;">
                      <strong style="color:#94A3B8;">ℹ What is a Honeypot Alert?</strong><br>
                      When you registered, our system planted fake decoy credentials
                      in the database alongside your encrypted data. These fake credentials
                      are mapped to your account. If any of them appear in a breach database,
                      it proves an attacker has accessed the raw database — your real data
                      may be at risk. <strong style="color:#E2E8F0;">Your actual passwords were
                      never stored in plaintext</strong> and remain encrypted.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- FOOTER -->
          <tr>
            <td style="background:#0F172A; padding:24px 40px; border-top:1px solid #1E293B; text-align:center;">
              <p style="margin:0 0 8px; color:#475569; font-size:12px;">
                Abhedya — Zero-Knowledge Secrets Manager
              </p>
              <p style="margin:0; color:#334155; font-size:11px;">
                This is an automated security alert. Do not reply to this email.<br>
                Alert ID: {alert_id}
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def _build_alert_plaintext(
    recipient_name: str,
    breach_details: Dict[str, Any],
    alert_id: str,
) -> str:
    """Build a plain-text fallback for email clients that don't render HTML."""
    severity = str(breach_details.get("severity", "critical")).upper()
    category = str(breach_details.get("category", "unknown")).replace("_", " ").title()
    provider = str(breach_details.get("provider", "—"))
    honeypot_id = str(breach_details.get("honeypot_id", "—"))
    triggered_at = str(breach_details.get("triggered_at", "Unknown"))
    triggered_ip = str(breach_details.get("triggered_ip", "Unknown"))

    return f"""\
========================================
🚨 SECURITY BREACH DETECTED
   Abhedya Honeypot Alert System
========================================

Severity: {severity}

Hello {recipient_name},

Our honeypot defense system has detected a breach involving your account.
A decoy credential planted in our vault was found compromised, indicating
unauthorized access to the database.

--- BREACH DETAILS ---
Alert ID:        {alert_id}
Honeypot ID:     {honeypot_id}
Credential Type: {category}
Provider:        {provider}
Detected At:     {triggered_at}
Source IP:        {triggered_ip}

--- RECOMMENDED ACTIONS ---
1. Change your master password immediately
2. Rotate all stored credentials in your vault
3. Enable two-factor authentication if not already active
4. Review active sessions and revoke unrecognized devices
5. Regenerate your honeypot traps from the dashboard

--- WHAT IS A HONEYPOT ALERT? ---
When you registered, our system planted fake decoy credentials in the
database alongside your encrypted data. If any of them appear in a
breach database, it proves an attacker has accessed the raw database.
Your actual passwords remain encrypted and were never stored in plaintext.

—
Abhedya — Zero-Knowledge Secrets Manager
This is an automated security alert. Do not reply.
Alert ID: {alert_id}
"""


# ============================================================================
#  3. SMTP SENDER
# ============================================================================

def _create_smtp_connection(
    host: str = "",
    port: int = 0,
    email: str = "",
    password: str = "",
    use_tls: bool = True,
    timeout: int = 0,
) -> smtplib.SMTP:
    """Create and authenticate an SMTP connection.

    Parameters use module-level defaults if not provided.

    Returns
    -------
    smtplib.SMTP
        An authenticated, ready-to-send SMTP connection.

    Raises
    ------
    smtplib.SMTPException
        If connection, TLS, or authentication fails.
    """
    host = host or SMTP_HOST
    port = port or SMTP_PORT
    email = email or SMTP_EMAIL
    password = password or SMTP_PASSWORD
    timeout = timeout or SMTP_TIMEOUT

    server = smtplib.SMTP(host, port, timeout=timeout)
    server.ehlo()

    if use_tls:
        context = ssl.create_default_context()
        server.starttls(context=context)
        server.ehlo()

    server.login(email, password)
    return server


def _send_email(
    server: smtplib.SMTP,
    sender_email: str,
    sender_name: str,
    recipient_email: str,
    subject: str,
    html_body: str,
    plain_body: str,
    alert_id: str,
) -> str:
    """Compose and send a MIME multipart email.

    Returns the Message-ID header of the sent email.
    """
    msg = MIMEMultipart("alternative")
    msg["From"] = f"{sender_name} <{sender_email}>"
    msg["To"] = recipient_email
    msg["Subject"] = subject
    msg["X-Mailer"] = "Abhedya-HoneypotAlert/1.0"
    msg["X-Alert-ID"] = alert_id
    msg["X-Priority"] = "1"  # High priority
    msg["Importance"] = "High"

    # Attach plain text first (fallback), then HTML (preferred)
    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    server.sendmail(sender_email, [recipient_email], msg.as_string())

    return msg.get("Message-ID", alert_id)


# ============================================================================
#  4. PUBLIC API
# ============================================================================

def send_breach_alert(
    recipient_email: str,
    recipient_name: str,
    breach_details: Dict[str, Any],
    *,
    smtp_host: str = "",
    smtp_port: int = 0,
    smtp_email: str = "",
    smtp_password: str = "",
    smtp_from_name: str = "",
    smtp_use_tls: bool = True,
    smtp_timeout: int = 0,
    skip_rate_limit: bool = False,
) -> Dict[str, Any]:
    """Send a honeypot breach alert email to a specific user via Gmail SMTP.

    This is the **primary entry point** for the backend to call when a
    honeypot decoy password is detected in a breach.

    Parameters
    ----------
    recipient_email : str
        The user's email address.
    recipient_name : str
        The user's display name (for personalization).
    breach_details : dict
        Breach information to include in the alert::

            {
                "honeypot_id":   "uuid-string",           # required
                "category":      "decoy_password",         # required
                "provider":      "vault",                  # optional
                "triggered_at":  "2026-04-07T01:30:00Z",   # required
                "triggered_ip":  "203.0.113.42",           # optional
                "severity":      "critical",               # optional (critical|high|medium|low)
            }

    smtp_host : str
        Override SMTP server (default: env SMTP_HOST or smtp.gmail.com).
    smtp_port : int
        Override SMTP port (default: env SMTP_PORT or 587).
    smtp_email : str
        Override sender email (default: env SMTP_EMAIL).
    smtp_password : str
        Override sender password (default: env SMTP_PASSWORD).
    smtp_from_name : str
        Override sender display name (default: env SMTP_FROM_NAME).
    smtp_use_tls : bool
        Whether to use STARTTLS (default: True).
    smtp_timeout : int
        Connection timeout in seconds (default: env SMTP_TIMEOUT or 30).
    skip_rate_limit : bool
        Bypass rate limiting (use for critical/emergency alerts only).

    Returns
    -------
    dict
        Result of the operation::

            {
                "success":     True/False,
                "alert_id":    "uuid-string",
                "message_id":  "email-message-id" or None,
                "recipient":   "sha256-hash-of-email (first 12 chars)",
                "timestamp":   "ISO 8601 UTC timestamp",
                "error":       None or "error description",
                "retries":     0,
            }

    Security
    --------
    - Raw email addresses are NEVER logged — only a truncated SHA-256 hash.
    - SMTP credentials are read from env vars and never stored in memory
      beyond the function scope.
    - Rate limiting prevents alert flooding attacks.
    """
    alert_id = str(uuid.uuid4())
    email_hash = hashlib.sha256(recipient_email.lower().encode()).hexdigest()[:12]
    timestamp = datetime.now(timezone.utc).isoformat()

    result: Dict[str, Any] = {
        "success": False,
        "alert_id": alert_id,
        "message_id": None,
        "recipient": email_hash,
        "timestamp": timestamp,
        "error": None,
        "retries": 0,
    }

    # ---- Validation ----
    if not recipient_email or "@" not in recipient_email:
        result["error"] = "Invalid recipient email address."
        logger.warning("Alert %s: invalid email (hash: %s).", alert_id, email_hash)
        return result

    sender = smtp_email or SMTP_EMAIL
    password = smtp_password or SMTP_PASSWORD
    if not sender or not password:
        result["error"] = (
            "SMTP credentials not configured. "
            "Set SMTP_EMAIL and SMTP_PASSWORD environment variables."
        )
        logger.error("Alert %s: SMTP credentials missing.", alert_id)
        return result

    # ---- Rate limiting ----
    if not skip_rate_limit and not _rate_limiter.is_allowed(recipient_email):
        result["error"] = (
            f"Rate limit exceeded for this user. "
            f"Max {ALERT_RATE_LIMIT} alerts per hour."
        )
        logger.warning(
            "Alert %s: rate limit hit for user (hash: %s), remaining: 0.",
            alert_id, email_hash,
        )
        return result

    # ---- Build email content ----
    from_name = smtp_from_name or SMTP_FROM_NAME
    severity = str(breach_details.get("severity", "critical")).upper()
    subject = f"🚨 [{severity}] Security Breach Detected — Abhedya Vault"

    html_body = _build_alert_html(recipient_name, breach_details, alert_id)
    plain_body = _build_alert_plaintext(recipient_name, breach_details, alert_id)

    # ---- Send with retries ----
    last_error: Optional[Exception] = None

    for attempt in range(1, MAX_RETRIES + 1):
        server: Optional[smtplib.SMTP] = None
        try:
            server = _create_smtp_connection(
                host=smtp_host,
                port=smtp_port,
                email=sender,
                password=password,
                use_tls=smtp_use_tls,
                timeout=smtp_timeout,
            )

            message_id = _send_email(
                server=server,
                sender_email=sender,
                sender_name=from_name,
                recipient_email=recipient_email,
                subject=subject,
                html_body=html_body,
                plain_body=plain_body,
                alert_id=alert_id,
            )

            result["success"] = True
            result["message_id"] = message_id
            result["retries"] = attempt - 1

            _rate_limiter.record(recipient_email)

            logger.info(
                "✅ Alert %s sent successfully to user (hash: %s) on attempt %d.",
                alert_id, email_hash, attempt,
            )
            return result

        except smtplib.SMTPAuthenticationError as exc:
            # Don't retry auth failures — credentials are wrong.
            result["error"] = (
                "SMTP authentication failed. Check SMTP_EMAIL and SMTP_PASSWORD. "
                "For Gmail, use an App Password (not your regular password)."
            )
            logger.error("Alert %s: SMTP auth failed: %s", alert_id, exc)
            return result

        except (smtplib.SMTPException, OSError, ConnectionError) as exc:
            last_error = exc
            result["retries"] = attempt
            logger.warning(
                "Alert %s: attempt %d/%d failed: %s",
                alert_id, attempt, MAX_RETRIES, exc,
            )
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF * attempt)

        except Exception as exc:
            last_error = exc
            logger.error(
                "Alert %s: unexpected error: %s", alert_id, exc, exc_info=True,
            )
            break

        finally:
            if server:
                try:
                    server.quit()
                except Exception:
                    pass

    result["error"] = f"Failed after {MAX_RETRIES} attempts: {type(last_error).__name__}: {last_error}"
    logger.error("Alert %s: all retries exhausted. Last error: %s", alert_id, last_error)
    return result


def send_batch_alerts(
    alerts: List[Dict[str, Any]],
    *,
    smtp_host: str = "",
    smtp_port: int = 0,
    smtp_email: str = "",
    smtp_password: str = "",
    smtp_from_name: str = "",
    smtp_use_tls: bool = True,
    smtp_timeout: int = 0,
    skip_rate_limit: bool = False,
) -> Dict[str, Any]:
    """Send breach alerts to multiple users in a single SMTP session.

    More efficient than calling ``send_breach_alert()`` in a loop because
    it reuses one SMTP connection for all emails.

    Parameters
    ----------
    alerts : list[dict]
        List of alert dicts, each containing::

            {
                "recipient_email": "user@example.com",
                "recipient_name":  "Display Name",
                "breach_details":  {...}  # same as send_breach_alert()
            }

    (Other parameters are the same as ``send_breach_alert()``.)

    Returns
    -------
    dict
        Batch result::

            {
                "total":      5,
                "sent":       4,
                "failed":     1,
                "rate_limited": 0,
                "results":    [...]  # individual result dicts
            }
    """
    batch_result: Dict[str, Any] = {
        "total": len(alerts),
        "sent": 0,
        "failed": 0,
        "rate_limited": 0,
        "results": [],
    }

    if not alerts:
        return batch_result

    sender = smtp_email or SMTP_EMAIL
    password = smtp_password or SMTP_PASSWORD
    from_name = smtp_from_name or SMTP_FROM_NAME

    if not sender or not password:
        error_msg = (
            "SMTP credentials not configured. "
            "Set SMTP_EMAIL and SMTP_PASSWORD environment variables."
        )
        for alert_data in alerts:
            batch_result["results"].append({
                "success": False,
                "alert_id": str(uuid.uuid4()),
                "recipient": hashlib.sha256(
                    alert_data.get("recipient_email", "").lower().encode()
                ).hexdigest()[:12],
                "error": error_msg,
            })
            batch_result["failed"] += 1
        return batch_result

    # Open a single SMTP connection for the batch
    server: Optional[smtplib.SMTP] = None
    try:
        server = _create_smtp_connection(
            host=smtp_host,
            port=smtp_port,
            email=sender,
            password=password,
            use_tls=smtp_use_tls,
            timeout=smtp_timeout,
        )
    except Exception as exc:
        error_msg = f"SMTP connection failed: {type(exc).__name__}: {exc}"
        logger.error("Batch alert: %s", error_msg)
        for alert_data in alerts:
            batch_result["results"].append({
                "success": False,
                "alert_id": str(uuid.uuid4()),
                "recipient": hashlib.sha256(
                    alert_data.get("recipient_email", "").lower().encode()
                ).hexdigest()[:12],
                "error": error_msg,
            })
            batch_result["failed"] += 1
        return batch_result

    try:
        for alert_data in alerts:
            recipient_email = alert_data.get("recipient_email", "")
            recipient_name = alert_data.get("recipient_name", "User")
            breach_details = alert_data.get("breach_details", {})
            alert_id = str(uuid.uuid4())
            email_hash = hashlib.sha256(
                recipient_email.lower().encode()
            ).hexdigest()[:12]

            individual_result: Dict[str, Any] = {
                "success": False,
                "alert_id": alert_id,
                "message_id": None,
                "recipient": email_hash,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": None,
            }

            # Validate
            if not recipient_email or "@" not in recipient_email:
                individual_result["error"] = "Invalid recipient email."
                batch_result["failed"] += 1
                batch_result["results"].append(individual_result)
                continue

            # Rate limit check
            if not skip_rate_limit and not _rate_limiter.is_allowed(recipient_email):
                individual_result["error"] = "Rate limit exceeded."
                batch_result["rate_limited"] += 1
                batch_result["failed"] += 1
                batch_result["results"].append(individual_result)
                continue

            # Build & send
            try:
                severity = str(breach_details.get("severity", "critical")).upper()
                subject = f"🚨 [{severity}] Security Breach Detected — Abhedya Vault"
                html_body = _build_alert_html(recipient_name, breach_details, alert_id)
                plain_body = _build_alert_plaintext(recipient_name, breach_details, alert_id)

                message_id = _send_email(
                    server=server,
                    sender_email=sender,
                    sender_name=from_name,
                    recipient_email=recipient_email,
                    subject=subject,
                    html_body=html_body,
                    plain_body=plain_body,
                    alert_id=alert_id,
                )

                individual_result["success"] = True
                individual_result["message_id"] = message_id
                _rate_limiter.record(recipient_email)
                batch_result["sent"] += 1

                logger.info(
                    "✅ Batch alert %s sent to user (hash: %s).",
                    alert_id, email_hash,
                )

            except Exception as exc:
                individual_result["error"] = f"{type(exc).__name__}: {exc}"
                batch_result["failed"] += 1
                logger.warning(
                    "Batch alert %s failed for user (hash: %s): %s",
                    alert_id, email_hash, exc,
                )

            batch_result["results"].append(individual_result)

    finally:
        try:
            server.quit()
        except Exception:
            pass

    return batch_result


def get_alert_config() -> Dict[str, Any]:
    """Return the current SMTP/alert configuration (without secrets).

    Useful for health-check endpoints and debugging.  SMTP password
    is NEVER exposed — only shows whether it's configured or not.
    """
    return {
        "smtp_host": SMTP_HOST,
        "smtp_port": SMTP_PORT,
        "smtp_email_configured": bool(SMTP_EMAIL),
        "smtp_password_configured": bool(SMTP_PASSWORD),
        "smtp_from_name": SMTP_FROM_NAME,
        "smtp_use_tls": SMTP_USE_TLS,
        "smtp_timeout": SMTP_TIMEOUT,
        "rate_limit_per_hour": ALERT_RATE_LIMIT,
        "max_retries": MAX_RETRIES,
    }


def check_smtp_connection(
    *,
    smtp_host: str = "",
    smtp_port: int = 0,
    smtp_email: str = "",
    smtp_password: str = "",
    smtp_use_tls: bool = True,
    smtp_timeout: int = 0,
) -> Dict[str, Any]:
    """Test SMTP connectivity and authentication without sending an email.

    Returns
    -------
    dict
        Connection test result::

            {
                "connected": True/False,
                "authenticated": True/False,
                "server_banner": "...",
                "tls_enabled": True/False,
                "error": None or "error description"
            }
    """
    result: Dict[str, Any] = {
        "connected": False,
        "authenticated": False,
        "server_banner": None,
        "tls_enabled": False,
        "error": None,
    }

    host = smtp_host or SMTP_HOST
    port = smtp_port or SMTP_PORT
    email = smtp_email or SMTP_EMAIL
    password = smtp_password or SMTP_PASSWORD
    timeout = smtp_timeout or SMTP_TIMEOUT

    if not email or not password:
        result["error"] = "SMTP credentials not configured."
        return result

    server: Optional[smtplib.SMTP] = None
    try:
        server = smtplib.SMTP(host, port, timeout=timeout)
        server.ehlo()
        result["connected"] = True

        if smtp_use_tls:
            context = ssl.create_default_context()
            server.starttls(context=context)
            server.ehlo()
            result["tls_enabled"] = True

        server.login(email, password)
        result["authenticated"] = True

    except smtplib.SMTPAuthenticationError as exc:
        result["connected"] = True
        result["error"] = f"Authentication failed: {exc}"

    except (smtplib.SMTPException, OSError, ConnectionError) as exc:
        result["error"] = f"Connection failed: {type(exc).__name__}: {exc}"

    except Exception as exc:
        result["error"] = f"Unexpected error: {type(exc).__name__}: {exc}"

    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass

    return result


# ============================================================================
#  5. CLI ENTRY POINT (standalone testing)
# ============================================================================

if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s | %(name)s | %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Abhedya Honeypot Breach Alert API — Standalone Testing"
    )
    sub = parser.add_subparsers(dest="command")

    # -- test-connection --
    sub.add_parser("test-connection", help="Test SMTP connectivity")

    # -- send-test --
    send_parser = sub.add_parser("send-test", help="Send a test alert email")
    send_parser.add_argument(
        "--to", type=str, required=True,
        help="Recipient email address",
    )
    send_parser.add_argument(
        "--name", type=str, default="Test User",
        help="Recipient display name",
    )

    # -- config --
    sub.add_parser("config", help="Show current SMTP configuration")

    args = parser.parse_args()

    if args.command == "test-connection":
        print("\n  Testing SMTP connection to Gmail...\n")
        result = check_smtp_connection()
        for key, value in result.items():
            icon = "✅" if value is True else ("❌" if value is False else "  ")
            print(f"  {icon} {key}: {value}")
        print()
        sys.exit(0 if result["authenticated"] else 1)

    elif args.command == "send-test":
        print(f"\n  Sending test breach alert to {args.to}...\n")
        result = send_breach_alert(
            recipient_email=args.to,
            recipient_name=args.name,
            breach_details={
                "honeypot_id": str(uuid.uuid4()),
                "category": "decoy_password",
                "provider": "vault",
                "triggered_at": datetime.now(timezone.utc).isoformat(),
                "triggered_ip": "203.0.113.42",
                "severity": "critical",
            },
            skip_rate_limit=True,
        )
        for key, value in result.items():
            icon = "✅" if value is True else ("❌" if value is False else "  ")
            print(f"  {icon} {key}: {value}")
        print()
        sys.exit(0 if result["success"] else 1)

    elif args.command == "config":
        print("\n  Current SMTP Configuration:\n")
        config = get_alert_config()
        for key, value in config.items():
            print(f"    {key}: {value}")
        print()

    else:
        parser.print_help()
        sys.exit(1)
