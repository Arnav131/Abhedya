"""
auditor.py — Heuristic Secret Identification Engine

Pure Python string analysis (O(1) complexity).
Detects developer tokens, API keys, legacy hashes, and weak passwords.
Returns a structured risk profile JSON.

IMPORTANT: This module NEVER persists any data. Analysis is ephemeral.
"""

import re
import math
import os
import string
from dataclasses import dataclass, field, asdict
from typing import List, Optional

try:
    from .pytorch_model import predict_strength_detailed, get_model_runtime_info
except Exception:  # pragma: no cover
    # Keep auditor resilient even if model deps are missing.
    predict_strength_detailed = None  # type: ignore[assignment]
    get_model_runtime_info = None  # type: ignore[assignment]


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


# Keep runtime model diagnostics off in public responses by default.
EXPOSE_MODEL_RUNTIME_DETAILS = _as_bool(
    os.getenv("ABHEDYA_EXPOSE_MODEL_RUNTIME_DETAILS", "false")
)


@dataclass
class RiskProfile:
    """Structured audit result."""
    identified_type: str = "Unknown"
    risk_level: str = "info"          # "critical" | "warning" | "info" | "safe"
    risk_score: int = 50              # 0–100 (100 = maximum risk)
    recommendations: List[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


# ════════════════════════════════════════════
# Entropy calculation
# ════════════════════════════════════════════

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in prob.values())


def _char_classes(s: str) -> List[str]:
    """Identify character classes present in a string."""
    classes = []
    if any(c in string.ascii_lowercase for c in s):
        classes.append("lowercase")
    if any(c in string.ascii_uppercase for c in s):
        classes.append("uppercase")
    if any(c in string.digits for c in s):
        classes.append("digits")
    if any(c in string.punctuation for c in s):
        classes.append("special")
    if any(c in string.whitespace for c in s):
        classes.append("whitespace")
    return classes


def _is_hex(s: str) -> bool:
    """Check if string is a valid hexadecimal string."""
    return bool(re.fullmatch(r'[0-9a-fA-F]+', s))


# ════════════════════════════════════════════
# Token / Key Detectors
# ════════════════════════════════════════════

def _detect_jwt(s: str) -> Optional[RiskProfile]:
    """Detect JSON Web Tokens (eyJ... pattern with 2 dots)."""
    s_stripped = s.strip()
    if s_stripped.startswith("eyJ") and s_stripped.count(".") == 2:
        parts = s_stripped.split(".")
        if all(len(p) > 0 for p in parts):
            return RiskProfile(
                identified_type="JSON Web Token (JWT)",
                risk_level="critical",
                risk_score=92,
                recommendations=[
                    "JWTs should never be stored as static secrets.",
                    "Rotate the signing key if this token grants elevated access.",
                    "Use short-lived tokens with refresh token rotation.",
                ],
                details={
                    "prefix_match": "eyJ",
                    "parts": 3,
                    "header_length": len(parts[0]),
                    "payload_length": len(parts[1]),
                },
            )
    return None


def _detect_aws_access_key(s: str) -> Optional[RiskProfile]:
    """Detect AWS IAM Access Key (AKIA prefix, 20 chars)."""
    s_stripped = s.strip()
    if re.fullmatch(r'AKIA[0-9A-Z]{16}', s_stripped):
        return RiskProfile(
            identified_type="AWS IAM Access Key",
            risk_level="critical",
            risk_score=98,
            recommendations=[
                "Rotate this key IMMEDIATELY in the AWS IAM console.",
                "Use IAM roles or temporary credentials (STS) instead.",
                "Enable MFA on the associated IAM user.",
                "Check CloudTrail for unauthorized usage.",
            ],
            details={"prefix_match": "AKIA", "length": len(s_stripped)},
        )
    return None


def _detect_aws_secret_key(s: str) -> Optional[RiskProfile]:
    """Detect AWS Secret Access Key (40-char base64-ish)."""
    s_stripped = s.strip()
    if re.fullmatch(r'[A-Za-z0-9/+=]{40}', s_stripped):
        entropy = _shannon_entropy(s_stripped)
        if entropy > 4.0:
            return RiskProfile(
                identified_type="Possible AWS Secret Access Key",
                risk_level="critical",
                risk_score=95,
                recommendations=[
                    "Rotate the corresponding AWS access key pair.",
                    "Never store AWS secrets in plaintext.",
                ],
                details={"length": 40, "entropy": round(entropy, 2)},
            )
    return None


def _detect_github_token(s: str) -> Optional[RiskProfile]:
    """Detect GitHub tokens (ghp_, gho_, ghs_, github_pat_ prefixes)."""
    s_stripped = s.strip()
    prefixes = {
        "ghp_": "GitHub Personal Access Token",
        "gho_": "GitHub OAuth Token",
        "ghs_": "GitHub Server-to-Server Token",
        "github_pat_": "GitHub Fine-Grained PAT",
    }
    for prefix, name in prefixes.items():
        if s_stripped.startswith(prefix) and len(s_stripped) > len(prefix) + 10:
            return RiskProfile(
                identified_type=name,
                risk_level="critical",
                risk_score=96,
                recommendations=[
                    f"Revoke this token at github.com/settings/tokens.",
                    "Use fine-grained PATs with minimal scope.",
                    "Set an expiration date on all GitHub tokens.",
                ],
                details={"prefix_match": prefix, "length": len(s_stripped)},
            )
    return None


def _detect_stripe_key(s: str) -> Optional[RiskProfile]:
    """Detect Stripe API keys."""
    s_stripped = s.strip()
    prefixes = {
        "sk_live_": "Stripe Live Secret Key",
        "pk_live_": "Stripe Live Publishable Key",
        "rk_live_": "Stripe Live Restricted Key",
        "sk_test_": "Stripe Test Secret Key",
        "pk_test_": "Stripe Test Publishable Key",
    }
    for prefix, name in prefixes.items():
        if s_stripped.startswith(prefix) and len(s_stripped) > len(prefix) + 10:
            is_live = "live" in prefix
            return RiskProfile(
                identified_type=name,
                risk_level="critical" if is_live else "warning",
                risk_score=97 if is_live else 40,
                recommendations=[
                    "Roll this key in the Stripe Dashboard immediately." if is_live
                    else "Test keys are lower risk but should still be protected.",
                    "Use restricted keys with minimal permissions.",
                ],
                details={"prefix_match": prefix, "is_live": is_live},
            )
    return None


def _detect_slack_token(s: str) -> Optional[RiskProfile]:
    """Detect Slack tokens."""
    s_stripped = s.strip()
    prefixes = {
        "xoxb-": "Slack Bot Token",
        "xoxp-": "Slack User Token",
        "xoxs-": "Slack Session Token",
        "xoxa-": "Slack App Token",
    }
    for prefix, name in prefixes.items():
        if s_stripped.startswith(prefix):
            return RiskProfile(
                identified_type=name,
                risk_level="critical",
                risk_score=90,
                recommendations=[
                    "Regenerate this token in the Slack API dashboard.",
                    "Use minimal OAuth scopes.",
                ],
                details={"prefix_match": prefix, "length": len(s_stripped)},
            )
    return None


def _detect_generic_api_key(s: str) -> Optional[RiskProfile]:
    """Detect generic API keys by common prefixes."""
    s_stripped = s.strip()
    prefixes = {
        "sk-": "OpenAI / Generic API Key",
        "key-": "Generic API Key",
        "api_": "Generic API Key",
        "apikey_": "Generic API Key",
        "bearer ": "Bearer Token",
    }
    for prefix, name in prefixes.items():
        if s_stripped.lower().startswith(prefix) and len(s_stripped) > 20:
            return RiskProfile(
                identified_type=name,
                risk_level="warning",
                risk_score=70,
                recommendations=[
                    "Verify if this is a production key and rotate if exposed.",
                    "Store API keys in environment variables, not in vaults meant for passwords.",
                ],
                details={"prefix_match": prefix, "length": len(s_stripped)},
            )
    return None


# ════════════════════════════════════════════
# Hash Detectors
# ════════════════════════════════════════════

def _detect_hash(s: str) -> Optional[RiskProfile]:
    """Detect common hash formats by length and hex pattern."""
    s_stripped = s.strip()

    if not _is_hex(s_stripped):
        # Check bcrypt
        if re.match(r'^\$2[aby]\$\d{2}\$', s_stripped) and len(s_stripped) == 60:
            return RiskProfile(
                identified_type="bcrypt Hash",
                risk_level="safe",
                risk_score=10,
                recommendations=[
                    "bcrypt is a strong hashing algorithm. This is safe to store.",
                ],
                details={"algorithm": "bcrypt", "length": 60},
            )
        # Check argon2
        if s_stripped.startswith("$argon2"):
            return RiskProfile(
                identified_type="Argon2 Hash",
                risk_level="safe",
                risk_score=5,
                recommendations=[
                    "Argon2 is the gold standard for password hashing. Excellent.",
                ],
                details={"algorithm": "argon2", "length": len(s_stripped)},
            )
        return None

    hash_types = {
        32: ("MD5 Hash", "critical", 90, [
            "MD5 is cryptographically broken — collisions are trivial.",
            "If this is a password hash, rehash with bcrypt or Argon2 immediately.",
            "If used for integrity checks, migrate to SHA-256.",
        ]),
        40: ("SHA-1 Hash", "critical", 85, [
            "SHA-1 is deprecated — practical collision attacks exist.",
            "Migrate to SHA-256 or SHA-3 for security-sensitive applications.",
        ]),
        64: ("SHA-256 Hash", "info", 30, [
            "SHA-256 is cryptographically strong for integrity checks.",
            "For password storage, prefer bcrypt/Argon2 over raw SHA-256.",
        ]),
        128: ("SHA-512 Hash", "info", 25, [
            "SHA-512 is strong. Ensure proper salting if used for passwords.",
        ]),
    }

    length = len(s_stripped)
    if length in hash_types:
        name, level, score, recs = hash_types[length]
        return RiskProfile(
            identified_type=name,
            risk_level=level,
            risk_score=score,
            recommendations=recs,
            details={
                "algorithm": name.split()[0],
                "length": length,
                "entropy": round(_shannon_entropy(s_stripped), 2),
            },
        )
    return None


# ════════════════════════════════════════════
# Password Strength Analysis
# ════════════════════════════════════════════

def _analyze_password_strength(s: str) -> RiskProfile:
    """Fallback analysis: treat as a password and assess strength."""
    entropy = _shannon_entropy(s)
    length = len(s)
    classes = _char_classes(s)
    num_classes = len(classes)

    # Common weak passwords check
    common_weak = [
        "password", "123456", "qwerty", "admin", "letmein",
        "welcome", "monkey", "dragon", "master", "login",
    ]
    if s.lower().strip() in common_weak:
        return RiskProfile(
            identified_type="Common Weak Password",
            risk_level="critical",
            risk_score=99,
            recommendations=[
                "This password appears in common breach databases.",
                "Change to a unique passphrase with 16+ characters.",
            ],
            details={"length": length, "entropy": round(entropy, 2), "common_match": True},
        )

    # Scoring
    score = 0  # Higher = stronger

    # Length scoring
    if length >= 20:
        score += 40
    elif length >= 16:
        score += 30
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 10
    else:
        score -= 10

    # Entropy scoring
    if entropy >= 4.0:
        score += 30
    elif entropy >= 3.5:
        score += 20
    elif entropy >= 3.0:
        score += 10

    # Character class scoring
    score += num_classes * 8

    # Clamp into a stable range for downstream risk mapping.
    strength_score = max(0, min(100, score))

    # Determine risk
    if score >= 55:
        return RiskProfile(
            identified_type="Strong Password / Secret",
            risk_level="safe",
            risk_score=max(5, min(30, 100 - strength_score)),
            recommendations=[
                "This looks like a strong secret. Safe to store.",
            ],
            details={
                "length": length,
                "entropy": round(entropy, 2),
                "char_classes": classes,
                "strength_score": strength_score,
            },
        )
    elif score >= 30:
        return RiskProfile(
            identified_type="Moderate Password",
            risk_level="warning",
            risk_score=max(30, min(74, 100 - strength_score)),
            recommendations=[
                "Consider using a longer passphrase (16+ characters).",
                "Add more character variety (uppercase, digits, symbols).",
            ],
            details={
                "length": length,
                "entropy": round(entropy, 2),
                "char_classes": classes,
                "strength_score": strength_score,
            },
        )
    else:
        return RiskProfile(
            identified_type="Weak Password",
            risk_level="critical",
            risk_score=max(75, min(100, 100 - strength_score)),
            recommendations=[
                "This password is dangerously weak.",
                "Use a passphrase with 16+ characters mixing letters, digits, and symbols.",
                "Consider using a password generator.",
            ],
            details={
                "length": length,
                "entropy": round(entropy, 2),
                "char_classes": classes,
                "strength_score": strength_score,
            },
        )


def _analyze_password_with_model(s: str) -> Optional[RiskProfile]:
    """Run ML-backed password predictability analysis when available.

    Returns None if model inference is unavailable, allowing graceful
    fallback to heuristic-only scoring.
    """
    if predict_strength_detailed is None:
        return None

    try:
        ml = predict_strength_detailed(s)
    except Exception:
        return None

    model_score = float(ml.get("score", 0.5))
    model_label = str(ml.get("label", "medium")).lower()
    entropy_score = float(ml.get("entropy_score", 0.5))
    runtime = {}
    if EXPOSE_MODEL_RUNTIME_DETAILS and get_model_runtime_info is not None:
        try:
            runtime = get_model_runtime_info()
        except Exception:
            runtime = {}

    model_kind = str(runtime.get("model_kind", ml.get("model_kind", "unknown")))
    model_device = str(runtime.get("device", ml.get("device", "unknown")))
    model_weights_path = str(runtime.get("weights_path", ml.get("weights_path", "")))
    model_weights_file = str(runtime.get("weights_file", ml.get("weights_file", "")))
    model_loaded = bool(runtime.get("model_loaded", ml.get("model_loaded", False)))
    weights_found = bool(runtime.get("weights_found", ml.get("weights_found", False)))
    engine = "pytorch_model"
    risk_score = max(0, min(100, int(round(model_score * 100))))

    model_details = {
        "model_label": model_label,
        "model_predictability": round(model_score, 4),
        "entropy_score": round(entropy_score, 4),
        "length": len(s),
        "engine": engine,
    }

    if EXPOSE_MODEL_RUNTIME_DETAILS:
        model_details.update(
            {
                "model_kind": model_kind,
                "model_device": model_device,
                "model_weights_file": model_weights_file,
                "model_weights_path": model_weights_path,
                "model_loaded": model_loaded,
                "weights_found": weights_found,
            }
        )

    if model_label == "weak":
        return RiskProfile(
            identified_type="Weak Password (AI Model)",
            risk_level="critical",
            risk_score=max(75, risk_score),
            recommendations=[
                "This secret is highly predictable according to the trained model.",
                "Use a unique passphrase with 16+ characters.",
                "Mix uppercase, lowercase, numbers, and symbols.",
            ],
            details=model_details,
        )

    if model_label == "medium":
        return RiskProfile(
            identified_type="Moderate Password (AI Model)",
            risk_level="warning",
            risk_score=max(35, min(74, risk_score)),
            recommendations=[
                "This secret is moderately predictable.",
                "Increase length and avoid dictionary-like patterns.",
                "Prefer generated passphrases for important accounts.",
            ],
            details=model_details,
        )

    return RiskProfile(
        identified_type="Strong Password / Secret (AI Model)",
        risk_level="safe",
        risk_score=min(30, risk_score),
        recommendations=[
            "This looks statistically strong according to the trained model.",
            "Keep using unique secrets per service.",
        ],
        details=model_details,
    )


# ════════════════════════════════════════════
# Main Analysis Pipeline
# ════════════════════════════════════════════

# Ordered by specificity — most specific detectors first
_DETECTORS = [
    _detect_jwt,
    _detect_aws_access_key,
    _detect_github_token,
    _detect_stripe_key,
    _detect_slack_token,
    _detect_generic_api_key,
    _detect_aws_secret_key,
    _detect_hash,
]


def analyze(secret: str) -> dict:
    """
    Analyze a secret string and return a risk profile.

    Runs through all detectors in order; first match wins.
    Falls back to password strength analysis if no pattern matches.

    Args:
        secret: The raw string to analyze.

    Returns:
        dict: Risk profile with identified_type, risk_level, risk_score,
              recommendations, and details.
    """
    if not secret or not secret.strip():
        return RiskProfile(
            identified_type="Empty Input",
            risk_level="info",
            risk_score=0,
            recommendations=["Please enter a secret to audit."],
        ).to_dict()

    s = secret.strip()

    # Run through specific detectors
    for detector in _DETECTORS:
        result = detector(s)
        if result is not None:
            return result.to_dict()

    # Hybrid password analysis: combine ML + heuristic and keep higher risk.
    heuristic_result = _analyze_password_strength(s)
    ml_result = _analyze_password_with_model(s)

    if ml_result is None:
        return heuristic_result.to_dict()

    chosen = ml_result if ml_result.risk_score >= heuristic_result.risk_score else heuristic_result
    chosen.details = dict(chosen.details)

    merged_details = {
        "analysis_mode": "hybrid_conservative",
        "heuristic_risk_score": heuristic_result.risk_score,
        "ml_risk_score": ml_result.risk_score,
    }

    # Only add ml_* copies when heuristic result won; otherwise those values
    # are already present as direct model_* fields in the chosen details.
    if chosen is heuristic_result:
        merged_details.update(
            {
                "ml_model_label": ml_result.details.get("model_label"),
                "ml_predictability": ml_result.details.get("model_predictability"),
                "ml_entropy_score": ml_result.details.get("entropy_score"),
            }
        )
        if EXPOSE_MODEL_RUNTIME_DETAILS:
            merged_details.update(
                {
                    "ml_model_kind": ml_result.details.get("model_kind"),
                    "ml_model_device": ml_result.details.get("model_device"),
                    "ml_weights_file": ml_result.details.get("model_weights_file"),
                    "ml_weights_path": ml_result.details.get("model_weights_path"),
                    "ml_model_loaded": ml_result.details.get("model_loaded"),
                    "ml_weights_found": ml_result.details.get("weights_found"),
                }
            )

    chosen.details.update(merged_details)

    return chosen.to_dict()
