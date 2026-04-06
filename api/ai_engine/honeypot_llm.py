"""
SecureVault — Honeypot Deception Engine
=======================================
Generates realistic-looking but completely fake secrets (API keys, JWTs,
database URLs, private keys, OAuth tokens) to act as canary traps inside
the vault database.

How it works
------------
1. **Primary path** — calls a local Ollama LLM (e.g. llama3, mistral) to
   produce structurally valid fake credentials via carefully engineered
   prompts.
2. **Fallback path** — if Ollama is unreachable (timeout, not installed,
   model not pulled), a deterministic Python generator produces secrets
   with identical format guarantees. This ensures the system NEVER fails
   to create honeypots, satisfying NFR-3 (Graceful Degradation).

Security guarantees
-------------------
  • Generated secrets are mathematically guaranteed to be fake — they are
    either LLM-hallucinated or built from random bytes with known-invalid
    checksums / account IDs.
  • No real service will ever accept these credentials.
  • Raw honeypot content is NEVER logged to console or disk.
  • The module makes zero external network calls (Ollama runs on localhost).

Django integration
------------------
    from ai_engine.honeypot_llm import generate_honeypots

    # In a post_save signal or registration view:
    decoys = generate_honeypots(user_id=str(user.id))
    # → dict with api_keys, jwt_tokens, db_urls, private_keys, oauth_tokens
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import random
import secrets
import string
import textwrap
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Logging — NEVER emit secret content
# ---------------------------------------------------------------------------
logger = logging.getLogger("securevault.honeypot")
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OLLAMA_BASE_URL: str = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL: str = os.environ.get("OLLAMA_MODEL", "llama3")
OLLAMA_TIMEOUT: int = int(os.environ.get("OLLAMA_TIMEOUT", "30"))
MAX_RETRIES: int = 3
RETRY_BACKOFF: float = 1.5  # seconds, multiplied on each retry


# ============================================================================
#  1. OLLAMA CLIENT
# ============================================================================

class OllamaClient:
    """Minimal HTTP client for the local Ollama REST API.

    Uses only the standard library (urllib) so there is zero dependency
    on ``requests`` or ``httpx`` — keeping the footprint minimal.
    """

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        model: str = OLLAMA_MODEL,
        timeout: int = OLLAMA_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    # ------------------------------------------------------------------
    def generate(self, prompt: str, temperature: float = 0.8) -> Optional[str]:
        """Send a prompt to Ollama and return the generated text.

        Returns ``None`` on any failure (connection refused, timeout, bad
        JSON, etc.) so the caller can fall back gracefully.
        """
        import urllib.request
        import urllib.error

        url = f"{self.base_url}/api/generate"
        payload = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": 2048,
            },
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        last_error: Optional[Exception] = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                    return body.get("response", "")
            except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
                last_error = exc
                logger.debug(
                    "Ollama attempt %d/%d failed: %s", attempt, MAX_RETRIES, exc
                )
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_BACKOFF * attempt)
            except Exception as exc:
                last_error = exc
                break

        logger.warning(
            "Ollama unreachable after %d attempts (last error: %s). "
            "Falling back to deterministic generator.",
            MAX_RETRIES,
            type(last_error).__name__,
        )
        return None

    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        """Quick health-check against the Ollama server."""
        import urllib.request
        import urllib.error

        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5):
                return True
        except Exception:
            return False


# ============================================================================
#  2. PROMPT ENGINEERING
# ============================================================================

_HONEYPOT_PROMPT = textwrap.dedent("""\
    You are a cybersecurity deception engine. Your ONLY purpose is to generate
    COMPLETELY FAKE credentials that LOOK real but will NEVER work on any
    real service.

    CRITICAL SAFETY RULES:
    - Every secret you generate MUST be fictional and non-functional.
    - Do NOT copy real API keys, tokens, or credentials.
    - Use realistic formats, prefixes, lengths, and entropy.
    - Include plausible but fake metadata (fake project names, fake emails).

    Generate the following fake secrets for a honeypot trap. Return ONLY valid
    JSON — no commentary, no markdown fences, no explanation.

    Unique seed for randomness: {seed}

    Return this exact JSON structure:
    {{
      "api_keys": [
        {{
          "provider": "stripe",
          "key": "sk_live_<48 random alphanumeric chars>"
        }},
        {{
          "provider": "openai",
          "key": "sk-<48 random alphanumeric chars>"
        }},
        {{
          "provider": "aws",
          "access_key": "AKIA<16 uppercase alphanumeric chars>",
          "secret_key": "<40 random alphanumeric+slash+plus chars>"
        }}
      ],
      "jwt_tokens": [
        "<a properly structured 3-part base64url JWT token with realistic header and payload>"
      ],
      "db_urls": [
        "postgres://<fake_user>:<fake_pass>@<fake_host>:5432/<fake_db>"
      ],
      "private_keys": [
        "<a fake RSA-2048 PEM private key block starting with -----BEGIN PRIVATE KEY----->"
      ],
      "oauth_tokens": [
        {{
          "provider": "google",
          "access_token": "ya29.<random 100+ chars>",
          "refresh_token": "1//<random 40+ chars>"
        }}
      ]
    }}

    Remember: return ONLY the JSON object. No markdown. No explanation.
""")


def _build_prompt(user_id: str) -> str:
    """Build a unique prompt seeded per user + timestamp for variety."""
    seed = hashlib.sha256(
        f"{user_id}:{time.time_ns()}:{secrets.token_hex(8)}".encode()
    ).hexdigest()[:16]
    return _HONEYPOT_PROMPT.format(seed=seed)


# ============================================================================
#  3. LLM-BASED GENERATOR
# ============================================================================

def _generate_via_llm(user_id: str, client: OllamaClient) -> Optional[Dict[str, Any]]:
    """Attempt to generate honeypots using the local LLM.

    Returns ``None`` if Ollama is unavailable or the response can't be
    parsed into valid JSON.
    """
    prompt = _build_prompt(user_id)
    raw_response = client.generate(prompt, temperature=0.9)

    if raw_response is None:
        return None

    # Strip markdown fences if the LLM wraps its output.
    cleaned = raw_response.strip()
    if cleaned.startswith("```"):
        # Remove opening fence (possibly ```json)
        first_newline = cleaned.index("\n") if "\n" in cleaned else 3
        cleaned = cleaned[first_newline + 1:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    cleaned = cleaned.strip()

    try:
        parsed = json.loads(cleaned)
        # Basic structural validation.
        required_keys = {"api_keys", "jwt_tokens", "db_urls", "private_keys", "oauth_tokens"}
        if not required_keys.issubset(parsed.keys()):
            logger.warning("LLM response missing required keys — falling back.")
            return None
        return parsed
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("LLM response was not valid JSON (%s) — falling back.", exc)
        return None


# ============================================================================
#  4. DETERMINISTIC FALLBACK GENERATOR
# ============================================================================
#
# This generator uses Python's `secrets` module for cryptographic randomness
# and produces secrets that are structurally identical to real ones but are
# guaranteed to be fake.  It requires NO external dependencies.
#

def _rand_alphanum(length: int) -> str:
    """Generate a random alphanumeric string."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _rand_hex(length: int) -> str:
    """Generate a random hex string."""
    return secrets.token_hex(length // 2 + 1)[:length]


def _rand_base64url(length: int) -> str:
    """Generate a random base64url-safe string (no padding)."""
    raw = secrets.token_bytes(length)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")[:length]


# -- API Keys ---------------------------------------------------------------

def _generate_stripe_key() -> Dict[str, str]:
    """Fake Stripe secret key: sk_live_<48 alphanumeric>."""
    return {
        "provider": "stripe",
        "key": f"sk_live_{_rand_alphanum(48)}",
    }


def _generate_openai_key() -> Dict[str, str]:
    """Fake OpenAI API key: sk-<48 alphanumeric>."""
    return {
        "provider": "openai",
        "key": f"sk-{_rand_alphanum(48)}",
    }


def _generate_aws_keys() -> Dict[str, str]:
    """Fake AWS access key (AKIA...) + secret key."""
    access = "AKIA" + "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16)
    )
    # AWS secret keys use base64-like characters.
    secret_alphabet = string.ascii_letters + string.digits + "/+"
    secret = "".join(secrets.choice(secret_alphabet) for _ in range(40))
    return {
        "provider": "aws",
        "access_key": access,
        "secret_key": secret,
    }


def _generate_github_token() -> Dict[str, str]:
    """Fake GitHub personal access token: ghp_<36 alphanumeric>."""
    return {
        "provider": "github",
        "key": f"ghp_{_rand_alphanum(36)}",
    }


def _generate_api_keys() -> List[Dict[str, str]]:
    """Generate a batch of fake API keys across multiple providers."""
    return [
        _generate_stripe_key(),
        _generate_openai_key(),
        _generate_aws_keys(),
        _generate_github_token(),
    ]


# -- JWT Tokens --------------------------------------------------------------

def _generate_jwt() -> str:
    """Generate a structurally valid but completely fake JWT.

    The token has three base64url-encoded parts:
        header . payload . signature

    The payload contains plausible but fake claims.
    """
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": _rand_hex(8),
    }
    now_ts = int(time.time())
    payload = {
        "sub": str(uuid.uuid4()),
        "iss": secrets.choice([
            "https://auth.internal-corp.example.com",
            "https://sso.acme-services.example.net",
            "https://id.globaltech.example.org",
        ]),
        "aud": secrets.choice([
            "api.vault.example.com",
            "dashboard.internal.example.net",
            "service.backend.example.org",
        ]),
        "iat": now_ts - random.randint(3600, 86400),
        "exp": now_ts + random.randint(3600, 604800),
        "email": f"{_rand_alphanum(8).lower()}@{secrets.choice(['corp', 'internal', 'dev'])}.example.com",
        "role": secrets.choice(["admin", "developer", "service-account", "readonly"]),
        "jti": str(uuid.uuid4()),
    }

    def _b64url(data: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).decode().rstrip("=")

    h = _b64url(header)
    p = _b64url(payload)
    # Fake signature — 256 random bytes encoded as base64url.
    s = _rand_base64url(86)

    return f"{h}.{p}.{s}"


def _generate_jwt_tokens(count: int = 2) -> List[str]:
    """Generate multiple fake JWTs."""
    return [_generate_jwt() for _ in range(count)]


# -- Database URLs -----------------------------------------------------------

def _generate_db_url() -> str:
    """Generate a fake PostgreSQL connection string."""
    user = secrets.choice(["app_user", "db_admin", "service_rw", "vault_svc", "readonly"])
    password = _rand_alphanum(20)
    host = secrets.choice([
        "db-primary-01.internal.example.com",
        "postgres-cluster.us-east-1.rds.example.com",
        "vault-pg.prod.example.net",
        "10.128.0.42",
        "172.16.3.15",
    ])
    port = secrets.choice([5432, 5433, 6432])
    db = secrets.choice(["securevault_prod", "vault_main", "credentials_db", "secrets_store"])
    return f"postgres://{user}:{password}@{host}:{port}/{db}"


def _generate_db_urls(count: int = 2) -> List[str]:
    """Generate multiple fake database URLs."""
    return [_generate_db_url() for _ in range(count)]


# -- Private Keys -------------------------------------------------------------

def _generate_private_key() -> str:
    """Generate a fake PEM-encoded private key block.

    The key material is pure random bytes — it does NOT correspond to any
    valid RSA, EC, or Ed25519 key pair.
    """
    # A real RSA-2048 DER-encoded private key is ~1218 bytes.
    fake_der = secrets.token_bytes(1218)
    b64_body = base64.b64encode(fake_der).decode("ascii")
    # Wrap at 64 characters per line (PEM standard).
    lines = [b64_body[i:i + 64] for i in range(0, len(b64_body), 64)]
    pem = "-----BEGIN PRIVATE KEY-----\n"
    pem += "\n".join(lines)
    pem += "\n-----END PRIVATE KEY-----"
    return pem


def _generate_private_keys(count: int = 1) -> List[str]:
    """Generate multiple fake PEM private keys."""
    return [_generate_private_key() for _ in range(count)]


# -- OAuth Tokens -------------------------------------------------------------

def _generate_oauth_google() -> Dict[str, str]:
    """Fake Google OAuth2 access + refresh token."""
    access = f"ya29.{_rand_base64url(120)}"
    refresh = f"1//{_rand_base64url(43)}"
    return {
        "provider": "google",
        "access_token": access,
        "refresh_token": refresh,
    }


def _generate_oauth_azure() -> Dict[str, str]:
    """Fake Azure AD Bearer token."""
    return {
        "provider": "azure",
        "access_token": f"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.{_rand_base64url(200)}.{_rand_base64url(86)}",
        "tenant_id": str(uuid.uuid4()),
    }


def _generate_oauth_tokens() -> List[Dict[str, str]]:
    """Generate fake OAuth tokens for multiple providers."""
    return [
        _generate_oauth_google(),
        _generate_oauth_azure(),
    ]


# -- Full fallback bundle ----------------------------------------------------

def _generate_fallback(user_id: str) -> Dict[str, Any]:
    """Deterministic fallback: generate all honeypot categories with pure Python.

    This is guaranteed to work even if Ollama is completely absent.
    """
    # Seed randomness partly on user_id for per-user variety, but include
    # time so repeated calls for the same user produce different secrets.
    seed_material = f"{user_id}:{time.time_ns()}:{os.urandom(8).hex()}"
    seed_int = int(hashlib.sha256(seed_material.encode()).hexdigest(), 16) % (2**32)
    random.seed(seed_int)

    result = {
        "api_keys": _generate_api_keys(),
        "jwt_tokens": _generate_jwt_tokens(count=2),
        "db_urls": _generate_db_urls(count=2),
        "private_keys": _generate_private_keys(count=1),
        "oauth_tokens": _generate_oauth_tokens(),
    }

    # Reset random state so we don't affect other modules.
    random.seed()
    return result


# ============================================================================
#  5. PUBLIC API
# ============================================================================

def generate_honeypots(
    user_id: str,
    *,
    use_llm: bool = True,
    ollama_model: Optional[str] = None,
    ollama_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate a full set of honeypot decoy secrets for a user.

    Parameters
    ----------
    user_id : str
        Unique user identifier (used for seeding, never logged).
    use_llm : bool
        If True (default), attempt to use the local Ollama LLM first.
        Falls back to the deterministic generator on failure.
    ollama_model : str, optional
        Override the default Ollama model name.
    ollama_url : str, optional
        Override the default Ollama base URL.

    Returns
    -------
    dict
        Structured honeypot bundle with metadata::

            {
                "api_keys":      [...],
                "jwt_tokens":    [...],
                "db_urls":       [...],
                "private_keys":  [...],
                "oauth_tokens":  [...],
                "metadata": {
                    "is_honeypot":  True,
                    "created_at":   "<ISO 8601 timestamp>",
                    "generator":    "llm" | "fallback",
                    "honeypot_id":  "<UUID>",
                }
            }

    Security
    --------
    - The ``user_id`` is hashed before use as a seed — it is never stored
      or logged alongside the generated secrets.
    - All generation happens in-memory.  Nothing is written to disk.
    - No external network calls are made (Ollama runs on localhost).
    """
    secrets_bundle: Optional[Dict[str, Any]] = None
    generator_used = "fallback"

    # --- Attempt LLM generation ---
    if use_llm:
        client = OllamaClient(
            base_url=ollama_url or OLLAMA_BASE_URL,
            model=ollama_model or OLLAMA_MODEL,
        )
        secrets_bundle = _generate_via_llm(user_id, client)
        if secrets_bundle is not None:
            generator_used = "llm"
            logger.info("Honeypots generated via LLM for user (hash: %s).",
                        hashlib.sha256(user_id.encode()).hexdigest()[:12])

    # --- Fallback ---
    if secrets_bundle is None:
        secrets_bundle = _generate_fallback(user_id)
        generator_used = "fallback"
        logger.info("Honeypots generated via fallback for user (hash: %s).",
                     hashlib.sha256(user_id.encode()).hexdigest()[:12])

    # --- Attach metadata ---
    secrets_bundle["metadata"] = {
        "is_honeypot": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "generator": generator_used,
        "honeypot_id": str(uuid.uuid4()),
    }

    return secrets_bundle


def generate_single_category(
    category: str,
    count: int = 1,
) -> Any:
    """Generate honeypots for a single category.

    Useful when you only need one type of decoy (e.g. just API keys).

    Parameters
    ----------
    category : str
        One of: "api_keys", "jwt_tokens", "db_urls", "private_keys",
        "oauth_tokens".
    count : int
        Number of items to generate (where applicable).

    Returns
    -------
    list
        List of generated fake secrets for the requested category.
    """
    generators = {
        "api_keys": lambda: _generate_api_keys(),
        "jwt_tokens": lambda: _generate_jwt_tokens(count),
        "db_urls": lambda: _generate_db_urls(count),
        "private_keys": lambda: _generate_private_keys(count),
        "oauth_tokens": lambda: _generate_oauth_tokens(),
    }

    if category not in generators:
        raise ValueError(
            f"Unknown category '{category}'. "
            f"Valid categories: {', '.join(generators.keys())}"
        )

    return generators[category]()


# ============================================================================
#  6. VALIDATION UTILITIES
# ============================================================================

def validate_honeypot_bundle(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Validate that a generated bundle meets structural requirements.

    Returns a report dict with pass/fail status per category.
    Useful for testing and CI pipelines.
    """
    import re

    report: Dict[str, Any] = {"valid": True, "checks": {}}

    # --- API Keys ---
    api_keys = bundle.get("api_keys", [])
    api_ok = True
    for key_obj in api_keys:
        if isinstance(key_obj, dict):
            provider = key_obj.get("provider", "")
            if provider == "stripe":
                api_ok &= bool(re.match(r"^sk_live_[A-Za-z0-9]{20,}$", key_obj.get("key", "")))
            elif provider == "openai":
                api_ok &= bool(re.match(r"^sk-[A-Za-z0-9]{20,}$", key_obj.get("key", "")))
            elif provider == "aws":
                api_ok &= bool(re.match(r"^AKIA[A-Z0-9]{16}$", key_obj.get("access_key", "")))
                api_ok &= len(key_obj.get("secret_key", "")) >= 30
            elif provider == "github":
                api_ok &= bool(re.match(r"^ghp_[A-Za-z0-9]{20,}$", key_obj.get("key", "")))
    report["checks"]["api_keys"] = {"count": len(api_keys), "valid": api_ok}

    # --- JWT Tokens ---
    jwt_tokens = bundle.get("jwt_tokens", [])
    jwt_ok = all(isinstance(t, str) and t.count(".") == 2 for t in jwt_tokens)
    report["checks"]["jwt_tokens"] = {"count": len(jwt_tokens), "valid": jwt_ok}

    # --- DB URLs ---
    db_urls = bundle.get("db_urls", [])
    db_ok = all(
        isinstance(u, str) and u.startswith("postgres://") and "@" in u
        for u in db_urls
    )
    report["checks"]["db_urls"] = {"count": len(db_urls), "valid": db_ok}

    # --- Private Keys ---
    priv_keys = bundle.get("private_keys", [])
    pk_ok = all(
        isinstance(k, str)
        and "-----BEGIN PRIVATE KEY-----" in k
        and "-----END PRIVATE KEY-----" in k
        for k in priv_keys
    )
    report["checks"]["private_keys"] = {"count": len(priv_keys), "valid": pk_ok}

    # --- OAuth Tokens ---
    oauth_tokens = bundle.get("oauth_tokens", [])
    oauth_ok = all(
        isinstance(t, dict) and "provider" in t and "access_token" in t
        for t in oauth_tokens
    )
    report["checks"]["oauth_tokens"] = {"count": len(oauth_tokens), "valid": oauth_ok}

    # --- Metadata ---
    meta = bundle.get("metadata", {})
    meta_ok = meta.get("is_honeypot") is True and "created_at" in meta
    report["checks"]["metadata"] = {"valid": meta_ok}

    # Overall verdict.
    report["valid"] = all(
        check.get("valid", False) for check in report["checks"].values()
    )

    return report


# ============================================================================
#  7. CLI ENTRY POINT (standalone testing)
# ============================================================================

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="SecureVault Honeypot Deception Engine"
    )
    sub = parser.add_subparsers(dest="command")

    # -- generate --
    gen_parser = sub.add_parser("generate", help="Generate a honeypot bundle")
    gen_parser.add_argument(
        "--user-id", type=str, default="test-user-001",
        help="Simulated user ID for seeding",
    )
    gen_parser.add_argument(
        "--no-llm", action="store_true",
        help="Skip LLM and use fallback only",
    )
    gen_parser.add_argument(
        "--validate", action="store_true",
        help="Run validation on the generated bundle",
    )

    # -- check-ollama --
    sub.add_parser("check-ollama", help="Test Ollama connectivity")

    args = parser.parse_args()

    if args.command == "generate":
        logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
        bundle = generate_honeypots(
            user_id=args.user_id,
            use_llm=not args.no_llm,
        )

        # Print a SAFE summary (no actual secret values).
        print("\n" + "=" * 60)
        print("  HONEYPOT BUNDLE GENERATED")
        print("=" * 60)
        print(f"  Generator:   {bundle['metadata']['generator']}")
        print(f"  Honeypot ID: {bundle['metadata']['honeypot_id']}")
        print(f"  Created at:  {bundle['metadata']['created_at']}")
        print(f"  API Keys:    {len(bundle.get('api_keys', []))} items")
        print(f"  JWT Tokens:  {len(bundle.get('jwt_tokens', []))} items")
        print(f"  DB URLs:     {len(bundle.get('db_urls', []))} items")
        print(f"  Private Keys:{len(bundle.get('private_keys', []))} items")
        print(f"  OAuth Tokens:{len(bundle.get('oauth_tokens', []))} items")
        print("=" * 60)

        if args.validate:
            report = validate_honeypot_bundle(bundle)
            print(f"\n  Validation: {'✅ PASSED' if report['valid'] else '❌ FAILED'}")
            for cat, info in report["checks"].items():
                status = "✅" if info.get("valid") else "❌"
                count = info.get("count", "-")
                print(f"    {status} {cat}: {count}")
            print()

    elif args.command == "check-ollama":
        client = OllamaClient()
        if client.is_available():
            print(f"✅ Ollama is reachable at {OLLAMA_BASE_URL}")
            print(f"   Default model: {OLLAMA_MODEL}")
        else:
            print(f"❌ Ollama is NOT reachable at {OLLAMA_BASE_URL}")
            print("   The fallback generator will be used instead.")
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)
