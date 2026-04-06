"""
Honeypot Views — Status & Regeneration Endpoints

Endpoints:
  GET  /api/honeypot/status/      — Summary of honeypot entries for the user
    GET  /api/honeypot/llm-status/  — Local LLM connectivity status
  POST /api/honeypot/regenerate/  — Re-generate honeypots for the user
    POST /api/honeypot/trigger/     — Mark honeypot as triggered + send SMTP alert

Security:
  - All endpoints require JWT authentication.
  - Users can only see/manage their own honeypot entries.
"""

import ipaddress
import hashlib
import logging
import uuid

from django.conf import settings
from django.db import transaction
from django.db.models import Count
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .honeypot_models import HoneypotEntry

logger = logging.getLogger("abhedya.honeypot.views")


def _extract_client_ip(request):
    """Best-effort extraction of client IP from request headers."""
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _normalize_ip(raw_ip):
    """Return a valid IP string or None when unavailable/invalid."""
    if not raw_ip:
        return None
    value = str(raw_ip).strip()
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _resolve_honeypot_entry_for_trigger(user, payload):
    """Resolve the honeypot entry to trigger based on request payload."""
    entries = HoneypotEntry.objects.filter(user=user)
    entry_id = payload.get("entry_id") or payload.get("honeypot_entry_id")

    if entry_id:
        return entries.filter(id=entry_id).first()

    fake_secret = payload.get("fake_secret")
    if fake_secret:
        return entries.filter(fake_secret=fake_secret).first()

    category = payload.get("category")
    provider = payload.get("provider")

    if category:
        entries = entries.filter(category=category)
    if provider:
        entries = entries.filter(provider=provider)

    unresolved = entries.filter(is_triggered=False).first()
    if unresolved:
        return unresolved

    return entries.first()


def _dispatch_honeypot_email_alert(user, entry, source_ip, severity):
    """Send SMTP breach alert using HONEYPOT_ALERT settings."""
    alert_settings = getattr(settings, "HONEYPOT_ALERT", {})

    if not bool(alert_settings.get("ENABLED", True)):
        return {
            "attempted": False,
            "success": False,
            "reason": "Honeypot alert email is disabled in server settings.",
        }

    recipient_email = (user.email or "").strip()
    if not recipient_email:
        return {
            "attempted": False,
            "success": False,
            "reason": "Authenticated user has no email configured.",
        }

    from ai_engine.honeypot_alert_api import send_breach_alert

    alert_result = send_breach_alert(
        recipient_email=recipient_email,
        recipient_name=user.get_full_name() or user.username or "User",
        breach_details={
            "honeypot_id": str(entry.honeypot_id),
            "category": entry.category,
            "provider": entry.provider or "vault",
            "triggered_at": entry.triggered_at.isoformat() if entry.triggered_at else timezone.now().isoformat(),
            "triggered_ip": source_ip or "Unknown",
            "severity": severity,
        },
        smtp_host=str(alert_settings.get("SMTP_HOST", "")),
        smtp_port=int(alert_settings.get("SMTP_PORT", 0) or 0),
        smtp_email=str(alert_settings.get("SMTP_EMAIL", "")),
        smtp_password=str(alert_settings.get("SMTP_PASSWORD", "")),
        smtp_from_name=str(alert_settings.get("SMTP_FROM_NAME", "Abhedya Security")),
        smtp_use_tls=bool(alert_settings.get("SMTP_USE_TLS", True)),
        smtp_timeout=int(alert_settings.get("SMTP_TIMEOUT", 0) or 0),
    )

    return {
        "attempted": True,
        "success": bool(alert_result.get("success", False)),
        "reason": alert_result.get("error") if not alert_result.get("success", False) else None,
        "alert_id": alert_result.get("alert_id"),
        "message_id": alert_result.get("message_id"),
    }


class HoneypotLLMStatusView(APIView):
    """GET /api/honeypot/llm-status/

    Returns current local LLM connectivity and effective mode selection.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            from ai_engine.honeypot_llm import get_local_llm_status

            config = getattr(settings, "HONEYPOT", {})
            status_payload = get_local_llm_status(
                backend=config.get("LLM_BACKEND", "ollama"),
                ollama_model=config.get("OLLAMA_MODEL"),
                ollama_url=config.get("OLLAMA_BASE_URL"),
                ollama_timeout=config.get("OLLAMA_TIMEOUT"),
                transformers_model=config.get("TRANSFORMERS_MODEL"),
            )

            return Response(
                {
                    "enabled": bool(config.get("ENABLED", True)),
                    "registration_uses_llm": bool(config.get("USE_LLM_ON_REGISTRATION", True)),
                    "status": status_payload,
                },
                status=status.HTTP_200_OK,
            )
        except Exception as exc:
            logger.error("Failed to resolve local LLM status: %s", exc, exc_info=True)
            return Response(
                {"error": "Failed to resolve local LLM status."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class HoneypotStatusView(APIView):
    """
    GET /api/honeypot/status/

    Returns a structured summary of the authenticated user's honeypot entries:
      - Total count
      - Count per category
      - Generator used
      - Number of triggered alerts
      - List of triggered entries (if any)
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        entries = HoneypotEntry.objects.filter(user=user)

        if not entries.exists():
            return Response(
                {
                    "honeypots_generated": False,
                    "message": "No honeypot entries found. They may still be generating.",
                    "total": 0,
                },
                status=status.HTTP_200_OK,
            )

        # Category breakdown
        category_counts = dict(
            entries.values_list("category")
            .annotate(count=Count("id"))
            .values_list("category", "count")
        )

        # Generator info (from the most recent batch)
        latest = entries.first()  # ordered by -created_at
        generator = latest.generator if latest else "unknown"
        honeypot_batch_id = str(latest.honeypot_id) if latest else None

        # Triggered alerts
        triggered = entries.filter(is_triggered=True)
        triggered_list = [
            {
                "id": str(t.id),
                "category": t.category,
                "provider": t.provider,
                "triggered_at": t.triggered_at.isoformat() if t.triggered_at else None,
                "triggered_ip": t.triggered_ip,
            }
            for t in triggered
        ]

        return Response(
            {
                "honeypots_generated": True,
                "total": entries.count(),
                "categories": category_counts,
                "generator": generator,
                "honeypot_batch_id": honeypot_batch_id,
                "created_at": latest.created_at.isoformat() if latest else None,
                "alerts": {
                    "triggered_count": triggered.count(),
                    "entries": triggered_list,
                },
            },
            status=status.HTTP_200_OK,
        )


class HoneypotRegenerateView(APIView):
    """
    POST /api/honeypot/regenerate/

    Delete all existing honeypot entries for the user and generate fresh ones.
    Useful if the user suspects their honeypots may have been catalogued.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        user_hash = hashlib.sha256(str(user.id).encode()).hexdigest()[:12]

        try:
            from ai_engine.honeypot_llm import generate_honeypots, get_local_llm_status

            config = getattr(settings, "HONEYPOT", {})
            backend = str(config.get("LLM_BACKEND", "ollama")).lower()
            llm_status = get_local_llm_status(
                backend=backend,
                ollama_model=config.get("OLLAMA_MODEL"),
                ollama_url=config.get("OLLAMA_BASE_URL"),
                ollama_timeout=config.get("OLLAMA_TIMEOUT"),
                transformers_model=config.get("TRANSFORMERS_MODEL"),
            )
            use_llm = backend != "fallback" and llm_status.get("llm_available", False)

            # Delete old entries
            old_count, _ = HoneypotEntry.objects.filter(user=user).delete()

            # Generate new bundle
            bundle = generate_honeypots(
                user_id=str(user.id),
                use_llm=use_llm,
                ollama_model=config.get("OLLAMA_MODEL"),
                ollama_url=config.get("OLLAMA_BASE_URL"),
                ollama_timeout=config.get("OLLAMA_TIMEOUT"),
            )
            metadata = bundle.get("metadata", {})
            honeypot_batch_id = uuid.UUID(
                metadata.get("honeypot_id", str(uuid.uuid4()))
            )
            generator_used = metadata.get("generator", "fallback")

            generator_map = {
                "llm": "ollama_llm",
                "transformers": "transformers_llm",
                "fallback": "fallback",
            }
            generator_choice = generator_map.get(generator_used, "fallback")

            entries = []

            # --- API Keys ---
            for key_obj in bundle.get("api_keys", []):
                provider = key_obj.get("provider", "unknown")
                if provider == "aws":
                    secret_val = (
                        f"access_key={key_obj.get('access_key', '')}\n"
                        f"secret_key={key_obj.get('secret_key', '')}"
                    )
                else:
                    secret_val = key_obj.get("key", "")
                entries.append(HoneypotEntry(
                    user=user,
                    category="api_key",
                    provider=provider,
                    fake_secret=secret_val,
                    honeypot_id=honeypot_batch_id,
                    generator=generator_choice,
                ))

            # --- JWT Tokens ---
            for token in bundle.get("jwt_tokens", []):
                entries.append(HoneypotEntry(
                    user=user,
                    category="jwt_token",
                    provider="jwt",
                    fake_secret=token,
                    honeypot_id=honeypot_batch_id,
                    generator=generator_choice,
                ))

            # --- Database URLs ---
            for db_url in bundle.get("db_urls", []):
                entries.append(HoneypotEntry(
                    user=user,
                    category="db_url",
                    provider="postgres",
                    fake_secret=db_url,
                    honeypot_id=honeypot_batch_id,
                    generator=generator_choice,
                ))

            # --- Private Keys ---
            for pkey in bundle.get("private_keys", []):
                entries.append(HoneypotEntry(
                    user=user,
                    category="private_key",
                    provider="rsa",
                    fake_secret=pkey,
                    honeypot_id=honeypot_batch_id,
                    generator=generator_choice,
                ))

            # --- OAuth Tokens ---
            for oauth_obj in bundle.get("oauth_tokens", []):
                provider = oauth_obj.get("provider", "unknown")
                token_parts = [f"{k}={v}" for k, v in oauth_obj.items() if k != "provider"]
                entries.append(HoneypotEntry(
                    user=user,
                    category="oauth_token",
                    provider=provider,
                    fake_secret="\n".join(token_parts),
                    honeypot_id=honeypot_batch_id,
                    generator=generator_choice,
                ))

            with transaction.atomic():
                HoneypotEntry.objects.bulk_create(entries)

            logger.info(
                "♻️  Regenerated %d honeypots for user (hash: %s), "
                "replaced %d old entries.",
                len(entries), user_hash, old_count,
            )

            return Response(
                {
                    "message": "Honeypots regenerated successfully.",
                    "old_entries_deleted": old_count,
                    "new_entries_created": len(entries),
                    "generator": generator_choice,
                    "llm_mode": llm_status.get("effective_mode"),
                    "llm_available": llm_status.get("llm_available"),
                    "honeypot_batch_id": str(honeypot_batch_id),
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as exc:
            logger.error(
                "Honeypot regeneration failed for user (hash: %s): %s",
                user_hash, exc,
                exc_info=True,
            )
            return Response(
                {"error": "Honeypot regeneration failed. Please try again."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class HoneypotTriggerView(APIView):
    """
    POST /api/honeypot/trigger/

    Marks a honeypot entry as triggered and dispatches an SMTP alert email
    to the authenticated user's email address.

    Request body (all fields optional except one identifier path):
      - entry_id | honeypot_entry_id : UUID of target honeypot entry
      - fake_secret                : exact fake secret match
      - category                   : fallback selector when no ID/secret is supplied
      - provider                   : optional selector alongside category
      - triggered_ip               : explicit source IP override
      - severity                   : critical/high/medium/low (default: critical)
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        payload = request.data if isinstance(request.data, dict) else {}

        entry = _resolve_honeypot_entry_for_trigger(user, payload)
        if not entry:
            return Response(
                {
                    "error": "No honeypot entry found for this user with the provided selectors.",
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        severity = str(payload.get("severity", "critical")).lower()
        if severity not in {"critical", "high", "medium", "low"}:
            severity = "critical"

        source_ip = _normalize_ip(payload.get("triggered_ip"))
        if not source_ip:
            source_ip = _normalize_ip(_extract_client_ip(request))

        was_already_triggered = entry.is_triggered
        entry.is_triggered = True
        entry.triggered_at = timezone.now()
        if source_ip:
            entry.triggered_ip = source_ip

        update_fields = ["is_triggered", "triggered_at"]
        if source_ip:
            update_fields.append("triggered_ip")
        entry.save(update_fields=update_fields)

        email_alert = _dispatch_honeypot_email_alert(
            user=user,
            entry=entry,
            source_ip=entry.triggered_ip,
            severity=severity,
        )

        if email_alert.get("attempted") and email_alert.get("success"):
            logger.warning(
                "🚨 Honeypot triggered for user (id=%s), entry=%s, category=%s, provider=%s. Alert email dispatched.",
                user.id,
                entry.id,
                entry.category,
                entry.provider,
            )
        elif email_alert.get("attempted"):
            logger.warning(
                "🚨 Honeypot triggered for user (id=%s), entry=%s. Email dispatch attempted but failed: %s",
                user.id,
                entry.id,
                email_alert.get("reason"),
            )
        else:
            logger.warning(
                "🚨 Honeypot triggered for user (id=%s), entry=%s. Email not attempted: %s",
                user.id,
                entry.id,
                email_alert.get("reason"),
            )

        return Response(
            {
                "message": "Honeypot alert recorded.",
                "already_triggered": was_already_triggered,
                "entry": {
                    "id": str(entry.id),
                    "honeypot_id": str(entry.honeypot_id),
                    "category": entry.category,
                    "provider": entry.provider,
                    "triggered_at": entry.triggered_at.isoformat() if entry.triggered_at else None,
                    "triggered_ip": entry.triggered_ip,
                },
                "email_alert": email_alert,
            },
            status=status.HTTP_200_OK,
        )
