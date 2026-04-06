"""
Honeypot Views — Status & Regeneration Endpoints

Endpoints:
  GET  /api/honeypot/status/      — Summary of honeypot entries for the user
    GET  /api/honeypot/llm-status/  — Local LLM connectivity status
  POST /api/honeypot/regenerate/  — Re-generate honeypots for the user

Security:
  - All endpoints require JWT authentication.
  - Users can only see/manage their own honeypot entries.
"""

import hashlib
import logging
import uuid

from django.conf import settings
from django.db import transaction
from django.db.models import Count
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .honeypot_models import HoneypotEntry

logger = logging.getLogger("abhedya.honeypot.views")


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
