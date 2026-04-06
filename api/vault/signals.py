"""
Vault Signals — Automatic Honeypot Generation on Registration

When a new User is created (via RegisterView or Django admin), this signal
fires and generates a full set of honeypot decoy secrets using the AI engine.

Generation is executed synchronously with deterministic fallback by default,
so entries are guaranteed to exist immediately after registration.
If anything fails, the error is logged and the user's account is still
created normally (NFR-3: Graceful Degradation).
"""

import hashlib
import logging
import uuid

from django.conf import settings
from django.contrib.auth.models import User
from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

logger = logging.getLogger("abhedya.honeypot.signals")


def _get_honeypot_config():
    """Retrieve HONEYPOT settings with safe defaults."""
    return getattr(settings, "HONEYPOT", {
        "ENABLED": True,
        "LLM_BACKEND": "ollama",
        "USE_LLM_ON_REGISTRATION": True,
        "DECOY_PASSWORDS_COUNT": 4,
    })


def _generate_and_store_honeypots(user_id: int) -> int:
    """
    Generate honeypot secrets and persist them as HoneypotEntry rows.

    Returns number of created rows. All errors are caught and logged.
    """
    from ai_engine.honeypot_llm import generate_honeypots, get_local_llm_status
    from vault.honeypot_models import HoneypotEntry

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        logger.warning("Skipping honeypot generation: user id=%s no longer exists.", user_id)
        return 0

    config = _get_honeypot_config()
    user_id_str = str(user.id)
    user_hash = hashlib.sha256(user_id_str.encode()).hexdigest()[:12]

    try:
        if HoneypotEntry.objects.filter(user=user).exists():
            logger.info(
                "Honeypots already exist for user (hash: %s) — skipping generation.",
                user_hash,
            )
            return 0

        # Determine LLM backend preference
        backend = str(config.get("LLM_BACKEND", "ollama")).lower()
        registration_prefers_llm = bool(config.get("USE_LLM_ON_REGISTRATION", True))

        llm_status = get_local_llm_status(
            backend=backend,
            ollama_model=config.get("OLLAMA_MODEL"),
            ollama_url=config.get("OLLAMA_BASE_URL"),
            ollama_timeout=config.get("OLLAMA_TIMEOUT"),
            transformers_model=config.get("TRANSFORMERS_MODEL"),
        )
        use_llm = registration_prefers_llm and llm_status.get("llm_available", False)

        logger.info(
            "Generating honeypots for user (hash: %s) via backend=%s, mode=%s, use_llm=%s",
            user_hash,
            backend,
            llm_status.get("effective_mode"),
            use_llm,
        )

        # Generate the full bundle
        bundle = generate_honeypots(
            user_id=user_id_str,
            use_llm=use_llm,
            ollama_model=config.get("OLLAMA_MODEL"),
            ollama_url=config.get("OLLAMA_BASE_URL"),
            ollama_timeout=config.get("OLLAMA_TIMEOUT"),
        )

        metadata = bundle.get("metadata", {})
        honeypot_batch_id = uuid.UUID(metadata.get("honeypot_id", str(uuid.uuid4())))
        generator_used = metadata.get("generator", "fallback")

        # Map generator names to model choices
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
            # AWS has two fields
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
            # Combine all token fields into one string
            token_parts = []
            for k, v in oauth_obj.items():
                if k != "provider":
                    token_parts.append(f"{k}={v}")
            secret_val = "\n".join(token_parts)

            entries.append(HoneypotEntry(
                user=user,
                category="oauth_token",
                provider=provider,
                fake_secret=secret_val,
                honeypot_id=honeypot_batch_id,
                generator=generator_choice,
            ))

        # Bulk-insert in a single transaction
        with transaction.atomic():
            HoneypotEntry.objects.bulk_create(entries)

        logger.info(
            "✅ Created %d honeypot entries for user (hash: %s) "
            "[batch: %s, generator: %s]",
            len(entries), user_hash, honeypot_batch_id, generator_choice,
        )
        return len(entries)

    except Exception as exc:
        # NFR-3: Never let honeypot generation break registration
        logger.error(
            "Honeypot generation failed for user (hash: %s): %s — "
            "user account was still created successfully.",
            user_hash, exc,
            exc_info=True,
        )
        return 0


@receiver(post_save, sender=User)
def create_honeypots_on_registration(sender, instance, created, **kwargs):
    """
    Signal handler: generate honeypot decoys when a new user is created.
    """
    if not created:
        return

    config = _get_honeypot_config()
    if not config.get("ENABLED", True):
        logger.info("Honeypot generation is disabled — skipping.")
        return

    created_count = _generate_and_store_honeypots(instance.id)
    logger.info(
        "Honeypot generation completed for user '%s' (created=%d).",
        instance.username,
        created_count,
    )
