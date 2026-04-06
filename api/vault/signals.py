"""
Vault Signals — Automatic Honeypot Generation on Registration

When a new User is created (via RegisterView or Django admin), this signal
fires and generates a full set of honeypot decoy secrets using the AI engine.

The generation runs in a background daemon thread so it never blocks the
registration HTTP response.  If anything fails, the error is logged and
the user's account is still created normally (NFR-3: Graceful Degradation).
"""

import hashlib
import logging
import threading
import uuid

from django.conf import settings
from django.contrib.auth.models import User
from django.db import close_old_connections, connections, transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

logger = logging.getLogger("securevault.honeypot.signals")


def _get_honeypot_config():
    """Retrieve HONEYPOT settings with safe defaults."""
    return getattr(settings, "HONEYPOT", {
        "ENABLED": True,
        "LLM_BACKEND": "auto",
        "DECOY_PASSWORDS_COUNT": 4,
    })


def _generate_and_store_honeypots(user):
    """
    Generate honeypot secrets and persist them as HoneypotEntry rows.

    This runs in a background thread — all errors are caught and logged.
    Django doesn't manage DB connections for manually-created threads,
    so we explicitly handle connection lifecycle here.
    """
    from ai_engine.honeypot_llm import generate_honeypots
    from vault.honeypot_models import HoneypotEntry

    config = _get_honeypot_config()
    user_id = str(user.id)
    user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:12]

    try:
        # Ensure a fresh DB connection for this thread
        close_old_connections()

        # Determine LLM backend preference
        backend = config.get("LLM_BACKEND", "auto")
        use_llm = backend != "fallback"

        logger.info(
            "Generating honeypots for new user (hash: %s) via backend=%s",
            user_hash, backend,
        )

        # Generate the full bundle
        bundle = generate_honeypots(
            user_id=user_id,
            use_llm=use_llm,
            ollama_model=config.get("OLLAMA_MODEL"),
            ollama_url=config.get("OLLAMA_BASE_URL"),
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

    except Exception as exc:
        # NFR-3: Never let honeypot generation break registration
        logger.error(
            "Honeypot generation failed for user (hash: %s): %s — "
            "user account was still created successfully.",
            user_hash, exc,
            exc_info=True,
        )
    finally:
        # Clean up DB connections for this thread
        connections.close_all()


@receiver(post_save, sender=User)
def create_honeypots_on_registration(sender, instance, created, **kwargs):
    """
    Signal handler: generate honeypot decoys when a new user is created.

    Runs in a daemon thread so the registration response is instant.
    """
    if not created:
        return

    config = _get_honeypot_config()
    if not config.get("ENABLED", True):
        logger.info("Honeypot generation is disabled — skipping.")
        return

    thread = threading.Thread(
        target=_generate_and_store_honeypots,
        args=(instance,),
        daemon=True,
        name=f"honeypot-gen-{instance.username}",
    )
    thread.start()
    logger.info(
        "Honeypot generation thread started for user '%s'.",
        instance.username,
    )
