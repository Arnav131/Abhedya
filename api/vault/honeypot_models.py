"""
Honeypot Models — Canary Trap Storage

Each HoneypotEntry stores a single fake credential generated at registration
time.  If an attacker exfiltrates the DB and tries to use one of these,
the ``is_triggered`` flag is flipped and the incident is logged.

Categories:
    api_key, jwt_token, db_url, private_key, oauth_token, decoy_password
"""

import uuid
from django.conf import settings
from django.db import models


class HoneypotEntry(models.Model):
    """
    A single fake credential planted as a canary trap.

    Fields:
        id            — UUID primary key
        user          — Owner (FK → auth user)
        category      — Type of fake secret (api_key, jwt_token, …)
        provider      — Service provider label (stripe, openai, aws, …)
        fake_secret   — The generated fake credential
        honeypot_id   — Groups entries from the same generation batch
        generator     — Which engine produced it (ollama_llm / transformers_llm / fallback)
        is_triggered  — Flipped True if the secret is ever "used"
        triggered_at  — Timestamp of trigger event
        triggered_ip  — Source IP of trigger event
        created_at    — Auto-set on creation
    """

    CATEGORY_CHOICES = [
        ("api_key", "API Key"),
        ("jwt_token", "JWT Token"),
        ("db_url", "Database URL"),
        ("private_key", "Private Key"),
        ("oauth_token", "OAuth Token"),
        ("decoy_password", "Decoy Password"),
    ]

    GENERATOR_CHOICES = [
        ("ollama_llm", "Ollama LLM"),
        ("transformers_llm", "Transformers LLM"),
        ("fallback", "Deterministic Fallback"),
    ]

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for this honeypot entry.",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="honeypot_entries",
        help_text="User whose vault this honeypot protects.",
    )
    category = models.CharField(
        max_length=32,
        choices=CATEGORY_CHOICES,
        help_text="Type of fake credential.",
    )
    provider = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="Simulated service provider (e.g. stripe, aws).",
    )
    fake_secret = models.TextField(
        help_text="The generated fake credential value.",
    )
    honeypot_id = models.UUIDField(
        help_text="Batch ID — groups all entries from a single generation run.",
    )
    generator = models.CharField(
        max_length=32,
        choices=GENERATOR_CHOICES,
        help_text="Which generation engine produced this entry.",
    )
    is_triggered = models.BooleanField(
        default=False,
        help_text="Set to True if this honeypot credential was accessed/used.",
    )
    triggered_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the honeypot was triggered.",
    )
    triggered_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Source IP address of the trigger event.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Honeypot Entry"
        verbose_name_plural = "Honeypot Entries"
        indexes = [
            models.Index(
                fields=["user", "category"],
                name="idx_honeypot_user_cat",
            ),
            models.Index(
                fields=["honeypot_id"],
                name="idx_honeypot_batch",
            ),
            models.Index(
                fields=["is_triggered"],
                name="idx_honeypot_triggered",
            ),
        ]

    def __str__(self):
        status = "🚨 TRIGGERED" if self.is_triggered else "🟢 dormant"
        return f"[{self.category}:{self.provider or '—'}] {status} — {self.user.username}"
