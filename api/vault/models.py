"""
Vault Models — Zero-Knowledge Ciphertext Storage

The VaultEntry model stores ONLY encrypted data. Django never sees plaintext.
All encryption/decryption happens client-side (React + Web Crypto API).
"""

import uuid
from django.conf import settings
from django.db import models


class VaultEntry(models.Model):
    """
    A single encrypted secret stored in the user's vault.

    Fields:
        id          — UUID primary key (avoids sequential ID enumeration)
        user        — Owner (FK to Django auth user)
        label       — Human-readable label (e.g. "Gmail", "AWS Prod")
        ciphertext  — Base64-encoded AES-256-GCM encrypted payload
        iv          — Base64-encoded initialization vector
        salt        — Base64-encoded PBKDF2 salt
        created_at  — Auto-set on creation
        updated_at  — Auto-set on every save
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for this vault entry.",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="vault_entries",
        help_text="Owner of this vault entry.",
    )
    label = models.CharField(
        max_length=255,
        help_text="User-defined label for this entry (stored in plaintext for UX).",
    )
    ciphertext = models.TextField(
        help_text="Base64-encoded AES-256-GCM ciphertext blob.",
    )
    iv = models.CharField(
        max_length=64,
        help_text="Base64-encoded initialization vector used for encryption.",
    )
    salt = models.CharField(
        max_length=128,
        help_text="Base64-encoded PBKDF2 salt used for key derivation.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]
        verbose_name = "Vault Entry"
        verbose_name_plural = "Vault Entries"
        indexes = [
            models.Index(fields=["user", "-updated_at"], name="idx_user_updated"),
        ]

    def __str__(self):
        return f"[{self.label}] — {self.user.username}"


# Import HoneypotEntry so Django discovers it for migrations
from .honeypot_models import HoneypotEntry  # noqa: E402, F401
