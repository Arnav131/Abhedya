from django.contrib import admin
from .models import VaultEntry
from .honeypot_models import HoneypotEntry


@admin.register(VaultEntry)
class VaultEntryAdmin(admin.ModelAdmin):
    list_display = ("label", "user", "created_at", "updated_at")
    list_filter = ("user", "created_at")
    search_fields = ("label", "user__username")
    readonly_fields = ("id", "created_at", "updated_at")
    ordering = ("-updated_at",)


@admin.register(HoneypotEntry)
class HoneypotEntryAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "category",
        "provider",
        "generator",
        "is_triggered",
        "created_at",
    )
    list_filter = ("category", "generator", "is_triggered", "created_at")
    search_fields = ("user__username", "provider", "honeypot_id")
    readonly_fields = (
        "id",
        "fake_secret",
        "honeypot_id",
        "generator",
        "is_triggered",
        "triggered_at",
        "triggered_ip",
        "created_at",
    )
    ordering = ("-created_at",)

    fieldsets = (
        ("Honeypot Info", {
            "fields": ("id", "user", "category", "provider", "generator", "honeypot_id"),
        }),
        ("Fake Credential (Read-Only)", {
            "fields": ("fake_secret",),
            "classes": ("collapse",),
            "description": "⚠️  This is a fake credential. Do not use it anywhere.",
        }),
        ("Trigger Detection", {
            "fields": ("is_triggered", "triggered_at", "triggered_ip"),
        }),
        ("Timestamps", {
            "fields": ("created_at",),
        }),
    )
