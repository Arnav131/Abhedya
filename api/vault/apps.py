from django.apps import AppConfig


class VaultConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "vault"

    def ready(self):
        # Import signals so the post_save hook for honeypot generation is
        # registered when Django starts up.
        import vault.signals  # noqa: F401
