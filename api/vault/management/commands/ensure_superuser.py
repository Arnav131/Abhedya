import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction


TRUE_VALUES = {"1", "true", "yes", "on"}


def _env_truthy(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return str(value).strip().lower() in TRUE_VALUES


class Command(BaseCommand):
    help = (
        "Create or update a Django superuser from environment variables. "
        "Safe to run repeatedly during deployment."
    )

    def handle(self, *args, **options):
        should_create = _env_truthy("DJANGO_SUPERUSER_CREATE", default=False)
        if not should_create:
            self.stdout.write(
                self.style.WARNING(
                    "Skipped ensure_superuser: set DJANGO_SUPERUSER_CREATE=true to enable."
                )
            )
            return

        username = (os.environ.get("DJANGO_SUPERUSER_USERNAME") or "").strip()
        email = (os.environ.get("DJANGO_SUPERUSER_EMAIL") or "").strip()
        password = (os.environ.get("DJANGO_SUPERUSER_PASSWORD") or "").strip()

        missing = [
            name
            for name, value in (
                ("DJANGO_SUPERUSER_USERNAME", username),
                ("DJANGO_SUPERUSER_EMAIL", email),
                ("DJANGO_SUPERUSER_PASSWORD", password),
            )
            if not value
        ]
        if missing:
            raise CommandError(
                "Missing required env vars for ensure_superuser: "
                + ", ".join(missing)
            )

        reset_password = _env_truthy("DJANGO_SUPERUSER_RESET_PASSWORD", default=True)

        User = get_user_model()
        with transaction.atomic():
            user = User.objects.filter(username=username).first()

            if user is None:
                User.objects.create_superuser(
                    username=username,
                    email=email,
                    password=password,
                )
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Created superuser '{username}' from deployment environment."
                    )
                )
                return

            changed = False
            if user.email != email:
                user.email = email
                changed = True

            if not user.is_staff:
                user.is_staff = True
                changed = True

            if not user.is_superuser:
                user.is_superuser = True
                changed = True

            if reset_password:
                user.set_password(password)
                changed = True

            if changed:
                user.save()
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Updated existing user '{username}' to deployment superuser settings."
                    )
                )
            else:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Superuser '{username}' already up to date."
                    )
                )
