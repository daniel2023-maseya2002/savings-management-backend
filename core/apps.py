# core/apps.py
from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"

    def ready(self):
        """
        In production (Render), automatically create an admin user
        using environment variables IF it does not exist yet.
        """
        import os
        from django.conf import settings
        from django.contrib.auth import get_user_model
        from django.db.utils import OperationalError, ProgrammingError

        # Only run this logic in production (not on your local dev)
        if settings.DEBUG:
            return

        User = get_user_model()

        username = os.environ.get("ADMIN_USERNAME")
        email = os.environ.get("ADMIN_EMAIL")
        password = os.environ.get("ADMIN_PASSWORD")

        # If env vars are not set, do nothing
        if not (username and email and password):
            print("[init] ADMIN_* environment variables not set, skipping auto-superuser.")
            return

        try:
            if not User.objects.filter(username=username).exists():
                print(f"[init] Creating default superuser: {username}")
                User.objects.create_superuser(
                    username=username,
                    email=email,
                    password=password,
                )
            else:
                print(f"[init] Superuser {username} already exists.")
        except (OperationalError, ProgrammingError):
            # Happens during first migrate when DB tables don't exist yet
            print("[init] Could not create superuser yet (DB not ready).")
            return
