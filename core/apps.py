# core/apps.py
from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"

    def ready(self):
        # Auto-create superuser in production (Render) if not exists
        import os
        from django.contrib.auth import get_user_model
        from django.db.utils import OperationalError, ProgrammingError

        User = get_user_model()

        username = os.environ.get("dan")
        email = os.environ.get("maseyadaniel@gmail.com")
        password = os.environ.get("Smooth1.")

        # If env vars not set, do nothing
        if not (username and email and password):
            return

        try:
            # Avoid duplicate creation
            if not User.objects.filter(username=username).exists():
                print(f"[init] Creating default superuser: {username}")
                User.objects.create_superuser(
                    username=username, email=email, password=password
                )
            else:
                print(f"[init] Superuser {username} already exists.")
        except (OperationalError, ProgrammingError):
            # DB not ready (e.g. during migrations)
            # Just ignore; next start will try again
            print("[init] Could not create superuser yet (DB not ready).")
            return
