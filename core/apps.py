# core/apps.py
from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"

    def ready(self):
        import os
        from django.contrib.auth import get_user_model
        from django.db.utils import OperationalError, ProgrammingError

        User = get_user_model()

        username = os.environ.get("ADMIN_USERNAME")
        email = os.environ.get("ADMIN_EMAIL")
        password = os.environ.get("ADMIN_PASSWORD")

        if not (username and email and password):
            print("[init] ADMIN_* env vars not all set, skipping superuser creation.")
            return

        try:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    "email": email,
                    "is_superuser": True,
                    "is_staff": True,
                },
            )

            if created:
                # Newly created → set password and flags
                user.set_password(password)
                user.is_superuser = True
                user.is_staff = True
                user.save()
                print(f"[init] Created superuser '{username}'")
            else:
                # Already exists → make sure it really is admin and the password matches env
                updated = False

                if not user.is_superuser or not user.is_staff:
                    user.is_superuser = True
                    user.is_staff = True
                    updated = True

                if user.email != email:
                    user.email = email
                    updated = True

                # Always reset password from env (so ADMIN_PASSWORD is the truth)
                user.set_password(password)
                updated = True

                if updated:
                    user.save()
                    print(f"[init] Updated superuser '{username}' from env vars")
                else:
                    print(f"[init] Superuser '{username}' already correct")

        except (OperationalError, ProgrammingError):
            print("[init] Could not create/update superuser yet (DB not ready).")
            return
