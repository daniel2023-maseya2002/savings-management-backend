from django.contrib.auth import get_user_model
from core.models import Notification

User = get_user_model()

def notify_admins(notif_type, title, message, meta=None):
    """Send a notification to all staff users."""
    meta = meta or {}
    admins = User.objects.filter(is_staff=True)
    for admin in admins:
        Notification.objects.create(
            user=admin,
            notif_type=notif_type,
            title=title,
            message=message,
            meta=meta
        )
