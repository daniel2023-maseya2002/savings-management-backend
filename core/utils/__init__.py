# core/utils/__init__.py
from .otp_utils import generate_otp, verify_otp
from .ip_utils import get_client_ip
from .push_utils import send_webpush, send_fcm_notification
from core.models import Notification


def create_user_notification(user, title, message, notif_type=None):
    """
    Utility to create and save a new notification for a user.
    """
    return Notification.objects.create(
        user=user,
        title=title,
        message=message,
        notif_type=notif_type or Notification.TYPE_GENERAL,
    )