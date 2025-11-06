import secrets
import hashlib
import hmac
import time
import json
from pywebpush import webpush, WebPushException
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
from pyfcm import FCMNotification
from .utils import send_branded_email

OTP_LENGTH = 6
OTP_TTL = timedelta(minutes=10)

def generate_otp():
    # 6-digit zero-padded number
    num = secrets.randbelow(10**OTP_LENGTH)
    return f"{num:0{OTP_LENGTH}d}"

def make_salt():
    return secrets.token_hex(8)  # 16 chars

def hash_otp(otp: str, salt: str):
    # HMAC with secret key + salt
    key = (salt + secrets.token_hex(8)).encode()  # extra randomness per call
    # you can also use settings.SECRET_KEY as HMAC key
    h = hmac.new(key, otp.encode(), hashlib.sha256).hexdigest()
    # store salt + hashed value (salt stored separately too)
    return h

def verify_otp(provided_otp: str, stored_hash: str, stored_salt: str):
    # re-create hash using same method
    # NOTE: because we used an extra ephemeral token in make_salt above, ensure consistency:
    # Simpler: use salt + secret_key as key so verification is deterministic:
    import hashlib, hmac
    from django.conf import settings
    key = (stored_salt + settings.SECRET_KEY).encode()
    expected = hmac.new(key, provided_otp.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, stored_hash)

def expires_at_now():
    return timezone.now() + OTP_TTL


def send_webpush(subscription, payload: dict, *args, **kwargs):
    """
    subscription: PushSubscription instance
    payload: dict with 'title' and 'body' (and optional data)
    """
    if not getattr(settings, "SEND_WEBPUSH_NOTIFICATIONS", False):
        return False

    try:
        webpush(
            subscription_info={
                "endpoint": subscription.endpoint,
                "keys": {"p256dh": subscription.p256dh, "auth": subscription.auth},
            },
            data=json.dumps(payload),
            vapid_private_key=settings.VAPID_PRIVATE_KEY,
            vapid_claims=settings.VAPID_CLAIMS,
        )
        return True
    except WebPushException as exc:
        print("WebPush failed:", exc)
        return False


_push_service = None
def get_push_service():
    global _push_service
    if _push_service is None:
        _push_service = FCMNotification(api_key=settings.FCM_SERVER_KEY)
    return _push_service

def send_fcm_notification(registration_id, title, body, data_message=None):
    if not getattr(settings, "SEND_FCM_NOTIFICATIONS", False):
        return None
    push_service = get_push_service()
    try:
        return push_service.notify_single_device(
            registration_id=registration_id,
            message_title=title,
            message_body=body,
            data_message=data_message or {}
        )
    except Exception as e:
        # log
        return None
    
def get_client_ip(request):
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        # “X-Forwarded-For: client, proxy1, proxy2”
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")

def send_otp_email(user, otp, expire):
    """Send OTP email using your custom HTML template."""
    try:
        send_branded_email(
            subject="Your Verification Code — CreditJambo",
            to_email=user.email,
            template_name="emails/otp_code.html",
            context={
                "user": user,
                "otp": otp,
                "expire": expire,
            },
        )
    except Exception as e:
        print(f"⚠️ OTP email failed: {e}")
