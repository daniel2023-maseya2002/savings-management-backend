# core/utils/push_utils.py
from pywebpush import webpush, WebPushException
import requests

def send_webpush(subscription_info, message_body, vapid_private_key, vapid_claims):
    """
    Send a push notification using Web Push protocol.
    """
    try:
        webpush(
            subscription_info=subscription_info,
            data=message_body,
            vapid_private_key=vapid_private_key,
            vapid_claims=vapid_claims,
        )
    except WebPushException as ex:
        print(f"WebPush failed: {ex}")
        return False
    return True


def send_fcm_notification(token, title, body, server_key):
    """
    Send a push notification via Firebase Cloud Messaging (FCM).
    """
    url = "https://fcm.googleapis.com/fcm/send"
    headers = {
        "Authorization": f"key={server_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "to": token,
        "notification": {
            "title": title,
            "body": body,
        },
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return True
    except requests.RequestException as e:
        print(f"FCM Notification Error: {e}")
        return False
