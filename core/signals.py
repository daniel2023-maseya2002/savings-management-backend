import threading
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from django.core.mail import send_mail
from .models import Transaction, Notification, PushSubscription, FCMDevice
from .utils import send_webpush, send_fcm_notification

LOW_BALANCE_THRESHOLD = getattr(settings, 'LOW_BALANCE_THRESHOLD', 100.00)


def safe_send_mail(subject, message, recipient_list):
    """Send email safely in a background thread."""
    def _send():
        try:
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, recipient_list, fail_silently=True)
        except Exception as e:
            print("Email send error:", e)
    threading.Thread(target=_send, daemon=True).start()


def safe_send_webpush(user, title, body):
    """Send web push safely."""
    def _send():
        try:
            for sub in PushSubscription.objects.filter(user=user):
                send_webpush(sub, title, body)
        except Exception as e:
            print("WebPush error:", e)
    threading.Thread(target=_send, daemon=True).start()


def safe_send_fcm(user, title, body, tx_id):
    """Send FCM push safely."""
    def _send():
        try:
            for d in FCMDevice.objects.filter(user=user):
                send_fcm_notification(
                    registration_id=d.registration_id,
                    title=title,
                    body=body,
                    data_message={"tx_id": str(tx_id)},
                )
        except Exception as e:
            print("FCM error:", e)
    threading.Thread(target=_send, daemon=True).start()


@receiver(post_save, sender=Transaction)
def transaction_post_save(sender, instance: Transaction, created, **kwargs):
    if not created:
        return

    user = instance.user

    try:
        # --- 1️⃣ Create notifications for deposits and withdrawals ---
        if instance.tx_type == Transaction.TYPE_DEPOSIT:
            Notification.objects.create(
                user=user,
                notif_type=Notification.TYPE_DEPOSIT,
                title="Deposit confirmed",
                message=f"Deposit of {instance.amount} completed. Balance: {instance.balance_after}",
                meta={"tx_id": instance.id},
            )

            safe_send_mail(
                subject="Deposit confirmation",
                message=f"Your deposit of {instance.amount} was successful. "
                        f"Balance: {instance.balance_after}",
                recipient_list=[user.email],
            )

        elif instance.tx_type == Transaction.TYPE_WITHDRAW:
            Notification.objects.create(
                user=user,
                notif_type=Notification.TYPE_WITHDRAW,
                title="Withdrawal alert",
                message=f"Withdrawal of {instance.amount} processed. Balance: {instance.balance_after}",
                meta={"tx_id": instance.id},
            )

            safe_send_mail(
                subject="Withdrawal alert",
                message=f"Your withdrawal of {instance.amount} was processed. "
                        f"Balance: {instance.balance_after}",
                recipient_list=[user.email],
            )

        # --- 2️⃣ Low balance warning ---
        try:
            bal = float(instance.balance_after)
            if bal <= float(LOW_BALANCE_THRESHOLD):
                Notification.objects.create(
                    user=user,
                    notif_type=Notification.TYPE_LOW_BALANCE,
                    title="Low balance warning",
                    message=(
                        f"Your balance is low ({instance.balance_after}). "
                        f"Minimum recommended: {LOW_BALANCE_THRESHOLD}"
                    ),
                    meta={"balance": str(instance.balance_after)},
                )

                safe_send_mail(
                    subject="Low balance warning",
                    message=f"Your balance is low ({instance.balance_after}). Please top up.",
                    recipient_list=[user.email],
                )
        except Exception as e:
            print("Low balance warning error:", e)

        # --- 3️⃣ Web Push Notifications ---
        title = "Deposit confirmed" if instance.tx_type == "DEPOSIT" else "Withdrawal alert"
        body = f"{instance.tx_type} of {instance.amount}. Balance: {instance.balance_after}"
        safe_send_webpush(user, title, body)

        # --- 4️⃣ Firebase Push Notifications ---
        safe_send_fcm(user, title, body, instance.id)

    except Exception as e:
        print("Transaction signal error:", e)
