from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from django.core.mail import send_mail
from .models import Transaction, Notification, PushSubscription
from .utils import send_webpush

# Import your FCM helpers
from .models import FCMDevice
from .utils import send_fcm_notification

LOW_BALANCE_THRESHOLD = getattr(settings, 'LOW_BALANCE_THRESHOLD', 100.00)


@receiver(post_save, sender=Transaction)
def transaction_post_save(sender, instance: Transaction, created, **kwargs):
    if not created:
        return

    user = instance.user

    # 1️⃣ Create notifications for deposits and withdrawals
    if instance.tx_type == Transaction.TYPE_DEPOSIT:
        Notification.objects.create(
            user=user,
            notif_type=Notification.TYPE_DEPOSIT,
            title="Deposit confirmed",
            message=f"Deposit of {instance.amount} completed. Balance: {instance.balance_after}",
            meta={"tx_id": instance.id}
        )

        try:
            send_mail(
                subject="Deposit confirmation",
                message=f"Your deposit of {instance.amount} was successful. Balance: {instance.balance_after}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
            )
        except Exception:
            pass

    elif instance.tx_type == Transaction.TYPE_WITHDRAW:
        Notification.objects.create(
            user=user,
            notif_type=Notification.TYPE_WITHDRAW,
            title="Withdrawal alert",
            message=f"Withdrawal of {instance.amount} processed. Balance: {instance.balance_after}",
            meta={"tx_id": instance.id}
        )

        try:
            send_mail(
                subject="Withdrawal alert",
                message=f"Your withdrawal of {instance.amount} was processed. Balance: {instance.balance_after}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
            )
        except Exception:
            pass

    # 2️⃣ Low balance warning
    try:
        bal = float(instance.balance_after)
        if bal <= float(LOW_BALANCE_THRESHOLD):
            Notification.objects.create(
                user=user,
                notif_type=Notification.TYPE_LOW_BALANCE,
                title="Low balance warning",
                message=f"Your balance is low ({instance.balance_after}). Minimum recommended: {LOW_BALANCE_THRESHOLD}",
                meta={"balance": str(instance.balance_after)}
            )

            try:
                send_mail(
                    subject="Low balance warning",
                    message=f"Your balance is low ({instance.balance_after}). Please top up.",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                )
            except Exception:
                pass
    except Exception:
        pass

    # 3️⃣ Web Push Notifications
    title = "Deposit confirmed" if instance.tx_type == "DEPOSIT" else "Withdrawal alert"
    body = f"{instance.tx_type} of {instance.amount}. Balance: {instance.balance_after}"

    for sub in PushSubscription.objects.filter(user=user):
        send_webpush(sub, title, body)

    # 4️⃣ Firebase Push Notifications
    for d in FCMDevice.objects.filter(user=user):
        send_fcm_notification(
            registration_id=d.registration_id,
            title=title,
            body=body,
            data_message={"tx_id": str(instance.id)}
        )
