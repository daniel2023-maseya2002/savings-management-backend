import threading
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from django.core.mail import send_mail
from .models import Transaction, Notification, PushSubscription, FCMDevice, LowBalanceRule
from core.utils.push_utils import send_webpush, send_fcm_notification
from core.utils.notify_admins import notify_admins
from django.contrib.auth import get_user_model

User = get_user_model()

def safe_send_mail(subject, message, recipient_list):
    def _send():
        try:
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, recipient_list, fail_silently=True)
        except Exception as e:
            print("Email send error:", e)
    threading.Thread(target=_send, daemon=True).start()

@receiver(post_save, sender=Transaction)
def transaction_post_save(sender, instance: Transaction, created, **kwargs):
    if not created:
        return

    user = instance.user
    print("Signal fired for transaction:", instance.id, instance.tx_type, instance.balance_after)

    try:
        # 1️⃣ Notify deposit or withdrawal
        if instance.tx_type == Transaction.TYPE_DEPOSIT:
            Notification.objects.create(
                user=user,
                notif_type=Notification.TYPE_DEPOSIT,
                title="Deposit confirmed",
                message=f"Deposit of {instance.amount} completed. Balance: {instance.balance_after}",
                meta={"tx_id": str(instance.id)},
            )
            safe_send_mail("Deposit confirmation",
                           f"Your deposit of {instance.amount} was successful. Balance: {instance.balance_after}",
                           [user.email])

        elif instance.tx_type == Transaction.TYPE_WITHDRAW:
            Notification.objects.create(
                user=user,
                notif_type=Notification.TYPE_WITHDRAW,
                title="Withdrawal alert",
                message=f"Withdrawal of {instance.amount} processed. Balance: {instance.balance_after}",
                meta={"tx_id": str(instance.id)},
            )
            safe_send_mail("Withdrawal alert",
                           f"Your withdrawal of {instance.amount} was processed. Balance: {instance.balance_after}",
                           [user.email])

        # 2️⃣ Low balance rule check
        rules = LowBalanceRule.objects.filter(enabled=True).filter(user=user) | LowBalanceRule.objects.filter(enabled=True, user__isnull=True)
        rules = rules.order_by('-created_at')

        rule_threshold = None
        for rule in rules:
            rule_threshold = rule.threshold
            break

        if rule_threshold is not None:
            bal = float(instance.balance_after)
            if bal <= float(rule_threshold):
                Notification.objects.create(
                    user=user,
                    notif_type=Notification.TYPE_LOW_BALANCE,
                    title="Low balance warning",
                    message=f"Your balance is low ({instance.balance_after}). Threshold: {rule_threshold}.",
                    meta={"balance": str(instance.balance_after)},
                )
                safe_send_mail("Low balance warning",
                               f"Your balance is low ({instance.balance_after}). Please top up.",
                               [user.email])

    except Exception as e:
        print("Transaction signal error:", e)

@receiver(post_save, sender=User)
def user_event_notifier(sender, instance, created, **kwargs):
    if created:
        # 🆕 When a new user registers
        notify_admins(
            notif_type=Notification.TYPE_NEW_USER,
            title="🆕 New User Registered",
            message=f"{instance.username} has created an account and awaits approval.",
            meta={"user_id": instance.id, "username": instance.username}
        )
    elif not instance.is_active:
        # 🚫 When a user gets blocked/deactivated
        notify_admins(
            notif_type=Notification.TYPE_USER_BLOCKED,
            title="🚫 User Blocked",
            message=f"{instance.username} has been blocked by an admin.",
            meta={"user_id": instance.id, "username": instance.username}
        )
