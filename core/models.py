import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.conf import settings

User = settings.AUTH_USER_MODEL


# -----------------------------
# Custom User Model
# -----------------------------
class User(AbstractUser):
    email = models.EmailField(unique=True)
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    password = models.CharField(max_length=255)
    otp_reset_token = models.CharField(max_length=64, null=True, blank=True)

    REQUIRED_FIELDS = ["email"]
    USERNAME_FIELD = "username"


# -----------------------------
# Device Model
# -----------------------------
class Device(models.Model):
    STATUS_PENDING = "PENDING"
    STATUS_APPROVED = "APPROVED"
    STATUS_REJECTED = "REJECTED"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="devices")
    device_id = models.CharField(max_length=255)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_PENDING)
    created_at = models.DateTimeField(default=timezone.now)
    verified_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ("user", "device_id")

    def __str__(self):
        return f"{self.user.username} - {self.device_id} ({self.status})"


# -----------------------------
# Transaction Model
# -----------------------------
class Transaction(models.Model):
    TYPE_DEPOSIT = "DEPOSIT"
    TYPE_WITHDRAW = "WITHDRAW"
    TYPE_CHOICES = [
        (TYPE_DEPOSIT, "Deposit"),
        (TYPE_WITHDRAW, "Withdraw"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="transactions")
    tx_type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    balance_after = models.DecimalField(max_digits=12, decimal_places=2)
    created_at = models.DateTimeField(default=timezone.now)
    meta = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.tx_type} {self.amount} at {self.created_at}"


# -----------------------------
# One-Time Code Model (OTP)
# -----------------------------
class OneTimeCode(models.Model):
    CHANNEL_EMAIL = "email"
    CHANNEL_SMS = "sms"
    CHANNEL_CHOICES = [
        (CHANNEL_EMAIL, "Email"),
        (CHANNEL_SMS, "SMS"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="otps")
    code_hash = models.CharField(max_length=128)
    salt = models.CharField(max_length=32)
    channel = models.CharField(max_length=10, choices=CHANNEL_CHOICES)
    destination = models.CharField(max_length=255)  # email or phone
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    attempts = models.IntegerField(default=0)
    max_attempts = models.IntegerField(default=5)

    class Meta:
        indexes = [
            models.Index(fields=["user", "created_at"]),
        ]

    def is_expired(self):
        return timezone.now() >= self.expires_at

    def mark_used(self):
        self.used = True
        self.save(update_fields=["used"])

# -----------------------------
# Notification
# -----------------------------

class Notification(models.Model):
    TYPE_LOW_BALANCE = "LOW_BALANCE"
    TYPE_DEPOSIT = "DEPOSIT_CONFIRMED"
    TYPE_WITHDRAW = "WITHDRAW_ALERT"
    TYPE_DEVICE = "DEVICE_EVENT"

    # 🆕 Admin/system event types
    TYPE_NEW_USER = "NEW_USER"
    TYPE_USER_APPROVED = "USER_APPROVAL_REQUIRED"
    TYPE_USER_BLOCKED = "USER_BLOCKED"
    TYPE_PASSWORD_RESET = "PASSWORD_RESET"

    NOTIF_CHOICES = [
        (TYPE_LOW_BALANCE, "Low balance"),
        (TYPE_DEPOSIT, "Deposit confirmed"),
        (TYPE_WITHDRAW, "Withdraw alert"),
        (TYPE_DEVICE, "Device event"),
        # 🆕
        (TYPE_NEW_USER, "New user registered"),
        (TYPE_USER_APPROVED, "User approval required"),
        (TYPE_USER_BLOCKED, "User blocked"),
        (TYPE_PASSWORD_RESET, "Password reset"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notifications"
    )
    notif_type = models.CharField(max_length=32, choices=NOTIF_CHOICES)
    title = models.CharField(max_length=200)
    message = models.TextField()
    meta = models.JSONField(default=dict, blank=True)
    read = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]

    def mark_read(self):
        if not self.read:
            self.read = True
            self.save(update_fields=["read"])


# -----------------------------
# Low Balance
# -----------------------------

class LowBalanceRule(models.Model):
    """
    A server-side rule for low-balance alerts.
    You can create a simple global rule (user=None) or per-user rule (user=User).
    """
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="low_balance_rules", null=True, blank=True)
    threshold = models.DecimalField(max_digits=12, decimal_places=2, help_text="Trigger when balance <= threshold")
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    last_low_balance_reminder = models.DateField(null=True, blank=True)


    class Meta:
        ordering = ["-created_at"]

from django.db import models
from django.conf import settings

class PushSubscription(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="push_subscriptions")
    endpoint = models.TextField()
    p256dh = models.CharField(max_length=512)
    auth = models.CharField(max_length=256)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.endpoint[:60]}"
    
class FCMDevice(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="fcm_devices")
    registration_id = models.CharField(max_length=512, unique=True)
    device_info = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)



class LoginActivity(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="login_activities")
    device_id = models.CharField(max_length=255, blank=True, default="")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, default="")
    success = models.BooleanField(default=True)  # in case you want to also log failures later
    message = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "created_at"]),
        ]

    def __str__(self):
        return f"{self.user.username} @ {self.created_at} (device={self.device_id})"

