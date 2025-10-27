from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

# Create your models here.

class User(AbstractUser):
    email = models.EmailField(unique=True)
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0)

    REQUIRED_FIELDS = ["email"]
    USERNAME_FIELD = "username"

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