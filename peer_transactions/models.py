# peer_transactions/models.py
import uuid
from decimal import Decimal
from django.conf import settings
from django.db import models
from django.utils import timezone

User = settings.AUTH_USER_MODEL


class UserBalance(models.Model):
    """
    Simple per-user balance snapshot used by the peer-to-peer transfer system.
    This is updated atomically when transfers are executed, and can be rebuilt
    by the management command if needed.

    NOTE:
    We use related_name='peer_balance' to avoid clashing with the existing
    User.balance DecimalField on your custom user model.
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="peer_balance",  # <--- CHANGED from "balance" to "peer_balance"
    )
    balance = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=Decimal("0.00"),
    )
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user} — {self.balance}"


class Transfer(models.Model):
    """
    Peer-to-peer transfer between two users.

    - amount: amount requested to move from sender to recipient.
    - fee: platform fee (e.g. 10% of amount).
    - net_amount: amount that the recipient actually receives.
      (in our current design, net_amount == amount, and sender pays amount + fee)
    - from_* / to_* balances: snapshot of balances before/after the transfer.
    """

    STATUS_REQUESTED = "requested"
    STATUS_PENDING = "pending"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"
    STATUS_CANCELLED = "cancelled"

    STATUS_CHOICES = [
      (STATUS_REQUESTED, "Requested"),
      (STATUS_PENDING, "Pending"),
      (STATUS_COMPLETED, "Completed"),
      (STATUS_FAILED, "Failed"),
      (STATUS_CANCELLED, "Cancelled"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="transfers_sent",
    )
    to_user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="transfers_received",
    )

    amount = models.DecimalField(max_digits=18, decimal_places=2)
    currency = models.CharField(max_length=12, default="USD")
    reference = models.CharField(max_length=128, blank=True, default="")
    note = models.TextField(blank=True, default="")

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_REQUESTED,
    )

    # === FEE FIELDS ===
    fee = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=Decimal("0.00"),
        help_text="Platform fee charged for this transfer.",
    )
    net_amount = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=Decimal("0.00"),
        help_text="Net amount delivered to recipient (after fee logic).",
    )

    # Auditable balance snapshots
    from_balance_before = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        null=True,
        blank=True,
    )
    from_balance_after = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        null=True,
        blank=True,
    )
    to_balance_before = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        null=True,
        blank=True,
    )
    to_balance_after = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        null=True,
        blank=True,
    )

    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["created_by"]),
            models.Index(fields=["to_user"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self):
        return f"Transfer {self.id} — {self.created_by} → {self.to_user} ${self.amount} [{self.status}]"

    # --- Helpers ---

    def set_fee_and_net(self, fee, net):
        """
        Store the computed fee + net amount on the transfer.
        This is called by the atomic transfer function before balances move.
        """
        self.fee = fee
        self.net_amount = net
        self.save(update_fields=["fee", "net_amount"])

    def mark_failed(self, reason: str = ""):
        """
        Mark transfer as failed and store the reason in metadata.
        """
        self.status = self.STATUS_FAILED
        self.metadata.setdefault("failure_reasons", []).append(reason)
        self.processed_at = timezone.now()
        self.save(update_fields=["status", "metadata", "processed_at"])

    def mark_completed(self, from_before, from_after, to_before, to_after):
        """
        Store snapshots and mark transfer as completed.
        """
        self.from_balance_before = from_before
        self.from_balance_after = from_after
        self.to_balance_before = to_before
        self.to_balance_after = to_after
        self.status = self.STATUS_COMPLETED
        self.processed_at = timezone.now()
        self.save(
            update_fields=[
                "from_balance_before",
                "from_balance_after",
                "to_balance_before",
                "to_balance_after",
                "status",
                "processed_at",
            ]
        )
