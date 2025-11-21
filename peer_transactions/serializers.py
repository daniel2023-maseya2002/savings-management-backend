# peer_transactions/serializers.py
from decimal import Decimal, ROUND_DOWN, getcontext

from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import Transfer

getcontext().prec = 28

User = get_user_model()

# Configurable fee percent (default 10%)
FEE_PERCENT = getattr(
    settings,
    "PEER_TRANSACTIONS_FEE_PERCENT",
    Decimal("0.10"),  # 10%
)

# Minimum allowed transfer amount
MIN_TRANSFER_AMOUNT = Decimal("100.00")


class TransferCreateSerializer(serializers.ModelSerializer):
    """
    Serializer used when a user *creates* a transfer.
    - Client provides: to_username, amount, currency, reference, note, metadata
    - Server computes: fee, net_amount
    """

    # User will send the username; internally we convert it to a User instance
    to_username = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = Transfer
        fields = (
            "id",
            "to_username",
            "amount",
            "currency",
            "reference",
            "note",
            "metadata",
            "fee",
            "net_amount",
        )
        read_only_fields = ("id", "fee", "net_amount")

    # === Field-level validators ===

    def validate_amount(self, value):
        """
        Ensure:
        - amount is positive
        - amount >= MIN_TRANSFER_AMOUNT (100)
        - rounded to 2 decimals
        """
        if value is None:
            raise serializers.ValidationError("Amount is required.")

        value = Decimal(str(value))

        if value <= 0:
            raise serializers.ValidationError("Amount must be greater than zero.")

        if value < MIN_TRANSFER_AMOUNT:
            raise serializers.ValidationError(
                f"Minimum transfer amount is {MIN_TRANSFER_AMOUNT}."
            )

        # Normalize to cents
        return value.quantize(Decimal("0.01"), rounding=ROUND_DOWN)

    def validate_to_username(self, v):
        """
        Ensure destination user exists and is not the same as the sender.
        """
        request = self.context.get("request")
        try:
            user = User.objects.get(username=v)
        except User.DoesNotExist:
            raise serializers.ValidationError("Destination user not found.")

        # Prevent self-transfer
        if request and request.user.is_authenticated:
            if user == request.user:
                raise serializers.ValidationError(
                    "You cannot send money to yourself."
                )

        # We return the User instance; create() will receive this
        return user

    def validate(self, attrs):
        """
        - Compute fee and net_amount.
        - Quick check: does sender have enough balance to cover amount + fee?
          (The authoritative check still happens inside perform_atomic_transfer.)
        """
        request = self.context.get("request")
        if not request or not request.user or not request.user.is_authenticated:
            raise serializers.ValidationError("Authentication is required.")

        sender = request.user

        amount = Decimal(str(attrs.get("amount")))
        fee = (amount * FEE_PERCENT).quantize(Decimal("0.01"), rounding=ROUND_DOWN)
        net = amount.quantize(Decimal("0.01"), rounding=ROUND_DOWN)

        # Store computed values temporarily in attrs (not model fields yet)
        attrs["_computed_fee"] = fee
        attrs["_computed_net"] = net

        # 🔍 Quick balance check using core.User.balance
        sender_balance = getattr(sender, "balance", Decimal("0.00")) or Decimal("0.00")
        total_required = (amount + fee).quantize(
            Decimal("0.01"),
            rounding=ROUND_DOWN,
        )

        if sender_balance < total_required:
            # non_field_errors is a common DRF pattern for global errors
            raise serializers.ValidationError(
                {"non_field_errors": ["Insufficient funds to cover amount plus fee."]}
            )

        return attrs

    def create(self, validated_data):
        """
        Create Transfer in 'requested' status with fee + net prefilled.
        The actual money movement is done later by the atomic transfer helper.
        """
        # This is a User instance because validate_to_username returned it
        to_user = validated_data.pop("to_username")

        fee = validated_data.pop("_computed_fee", None)
        net = validated_data.pop("_computed_net", None)

        created_by = self.context["request"].user

        transfer = Transfer.objects.create(
            created_by=created_by,
            to_user=to_user,
            fee=fee or Decimal("0.00"),
            net_amount=net or validated_data.get("amount"),
            **validated_data,
        )
        return transfer


class TransferSerializer(serializers.ModelSerializer):
    """
    Full read serializer for listing / viewing transfers.
    Includes usernames and all fields.
    """
    created_by_username = serializers.CharField(
        source="created_by.username",
        read_only=True,
    )
    to_username = serializers.CharField(
        source="to_user.username",
        read_only=True,
    )

    class Meta:
        model = Transfer
        fields = "__all__"
        read_only_fields = (
            "from_balance_before",
            "from_balance_after",
            "to_balance_before",
            "to_balance_after",
            "processed_at",
        )
