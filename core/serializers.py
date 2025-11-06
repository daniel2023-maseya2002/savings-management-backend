from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Device, Transaction, OneTimeCode, Notification,  PushSubscription, FCMDevice, LowBalanceRule, LoginActivity
from decimal import Decimal
from rest_framework import serializers
from django.conf import settings
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
import re

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        max_length=128,
        style={"input_type": "password"},
        error_messages={"min_length": "Password must be at least 8 characters long."},
    )
    confirm_password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )

    class Meta:
        model = User
        fields = ("username", "email", "password", "confirm_password")

    def validate_username(self, value):
        if not re.match(r"^[a-zA-Z0-9_.-]+$", value):
            raise serializers.ValidationError(
                "Username can only contain letters, numbers, dots, underscores, and hyphens."
            )
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("This username is already taken.")
        return value

    def validate_email(self, value):
        value = value.lower().strip()
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already registered.")
        return value

    def validate(self, data):
        password = data.get("password")
        confirm_password = data.get("confirm_password")

        if password != confirm_password:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})

        # Optional: enforce stronger passwords
        if not re.search(r"[A-Z]", password):
            raise serializers.ValidationError({"password": "Must include at least one uppercase letter."})
        if not re.search(r"[a-z]", password):
            raise serializers.ValidationError({"password": "Must include at least one lowercase letter."})
        if not re.search(r"\d", password):
            raise serializers.ValidationError({"password": "Must include at least one number."})
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise serializers.ValidationError({"password": "Must include at least one special character."})

        return data

    def create(self, validated_data):
        password = validated_data.pop("password")
        validated_data.pop("confirm_password", None)
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    device_id = serializers.CharField()

class UserDTO(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "balance", "is_staff", "is_superuser")
        read_only_fields = fields


class DeviceSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    class Meta:
        model = Device
        fields = ["id", "user", "username", "device_id", "status", "created_at", "verified_at"]
        read_only_fields = ["id", "user", "status", "created_at", "verified_at", "username"]

class DeviceCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ["device_id"]

    def create(self, validated_data):
        user = self.context["request"].user
        # if device exists for this return existing? we'll create but unique_together prevents dup
        return Device.objects.create(user=user, **validated_data)

class DeviceAdminSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    user_email = serializers.CharField(source="user.email", read_only=True)

    class Meta:
        model = Device
        fields = ["id", "user", "username", "user_email", "device_id", "status", "created_at", "verified_at"]
        read_only_fields = ["id", "user", "username", "user_email", "device_id", "created_at", "verified_at"]

class TransactionSerializer(serializers.ModelSerializer):
    class meta:
        model = Transaction
        fields = "__all__"


# Use an Amount serializer for deposit/withdraw
class AmountSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=12, decimal_places=2, min_value=Decimal("0.01"))

class TransactionResponseSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    tx_type = serializers.CharField()
    amount = serializers.DecimalField(max_digits=12, decimal_places=2)
    balance_after =  serializers.DecimalField(max_digits=12, decimal_places=2)
    created_at = serializers.DateTimeField()

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ("id", "tx_type", "amount", "balance_after", "created_at", "meta")
        read_only_fields = fields

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8, write_only=True)

class OTPRequestSerializer(serializers.Serializer):
    identifier = serializers.CharField()  # phone or email, or username
    channel = serializers.ChoiceField(choices=("email","sms"))

class OTPVerifySerializer(serializers.Serializer):
    identifier = serializers.CharField(required=True, allow_blank=False)
    otp = serializers.CharField(required=True, allow_blank=False)
    new_password = serializers.CharField(min_length=8, required=False, allow_blank=True)

class OneTimeCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = OneTimeCode
        fields = ("id", "channel", "destination", "created_at", "expires_at", "used", "attempts")
        read_only_fields = fields

class StatsSerializer(serializers.Serializer):
    total_deposits = serializers.DecimalField(max_digits=12, decimal_places=2)
    total_withdrawals = serializers.DecimalField(max_digits=12, decimal_places=2)
    tx_count = serializers.IntegerField()
    latest_balance = serializers.DecimalField(max_digits=12, decimal_places=2)

# serializers.py
from rest_framework import serializers
from core.models import Notification


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = [
            "id",
            "notif_type",
            "title",
            "message",
            "meta",      # ✅ correct field name
            "read",      # ✅ correct field name
            "created_at",
        ]
        read_only_fields = ["id", "created_at"]



class NotificationCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ["title", "body", "data", "read"]  # used if server/API wants to create notifications manually

class LowBalanceRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = LowBalanceRule
        fields = ["id", "user", "threshold", "enabled", "created_at"]
        read_only_fields = ["id", "created_at"]
class PushSubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = PushSubscription
        fields = ("id", "endpoint", "p256dh", "auth")

class FCMDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = FCMDevice
        fields = ("id", "registration_id", "device_info")


class LoginActivitySerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    email = serializers.EmailField(source="user.email", read_only=True)

    class Meta:
        model = LoginActivity
        fields = [
            "id", "username", "email", "device_id",
            "ip_address", "user_agent", "success", "message", "created_at"
        ]

# Admin management

class AdminUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # expose safe fields + admin-controllable flags
        fields = [
            "id", "username", "email", "balance",
            "is_active", "is_staff", "date_joined", "last_login",
        ]
        read_only_fields = ["date_joined", "last_login", "id"]

class AdminUserCreateSerializer(serializers.ModelSerializer):
    # only on create
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ["username", "email", "password", "balance", "is_active", "is_staff"]

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

class AdminSetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(min_length=8)
