from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Device, Transaction, OneTimeCode, Notification,  PushSubscription, FCMDevice
from decimal import Decimal
from rest_framework import serializers
from django.conf import settings
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = ("username", "email", "password")

    def create(self, validated_data):
        password = validated_data.pop("password")
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
        fields = ("id", "username", "email", "balance")
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

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ('id','notif_type','title','message','created_at','read','meta')


class PushSubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = PushSubscription
        fields = ("id", "endpoint", "p256dh", "auth")

class FCMDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = FCMDevice
        fields = ("id", "registration_id", "device_info")

