from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Device, Transaction
from decimal import Decimal
from rest_framework import serializers
from django.conf import settings

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

class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = "__all__"

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