from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegisterSerializer, LoginSerializer, AmountSerializer, TransactionResponseSerializer
from .models import Device, Transaction
from rest_framework.permissions import IsAuthenticated
from django.db import transaction
from decimal import Decimal
from django.utils import timezone

User = get_user_model()

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        s = RegisterSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        user = s.save()
        return Response({"id": user.id, "username": user.username, "email": user.email}, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data.get("username")
        password = serializer.validated_data.get("password")
        device_id = serializer.validated_data.get("device_id")

        user = authenticate(request, username=username, password=password)
        if not user:
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        # get or create device
        device, created = Device.objects.get_or_create(user=user, device_id=device_id)

        if device.status == Device.STATUS_PENDING:
            return Response({"detail": "Device pending approval"}, status=status.HTTP_403_FORBIDDEN)
        if device.status == Device.STATUS_REJECTED:
            return Response({"detail": "Device rejected"}, status=status.HTTP_403_FORBIDDEN)

        # APPROVED -> issue tokens
        refresh = RefreshToken.for_user(user)
        data = {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "balance": str(user.balance),
            },
        }
        return Response(data, status=status.HTTP_200_OK)

# Make the deposit 
class DepositView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        s = AmountSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        amount = s.validated_data["amount"]

        with transaction.atomic():
            # Lock the user row to avoid race conditions
            user = User.objects.select_for_update().get(pk=request.user.pk)
            new_balance = (user.balance or Decimal("0.00")) + amount
            user.balance = new_balance
            user.save()

            tx = Transaction.objects.create(
                user=user,
                tx_type=Transaction.TYPE_DEPOSIT,
                amount=amount,
                balance_after=new_balance,
                created_at=timezone.now(),
            )

        resp = TransactionResponseSerializer(tx).data
        return Response(resp, status=status.HTTP_201_CREATED)


# Withdraw money
class WithdrawView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        s = AmountSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        amount = s.validated_data["amount"]

        with transaction.atomic():
            user = User.objects.select_for_update().get(pk=request.user.pk)
            current_balance = user.balance or Decimal("0.00")
            if current_balance < amount:
                return Response({"detail": "Insufficient funds"}, status=status.HTTP_400_BAD_REQUEST)
            
            new_balance = current_balance - amount
            user.balance = new_balance
            user.save()

            tx = Transaction.objects.create(
                user=user,
                tx_type=Transaction.TYPE_WITHDRAW,
                amount=amount,
                balance_after=new_balance,
                created_at=timezone.now(),
            )
        
        resp = TransactionResponseSerializer(tx).data
        return Response(resp, status=status.HTTP_201_CREATED)


#  Check the balance
class BalanceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({"balance": str(user.balance)}, status=status.HTTP_200_OK)
