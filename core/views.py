import hashlib
import hmac
import secrets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions, generics
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    AmountSerializer,
    TransactionResponseSerializer,
    TransactionSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    OTPRequestSerializer,
    OTPVerifySerializer,
)
from .models import Device, Transaction, OneTimeCode
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.db import transaction
from decimal import Decimal
from django.utils import timezone
from rest_framework.pagination import PageNumberPagination
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse
from .utils import generate_otp
from .notify import send_otp_email, send_otp_sms
from datetime import timedelta
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

User = get_user_model()


# ------------------ REGISTER ------------------
class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        s = RegisterSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        user = s.save()
        return Response(
            {"id": user.id, "username": user.username, "email": user.email},
            status=status.HTTP_201_CREATED,
        )


# ------------------ LOGIN ------------------
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
            return Response(
                {"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
            )

        # Get or create device
        device, created = Device.objects.get_or_create(user=user, device_id=device_id)

        if device.status == Device.STATUS_PENDING:
            return Response(
                {"detail": "Device pending approval"},
                status=status.HTTP_403_FORBIDDEN,
            )
        if device.status == Device.STATUS_REJECTED:
            return Response(
                {"detail": "Device rejected"}, status=status.HTTP_403_FORBIDDEN
            )

        # Approved -> issue tokens
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


# ------------------ DEPOSIT ------------------
class DepositView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        s = AmountSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        amount = s.validated_data["amount"]

        with transaction.atomic():
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


# ------------------ WITHDRAW ------------------
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
                return Response(
                    {"detail": "Insufficient funds"}, status=status.HTTP_400_BAD_REQUEST
                )

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


# ------------------ BALANCE ------------------
class BalanceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({"balance": str(user.balance)}, status=status.HTTP_200_OK)


# ------------------ TRANSACTIONS ------------------
class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100


class TransactionListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TransactionSerializer
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        user = self.request.user
        qs = Transaction.objects.filter(user=user).order_by("-created_at")

        tx_type = self.request.query_params.get("type")
        if tx_type:
            qs = qs.filter(tx_type=tx_type.upper())

        return qs


# ------------------ PASSWORD RESET ------------------
@method_decorator(csrf_exempt, name="dispatch")
class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        s = PasswordResetRequestSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        email = s.validated_data["email"]

        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            return Response(
                {"detail": "If an account with that email exists, a password reset email has been sent."},
                status=status.HTTP_200_OK,
            )

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_path = reverse("password_reset_confirm")
        reset_url = f"{request.scheme}://{request.get_host()}{reset_path}?uid={uid}&token={token}"

        subject = "Password reset request"
        message = (
            f"Hi {user.username},\n\n"
            "We received a request to reset your password.\n"
            f"Reset link: {reset_url}\n\n"
            "If you didn’t request this, you can ignore this email.\n\n"
            "Thanks."
        )

        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)
        return Response(
            {"detail": "If an account with that email exists, a password reset email has been sent."},
            status=status.HTTP_200_OK,
        )


@method_decorator(csrf_exempt, name="dispatch")
class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        s = PasswordResetConfirmSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        uid = s.validated_data["uid"]
        token = s.validated_data["token"]
        new_password = s.validated_data["new_password"]

        try:
            uid_decoded = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=uid_decoded)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"detail": "Invalid UID"}, status=status.HTTP_400_BAD_REQUEST)

        if not default_token_generator.check_token(user, token):
            return Response({"detail": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({"detail": "Password has been reset successfully."}, status=status.HTTP_200_OK)


# ------------------ OTP ------------------
@method_decorator(csrf_exempt, name="dispatch")
class OTPRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        s = OTPRequestSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        identifier = s.validated_data["identifier"]
        channel = s.validated_data["channel"]

        try:
            if "@" in identifier:
                user = User.objects.get(email__iexact=identifier)
                dest = user.email
                channel = "email"
            else:
                user = User.objects.get(phone=identifier)
                dest = user.phone
                channel = "sms"
        except User.DoesNotExist:
            return Response({"detail": "If an account exists, an OTP was sent."}, status=status.HTTP_200_OK)

        last = OneTimeCode.objects.filter(user=user, channel=channel).order_by("-created_at").first()
        if last and (timezone.now() - last.created_at).total_seconds() < 60:
            return Response({"detail": "OTP recently sent. Try again later."}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        otp = generate_otp()
        salt = secrets.token_hex(8)
        key = (salt + settings.SECRET_KEY).encode()
        code_hash = hmac.new(key, otp.encode(), hashlib.sha256).hexdigest()
        expire = timezone.now() + timedelta(minutes=10)

        OneTimeCode.objects.create(
            user=user,
            code_hash=code_hash,
            salt=salt,
            channel=channel,
            destination=dest,
            expires_at=expire,
        )

        if channel == "email":
            send_otp_email(dest, otp, expire)
        else:
            send_otp_sms(dest, otp, expire)

        return Response({"detail": "If an account exists, an OTP was sent."}, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name="dispatch")
class OTPVerifyView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        s = OTPVerifySerializer(data=request.data)
        s.is_valid(raise_exception=True)
        identifier = s.validated_data["identifier"]
        otp = s.validated_data["otp"]
        new_password = s.validated_data.get("new_password")

        try:
            if "@" in identifier:
                user = User.objects.get(email__iexact=identifier)
                channel = "email"
            else:
                user = User.objects.get(phone=identifier)
                channel = "sms"
        except User.DoesNotExist:
            return Response({"detail": "Invalid code or identifier."}, status=status.HTTP_400_BAD_REQUEST)

        otc = OneTimeCode.objects.filter(user=user, channel=channel, used=False).order_by("-created_at").first()
        if not otc or otc.is_expired():
            return Response({"detail": "Invalid or expired code."}, status=status.HTTP_400_BAD_REQUEST)
        if otc.attempts >= otc.max_attempts:
            return Response({"detail": "Too many attempts."}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        key = (otc.salt + settings.SECRET_KEY).encode()
        expected = hmac.new(key, otp.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, otc.code_hash):
            otc.attempts += 1
            otc.save(update_fields=["attempts"])
            return Response({"detail": "Invalid code."}, status=status.HTTP_400_BAD_REQUEST)

        otc.mark_used()

        if new_password:
            user.set_password(new_password)
            user.save()
            return Response({"detail": "Password reset successful."}, status=status.HTTP_200_OK)

        return Response({"detail": "OTP verified."}, status=status.HTTP_200_OK)
