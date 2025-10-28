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
    UserDTO,
    DeviceSerializer,
    StatsSerializer,
    NotificationSerializer,
    PushSubscriptionSerializer,
    FCMDeviceSerializer,
)
from .models import Device, Transaction, OneTimeCode, Notification, PushSubscription
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
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
from rest_framework.generics import UpdateAPIView
from rest_framework.throttling import ScopedRateThrottle
from django.shortcuts import get_object_or_404
from django.db.models import Sum, Count, F, Q
from datetime import timedelta
from django.db.models.functions import TruncMonth

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
    throttle_scope = "login"               # scoped throttle (config in settings)
    throttle_classes = []                  # set to ScopedRateThrottle where you configure

    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")
        device_id = request.data.get("device_id")

        if not username or not password:
            return Response({"detail": "username and password required"}, status=status.HTTP_400_BAD_REQUEST)

        if not device_id:
            return Response({"detail": "device_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, username=username, password=password)
        if not user:
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        # get or create device
        device, created = Device.objects.get_or_create(user=user, device_id=device_id)
        device.created_at = device.created_at or timezone.now()
        device.save(update_fields=["created_at"])

        # enforce approval
        if device.status != Device.STATUS_APPROVED:
            return Response({
                "detail": "Device not approved. Contact an admin to approve this device.",
                "device_status": device.status
            }, status=status.HTTP_403_FORBIDDEN)

        # issue tokens
        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)
        return Response({
            "access": access,
            "refresh": str(refresh),
            "user": UserDTO(user).data
        }, status=status.HTTP_200_OK)


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
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "otp"

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

class DeviceVerifyView(UpdateAPIView):
    """
    Allows an admin to verify or reject a user's device.
    Example:
      PATCH /api/admin/devices/<uuid>/verify/
      Body: { "status": "APPROVED" }  or  { "status": "REJECTED" }
    """
    permission_classes = [IsAdminUser]
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    lookup_field = "id"

    def patch(self, request, *args, **kwargs):
        device = self.get_object()
        status_value = request.data.get("status")

        if status_value not in [Device.STATUS_APPROVED, Device.STATUS_REJECTED]:
            return Response(
                {"detail": "Invalid status. Must be 'APPROVED' or 'REJECTED'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        device.status = status_value
        device.save(update_fields=["status"])

        return Response(
            {"detail": f"Device {status_value.lower()} successfully."},
            status=status.HTTP_200_OK,
        )

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
        Body: {"refresh": "<refresh_token>"}
        This blacklists the provided refresh token
        """
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"detail": "refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            token = RefreshToken(refresh_token)
            token.blacklist() # <-- raises if blacklisting fails
        except Exception:
            return Response({"detail": "Invalid token or token already blacklisted."}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({"detail": "Logout successful."}, status=status.HTTP_200_OK)
    
class UserDeviceListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = DeviceSerializer

    def get_queryset(self):
        # only devices belonging to the authenticated user
        return Device.objects.filter(user=self.request.user).order_by("-created_at")

class DeviceRequestVerificationView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, id, *args, **kwargs):
        # `id` is device UUID in path
        device = get_object_or_404(Device, id=id, user=request.user)

        if device.status == Device.STATUS_APPROVED:
            return Response({"detail": "Device already approved."}, status=status.HTTP_400_BAD_REQUEST)

        device.status = Device.STATUS_PENDING
        device.created_at = device.created_at or timezone.now()
        device.save(update_fields=["status"])

        return Response({"detail": "Verification requested."}, status=status.HTTP_200_OK)

class DeviceAdminUpdateView(UpdateAPIView):
    """
    Admin can PATCH to set status to APPROVED or REJECTED.
    PATCH body: {"status": "APPROVED"} or {"status":"REJECTED"}
    """
    permission_classes = [IsAdminUser]
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    lookup_field = "id"

class AnalyticsView(APIView):
    """
    GET /api/savings/analytics/  (admin or authenticated depending on needs)
    Returns basic stats and monthly aggregated series for charts.
    """
    permission_classes = [IsAuthenticated]   # change to IsAdminUser if only admins

    def get(self, request):
        user = request.user

        qs = Transaction.objects.filter(user=user)  # per-user stats
        totals = qs.aggregate(
            total_deposits=Sum('amount', filter=Q(tx_type='DEPOSIT')),
            total_withdrawals=Sum('amount', filter=Q(tx_type='WITHDRAW')),
            tx_count=Count('id'),
        )

        # fallback 0
        total_deposits = totals['total_deposits'] or 0
        total_withdrawals = totals['total_withdrawals'] or 0
        tx_count = totals['tx_count'] or 0

        # latest balance can come from user's balance field
        latest_balance = getattr(user, 'balance', 0)

        # monthly series for last 6 months
        six_months_ago = timezone.now() - timedelta(days=30 * 6)
        monthly = (
            qs.filter(created_at__gte=six_months_ago)
            .annotate(month=TruncMonth('created_at'))
            .values('month')
            .annotate(total=Sum('amount', filter=Q(tx_type='DEPOSIT')), withdrawals=Sum('amount', filter=Q(tx_type='WITHDRAW')))
            .order_by('month')
        )
        # Format monthly series as list of dicts
        monthly_series = [
            {
                'month': m['month'].date().isoformat(),
                'deposits': m.get('total') or 0,
                'withdrawals': m.get('withdrawals') or 0,
            }
            for m in monthly
        ]

        data = {
            'total_deposits': total_deposits,
            'total_withdrawals': total_withdrawals,
            'tx_count': tx_count,
            'latest_balance': latest_balance,
            'monthly': monthly_series,
        }
        # validate & return
        serializer = StatsSerializer({
            'total_deposits': data['total_deposits'],
            'total_withdrawals': data['total_withdrawals'],
            'tx_count': data['tx_count'],
            'latest_balance': data['latest_balance'],
        })
        return Response({'summary': serializer.data, 'monthly': monthly_series})

class NotificationListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = NotificationSerializer

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user).order_by('-created_at')
    

class PushSubscriptionCreateView(generics.CreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = PushSubscriptionSerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class FCMDeviceCreateView(generics.CreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = FCMDeviceSerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
