import hashlib
import hmac
import secrets
import traceback
import threading
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions, generics, viewsets
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
    DeviceCreateSerializer, 
    DeviceAdminSerializer,
    LowBalanceRuleSerializer,
    LoginActivitySerializer,
    AdminUserSerializer,
    AdminUserCreateSerializer,
    AdminSetPasswordSerializer,
)
from .models import Device, Transaction, OneTimeCode, Notification, PushSubscription, LowBalanceRule,  LoginActivity
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
from .utils import generate_otp, get_client_ip
from .notify import send_otp_email, send_otp_sms
from datetime import timedelta
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework.generics import UpdateAPIView, ListAPIView
from rest_framework.throttling import ScopedRateThrottle
from django.shortcuts import get_object_or_404
from django.db.models import Sum, Count, F, Q
from datetime import timedelta
from django.db.models.functions import TruncMonth
from rest_framework.decorators import api_view, permission_classes, action
from django.utils.dateparse import parse_datetime
from rest_framework.filters import SearchFilter, OrderingFilter
from core import models
from .utils.email_utils import send_branded_email
from  rest_framework.pagination import PageNumberPagination
from .utils.email_utils import send_branded_email
from core.utils.notify_admins import notify_admins
from .utils import create_user_notification  # helper from earlier

User = get_user_model()


class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_staff)


# ------------------ REGISTER ------------------
class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            print("❌ REGISTER ERRORS:", serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save()

        # ✅ Create device in PENDING state if device_id is sent
        device_id = request.data.get("device_id")
        if device_id:
            Device.objects.get_or_create(
                user=user,
                device_id=device_id,
                defaults={"status": Device.STATUS_PENDING},
            )

        # 🔔 Notify admins about new user registration (approval required)
        notify_admins(
            notif_type=Notification.TYPE_USER_APPROVED,
            title="🧾 New User Registration",
            message=f"User '{user.username}' has created an account and is awaiting device approval.",
            meta={"user_id": user.id},
        )

        return Response(
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "message": "Account created successfully! Awaiting device approval.",
            },
            status=status.HTTP_201_CREATED,
        )
# ------------------ LOGIN ------------------
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            username = request.data.get("username")
            password = request.data.get("password")
            device_id = request.data.get("device_id")

            if not username or not password:
                return Response(
                    {"detail": "Username and password are required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = authenticate(request, username=username, password=password)
            if not user:
                return Response(
                    {"detail": "Invalid username or password."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # 🧑‍💼 Admins bypass device checks
            if user.is_staff or user.is_superuser:
                refresh = RefreshToken.for_user(user)

                # ✅ Record login activity
                LoginActivity.objects.create(
                    user=user,
                    device_id=device_id or "",
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    success=True,
                    message="Admin login",
                )

                user.last_login = timezone.now()
                user.save(update_fields=["last_login"])

                return Response(
                    {
                        "access": str(refresh.access_token),
                        "refresh": str(refresh),
                        "user": {
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "balance": str(user.balance),
                            "is_staff": user.is_staff,
                            "last_login": user.last_login,
                        },
                    },
                    status=status.HTTP_200_OK,
                )

            # 🧠 Normal users must include device_id
            if not device_id:
                return Response(
                    {"detail": "Device ID is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Ensure device exists
            with transaction.atomic():
                device, created = Device.objects.select_for_update().get_or_create(
                    user=user, device_id=device_id
                )
                if created:
                    device.created_at = timezone.now()
                    device.save(update_fields=["created_at"])

            # 🧱 Check approval
            if hasattr(device, "status") and device.status != Device.STATUS_APPROVED:
                LoginActivity.objects.create(
                    user=user,
                    device_id=device_id,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    success=False,
                    message="Device not approved",
                )
                return Response(
                    {
                        "detail": "Device not approved. Please wait for admin approval.",
                        "device_status": device.status,
                        "approved": False,
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

            # ✅ Issue JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token

            # ✅ Update last login
            user.last_login = timezone.now()
            user.save(update_fields=["last_login"])

            # ✅ Record login activity
            LoginActivity.objects.create(
                user=user,
                device_id=device_id,
                ip_address=get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                success=True,
                message="login",
            )

            # ✅ Build response with extended info
            return Response(
                {
                    "access": str(access_token),
                    "refresh": str(refresh),
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "balance": str(user.balance),
                        "is_staff": user.is_staff,
                        "last_login": user.last_login,
                    },
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            print("🔥 LOGIN ERROR:", e)
            traceback.print_exc()
            return Response(
                {"detail": f"Server error: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class AdminLoginActivityListView(ListAPIView):
    permission_classes = [IsAdminUser]
    serializer_class = LoginActivitySerializer

    def get_queryset(self):
        qs = LoginActivity.objects.select_related("user").all()

        # Filters: ?user=dan or ?email=... or ?from=ISO&to=ISO or ?q=search
        username = self.request.query_params.get("user")
        email = self.request.query_params.get("email")
        q = self.request.query_params.get("q")
        from_dt = self.request.query_params.get("from")
        to_dt = self.request.query_params.get("to")

        if username:
            qs = qs.filter(user__username__iexact=username)
        if email:
            qs = qs.filter(user__email__iexact=email)
        if from_dt:
            dt = parse_datetime(from_dt)
            if dt:
                qs = qs.filter(created_at__gte=dt)
        if to_dt:
            dt = parse_datetime(to_dt)
            if dt:
                qs = qs.filter(created_at__lte=dt)
        if q:
            qs = qs.filter(
                models.Q(user__username__icontains=q) |
                models.Q(user__email__icontains=q) |
                models.Q(device_id__icontains=q) |
                models.Q(ip_address__icontains=q) |
                models.Q(user_agent__icontains=q) |
                models.Q(message__icontains=q)
            )

        return qs.order_by("-created_at")
    

class AdminUserViewSet(viewsets.ModelViewSet):
    """
    Admin CRUD over users.
    """
    permission_classes = [IsAdminUser]
    queryset = User.objects.all().order_by("-date_joined")
    serializer_class = AdminUserSerializer
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ["username", "email"]
    ordering_fields = ["date_joined", "last_login", "username", "email", "balance"]

    def get_serializer_class(self):
        if self.action == "create":
            return AdminUserCreateSerializer
        return AdminUserSerializer

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        # safety rails: prevent deleting self or superuser (optional)
        if instance == request.user:
            return Response({"detail": "You cannot delete yourself."}, status=400)
        if instance.is_superuser:
            return Response({"detail": "Superuser cannot be deleted."}, status=400)
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=["post"])
    def set_password(self, request, pk=None):
        """
        POST /api/admin/users/{id}/set_password/
        body: { "new_password": "..." }
        """
        user = self.get_object()
        # safety: allow setting your own password too
        ser = AdminSetPasswordSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        user.set_password(ser.validated_data["new_password"])
        user.save(update_fields=["password"])
        return Response({"detail": "Password updated."})

    @action(detail=True, methods=["post"])
    def toggle_active(self, request, pk=None):
        """
        POST /api/admin/users/{id}/toggle_active/
        """
        user = self.get_object()
        if user == request.user:
            return Response({"detail": "You cannot deactivate yourself."}, status=400)
        user.is_active = not user.is_active
        user.save(update_fields=["is_active"])
        return Response({"detail": "Toggled.", "is_active": user.is_active})

    @action(detail=True, methods=["post"])
    def set_role(self, request, pk=None):
        """
        POST /api/admin/users/{id}/set_role/
        body: { "is_staff": true/false }
        """
        user = self.get_object()
        if user == request.user and request.data.get("is_staff") is False:
            return Response({"detail": "You cannot remove your own admin role."}, status=400)
        is_staff = bool(request.data.get("is_staff"))
        user.is_staff = is_staff
        user.save(update_fields=["is_staff"])
        return Response({"detail": "Role updated.", "is_staff": user.is_staff})


# ------------------ DEPOSIT ------------------
class DepositView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        s = AmountSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        amount = s.validated_data["amount"]

        try:
            with transaction.atomic():
                user = User.objects.select_for_update().get(pk=request.user.pk)
                new_balance = (user.balance or Decimal("0.00")) + amount
                user.balance = new_balance
                user.save(update_fields=["balance"])

                tx = Transaction.objects.create(
                    user=user,
                    tx_type=Transaction.TYPE_DEPOSIT,
                    amount=amount,
                    balance_after=new_balance,
                    created_at=timezone.now(),
                )

                # ✅ Deposit success notification
                Notification.objects.create(
                    user=user,
                    notif_type=Notification.TYPE_DEPOSIT,
                    title="Deposit Successful",
                    message=f"You deposited {amount}. Your new balance is {new_balance}.",
                    meta={"amount": str(amount), "balance": str(new_balance)},
                )

                # ✅ Deposit email
                try:
                    send_branded_email(
                        subject="Deposit Successful — CreditJambo",
                        to_email=user.email,
                        template_name="emails/deposit_success.html",
                        context={"user": user, "amount": amount, "balance": new_balance},
                    )
                except Exception as e:
                    print(f"⚠️ Deposit email failed: {e}")

                # ✅ Low balance rule check
                rules = LowBalanceRule.objects.filter(enabled=True).filter(
                    Q(user=user) | Q(user__isnull=True)
                )

                if not rules.exists():
                    # Auto fallback rule (system-wide 50 threshold)
                    rules = [type("Rule", (), {"threshold": Decimal("50.00")})()]

                for rule in rules:
                    if user.balance <= rule.threshold:
                        Notification.objects.create(
                            user=user,
                            notif_type=Notification.TYPE_LOW_BALANCE,
                            title="Low Balance Warning",
                            message=f"Your balance is {user.balance}. Threshold: {rule.threshold}.",
                            meta={"threshold": str(rule.threshold)},
                        )

                        # ✅ Send daily reminder email asynchronously
                        def _daily_reminder():
                            try:
                                # Prevent duplicate same-day email
                                if getattr(user, "last_low_balance_reminder", None) == date.today():
                                    return
                                send_branded_email(
                                    subject="Low Balance Warning — CreditJambo",
                                    to_email=user.email,
                                    template_name="emails/low_balance_warning.html",
                                    context={
                                        "user": user,
                                        "balance": user.balance,
                                        "threshold": rule.threshold,
                                    },
                                )
                                # Save reminder date
                                user.last_low_balance_reminder = date.today()
                                user.save(update_fields=["last_low_balance_reminder"])
                            except Exception as e:
                                print(f"⚠️ Low balance reminder failed: {e}")

                        threading.Thread(target=_daily_reminder, daemon=True).start()
                        break

            resp = TransactionResponseSerializer(tx).data
            return Response(resp, status=status.HTTP_201_CREATED)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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
                    {"detail": "Insufficient funds"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            new_balance = current_balance - amount
            user.balance = new_balance
            user.save(update_fields=["balance"])

            tx = Transaction.objects.create(
                user=user,
                tx_type=Transaction.TYPE_WITHDRAW,
                amount=amount,
                balance_after=new_balance,
                created_at=timezone.now(),
            )

        # ✅ Withdrawal notification
        try:
            Notification.objects.create(
                user=user,
                notif_type=Notification.TYPE_WITHDRAW,
                title="Withdrawal Successful",
                message=f"You withdrew {amount}. Your new balance is {new_balance}.",
                meta={"amount": str(amount), "balance": str(new_balance)},
            )
        except Exception as e:
            print(f"⚠️ Notification create failed: {e}")

        # ✅ Email
        try:
            send_branded_email(
                subject="Withdrawal Successful — CreditJambo",
                to_email=user.email,
                template_name="emails/withdraw_success.html",
                context={"user": user, "amount": amount, "balance": new_balance},
            )
        except Exception as e:
            print(f"⚠️ Withdraw email failed: {e}")

        # ✅ Low balance logic
        try:
            rules = LowBalanceRule.objects.filter(enabled=True).filter(
                Q(user=user) | Q(user__isnull=True)
            )

            if not rules.exists():
                rules = [type("Rule", (), {"threshold": Decimal("50.00")})()]

            for rule in rules:
                if user.balance <= rule.threshold:
                    Notification.objects.create(
                        user=user,
                        notif_type=Notification.TYPE_LOW_BALANCE,
                        title="Low Balance Warning",
                        message=f"Your balance is {user.balance}. Threshold: {rule.threshold}.",
                        meta={"threshold": str(rule.threshold)},
                    )

                    # ✅ Daily email reminder
                    def _daily_reminder():
                        try:
                            if getattr(user, "last_low_balance_reminder", None) == date.today():
                                return
                            send_branded_email(
                                subject="Low Balance Warning — CreditJambo",
                                to_email=user.email,
                                template_name="emails/low_balance_warning.html",
                                context={
                                    "user": user,
                                    "balance": user.balance,
                                    "threshold": rule.threshold,
                                },
                            )
                            user.last_low_balance_reminder = date.today()
                            user.save(update_fields=["last_low_balance_reminder"])
                        except Exception as e:
                            print(f"⚠️ Low balance reminder failed: {e}")

                    threading.Thread(target=_daily_reminder, daemon=True).start()
                    break
        except Exception as e:
            print(f"⚠️ Low balance notification failed: {e}")

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
# @method_decorator(csrf_exempt, name="dispatch")
# class PasswordResetRequestView(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         s = PasswordResetRequestSerializer(data=request.data)
#         s.is_valid(raise_exception=True)
#         email = s.validated_data["email"]

#         try:
#             user = User.objects.get(email__iexact=email)
#         except User.DoesNotExist:
#             return Response(
#                 {"detail": "If an account with that email exists, a password reset email has been sent."},
#                 status=status.HTTP_200_OK,
#             )

#         uid = urlsafe_base64_encode(force_bytes(user.pk))
#         token = default_token_generator.make_token(user)
#         reset_path = reverse("password_reset_confirm")
#         reset_url = f"{request.scheme}://{request.get_host()}{reset_path}?uid={uid}&token={token}"

#         subject = "Password reset request"
#         message = (
#             f"Hi {user.username},\n\n"
#             "We received a request to reset your password.\n"
#             f"Reset link: {reset_url}\n\n"
#             "If you didn’t request this, you can ignore this email.\n\n"
#             "Thanks."
#         )

#         send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)
#         return Response(
#             {"detail": "If an account with that email exists, a password reset email has been sent."},
#             status=status.HTTP_200_OK,
#         )


# @method_decorator(csrf_exempt, name="dispatch")
# class PasswordResetConfirmView(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         s = PasswordResetConfirmSerializer(data=request.data)
#         s.is_valid(raise_exception=True)
#         uid = s.validated_data["uid"]
#         token = s.validated_data["token"]
#         new_password = s.validated_data["new_password"]

#         try:
#             uid_decoded = force_str(urlsafe_base64_decode(uid))
#             user = User.objects.get(pk=uid_decoded)
#         except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#             return Response({"detail": "Invalid UID"}, status=status.HTTP_400_BAD_REQUEST)

#         if not default_token_generator.check_token(user, token):
#             return Response({"detail": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

#         user.set_password(new_password)
#         user.save()
#         return Response({"detail": "Password has been reset successfully."}, status=status.HTTP_200_OK)


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

        user = None
        dest = None
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

        try:
            if channel == "email":
                send_branded_email(
                    subject="Your Verification Code — CreditJambo",
                    to_email=user.email,
                    template_name="emails/otp_code.html",
                    context={"user": user, "otp": otp, "expire": expire},
                )
            else:
                send_otp_sms(
                    dest,
                    f"Muraho {user.first_name}, your CreditJambo OTP is {otp}. It expires in 10 minutes."
                )
        except Exception as e:
            print(f"⚠️ OTP send failed: {e}")

        # 🔔 Notify admins (optional): password reset requested
        notify_admins(
            notif_type=Notification.TYPE_PASSWORD_RESET,
            title="🔐 Password Reset Requested",
            message=f"User '{user.username}' requested a password reset OTP.",
            meta={"user_id": user.id},
        )

        return Response({"detail": "If an account exists, an OTP was sent."}, status=status.HTTP_200_OK)

@method_decorator(csrf_exempt, name="dispatch")
class OTPVerifyView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        print("DEBUG OTP VERIFY DATA:", request.data)
        s = OTPVerifySerializer(data=request.data)
        s.is_valid(raise_exception=True)
        identifier = s.validated_data["identifier"]
        otp = s.validated_data["otp"]
        print("DEBUG identifier:", identifier, "otp:", otp)

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

        # ✅ store token directly on user instead of profile
        reset_token = secrets.token_hex(16)
        user.otp_reset_token = reset_token
        user.save(update_fields=["otp_reset_token"])

        return Response({
            "detail": "OTP verified successfully.",
            "reset_token": reset_token
        }, status=status.HTTP_200_OK)

@method_decorator(csrf_exempt, name="dispatch")
class OTPNewPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        reset_token = request.data.get("reset_token")
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        if not reset_token:
            return Response({"detail": "Missing reset token."}, status=status.HTTP_400_BAD_REQUEST)
        if not new_password or not confirm_password:
            return Response({"detail": "Please fill all fields."}, status=status.HTTP_400_BAD_REQUEST)
        if new_password != confirm_password:
            return Response({"detail": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # ✅ get from user.otp_reset_token (not user.profile)
            user = User.objects.get(otp_reset_token=reset_token)
        except User.DoesNotExist:
            return Response({"detail": "Invalid or expired reset token."}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.otp_reset_token = None  # clear token after use
        user.save(update_fields=["password", "otp_reset_token"])

        return Response({"detail": "Password reset successful!"}, status=status.HTTP_200_OK)

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
    
class UserDeviceListView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = DeviceSerializer

    def get_queryset(self):
        # only devices belonging to the authenticated user
        return Device.objects.filter(user=self.request.user).order_by("-created_at")
    
    def get_serializer_class(self):
        if self.request.method == "POST":
            return DeviceCreateSerializer
        return DeviceSerializer
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

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

# ------------------ NOTIFICATIONS ------------------
class NotificationListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = NotificationSerializer
    pagination_class = None

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user).order_by("-created_at")


@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated])
def notification_mark_read(request, pk):
    notif = Notification.objects.filter(user=request.user, id=pk).first()
    if not notif:
        return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
    notif.mark_read()
    return Response({"detail": "Marked read."})


# Low-balance rule management (admin or owner)
class LowBalanceRuleListCreateView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]  # admin only for global ops
    serializer_class = LowBalanceRuleSerializer

    def get_queryset(self):
        # Admins can view all; normal users see their own rules
        if self.request.user.is_staff:
            return LowBalanceRule.objects.all()
        return LowBalanceRule.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        if not self.request.user.is_staff:
            serializer.save(user=self.request.user)
        else:
            serializer.save()

class LowBalanceRuleDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = LowBalanceRuleSerializer
    lookup_field = "pk"

    def get_queryset(self):
        if self.request.user.is_staff:
            return LowBalanceRule.objects.all()
        return LowBalanceRule.objects.filter(user=self.request.user)

    def perform_update(self, serializer):
        rule = serializer.save()
        user = self.request.user

        # ✅ Check immediately if user already under threshold
        if user.balance is not None and user.balance <= rule.threshold:
            Notification.objects.create(
                user=user,
                notif_type=Notification.TYPE_LOW_BALANCE,
                title="Low Balance Warning",
                message=f"Your balance ({user.balance}) is already below your new threshold ({rule.threshold}).",
                meta={"threshold": str(rule.threshold)},
            )

            # optional: email immediately
            from django.conf import settings
            from django.core.mail import send_mail
            import threading

            def _send_email():
                send_mail(
                    subject="Low Balance Warning",
                    message=f"Hi {user.username}, your balance ({user.balance}) is already below your new rule ({rule.threshold}).",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=True,
                )

            threading.Thread(target=_send_email, daemon=True).start()


# Lightweight analytics endpoint for admin dashboard
@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def admin_analytics(request):
    if not request.user.is_staff:
        return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

    try:
        now = timezone.now()
        since = now - timezone.timedelta(days=30)
        txs = Transaction.objects.filter(created_at__gte=since)

        total_deposits = (
            txs.filter(tx_type=Transaction.TYPE_DEPOSIT)
            .aggregate(total=Sum("amount"))["total"]
            or Decimal("0.00")
        )
        total_withdraws = (
            txs.filter(tx_type=Transaction.TYPE_WITHDRAW)
            .aggregate(total=Sum("amount"))["total"]
            or Decimal("0.00")
        )
        tx_count = txs.count()

        # Safely convert decimals to floats
        top_users = [
            {
                "id": u["id"],
                "username": u["username"],
                "balance": float(u["balance"]) if isinstance(u["balance"], Decimal) else u["balance"],
            }
            for u in User.objects.order_by("-balance").values("id", "username", "balance")[:5]
        ]

        pending_devices = Device.objects.filter(status=Device.STATUS_PENDING).count()
        total_users = User.objects.count()
        active_devices = Device.objects.filter(status=Device.STATUS_APPROVED).count()

        recent_alerts = list(
            Notification.objects.filter(notif_type=Notification.TYPE_LOW_BALANCE)
            .order_by("-created_at")
            .values("id", "user__username", "message", "created_at")[:5]
        )

        payload = {
            "summary": {
                "total_deposits_last_30d": float(total_deposits),
                "total_withdraws_last_30d": float(total_withdraws),
                "tx_count_last_30d": tx_count,
                "total_users": total_users,
                "active_devices": active_devices,
                "pending_devices": pending_devices,
            },
            "top_users_by_balance": top_users,
            "recent_low_balance_alerts": recent_alerts,
        }

        return Response(payload, status=status.HTTP_200_OK)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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

# Admin: list all pending devices (or all devices)
class AdminDeviceListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]
    serializer_class = DeviceAdminSerializer

    def get_queryset(self):
        status_filter = self.request.query_params.get("status")
        qs = Device.objects.all().order_by("-created_at")
        if status_filter:
            qs = qs.filter(status=status_filter.upper())
        return qs

# ✅ Admin: approve device
@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated])
def admin_approve_device(request, pk):
    try:
        device = get_object_or_404(Device, pk=pk)

        if device.status == Device.STATUS_APPROVED:
            return Response({"detail": "Already approved."}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Approve and mark verified
        device.status = Device.STATUS_APPROVED
        device.verified_at = timezone.now()
        device.save(update_fields=["status", "verified_at"])

        # ✅ Create user notification
        create_user_notification(
            user=device.user,
            notif_type=Notification.TYPE_USER_APPROVED,
            title="✅ Device Approved",
            message=f"Your device '{device.device_id}' has been approved by admin.",
            meta={"device_id": str(device.id), "status": device.status},
        )

        # ✅ Notify all admins
        notify_admins(
            notif_type=Notification.TYPE_USER_APPROVED,
            title="🟢 Device Approved",
            message=f"Device {device.device_id} for user '{device.user.username}' was approved.",
            meta={"device_id": str(device.id), "user_id": device.user.id},
        )

        return Response({"detail": "Device approved.", "id": str(device.id)})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ✅ Admin: reject device
@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated])
def admin_reject_device(request, pk):
    try:
        device = get_object_or_404(Device, pk=pk)

        if device.status == Device.STATUS_REJECTED:
            return Response({"detail": "Already rejected."}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Update status
        device.status = Device.STATUS_REJECTED
        device.save(update_fields=["status"])

        # ✅ Notify user
        create_user_notification(
            user=device.user,
            notif_type=Notification.TYPE_USER_REJECTED,
            title="🚫 Device Rejected",
            message=f"Your device '{device.device_id}' has been rejected by admin.",
            meta={"device_id": str(device.id), "status": device.status},
        )

        # ✅ Notify all admins
        notify_admins(
            notif_type=Notification.TYPE_USER_REJECTED,
            title="🔴 Device Rejected",
            message=f"Device {device.device_id} for user '{device.user.username}' was rejected.",
            meta={"device_id": str(device.id), "user_id": device.user.id},
        )

        return Response({"detail": "Device rejected.", "id": str(device.id)})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminNotificationListView(generics.ListAPIView):
    """
    ✅ List notifications for admin users
    """
    permission_classes = [permissions.IsAuthenticated, IsAdmin]
    serializer_class = NotificationSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return Notification.objects.filter(user__is_staff=True).order_by("-created_at")
        return Notification.objects.filter(user=user).order_by("-created_at")


# ==============================
# ✅ NORMAL USER ENDPOINTS
# ==============================

@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated])
def mark_notification_read(request, pk):
    """
    ✅ Mark a single notification as read (for normal user)
    """
    notif = get_object_or_404(Notification, pk=pk, user=request.user)
    if hasattr(notif, "mark_read"):
        notif.mark_read()
    else:
        notif.read = True
        notif.save(update_fields=["read"])
    return Response({"detail": "Notification marked as read."}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated])
def mark_all_notifications_read(request):
    """
    ✅ Mark all notifications for the current user as read
    """
    updated = Notification.objects.filter(user=request.user, read=False).update(read=True)
    return Response(
        {"detail": f"{updated} notifications marked as read."},
        status=status.HTTP_200_OK,
    )


# ==============================
# ✅ ADMIN ENDPOINTS
# ==============================


@api_view(["PATCH"])
@permission_classes([permissions.IsAuthenticated, IsAdmin])
def admin_mark_notification_read(request, pk):
    """
    ✅ Allows admin to mark any notification as read
    """
    try:
        notif = get_object_or_404(Notification, pk=pk)
        # handle both 'read' and 'is_read' field naming
        if hasattr(notif, "read"):
            notif.read = True
        elif hasattr(notif, "read"):
            notif.is_read = True
        notif.save()
        return Response(
            {"detail": "Admin notification marked as read."},
            status=status.HTTP_200_OK,
        )
    except Exception as e:
        traceback.print_exc()
        return Response(
            {"detail": f"Error: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated, IsAdmin])
def admin_mark_all_notifications_read(request):
    """
    ✅ Allows admin to mark ALL notifications as read
    """
    try:
        # handle both field names
        if "is_read" in [f.name for f in Notification._meta.fields]:
            updated = Notification.objects.filter(read=False).update(read=True)
        else:
            updated = Notification.objects.filter(read=False).update(read=True)

        return Response(
            {"detail": f"{updated} admin notifications marked as read."},
            status=status.HTTP_200_OK,
        )
    except Exception as e:
        traceback.print_exc()
        return Response(
            {"detail": f"Error: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )



class AdminNotificationViewSet(viewsets.ModelViewSet):
    queryset = Notification.objects.all().order_by("-created_at")
    serializer_class = NotificationSerializer  # adjust to your serializer

    @action(detail=True, methods=["patch"], url_path="mark_read")
    def mark_read(self, request, pk=None):
        try:
            notif = self.get_object()
            notif.is_read = True
            notif.save()
            return Response({"message": "Notification marked as read."}, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({"error": "Notification not found."}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=["post"], url_path="mark_all_read")
    def mark_all_read(self, request):
        updated = Notification.objects.filter(read=False).update(read=True)
        return Response(
            {"message": f"{updated} notifications marked as read."},
            status=status.HTTP_200_OK
        )