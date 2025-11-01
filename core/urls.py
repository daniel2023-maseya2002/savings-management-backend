from django.urls import path, include
from .views import(
    RegisterView, LoginView, DepositView, WithdrawView, BalanceView, 
    TransactionListView,
    OTPVerifyView, OTPRequestView, DeviceVerifyView, UserDeviceListView,
    DeviceAdminUpdateView, DeviceRequestVerificationView, LogoutView,
    PushSubscriptionCreateView, FCMDeviceCreateView, OTPNewPasswordView, AdminDeviceListView,
    admin_approve_device, admin_reject_device, LowBalanceRuleDetailView, LowBalanceRuleListCreateView, notification_mark_read,
    admin_analytics, NotificationListView, AdminLoginActivityListView, AdminUserViewSet
) 
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register(r"admin/users", AdminUserViewSet, basename="admin-users")

urlpatterns = [
    path("", include(router.urls)),
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("savings/deposit/", DepositView.as_view(), name="deposit"),
    path("savings/withdraw/", WithdrawView.as_view(), name="withdraw"),
    path("savings/balance/", BalanceView.as_view(), name="balance"),
    path("savings/transactions/", TransactionListView.as_view(), name="transactions"),
    # path("auth/password-reset/", PasswordResetRequestView.as_view(), name="password_reset_request"),
    # path("auth/password-reset-confirm/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
    path("auth/otp/request/", OTPRequestView.as_view(), name="otp_request"),
    path("auth/otp/verify/", OTPVerifyView.as_view(), name="otp_verify"),
    path("auth/otp/new-password/", OTPNewPasswordView.as_view(), name="otp_new_password"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("admin/devices/<int:pk>/verify/", DeviceVerifyView.as_view(), name="device_verify"),

    # user device routes
    path("auth/devices/", UserDeviceListView.as_view(), name="user_devices"),
    path("auth/devices/<int:id>/request-verification/", DeviceRequestVerificationView.as_view(), name="device_request_verification"),


    # admin device approve
    path("auth/admin/devices/<uuid:id>/", DeviceAdminUpdateView.as_view(), name="admin_device_update"),

    # logout
    path("auth/logout/", LogoutView.as_view(), name="logout"),

    path("push/subscribe/", PushSubscriptionCreateView.as_view(), name="push_subscribe"),

    path("fcm/register/", FCMDeviceCreateView.as_view(), name="fcm_register"),

    # Admin device management
    path("admin/devices/", AdminDeviceListView.as_view(), name="admin_devices"),
    path("admin/devices/<int:pk>/approve/", admin_approve_device, name="admin_device_approve"),
    path("admin/devices/<int:pk>/reject/", admin_reject_device, name="admin_device_reject"),

    path("notifications/<int:pk>/mark-read/", notification_mark_read, name="notification_mark_read"),

    # low balance rules
    path("alerts/low-balance/", LowBalanceRuleListCreateView.as_view(), name="low_balance_rules"),
    path("alerts/low-balance/<int:pk>/", LowBalanceRuleDetailView.as_view(), name="low_balance_rule_detail"),

    # admin analytics
    path("admin/analytics/", admin_analytics, name="admin_analytics"),

    path("notifications/", NotificationListView.as_view(), name="notifications"),

    path("admin/login-activity/", AdminLoginActivityListView.as_view(), name="admin_login_activity"),


]
