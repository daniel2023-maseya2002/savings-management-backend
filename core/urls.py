from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    RegisterView, LoginView, DepositView, WithdrawView, BalanceView,
    TransactionListView, OTPVerifyView, OTPRequestView, DeviceVerifyView,
    UserDeviceListView, DeviceAdminUpdateView, DeviceRequestVerificationView,
    LogoutView, PushSubscriptionCreateView, FCMDeviceCreateView, OTPNewPasswordView,
    AdminDeviceListView, admin_approve_device, admin_reject_device,
    LowBalanceRuleDetailView, LowBalanceRuleListCreateView, notification_mark_read,
    admin_analytics, NotificationListView, AdminLoginActivityListView,
    AdminUserViewSet, AdminNotificationListView, AdminNotificationViewSet,
    admin_mark_notification_read, mark_notification_read,
    mark_all_notifications_read, admin_mark_all_notifications_read
)

# ✅ Single unified router
router = DefaultRouter()
router.register(r"admin/users", AdminUserViewSet, basename="admin-users")
router.register(r"admin/notifications", AdminNotificationViewSet, basename="admin-notifications")

urlpatterns = [
    path("", include(router.urls)),

    # Authentication
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),

    # OTP
    path("auth/otp/request/", OTPRequestView.as_view(), name="otp_request"),
    path("auth/otp/verify/", OTPVerifyView.as_view(), name="otp_verify"),
    path("auth/otp/new-password/", OTPNewPasswordView.as_view(), name="otp_new_password"),

    # Savings
    path("savings/deposit/", DepositView.as_view(), name="deposit"),
    path("savings/withdraw/", WithdrawView.as_view(), name="withdraw"),
    path("savings/balance/", BalanceView.as_view(), name="balance"),
    path("savings/transactions/", TransactionListView.as_view(), name="transactions"),

    # Devices
    path("auth/devices/", UserDeviceListView.as_view(), name="user_devices"),
    path("auth/devices/<int:id>/request-verification/", DeviceRequestVerificationView.as_view(), name="device_request_verification"),
    path("admin/devices/<int:pk>/verify/", DeviceVerifyView.as_view(), name="device_verify"),
    path("auth/admin/devices/<uuid:id>/", DeviceAdminUpdateView.as_view(), name="admin_device_update"),
    path("admin/devices/", AdminDeviceListView.as_view(), name="admin_devices"),
    path("admin/devices/<int:pk>/approve/", admin_approve_device, name="admin_device_approve"),
    path("admin/devices/<int:pk>/reject/", admin_reject_device, name="admin_device_reject"),

    # Push Notifications
    path("push/subscribe/", PushSubscriptionCreateView.as_view(), name="push_subscribe"),
    path("fcm/register/", FCMDeviceCreateView.as_view(), name="fcm_register"),

    # Normal user notifications
    path("notifications/", NotificationListView.as_view(), name="notifications"),
    path("notifications/<int:pk>/mark-read/", mark_notification_read, name="notification_mark_read"),
    path("notifications/mark-all-read/", mark_all_notifications_read, name="notification_mark_all_read"),

    # ✅ Admin notifications
    path("admin/notifications/", AdminNotificationListView.as_view(), name="admin-notifications"),
    path("admin/notifications/<int:pk>/mark_read/", admin_mark_notification_read, name="admin_mark_notification_read"),
    path("admin/notifications/mark_all_read/", admin_mark_all_notifications_read, name="admin_mark_all_notifications_read"),

    # Admin analytics and activity
    path("admin/analytics/", admin_analytics, name="admin_analytics"),
    path("admin/login-activity/", AdminLoginActivityListView.as_view(), name="admin_login_activity"),

    # Low balance rules
    path("alerts/low-balance/", LowBalanceRuleListCreateView.as_view(), name="low_balance_rules"),
    path("alerts/low-balance/<int:pk>/", LowBalanceRuleDetailView.as_view(), name="low_balance_rule_detail"),
]
