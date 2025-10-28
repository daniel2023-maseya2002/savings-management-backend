from django.urls import path
from .views import(
    RegisterView, LoginView, DepositView, WithdrawView, BalanceView, 
    TransactionListView, PasswordResetConfirmView, PasswordResetRequestView, 
    OTPVerifyView, OTPRequestView, DeviceVerifyView, UserDeviceListView,
    DeviceAdminUpdateView, DeviceRequestVerificationView, LogoutView,
    PushSubscriptionCreateView, FCMDeviceCreateView,
) 
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("savings/deposit/", DepositView.as_view(), name="deposit"),
    path("savings/withdraw/", WithdrawView.as_view(), name="withdraw"),
    path("savings/balance/", BalanceView.as_view(), name="balance"),
    path("savings/transactions/", TransactionListView.as_view(), name="transactions"),
    path("auth/password-reset/", PasswordResetRequestView.as_view(), name="password_reset_request"),
    path("auth/password-reset-confirm/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
    path("auth/otp/request/", OTPRequestView.as_view(), name="otp_request"),
    path("auth/otp/verify/", OTPVerifyView.as_view(), name="otp_verify"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("admin/devices/<uuid:id>/verify/", DeviceVerifyView.as_view(), name="device_verify"),

    # user device routes
path("auth/devices/", UserDeviceListView.as_view(), name="user_devices"),
path("auth/devices/<int:id>/request-verification/", DeviceRequestVerificationView.as_view(), name="device_request_verification"),


# admin device approve
path("auth/admin/devices/<uuid:id>/", DeviceAdminUpdateView.as_view(), name="admin_device_update"),

# logout
path("auth/logout/", LogoutView.as_view(), name="logout"),

path("push/subscribe/", PushSubscriptionCreateView.as_view(), name="push_subscribe"),

path("fcm/register/", FCMDeviceCreateView.as_view(), name="fcm_register"),


]
