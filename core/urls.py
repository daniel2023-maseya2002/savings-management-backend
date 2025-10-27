from django.urls import path
from .views import RegisterView, LoginView, DepositView, WithdrawView, BalanceView, TransactionListView, PasswordResetConfirmView, PasswordResetRequestView, OTPVerifyView, OTPRequestView
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
]
