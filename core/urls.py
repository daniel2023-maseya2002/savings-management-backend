from django.urls import path
from .views import RegisterView, LoginView, DepositView, WithdrawView

urlpatterns = [
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("savings/deposit/", DepositView.as_view(), name="deposit"),
    path("savings/withdraw/", WithdrawView.as_view(), name="withdraw"),
]
