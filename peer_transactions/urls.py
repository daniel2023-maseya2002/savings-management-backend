from django.urls import path
from .views import (
    CreateTransferView,
    UserTransfersListView,
    TransferDetailView,
    AdminApproveView,
    AdminTransfersListView,   # <-- NEW
)

urlpatterns = [
    # Create a transfer (POST)
    path("transfers/create/", CreateTransferView.as_view(), name="peer-transfer-create"),

    # List my transfers (GET)
    path("transfers/mine/", UserTransfersListView.as_view(), name="peer-transfer-list"),

    # Admin: list ALL transfers (GET)
    path("transfers/admin/", AdminTransfersListView.as_view(), name="peer-transfer-admin-list"),

    # Transfer detail (GET)
    path("transfers/<uuid:id>/", TransferDetailView.as_view(), name="peer-transfer-detail"),

    # Admin manual approve/fail (POST)
    path("transfers/<uuid:id>/admin-approve/", AdminApproveView.as_view(), name="peer-transfer-admin-approve"),
]
