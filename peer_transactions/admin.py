# peer_transactions/admin.py
from django.contrib import admin
from .models import UserBalance, Transfer

@admin.register(UserBalance)
class UserBalanceAdmin(admin.ModelAdmin):
    list_display = ("user", "balance", "updated_at")
    search_fields = ("user__username", "user__email")


@admin.register(Transfer)
class TransferAdmin(admin.ModelAdmin):
    list_display = ("id", "created_by", "to_user", "amount", "currency", "status", "created_at", "processed_at")
    list_filter = ("status", "currency", "created_at")
    search_fields = ("created_by__username", "to_user__username", "reference")
    readonly_fields = ("from_balance_before", "from_balance_after", "to_balance_before", "to_balance_after", "processed_at")

