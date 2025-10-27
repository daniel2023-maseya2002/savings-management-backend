from django.contrib import admin
from django.contrib.auth import get_user_model
from .models import Device, Transaction

# Register your models here.

User = get_user_model()

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("id", "username", "email", "balance", "is_staff", "is_superuser")

@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "device_id", "status", "created_at", "verified_at")
    list_filter = ("status",)
    actions = ["approve_devices", "reject_devices"]

    def approve_devices(self, request, queryset):
        queryset.update(status=Device.STATUS_APPROVED)
    approve_devices.short_description = "Approve selected devices"

    def reject_devices(self, request, queryset):
        queryset.update(status=Device.STATUS_REJECTED)
    reject_devices.short_description = "Reject selected devices"


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "tx_type", "amount", "balance_after", "created_at")