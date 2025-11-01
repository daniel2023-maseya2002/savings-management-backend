from django.contrib import admin
from django.contrib.auth import get_user_model
from .models import Device, Transaction, OneTimeCode, LoginActivity

# Register your models here.

User = get_user_model()

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("id", "username", "email", "balance", "is_active", "is_staff")
    search_fields = ("username", "email")
    readonly_fields = ("id",)

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
    search_fields = ("user_username", "user_email")

@admin.register(OneTimeCode)
class OneTimeCodeAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "channel", "destination", "created_at", "expires_at", "attempts")
    search_fields = ("user_username", "user_email", "destination")

@admin.register(LoginActivity)
class LoginActivityAdmin(admin.ModelAdmin):
    list_display = ("user", "device_id", "ip_address", "created_at", "success", "message")
    list_filter = ("success", "created_at")
    search_fields = ("user__username", "user__email", "device_id", "ip_address", "message")