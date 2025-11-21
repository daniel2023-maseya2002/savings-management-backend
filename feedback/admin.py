from django.contrib import admin
from .models import Feedback, FeedbackComment

@admin.register(Feedback)
class FeedbackAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "title", "rating", "status", "created_at", "updated_at")
    list_filter = ("status", "is_public", "rating", "created_at")
    search_fields = ("title", "message", "user__username", "user__email")
    readonly_fields = ("created_at", "updated_at")


@admin.register(FeedbackComment)
class FeedbackCommentAdmin(admin.ModelAdmin):
    list_display = ("id", "feedback", "user", "is_internal", "created_at")
    list_filter = ("is_internal",)
    search_fields = ("content", "user__username", "feedback__title")