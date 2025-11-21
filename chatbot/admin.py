# chatbot/admin.py
from django.contrib import admin
from .models import Conversation

@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "user_message", "bot_reply", "created_at")
    list_filter = ("created_at", "user")
    search_fields = ("user__username", "user_message", "bot_reply")
    readonly_fields = ("created_at",)
