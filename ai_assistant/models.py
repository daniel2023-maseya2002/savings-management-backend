# ai_assistant/models.py
import uuid

from django.conf import settings
from django.db import models


class AIConversation(models.Model):
    """
    One conversation (thread) between a user and the AI assistant.
    - grouped by user
    - has a mode (budget, transactions, notifications, general)
    """

    MODE_BUDGET = "budget"
    MODE_TRANSACTIONS = "transactions"
    MODE_NOTIFICATIONS = "notifications"
    MODE_GENERAL = "general"

    MODE_CHOICES = [
        (MODE_BUDGET, "Budget"),
        (MODE_TRANSACTIONS, "Transactions"),
        (MODE_NOTIFICATIONS, "Notifications"),
        (MODE_GENERAL, "General"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ai_conversations",
    )
    title = models.CharField(max_length=200, blank=True)
    mode = models.CharField(
        max_length=32,
        choices=MODE_CHOICES,
        default=MODE_GENERAL,
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self):
        return f"{self.user} — {self.title or self.mode} ({self.id})"


class AIMessage(models.Model):
    """
    A single message in a conversation.
    role:
      - user       : human user
      - assistant  : AI
      - system     : internal/system note (rare)
    """

    ROLE_USER = "user"
    ROLE_ASSISTANT = "assistant"
    ROLE_SYSTEM = "system"

    ROLE_CHOICES = [
        (ROLE_USER, "User"),
        (ROLE_ASSISTANT, "Assistant"),
        (ROLE_SYSTEM, "System"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    conversation = models.ForeignKey(
        AIConversation,
        on_delete=models.CASCADE,
        related_name="messages",
    )
    role = models.CharField(max_length=16, choices=ROLE_CHOICES)
    content = models.TextField()
    meta = models.JSONField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"[{self.role}] {self.content[:40]}..."
