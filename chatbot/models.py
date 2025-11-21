# chatbot/models.py
from django.db import models
from django.conf import settings

class Conversation(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="conversations"
    )
    user_message = models.TextField()
    bot_reply = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        user_repr = getattr(self.user, "username", None) or "Anonymous"
        return f"Conv {self.id} ({user_repr}) {self.created_at:%Y-%m-%d %H:%M}"
