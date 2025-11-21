# feedback/models.py
from django.conf import settings
from django.db import models
import uuid

User = settings.AUTH_USER_MODEL

class Feedback(models.Model):
    STATUS_CHOICES = (
        ("open", "Open"),
        ("in_progress", "In progress"),
        ("closed", "Closed"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    message = models.TextField()
    rating = models.IntegerField(null=True, blank=True)
    is_public = models.BooleanField(default=False)
    # set default here:
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default="in_progress")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} ({self.status})"


class FeedbackComment(models.Model):
    """
    Comments on feedback. Admins/staff can comment; users can comment on their own feedback.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    feedback = models.ForeignKey(Feedback, related_name="comments", on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name="feedback_comments", on_delete=models.CASCADE)
    content = models.TextField()
    is_internal = models.BooleanField(default=False)  # admin-only internal notes
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"Comment by {self.user} on {self.feedback.id}"
