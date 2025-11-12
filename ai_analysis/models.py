# ai_analysis/models.py
from django.db import models
from django.conf import settings

class AnalysisReport(models.Model):
    """
    Stores admin-triggered transaction analysis reports.
    """
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    name = models.CharField(max_length=255, blank=True)
    params = models.JSONField(null=True, blank=True)
    summary = models.JSONField(null=True, blank=True)
    anomalies = models.JSONField(null=True, blank=True)
    clusters = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.name or 'Analysis'} ({self.created_at:%Y-%m-%d %H:%M})"
