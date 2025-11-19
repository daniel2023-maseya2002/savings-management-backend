# ai_analysis/models.py
from django.db import models
from django.conf import settings

class AnalysisReport(models.Model):
    name = models.CharField(max_length=255, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    params = models.JSONField(default=dict, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    anomalies = models.JSONField(default=list, blank=True)
    clusters = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.name or 'Analysis'} ({self.created_at:%Y-%m-%d %H:%M})"

class TransactionFlag(models.Model):
    """
    Record that an admin flagged a transaction for review.
    """
    FLAG_REASON_MAX = 512

    transaction_id = models.BigIntegerField()  # store id to avoid FK issues if transaction deleted
    transaction_ref = models.CharField(max_length=255, blank=True, null=True)
    flagged_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    reason = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False)
    resolved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="flags_resolved")
    resolved_at = models.DateTimeField(null=True, blank=True)
    note = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    analysis_report = models.ForeignKey("AnalysisReport", on_delete=models.SET_NULL, null=True, blank=True, related_name="flags")


    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"Flag tx={self.transaction_id} by {getattr(self.flagged_by,'username',None)}"


class ReportNote(models.Model):
    """
    Admin note attached to an AnalysisReport (for workflow/collaboration).
    """
    report = models.ForeignKey("ai_analysis.AnalysisReport", on_delete=models.CASCADE, related_name="notes")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    pinned = models.BooleanField(default=False)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"Note by {getattr(self.created_by,'username',None)} on report {self.report_id}"


class AuditLog(models.Model):
    ADMIN_ACTIONS = [
        ("freeze_user", "freeze_user"),
        ("unfreeze_user", "unfreeze_user"),
        ("flag_transaction", "flag_transaction"),
        ("resolve_flag", "resolve_flag"),
        ("add_note", "add_note"),
        ("export_report", "export_report"),
    ]

    admin = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    action_type = models.CharField(max_length=64, choices=ADMIN_ACTIONS)
    target_type = models.CharField(max_length=64, blank=True, null=True)
    target_id = models.BigIntegerField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    admin_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True, null=True)
    request_id = models.CharField(max_length=64, blank=True, null=True)

    class Meta:
        ordering = ("-created_at",)
