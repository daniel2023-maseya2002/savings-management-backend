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
    """
    Generic audit log for admin actions.
    action_type: e.g., 'freeze_user','unfreeze_user','flag_transaction','resolve_flag','add_report_note'
    target_type: 'user'|'transaction'|'report'|'flag' ...
    target_id: integer id of the target
    admin: FK to user who performed action
    metadata: JSONField with optional context
    """
    ACTION_CHOICES = [
        ("freeze_user","freeze_user"),
        ("unfreeze_user","unfreeze_user"),
        ("flag_transaction","flag_transaction"),
        ("resolve_flag","resolve_flag"),
        ("add_report_note","add_report_note"),
        ("update_report_note","update_report_note"),
    ]

    admin = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="audit_actions")
    action_type = models.CharField(max_length=64, choices=ACTION_CHOICES)
    target_type = models.CharField(max_length=64)
    target_id = models.BigIntegerField(null=True, blank=True)
    metadata = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.action_type} by {getattr(self.admin,'username',None)} on {self.target_type}:{self.target_id}"