# ai_analysis/serializers.py
from rest_framework import serializers
from .models import AnalysisReport, ReportNote, TransactionFlag, AuditLog
from core.models import Transaction
from django.contrib.auth import get_user_model



User = get_user_model()

class AnalysisReportSerializer(serializers.ModelSerializer):
    created_by = serializers.CharField(source="created_by.username", read_only=True)

    class Meta:
        model = AnalysisReport
        fields = "__all__"
        read_only_fields = ["id","created_by","summary","anomalies","clusters","created_at"]


class TransactionDetailSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    class Meta:
        model = Transaction
        fields = [
            "id",
            "tx_type",
            "amount",
            "balance_after",
            "created_at",
            "meta",
            "user",
        ]

    def get_user(self, obj):
        if not getattr(obj, "user", None):
            return None
        u = obj.user
        return {
            "id": u.id,
            "username": getattr(u, "username", None),
        }


class TransactionFlagSerializer(serializers.ModelSerializer):
    flagged_by = serializers.SerializerMethodField()
    resolved_by = serializers.SerializerMethodField()
    analysis_report = serializers.SerializerMethodField()  # will include limited report info if linked

    class Meta:
        model = TransactionFlag
        fields = [
            "id",
            "transaction_id",
            "transaction_ref",
            "flagged_by",
            "reason",
            "created_at",
            "resolved",
            "resolved_by",
            "resolved_at",
            "note",
            "metadata",
            "analysis_report",
        ]
        read_only_fields = ["id", "created_at"]

    def get_flagged_by(self, obj):
        u = getattr(obj, "flagged_by", None)
        if not u:
            return None
        return {"id": getattr(u, "pk", None), "username": getattr(u, "username", None)}

    def get_resolved_by(self, obj):
        u = getattr(obj, "resolved_by", None)
        if not u:
            return None
        return {"id": getattr(u, "pk", None), "username": getattr(u, "username", None)}

    def get_analysis_report(self, obj):
        # If your TransactionFlag links to an analysis report via FK named analysis_report
        ar = getattr(obj, "analysis_report", None)
        if not ar:
            return None
        # If you have a serializer for AnalysisReport, use it; otherwise return a small summary
        if AnalysisReportSerializer:
            return AnalysisReportSerializer(ar).data
        return {"id": getattr(ar, "pk", None), "name": getattr(ar, "name", None), "created_at": getattr(ar, "created_at", None)}
class ReportNoteSerializer(serializers.ModelSerializer):
    created_by = serializers.CharField(source="created_by.username", read_only=True)

    class Meta:
        model = ReportNote
        fields = ["id","report","created_by","body","created_at","pinned"]
        read_only_fields = ["id","created_by","created_at"]


class AuditLogSerializer(serializers.ModelSerializer):
    admin_username = serializers.CharField(source="admin.username", read_only=True)

    class Meta:
        model = AuditLog
        fields = ["id", "admin", "admin_username", "action_type", "target_type", "target_id",
            "metadata", "created_at", "admin_ip", "user_agent", "request_id",]
        read_only_fields = ["id","admin","created_at"]


class TransactionProxySerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        # Expose a reasonable subset by default; change to '__all__' if you want everything.
        fields = [
            "id",
            "amount",
            "tx_type",
            "status",
            "user_id",
            "reference",
            "balance_after",
            "created_at",
            "device",  # optional
        ]