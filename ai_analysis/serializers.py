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
        fields = ["id","created_by","name","params","summary","anomalies","clusters","created_at"]
        read_only_fields = ["id","created_by","summary","anomalies","clusters","created_at"]

class TransactionDetailSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    class Meta:
        model = Transaction
        # choose safe fields you want admins to see — include description, amounts, timestamps
        fields = [
            "id", "amount", "status", "created_at", "description", "reference", "user"
        ]
        # if your Transaction model doesn't have 'reference', remove it or replace with actual field name.

    def get_user(self, obj):
        if not getattr(obj, "user", None):
            return None
        u = obj.user
        return {"id": u.id, "username": getattr(u, "username", None)}

class TransactionFlagSerializer(serializers.ModelSerializer):
    flagged_by = serializers.CharField(source="flagged_by.username", read_only=True)
    resolved_by = serializers.CharField(source="resolved_by.username", read_only=True)

    class Meta:
        model = TransactionFlag
        fields = ["id","transaction_id","transaction_ref","flagged_by","reason","created_at","resolved","resolved_by","resolved_at","note"]
        read_only_fields = ["id","flagged_by","created_at","resolved_by","resolved_at"]


class ReportNoteSerializer(serializers.ModelSerializer):
    created_by = serializers.CharField(source="created_by.username", read_only=True)

    class Meta:
        model = ReportNote
        fields = ["id","report","created_by","body","created_at","pinned"]
        read_only_fields = ["id","created_by","created_at"]


class AuditLogSerializer(serializers.ModelSerializer):
    admin = serializers.CharField(source="admin.username", read_only=True)

    class Meta:
        model = AuditLog
        fields = ["id","admin","action_type","target_type","target_id","metadata","created_at"]
        read_only_fields = ["id","admin","created_at"]