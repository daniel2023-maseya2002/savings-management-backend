# ai_analysis/admin.py
from django.contrib import admin
from .models import AnalysisReport, TransactionFlag, ReportNote, AuditLog

@admin.register(AnalysisReport)
class AnalysisReportAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "created_by", "created_at")
    readonly_fields = ("params", "summary", "anomalies", "clusters")
    search_fields = ("name", "created_by__username")

@admin.register(TransactionFlag)
class TransactionFlagAdmin(admin.ModelAdmin):
    list_display = ("id","transaction_id","flagged_by","created_at","resolved")
    list_filter = ("resolved",)
    search_fields = ("transaction_id","transaction_ref","flagged_by__username")

@admin.register(ReportNote)
class ReportNoteAdmin(admin.ModelAdmin):
    list_display = ("id","report","created_by","created_at","pinned")
    search_fields = ("report__id","created_by__username","body")

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("id","action_type","admin","target_type","target_id","created_at")
    search_fields = ("admin__username","action_type","target_type")
