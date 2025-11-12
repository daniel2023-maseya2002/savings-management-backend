# ai_analysis/admin.py
from django.contrib import admin
from .models import AnalysisReport

@admin.register(AnalysisReport)
class AnalysisReportAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "created_by", "created_at")
    readonly_fields = ("params", "summary", "anomalies", "clusters")
    search_fields = ("name", "created_by__username")
