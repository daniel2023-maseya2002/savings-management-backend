# ai_analysis/urls.py
from django.urls import path
from .views import (
    run_analysis_async,
    analysis_task_status,
    list_reports,
    get_report,
    export_report_csv,
    get_report_masked,
    transaction_detail,
)

urlpatterns = [
    path("admin/analysis/run/", run_analysis_async, name="ai-analysis-run-async"),
    path("admin/analysis/task/<str:task_id>/", analysis_task_status, name="ai-analysis-task-status"),
    path("admin/analysis/", list_reports, name="ai-analysis-list"),
    path("admin/analysis/<int:report_id>/", get_report, name="ai-analysis-get"),
    path("admin/analysis/<int:report_id>/export/", export_report_csv, name="ai-analysis-export"),
    path("admin/analysis/<int:report_id>/masked/", get_report_masked, name="ai-analysis-get-masked"),
    path("admin/transaction/<int:tx_id>/", transaction_detail, name="ai-transaction-detail"),
]
