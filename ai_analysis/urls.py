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
     freeze_user,
    unfreeze_user,
    flag_transaction,
    resolve_flag,
    add_report_note,
    list_audit_logs,
)

urlpatterns = [
    path("admin/analysis/run/", run_analysis_async, name="ai-analysis-run-async"),
    path("admin/analysis/task/<str:task_id>/", analysis_task_status, name="ai-analysis-task-status"),
    path("admin/analysis/", list_reports, name="ai-analysis-list"),
    path("admin/analysis/<int:report_id>/", get_report, name="ai-analysis-get"),
    path("admin/analysis/<int:report_id>/export/", export_report_csv, name="ai-analysis-export"),
    path("admin/analysis/<int:report_id>/masked/", get_report_masked, name="ai-analysis-get-masked"),
    path("admin/transaction/<int:tx_id>/", transaction_detail, name="ai-transaction-detail"),

    # user freeze/unfreeze
    path("admin/user/<int:user_id>/freeze/", freeze_user, name="ai-freeze-user"),
    path("admin/user/<int:user_id>/unfreeze/", unfreeze_user, name="ai-unfreeze-user"),

    # flag/resolve transaction
    path("admin/transaction/<int:tx_id>/flag/", flag_transaction, name="ai-flag-transaction"),
    path("admin/flag/<int:flag_id>/resolve/", resolve_flag, name="ai-resolve-flag"),

    # report notes
    path("admin/report/<int:report_id>/note/", add_report_note, name="ai-add-report-note"),

    # audit logs
    path("admin/audit/", list_audit_logs, name="ai-audit-list"),
]
