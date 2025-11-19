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
    list_transaction_flags,
    add_note_to_analysis,
    ai_analysis_list,
    TransactionProxyDetail,
)
from . import views

urlpatterns = [

    # -------------------------
    # ANALYSIS REPORTS
    # -------------------------
    path("admin/analysis/run/", run_analysis_async, name="ai-analysis-run-async"),
    path("admin/analysis/task/<str:task_id>/", analysis_task_status, name="ai-analysis-task-status"),
    path("admin/analysis/", list_reports, name="ai-analysis-list"),
    path("admin/analysis/<int:report_id>/", get_report, name="ai-analysis-get"),
    path("admin/analysis/<int:report_id>/export/", export_report_csv, name="ai-analysis-export"),
    path("admin/analysis/<int:report_id>/masked/", get_report_masked, name="ai-analysis-get-masked"),
    path("admin/analysis/<int:analysis_id>/note/", add_note_to_analysis, name="ai_admin_add_note"),

    # This was stray in your file; keeping it here clean
    path("admin/analysis/list/", ai_analysis_list, name="ai-analysis-list-alt"),

    # -------------------------
    # TRANSACTION DETAIL (NEW CLEAN URL)
    # -------------------------
    path("transaction/<int:tx_id>/", transaction_detail, name="ai-transaction-detail"),

    # -------------------------
    # TRANSACTION FLAGS
    # -------------------------
    path("admin/transaction/<int:tx_id>/flag/", views.flag_transaction, name="ai-flag-transaction"),
    path("admin/transaction/flags/", views.list_transaction_flags, name="ai-list-flags"),
    path("admin/transaction/flag/<int:flag_id>/resolve/", views.resolve_flag, name="ai-resolve-flag"),
    path("admin/transaction/flag/<int:flag_id>/", views.get_flag, name="ai-get-flag"),

    # -------------------------
    # USER ACTIONS
    # -------------------------
    path("admin/user/<int:user_id>/freeze/", views.freeze_user, name="ai-freeze-user"),
    path("admin/user/<int:user_id>/unfreeze/", views.unfreeze_user, name="ai-unfreeze-user"),

    # -------------------------
    # AUDIT LOGS
    # -------------------------
    path("admin/audit/", list_audit_logs, name="ai-audit-list"),

    path("transaction/<int:pk>/", TransactionProxyDetail.as_view(), name="ai-transaction-detail"),
]
