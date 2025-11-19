# ai_analysis/views.py
import csv
import io
import logging
import re
from django.utils import timezone
from django.core.cache import cache
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework import status, permissions
from celery.result import AsyncResult
from rest_framework.pagination import PageNumberPagination
from .tasks import send_admin_notification 
from .helpers import create_audit_log

from .models import AnalysisReport, TransactionFlag, ReportNote, AuditLog
from .serializers import AnalysisReportSerializer, TransactionDetailSerializer, TransactionFlagSerializer, ReportNoteSerializer, AuditLogSerializer, TransactionProxySerializer
from .ai_helpers import df_from_queryset, summary_stats, mask_anomalies_list, mask_clusters, mask_possibly_sensitive_string  # keep for sync fallback if needed
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from .utils import log_admin_action
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView


# import Celery task
from .tasks import run_analysis_task

# import your Transaction model
from core.models import Transaction
from django.db import transaction
from django.db import transaction as db_transaction
from django.db import transaction as django_transaction
from django.utils.dateparse import parse_date



CACHE_TIMEOUT = 30  # seconds; adjust
logger = logging.getLogger(__name__)
User = get_user_model()

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 30
    page_size_query_param = "page_size"
    max_page_size = 200

@api_view(["GET"])
@permission_classes([IsAdminUser])
def list_reports(request):
    qs = AnalysisReport.objects.all().order_by("-created_at")

    # optional date filtering: start and end are yyyy-mm-dd or ISO
    start = request.query_params.get("start")
    end = request.query_params.get("end")
    if start:
        d = parse_date(start)
        if d:
            qs = qs.filter(created_at__date__gte=d)
    if end:
        d2 = parse_date(end)
        if d2:
            qs = qs.filter(created_at__date__lte=d2)

    paginator = StandardResultsSetPagination()
    page = paginator.paginate_queryset(qs, request)
    serializer = AnalysisReportSerializer(page, many=True)
    return paginator.get_paginated_response(serializer.data)

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def ai_analysis_list(request):
    """
    Returns list of analysis reports (with pagination + optional date filters)
    React expects payload shape: { count, page, results }
    """

    qs = AnalysisReport.objects.all().order_by("-created_at")

    # --- Optional filters ---
    start = request.GET.get("start")
    end = request.GET.get("end")

    if start:
        d = parse_date(start)
        if d:
            qs = qs.filter(created_at__date__gte=d)

    if end:
        d = parse_date(end)
        if d:
            qs = qs.filter(created_at__date__lte=d)

    # --- Pagination (React already sends page & page_size) ---
    paginator = PageNumberPagination()
    paginator.page_size = int(request.GET.get("page_size", 20))
    page = paginator.paginate_queryset(qs, request)

    serialized = AnalysisReportSerializer(page, many=True).data

    return Response({
        "count": paginator.page.paginator.count,
        "page": paginator.page.number,
        "results": serialized
    })

@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def run_analysis_async(request):
    """
    Enqueue an analysis job (returns task id). Admin-only.
    Accepts same POST body as earlier run_analysis.
    """
    data = request.data or {}
    params = {
        "start": data.get("start"),
        "end": data.get("end"),
        "method": data.get("method", "isolation_forest"),
        "contamination": float(data.get("contamination", 0.01)),
        "n_clusters": int(data.get("n_clusters", 4)),
        "name": data.get("name"),
        "created_by_id": request.user.id,
    }

    # Optionally: quick validation, deny if too large/time-range etc.
    # enqueue task
    task = run_analysis_task.apply_async(kwargs={"params": params})
    return Response({"task_id": task.id, "status": "queued"}, status=status.HTTP_202_ACCEPTED)


@api_view(["GET"])
@permission_classes([IsAdminUser])
def analysis_task_status(request, task_id):
    """
    Check Celery task status and return report_id if ready.
    """
    result = AsyncResult(task_id)
    resp = {"task_id": task_id, "state": result.state}
    if result.state == "SUCCESS":
        try:
            out = result.result or {}
            report_id = out.get("report_id")
            resp["report_id"] = report_id
        except Exception:
            resp["report_id"] = None
    elif result.state == "FAILURE":
        # include a brief error message
        resp["error"] = str(result.result)
    return Response(resp)


@api_view(["GET"])
@permission_classes([IsAdminUser])
def get_report(request, report_id):
    try:
        r = AnalysisReport.objects.get(pk=report_id)
    except AnalysisReport.DoesNotExist:
        return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)
    serializer = AnalysisReportSerializer(r)
    return Response(serializer.data)


@api_view(["GET"])
@permission_classes([IsAdminUser])
def export_report_csv(request, report_id):
    """
    Export anomalies (or clusters) of a given report as CSV.
    Query param: part=anomalies|clusters|summary (default anomalies)
    """
    part = request.query_params.get("part", "anomalies")
    try:
        r = AnalysisReport.objects.get(pk=report_id)
    except AnalysisReport.DoesNotExist:
        return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)

    # Build CSV
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    if part == "anomalies":
        writer.writerow(["transaction_id", "user_id", "amount", "score", "is_anomaly"])
        for a in r.anomalies or []:
            writer.writerow([a.get("id"), a.get("user_id"), a.get("amount"), a.get("score"), a.get("is_anomaly")])
        content = buffer.getvalue()
        buffer.close()
        filename = f"report_{report_id}_anomalies.csv"
    elif part == "clusters":
        writer.writerow(["cluster_id", "count", "total_amount", "avg_amount", "sample_ids"])
        for cid, info in (r.clusters or {}).items():
            writer.writerow([cid, info.get("count"), info.get("total_amount"), info.get("avg_amount"), ",".join(map(str, info.get("sample_ids", [])))])
        content = buffer.getvalue()
        buffer.close()
        filename = f"report_{report_id}_clusters.csv"
    else:
        # summary
        writer.writerow(["key", "value"])
        for k, v in (r.summary or {}).items():
            writer.writerow([k, v])
        content = buffer.getvalue()
        buffer.close()
        filename = f"report_{report_id}_summary.csv"

    # Return streaming response
    from django.http import HttpResponse
    response = HttpResponse(content, content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response

@api_view(["GET"])
@permission_classes([IsAdminUser])
def get_report_masked(request, report_id):
    """
    Return report with PII masked (admin-only).
    """
    try:
        r = AnalysisReport.objects.get(pk=report_id)
    except AnalysisReport.DoesNotExist:
        return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)

    # Deep copy-ish: we will return masked variants alongside original metadata
    data = AnalysisReportSerializer(r).data

    # Mask anomalies
    data["anomalies_masked"] = mask_anomalies_list(r.anomalies or [])
    # Mask clusters (if they contain strings)
    data["clusters_masked"] = mask_clusters(r.clusters or {})
    # Mask summary text fields if any (we'll mask string values)
    summary = r.summary or {}
    safe_summary = {}
    for k, v in summary.items():
        if isinstance(v, str):
            safe_summary[k] = mask_possibly_sensitive_string(v)
        else:
            safe_summary[k] = v
    data["summary_masked"] = safe_summary

    return Response(data)

def mask_possibly_sensitive_string(s: str) -> str:
    """
    Simple heuristic masking for PII-like strings:
    - email-like: keep first char + mask + domain
    - long numeric strings (card/phone): keep last 4
    - otherwise: show short prefix/suffix and mask middle
    """
    if not isinstance(s, str):
        return s
    s = s.strip()
    # email
    if "@" in s and "." in s.split("@")[-1]:
        local, domain = s.split("@", 1)
        if len(local) <= 2:
            return "*" * len(local) + "@" + domain
        return local[0] + ("*" * (max(1, len(local) - 2))) + local[-1] + "@" + domain

    # long numeric sequences (phone, card)
    if re.fullmatch(r"[0-9\-\s]{8,}", s):
        digits = re.sub(r"\D", "", s)
        if len(digits) <= 4:
            return "*" * len(digits)
        return "*" * (len(digits) - 4) + digits[-4:]

    # generic: mask middle leaving up to 6 chars visible
    if len(s) <= 6:
        return s[0] + "*" * (max(0, len(s) - 1))
    prefix = s[:3]
    suffix = s[-3:]
    return prefix + ("*" * (len(s) - 6)) + suffix

def mask_pii(obj):
    """
    Recursively mask possibly sensitive info in dicts/lists/strings.
    Only masks keys: username, email, phone, reference, account.
    """
    if isinstance(obj, str):
        return mask_possibly_sensitive_string(obj)
    elif isinstance(obj, dict):
        new_obj = {}
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                new_obj[k] = mask_pii(v)
            elif isinstance(v, str) and k.lower() in ("username", "email", "phone", "reference", "account"):
                new_obj[k] = mask_possibly_sensitive_string(v)
            else:
                new_obj[k] = v
        return new_obj
    elif isinstance(obj, list):
        return [mask_pii(item) for item in obj]
    return obj


@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def transaction_detail(request, tx_id):
    """
    Admin-only endpoint: return transaction details for a given tx_id.
    PII is masked where appropriate.
    Flags related to the transaction are included.
    """
    try:
        tx = get_object_or_404(Transaction, pk=tx_id)

        serializer = TransactionDetailSerializer(tx, context={"request": request})
        payload = mask_pii(serializer.data)

        # Attach transaction flags
        flags_qs = TransactionFlag.objects.filter(transaction_id=tx.pk).order_by("-created_at")
        flags_serialized = TransactionFlagSerializer(flags_qs, many=True).data if flags_qs.exists() else []
        payload["flags"] = flags_serialized

        return Response(payload, status=status.HTTP_200_OK)

    except Transaction.DoesNotExist:
        return Response({"detail": "Transaction not found."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as exc:
        logger.exception("Error in transaction_detail for tx_id=%s: %s", tx_id, exc)
        return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

# Freeze user
@api_view(["POST"])
@authentication_classes([JWTAuthentication])  # include JWT auth
@permission_classes([IsAdminUser])
def freeze_user(request, user_id):
    admin = request.user
    target = get_object_or_404(User, pk=user_id)
    
    if getattr(target, "is_superuser", False):
        return Response({"detail": "Cannot freeze superuser."}, status=status.HTTP_400_BAD_REQUEST)
    if target == admin:
        return Response({"detail": "Cannot freeze your own account."}, status=status.HTTP_400_BAD_REQUEST)

    with transaction.atomic():
        target.is_active = False
        target.save(update_fields=["is_active"])
        create_audit_log(
            request=request, admin=admin, action_type="freeze_user", 
            target_type="user", target_id=target.pk, 
            metadata={"username": target.username}
        )

    try:
        send_admin_notification.delay({"type": "freeze_user", "user_id": target.pk, "admin": admin.username})
    except Exception:
        logger.exception("Failed to send admin notification")

    return Response({"detail": f"User {user_id} frozen successfully."})


@api_view(["POST"])
@authentication_classes([JWTAuthentication])  # include JWT auth
@permission_classes([IsAdminUser])
def unfreeze_user(request, user_id):
    admin = request.user
    target = get_object_or_404(User, pk=user_id)

    with transaction.atomic():
        target.is_active = True
        target.save(update_fields=["is_active"])
        create_audit_log(
            request=request,
            admin=admin,
            action_type="unfreeze_user",
            target_type="user",
            target_id=target.pk,
            metadata={"username": target.username}
        )

    try:
        send_admin_notification.delay({"type": "unfreeze_user", "user_id": target.pk, "admin": admin.username})
    except Exception:
        logger.exception("Failed to send admin notification")

    return Response({"detail": f"User {user_id} unfrozen."})

# Flag a transaction
@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def flag_transaction(request, tx_id):
    """
    Admin flags a transaction for review.
    Body:
      {
        "reason": "...",
        "note": "...",
        "metadata": {...},
        "analysis_report_id": 123
      }
    """
    admin = request.user
    data = request.data or {}

    reason = str(data.get("reason", "")).strip()
    note = str(data.get("note", "")).strip()
    metadata = data.get("metadata", {})

    # Ensure metadata is JSON serializable
    try:
        import json
        json.dumps(metadata)
    except Exception:
        metadata = {}

    analysis_id = data.get("analysis_report_id")

    try:
        with db_transaction.atomic():

            # ✅ Correct models (ai_analysis.models)
            from ai_analysis.models import AnalysisReport, TransactionFlag

            # Validate analysis_report_id
            if analysis_id and not AnalysisReport.objects.filter(pk=analysis_id).exists():
                analysis_id = None

            # Create flag entry
            flag = TransactionFlag.objects.create(
                transaction_id=tx_id,
                transaction_ref=str(metadata.get("ref") or ""),
                flagged_by=admin,
                reason=reason,
                note=note,
                metadata=metadata,
                analysis_report_id=analysis_id
            )

    except Exception as exc:
        logger.exception("Error creating TransactionFlag for tx_id=%s", tx_id)
        return Response({"detail": "Error creating flag"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Audit log
    try:
        from ai_analysis.utils import create_audit_log
        create_audit_log(
            admin=admin,
            action_type="flag_transaction",
            target_type="transaction",
            target_id=tx_id,
            metadata={"reason": reason, "analysis_report_id": analysis_id}
        )
    except Exception as exc:
        logger.warning("Failed to create audit log: %s", exc)

    # Clear cache
    try:
        cache.delete_pattern(f"tx_flags:{admin.pk}:*")
    except Exception:
        pass

    # Notifications
    try:
        from ai_analysis.tasks import send_admin_notification
        send_admin_notification.delay({
            "type": "flag_transaction",
            "flag_id": flag.id,
            "transaction_id": tx_id,
            "reason": reason
        })
    except Exception:
        pass

    # Serialize
    try:
        from ai_analysis.serializers import TransactionFlagSerializer
        serializer = TransactionFlagSerializer(flag)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    except Exception:
        return Response({"detail": "Flag created but serialization failed"}, status=status.HTTP_201_CREATED)


# Resolve flag (mark resolved)
@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def resolve_flag(request, flag_id):
    """
    Mark a flagged transaction as resolved.
    Admin-only.
    Body params:
    - note: optional admin note to append
    - resolved: boolean (default True)
    """
    admin = request.user
    data = request.data or {}
    note = str(data.get("note", "")).strip()
    resolved = bool(data.get("resolved", True))

    flag = get_object_or_404(TransactionFlag, pk=flag_id)

    flag.resolved = resolved
    flag.resolved_by = admin
    flag.resolved_at = timezone.now()
    if note:
        flag.note = (flag.note or "") + "\n\n[Admin note] " + note
    flag.save(update_fields=["resolved", "resolved_by", "resolved_at", "note"])

    # Create audit log
    try:
        create_audit_log(
            admin=admin,
            action_type="resolve_flag",
            target_type="transaction_flag",
            target_id=flag.id,
            metadata={"resolved": flag.resolved, "note": note}
        )
    except Exception:
        pass  # safe fail

    # Invalidate cache for flags
    try:
        cache.delete_pattern(f"tx_flags:{admin.pk}:*")
    except Exception:
        pass  # safe fail

    # Notify other admins asynchronously
    try:
        send_admin_notification.delay({
            "type": "resolve_flag",
            "flag_id": flag.id,
            "resolved_by": admin.username
        })
    except Exception:
        pass  # safe fail

    return Response({"detail": "Flag resolved."}, status=200)

# Add note to report
@api_view(["POST"])
@permission_classes([IsAdminUser])
def add_report_note(request, report_id):
    admin = request.user
    data = request.data or {}
    body = (data.get("body") or "").strip()
    pinned = bool(data.get("pinned", False))
    if not body:
        return Response({"detail":"Note body required"}, status=status.HTTP_400_BAD_REQUEST)

    report = get_object_or_404(AnalysisReport, pk=report_id)
    with transaction.atomic():
        note = ReportNote.objects.create(report=report, created_by=admin, body=body, pinned=pinned)
        AuditLog.objects.create(
            admin=admin,
            action_type="add_report_note",
            target_type="report",
            target_id=report.pk,
            metadata={"note_id": note.pk}
        )
    serializer = ReportNoteSerializer(note)
    return Response(serializer.data, status=status.HTTP_201_CREATED)


# List audit logs (with pagination/simple filtering)
@api_view(["GET"])
@permission_classes([IsAdminUser])
def list_audit_logs(request):
    # similar filtering
    qs = AuditLog.objects.select_related("admin").all().order_by("-created_at")
    action = request.query_params.get("action")
    start = request.query_params.get("start_date")
    end = request.query_params.get("end_date")

    if action:
        qs = qs.filter(action_type=action)
    if start:
        try:
            start_dt = timezone.datetime.fromisoformat(start)
        except Exception:
            start_dt = None
        if start_dt:
            qs = qs.filter(created_at__gte=start_dt)
    if end:
        try:
            end_dt = timezone.datetime.fromisoformat(end)
        except Exception:
            end_dt = None
        if end_dt:
            qs = qs.filter(created_at__lte=end_dt)

    paginator = StandardResultsSetPagination()
    page = paginator.paginate_queryset(qs, request)
    serializer = AuditLogSerializer(page, many=True)
    return paginator.get_paginated_response(serializer.data)

@api_view(["POST"])
@permission_classes([IsAdminUser])
def add_note_to_analysis(request, analysis_id):
    admin = request.user
    note_text = (request.data.get("note") or "").strip()
    if not note_text:
        return Response({"detail": "note field required"}, status=status.HTTP_400_BAD_REQUEST)

    report = get_object_or_404(AnalysisReport, pk=analysis_id)
    note = ReportNote.objects.create(report=report, created_by=admin, body=note_text, pinned=bool(request.data.get("pinned", False)))

    # audit
    from .utils import create_audit_log
    create_audit_log(request=request, admin=admin, action_type="add_note", target_type="analysis", target_id=report.pk, metadata={"note_id": note.pk})

    serializer = ReportNoteSerializer(note)
    return Response(serializer.data, status=status.HTTP_201_CREATED)

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def list_transaction_flags(request):
    """
    Admin-only: returns paginated transaction flags with optional filters:
    - transaction=<id>
    - flagged_by=<username substring>
    - start_date=<ISO format>
    - end_date=<ISO format>
    
    Response is cached per user/query for short period.
    """
    qs = TransactionFlag.objects.select_related("flagged_by", "resolved_by", "analysis_report").all().order_by("-created_at")

    # Filtering
    tx = request.query_params.get("transaction")
    flagged_by_q = request.query_params.get("flagged_by")
    start = request.query_params.get("start_date")
    end = request.query_params.get("end_date")

    if tx:
        qs = qs.filter(transaction_id=tx)
    if flagged_by_q:
        qs = qs.filter(flagged_by__username__icontains=flagged_by_q)

    if start:
        try:
            start_dt = timezone.datetime.fromisoformat(start)
            qs = qs.filter(created_at__gte=start_dt)
        except Exception:
            pass

    if end:
        try:
            end_dt = timezone.datetime.fromisoformat(end)
            qs = qs.filter(created_at__lte=end_dt)
        except Exception:
            pass

    # Cache key
    cache_key = f"tx_flags:{request.user.pk}:{request.get_full_path()}"
    cached = cache.get(cache_key)
    if cached:
        return Response(cached)

    # Pagination
    paginator = StandardResultsSetPagination()
    page = paginator.paginate_queryset(qs, request)
    serializer = TransactionFlagSerializer(page, many=True)
    resp = paginator.get_paginated_response(serializer.data).data

    # Store short-term cache
    cache.set(cache_key, resp, CACHE_TIMEOUT)
    return Response(resp)

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def get_flag(request, flag_id):
    """
    Admin-only: retrieve a single transaction flag by ID.
    """
    flag = get_object_or_404(TransactionFlag, pk=flag_id)
    serializer = TransactionFlagSerializer(flag)
    return Response(serializer.data, status=status.HTTP_200_OK)


class TransactionProxyDetail(APIView):
    """
    Read-only proxy to fetch core.Transaction by pk.

    URL: /api/ai_analysis/transaction/<pk>/
    Permission: admin-only by default (safe for admin tooling).
    """
    permission_classes = [permissions.IsAdminUser]  # change to IsAuthenticated for non-admin access

    def get(self, request, pk, format=None):
        tx = get_object_or_404(Transaction, pk=pk)
        serializer = TransactionProxySerializer(tx)
        return Response(serializer.data, status=status.HTTP_200_OK)