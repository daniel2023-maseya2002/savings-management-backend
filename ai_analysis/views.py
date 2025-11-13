# ai_analysis/views.py
import csv
import io
import logging
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from celery.result import AsyncResult

from .models import AnalysisReport, TransactionFlag, ReportNote, AuditLog
from .serializers import AnalysisReportSerializer, TransactionDetailSerializer, TransactionFlagSerializer, ReportNoteSerializer, AuditLogSerializer
from .ai_helpers import df_from_queryset, summary_stats, mask_anomalies_list, mask_clusters, mask_possibly_sensitive_string  # keep for sync fallback if needed
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from .utils import log_admin_action
from rest_framework_simplejwt.authentication import JWTAuthentication


# import Celery task
from .tasks import run_analysis_task

# import your Transaction model
from core.models import Transaction
from django.db import transaction
from django.db import transaction as db_transaction



logger = logging.getLogger(__name__)
User = get_user_model()

@api_view(["POST"])
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
def list_reports(request):
    qs = AnalysisReport.objects.all().order_by("-created_at")
    page = int(request.query_params.get("page", 1))
    page_size = int(request.query_params.get("page_size", 20))
    start = (page - 1) * page_size
    end = start + page_size
    items = qs[start:end]
    serializer = AnalysisReportSerializer(items, many=True)
    return Response({"count": qs.count(), "results": serializer.data})


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


@api_view(["GET"])
@permission_classes([IsAdminUser])
def transaction_detail(request, tx_id):
    """
    Admin-only: return transaction details for id tx_id, with PII masked.
    The serializer returns a small set of safe fields. If you need more fields, add them to the serializer.
    """
    tx = get_object_or_404(Transaction, pk=tx_id)
    serializer = TransactionDetailSerializer(tx)
    payload = serializer.data

    # sanitize any string fields in payload (description, reference, etc.)
    for k, v in list(payload.items()):
        if isinstance(v, str):
            payload[k] = mask_possibly_sensitive_string(v)
        elif isinstance(v, dict):
            # sanitize nested user info username if present
            if "username" in v and isinstance(v["username"], str):
                payload["user"]["username"] = mask_possibly_sensitive_string(v["username"])

    return Response(payload)

# Freeze user
@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def freeze_user(request, user_id):
    admin = request.user
    target = get_object_or_404(User, pk=user_id)

    if getattr(target, "is_superuser", False):
        return Response({"detail": "Cannot freeze superuser."}, status=status.HTTP_400_BAD_REQUEST)
    if target == admin:
        return Response({"detail": "Cannot freeze your own account."}, status=status.HTTP_400_BAD_REQUEST)

    with django_transaction.atomic():
        target.is_active = False
        target.save(update_fields=["is_active"])
        try:
            AuditLog.objects.create(
                admin=admin,
                action_type="freeze_user",
                target_type="user",
                target_id=target.pk,
                metadata={"username": getattr(target, "username", None)},
            )
        except Exception:
            logger.exception("Failed to create AuditLog for freeze_user")

    return Response({"detail": f"User {user_id} frozen successfully."}, status=status.HTTP_200_OK)


@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def unfreeze_user(request, user_id):
    admin = request.user
    target = get_object_or_404(User, pk=user_id)
    with django_transaction.atomic():
        target.is_active = True
        target.save(update_fields=["is_active"])
        try:
            AuditLog.objects.create(
                admin=admin,
                action_type="unfreeze_user",
                target_type="user",
                target_id=target.pk,
                metadata={"username": getattr(target, "username", None)},
            )
        except Exception:
            logger.exception("Failed to create AuditLog for unfreeze_user")
    return Response({"detail": f"User {user_id} unfrozen."}, status=status.HTTP_200_OK)

# Flag a transaction
@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def flag_transaction(request, tx_id):
    admin = request.user
    try:
        payload = request.data or {}
        reason = (payload.get("reason") or "").strip()
        metadata = payload.get("metadata") or {}
        transaction_ref = payload.get("transaction_ref")

        if metadata and not isinstance(metadata, (dict, list)):
            return Response({"detail": "metadata must be a JSON object or array"}, status=status.HTTP_400_BAD_REQUEST)

        with db_transaction.atomic():
            flag = TransactionFlag.objects.create(
                transaction_id=int(tx_id),
                transaction_ref=transaction_ref,
                flagged_by=admin,
                reason=reason,
                metadata=metadata,
            )

            # audit log (best-effort)
            try:
                AuditLog.objects.create(
                    admin=admin,
                    action_type="flag_transaction",
                    target_type="transaction",
                    target_id=flag.transaction_id,
                    metadata={"flag_id": flag.pk, "reason": reason, "metadata": metadata},
                )
            except Exception:
                logger.exception("Failed to create AuditLog for flag_transaction")

        serializer = TransactionFlagSerializer(flag)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    except ValueError:
        return Response({"detail": "Invalid transaction id"}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as exc:
        logger.exception("flag_transaction error tx_id=%s admin=%s: %s", tx_id, getattr(admin, "pk", None), exc)
        from django.conf import settings
        if getattr(settings, "DEBUG", False):
            return Response({"detail": "Internal error", "error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Resolve flag (mark resolved)
@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def resolve_flag(request, flag_id):
    admin = request.user
    payload = request.data or {}
    note = payload.get("note", "")
    resolved = payload.get("resolved", True)

    flag = get_object_or_404(TransactionFlag, pk=flag_id)
    with db_transaction.atomic():
        flag.resolved = bool(resolved)
        flag.resolved_by = admin
        flag.resolved_at = timezone.now()
        if note:
            if flag.note:
                flag.note = f"{flag.note}\n\n[Resolved note by {admin.username} at {flag.resolved_at}]\n{note}"
            else:
                flag.note = note
        flag.save(update_fields=["resolved", "resolved_by", "resolved_at", "note"])

        # audit log
        try:
            AuditLog.objects.create(
                admin=admin,
                action_type="resolve_flag",
                target_type="transaction_flag",
                target_id=flag.pk,
                metadata={"resolved": flag.resolved, "note": note},
            )
        except Exception:
            logger.exception("Failed to create AuditLog for resolve_flag")

    return Response(TransactionFlagSerializer(flag).data, status=status.HTTP_200_OK)


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
    q = AuditLog.objects.all().order_by("-created_at")
    # optional filters: action_type, admin, target_type
    action = request.query_params.get("action")
    admin_q = request.query_params.get("admin")
    target_type = request.query_params.get("target_type")
    if action:
        q = q.filter(action_type=action)
    if admin_q:
        # allow admin username or id
        if admin_q.isdigit():
            q = q.filter(admin__id=int(admin_q))
        else:
            q = q.filter(admin__username__icontains=admin_q)
    if target_type:
        q = q.filter(target_type__iexact=target_type)
    page = int(request.query_params.get("page", 1))
    page_size = int(request.query_params.get("page_size", 30))
    start = (page - 1) * page_size
    end = start + page_size
    items = q[start:end]
    serializer = AuditLogSerializer(items, many=True)
    return Response({"count": q.count(), "results": serializer.data})

@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def add_note_to_analysis(request, analysis_id):
    report = get_object_or_404(AnalysisReport, pk=analysis_id)
    note_text = (request.data.get("note") or "").strip()
    if not note_text:
        return Response({"detail": "note field required"}, status=status.HTTP_400_BAD_REQUEST)

    note_entry = {
        "by": getattr(request.user, "username", "unknown"),
        "user_id": getattr(request.user, "pk", None),
        "text": note_text,
        "meta": request.data.get("meta", {}),
        "ts": timezone.now().isoformat()
    }

    notes = (report.notes or [])
    notes.append(note_entry)
    report.notes = notes
    report.save(update_fields=["notes"])

    log_admin_action(request.user, "add_note_analysis", target_type="analysis", target_id=report.pk, payload={"note": note_text, "note_by": note_entry["by"]})

    return Response({"detail": "Note added.", "note": note_entry}, status=status.HTTP_200_OK)

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def list_transaction_flags(request):
    qs = TransactionFlag.objects.all().order_by("-created_at")
    tx = request.query_params.get("transaction")
    user_q = request.query_params.get("flagged_by")
    if tx:
        try:
            qs = qs.filter(transaction_id=int(tx))
        except ValueError:
            return Response({"detail": "Invalid transaction query param"}, status=status.HTTP_400_BAD_REQUEST)
    if user_q:
        qs = qs.filter(flagged_by__username__icontains=user_q)

    serializer = TransactionFlagSerializer(qs[:200], many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def get_flag(request, flag_id):
    flag = get_object_or_404(TransactionFlag, pk=flag_id)
    return Response(TransactionFlagSerializer(flag).data, status=status.HTTP_200_OK)