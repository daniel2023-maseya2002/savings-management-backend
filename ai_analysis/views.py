# ai_analysis/views.py
import csv
import io
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from celery.result import AsyncResult

from .models import AnalysisReport
from .serializers import AnalysisReportSerializer, TransactionDetailSerializer
from .ai_helpers import df_from_queryset, summary_stats, mask_anomalies_list, mask_clusters, mask_possibly_sensitive_string  # keep for sync fallback if needed
from django.shortcuts import get_object_or_404


# import Celery task
from .tasks import run_analysis_task

# import your Transaction model
from core.models import Transaction

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