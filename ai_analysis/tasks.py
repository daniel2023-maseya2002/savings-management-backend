# ai_analysis/tasks.py
from celery import shared_task
from django.utils import timezone
from .models import AnalysisReport
from .ai_helpers import df_from_queryset, summary_stats, detect_anomalies_isolation, cluster_transactions
# adjust the import to your Transaction model
from core.models import Transaction

@shared_task(bind=True)
def run_analysis_task(self, params):
    start = params.get("start")
    end = params.get("end")
    contamination = float(params.get("contamination", 0.01))
    n_clusters = int(params.get("n_clusters", 4))
    qs = Transaction.objects.all().order_by("-created_at")
    if start:
        qs = qs.filter(created_at__gte=start)
    if end:
        qs = qs.filter(created_at__lte=end)
    df = df_from_queryset(qs)
    summary = summary_stats(df)
    anomalies = detect_anomalies_isolation(df, contamination=contamination)
    clusters = cluster_transactions(df, n_clusters=n_clusters)
    report = AnalysisReport.objects.create(
        created_by_id=params.get("created_by_id"),
        name=params.get("name", f"Report {timezone.now().isoformat()}"),
        params=params,
        summary=summary,
        anomalies=anomalies[:500],
        clusters=clusters
    )
    # return report id to result backend
    return {"report_id": report.id}
