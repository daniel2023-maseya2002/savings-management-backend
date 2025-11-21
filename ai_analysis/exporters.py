from .models import TransactionFlag

# build anomalies list as dicts
anomaly_rows = [...]  # list of dicts with at least 'transaction_id' or 'id'

# fetch all flags for these tx ids
tx_ids = [r["id"] for r in anomaly_rows]
flags_qs = TransactionFlag.objects.filter(transaction_id__in=tx_ids)
flags_map = {}
for f in flags_qs:
    flags_map.setdefault(f.transaction_id, []).append({
        "flagged_by": f.flagged_by.username if f.flagged_by else None,
        "reason": f.reason,
        "metadata": f.metadata,
        "created_at": f.created_at.isoformat(),
    })

# attach to rows
for row in anomaly_rows:
    row["admin_flags"] = flags_map.get(row["id"], [])
