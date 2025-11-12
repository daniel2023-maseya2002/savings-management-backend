# ai_analysis/ai_helpers.py

import json
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import re

# ---------------------------------------------------------------------
# 🧩 Data & JSON Helpers
# ---------------------------------------------------------------------

def json_safe(obj):
    """Convert numpy/pandas outputs to JSON-serializable types."""
    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, (np.ndarray,)):
        return obj.tolist()
    if isinstance(obj, list):
        return [json_safe(i) for i in obj]
    return obj


def df_from_queryset(qs, field_map=None):
    """
    Convert a queryset of transactions to a pandas DataFrame.
    field_map: optional dict mapping expected names to model attributes, e.g.
      {"id": "id", "amount": "amount", "created_at": "created_at",
       "status": "status", "user_id": "user_id", "description":"description"}
    """
    fm = field_map or {}
    rows = []

    for t in qs:
        def get_field(name, default=""):
            attr = fm.get(name, name)
            val = getattr(t, attr, None)
            if name == "user_id" and val is None and hasattr(t, "user"):
                try:
                    return getattr(t.user, "id", None)
                except Exception:
                    return None
            return val or default

        rows.append({
            "id": get_field("id"),
            "amount": float(get_field("amount") or 0.0),
            "status": get_field("status"),
            "created_at": get_field("created_at"),
            "user_id": get_field("user_id"),
            "description": get_field("description"),
        })

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    # Normalize columns
    df["created_at"] = pd.to_datetime(df["created_at"])
    df["hour"] = df["created_at"].dt.hour
    df["dayofweek"] = df["created_at"].dt.dayofweek
    df["abs_amount"] = df["amount"].abs()
    return df


# ---------------------------------------------------------------------
# 📊 Analysis / AI Functions
# ---------------------------------------------------------------------

def summary_stats(df):
    """Compute summary statistics for transactions."""
    if df.empty:
        return {}

    stats = {
        "count": int(len(df)),
        "total_amount": float(df["amount"].sum()),
        "avg_amount": float(df["amount"].mean()),
        "median_amount": float(df["amount"].median()),
        "min_amount": float(df["amount"].min()),
        "max_amount": float(df["amount"].max()),
        "by_status": df.groupby("status")["id"].count().to_dict(),
        "top_users_by_volume": df.groupby("user_id")["amount"].sum().abs()
                                 .sort_values(ascending=False).head(10).to_dict(),
        "top_users_by_count": df.groupby("user_id")["id"].count()
                                 .sort_values(ascending=False).head(10).to_dict(),
        "by_hour": df.groupby("hour")["amount"].sum().to_dict()
    }
    return json_safe(stats)


def detect_anomalies_isolation(df, contamination=0.01, features=None):
    """Detect anomalies using IsolationForest."""
    if df.empty:
        return []

    feat_cols = features or ["abs_amount", "hour", "dayofweek"]
    X = df[feat_cols].fillna(0).values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    model = IsolationForest(contamination=contamination, random_state=42)
    preds = model.fit_predict(Xs)
    scores = model.decision_function(Xs)

    out = []
    for i, idx in enumerate(df.index):
        out.append({
            "id": int(df.loc[idx, "id"]),
            "amount": float(df.loc[idx, "amount"]),
            "user_id": int(df.loc[idx, "user_id"]) if pd.notna(df.loc[idx, "user_id"]) else None,
            "score": float(scores[i]),
            "is_anomaly": int(preds[i] == -1),
        })

    # sort by score (most anomalous first)
    return sorted(out, key=lambda r: r["score"])


def cluster_transactions(df, n_clusters=4, features=None):
    """Cluster transactions using KMeans."""
    if df.empty:
        return {}

    feat_cols = features or ["abs_amount", "hour"]
    X = df[feat_cols].fillna(0).values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    k = min(n_clusters, len(df))
    model = KMeans(n_clusters=k, random_state=42)
    labels = model.fit_predict(Xs)
    df = df.copy()
    df["cluster"] = labels

    clusters = {}
    for c in range(k):
        subset = df[df["cluster"] == c]
        clusters[c] = {
            "count": int(len(subset)),
            "total_amount": float(subset["amount"].sum()),
            "avg_amount": float(subset["amount"].mean()) if len(subset) > 0 else 0,
            "sample_ids": list(map(int, subset["id"].head(10).tolist())),
        }

    return json_safe(clusters)


# ---------------------------------------------------------------------
# 🕵️ PII Masking Helpers
# ---------------------------------------------------------------------

_DIGIT_SEQ_RE = re.compile(r"\d{4,}")  # sequences of 4+ digits (likely account numbers)

def mask_digits_keep_last(value: str, keep: int = 4, mask_char: str = "*"):
    """
    Replace sequences of digits length >= keep with masked version keeping last `keep` digits.
    Example: "acct 1234567890" -> "acct ******7890"
    """
    def repl(m):
        s = m.group(0)
        if len(s) <= keep:
            return s
        masked = mask_char * (len(s) - keep) + s[-keep:]
        return masked
    return _DIGIT_SEQ_RE.sub(repl, value)


def mask_possibly_sensitive_string(value):
    """
    Basic sanitizer for free text fields: mask long digit sequences and optionally emails / phones.
    Returns original if nothing to mask.
    """
    if not isinstance(value, str):
        return value

    v = value.strip()
    if "@" in v:
        # mask email local-part (keep 1 char + stars) -> a***@domain.com
        parts = v.split("@", 1)
        local = parts[0]
        if len(local) > 1:
            local_masked = local[0] + ("*" * (min(6, len(local) - 1)))
        else:
            local_masked = "*" * len(local)
        return local_masked + "@" + parts[1]

    # mask digit sequences
    v2 = mask_digits_keep_last(v, keep=4)
    return v2


def mask_anomalies_list(anomalies):
    """Walk anomalies list and mask likely-sensitive values."""
    if not anomalies:
        return anomalies

    out = []
    for a in anomalies:
        item = {}
        for k, v in (a or {}).items():
            if isinstance(v, str):
                item[k] = mask_possibly_sensitive_string(v)
            elif isinstance(v, list):
                item[k] = [mask_possibly_sensitive_string(x) if isinstance(x, str) else x for x in v]
            else:
                item[k] = v
        out.append(item)
    return out


def mask_clusters(clusters):
    """Mask cluster info (string fields only)."""
    if not clusters:
        return clusters

    safe = {}
    for cid, info in clusters.items():
        safe_info = {}
        for k, v in (info or {}).items():
            if isinstance(v, str):
                safe_info[k] = mask_possibly_sensitive_string(v)
            elif isinstance(v, list):
                safe_info[k] = [mask_possibly_sensitive_string(x) if isinstance(x, str) else x for x in v]
            else:
                safe_info[k] = v
        safe[cid] = safe_info
    return safe
