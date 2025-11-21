# ai_analysis/helpers.py
import uuid
from .models import AuditLog

def create_audit_log(request=None, admin=None, action_type="", target_type=None, target_id=None, metadata=None):
    """
    If request is provided, we extract IP, UA and request_id (if middleware added).
    """
    meta = metadata or {}
    ip = None
    ua = None
    req_id = None

    if request is not None:
        ip = request.META.get("REMOTE_ADDR") or request.META.get("HTTP_X_FORWARDED_FOR")
        ua = request.META.get("HTTP_USER_AGENT")
        req_id = getattr(request, "request_id", None)

    # If admin param provided then use it (callers often provide it)
    admin_user = admin or (getattr(request, "user", None) if request else None)

    AuditLog.objects.create(
        admin=admin_user,
        action_type=action_type,
        target_type=target_type,
        target_id=target_id,
        metadata=meta,
        admin_ip=ip,
        user_agent=ua,
        request_id=req_id
    )
