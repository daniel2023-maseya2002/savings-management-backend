# ai_analysis/utils.py
import logging
from .models import AuditLog

logger = logging.getLogger(__name__)

def log_admin_action(actor, action, target_type=None, target_id=None, payload=None):
    try:
        AuditLog.objects.create(
            actor=actor if hasattr(actor, "pk") else None,
            action=action,
            target_type=(target_type or ""),
            target_id=(int(target_id) if target_id is not None else None),
            payload=(payload or {})
        )
    except Exception:
        logger.exception("Failed to create audit log for %s %s:%s", action, target_type, target_id)

def create_audit_log(request=None, admin=None, action_type=None, target_type=None, target_id=None, metadata=None):
    """
    Create an AuditLog entry. Accepts either request (to capture IP/UA) or admin user.
    Use consistently across views.
    """
    try:
        if admin is None and request is not None:
            admin = getattr(request, "user", None)

        entry = AuditLog.objects.create(
            admin=admin if hasattr(admin, "pk") else None,
            action_type=action_type or "other",
            target_type=(target_type or ""),
            target_id=(int(target_id) if target_id is not None else None),
            metadata=(metadata or {}),
            admin_ip=(request.META.get("REMOTE_ADDR") if request is not None else None),
            user_agent=(request.META.get("HTTP_USER_AGENT") if request is not None else None),
            request_id=(request.META.get("HTTP_X_REQUEST_ID") if request is not None else None),
        )
        return entry
    except Exception as exc:
        logger.exception("create_audit_log failed: %s", exc)
        return None