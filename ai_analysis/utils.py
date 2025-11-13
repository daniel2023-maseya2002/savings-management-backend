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
