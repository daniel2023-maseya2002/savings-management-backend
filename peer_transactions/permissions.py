# peer_transactions/permissions.py
from rest_framework import permissions

class IsSenderOrAdmin(permissions.BasePermission):
    """
    Allow access if user is the sender (created_by) or staff.
    """
    def has_object_permission(self, request, view, obj):
        return request.user.is_staff or obj.created_by_id == request.user.id
