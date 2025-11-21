# feedback/permissions.py
from rest_framework import permissions

class IsOwnerOrStaff(permissions.BasePermission):
    """
    Allow access if request.user is owner of object or is staff.
    """

    def has_object_permission(self, request, view, obj):
        if getattr(request.user, "is_staff", False):
            return True
        # object expected to have .user field
        return getattr(obj, "user", None) == request.user

class IsCommentOwnerOrStaff(permissions.BasePermission):
    """
    For comments: owner or staff can edit/delete.
    """
    def has_object_permission(self, request, view, obj):
        if getattr(request.user, "is_staff", False):
            return True
        return obj.user == request.user
