# feedback/views.py
from django.shortcuts import get_object_or_404, render
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from .models import Feedback, FeedbackComment
from .serializers import FeedbackSerializer, FeedbackCommentSerializer
from .permissions import IsOwnerOrStaff, IsCommentOwnerOrStaff
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser

# List & create for regular users (list returns only user's feedback)
class FeedbackListCreateView(generics.ListCreateAPIView):
    queryset = Feedback.objects.all().order_by("-created_at")
    serializer_class = FeedbackSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # regular users see their feedbacks; admin sees all
        user = self.request.user
        if user.is_staff:
            return Feedback.objects.all().order_by("-created_at")
        return Feedback.objects.filter(user=user).order_by("-created_at")

    def perform_create(self, serializer):
        # serializer.create will associate user and ignore status for non-staff
        serializer.save()


# Retrieve and update: user can only update certain fields; staff can update status/is_public freely
class FeedbackDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Feedback.objects.all()
    serializer_class = FeedbackSerializer
    permission_classes = [permissions.IsAuthenticated]

    def check_object_permissions(self, request, obj):
        # Allow owner or staff
        if obj.user != request.user and not request.user.is_staff:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("You do not have permission to view/modify this feedback.")
        return super().check_object_permissions(request, obj)

# Staff-only list to get all feedback (convenience)
class FeedbackAdminListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser]
    serializer_class = FeedbackSerializer
    queryset = Feedback.objects.all().order_by("-created_at")


# Comments
class FeedbackCommentListCreateView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = FeedbackCommentSerializer

    def get_queryset(self):
        feedback_id = self.kwargs.get("feedback_id")
        return FeedbackComment.objects.filter(feedback_id=feedback_id).order_by("created_at")

    def perform_create(self, serializer):
        feedback_id = self.kwargs.get("feedback_id")
        feedback = Feedback.objects.get(id=feedback_id)
        # only owner or staff can comment? Usually both can comment; here allow both
        # but restrict internal comments by serializer validation
        serializer.save(user=self.request.user, feedback=feedback)


class FeedbackCommentDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAuthenticated, IsCommentOwnerOrStaff]
    serializer_class = FeedbackCommentSerializer
    queryset = FeedbackComment.objects.all()
    lookup_field = "id"


@api_view(["PATCH"])
@permission_classes([IsAdminUser])
def feedback_status_update(request, pk):
    f = get_object_or_404(Feedback, pk=pk)
    status_val = request.data.get("status")
    if status_val not in dict(Feedback.STATUS_CHOICES):
        return Response({"detail": "Invalid status"}, status=400)
    f.status = status_val
    f.save(update_fields=["status","updated_at"])
    return Response(FeedbackSerializer(f, context={"request":request}).data)