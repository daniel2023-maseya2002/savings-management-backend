from django.urls import path
from . import views

urlpatterns = [
    # List (user sees own feedback only) + Create
    path("", views.FeedbackListCreateView.as_view(), name="feedback-list-create"),

    # Admin: view all feedback
    path("admin/", views.FeedbackAdminListView.as_view(), name="feedback-admin-list"),

    # Retrieve / Update / Delete specific feedback
    # FeedbackDetailView uses default lookup_field="pk"
    path("<uuid:pk>/", views.FeedbackDetailView.as_view(), name="feedback-detail"),

    # Staff-only status update endpoint
    path("<uuid:pk>/status/", views.feedback_status_update, name="feedback-status-update"),

    # Comments list + create for a given feedback
    path("<uuid:feedback_id>/comments/", views.FeedbackCommentListCreateView.as_view(), name="feedback-comments"),

    # Comments retrieve/update/delete
    # lookup_field = "id"
    path("comments/<uuid:id>/", views.FeedbackCommentDetailView.as_view(), name="feedback-comment-detail"),
]
