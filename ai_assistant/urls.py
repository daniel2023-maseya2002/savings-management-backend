# ai_assistant/urls.py
from django.urls import path
from .views import ConversationListView, ConversationRetrieveView, AIChatView, assistant_stream

urlpatterns = [
    path("conversations/", ConversationListView.as_view(), name="ai-conversation-list"),
    path("conversations/<uuid:id>/", ConversationRetrieveView.as_view(), name="ai-conversation-detail"),
    path("assistant/", AIChatView.as_view(), name="ai-assistant"),
    path("assistant/stream/", assistant_stream, name="ai-assistant-stream"),
]
