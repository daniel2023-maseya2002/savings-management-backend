# chatbot/urls.py
from django.urls import path
from .views import message, history, admin_list_conversations, all_conversations

urlpatterns = [
    path("message/", message, name="chat-message"),
    path("history/", history, name="chat-history"),
    path("all/", admin_list_conversations, name="chat-all"),  # Admin-only endpoint
    path("all-old/", all_conversations, name="chat-all-old")
]
