# chatbot/urls.py
from django.urls import path
from .views import message, history, admin_list_conversations

urlpatterns = [
    path("api/chat/message/", message, name="chat-message"),
    path("api/chat/history/", history, name="chat-history"),
    path("all/", admin_list_conversations, name="chat-all"),  # <-- 
]
