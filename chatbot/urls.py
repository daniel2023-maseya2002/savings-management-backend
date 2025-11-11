# chatbot/urls.py
from django.urls import path
from .views import message, history

urlpatterns = [
    path("api/chat/message/", message, name="chat-message"),
    path("api/chat/history/", history, name="chat-history"),
]
