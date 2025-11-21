"""
URL configuration for savings_api project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
# savings_api/urls.py
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,  # <-- ADDED
)
from core import views as core_views

urlpatterns = [

    path("api/whoami-debug/", core_views.whoami_debug),
    path('admin/', admin.site.urls),

    # core api (if you already have other core endpoints)
    path("api/", include("core.urls")),

    # token endpoints (AllowAny by default)
    path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/token/verify/", TokenVerifyView.as_view(), name="token_verify"),  # <-- ADDED

    # Chatbot app included under /api/chat/
    path("api/chat/", include("chatbot.urls")),

    # Ai_Analyst
    path("api/ai/", include("ai_analysis.urls")),
    # savings_api/urls.py (append)

    # Peer_Transactions
    path("api/peer/", include("peer_transactions.urls")),

    # Ai_Assistance
    path("api/ai/", include("ai_assistant.urls")),


    # Feedback

     path("api/feedback/", include("feedback.urls")),

]

FCM_SERVER_KEY = "<your_firebase_server_key_here>"
SEND_FCM_NOTIFICATIONS = True

