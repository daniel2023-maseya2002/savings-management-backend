# chatbot/views.py
import json
import re
import logging
from pathlib import Path

from django.core.paginator import Paginator
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status

from .models import Conversation
from .serializers import ConversationSerializer
from rest_framework.pagination import PageNumberPagination


logger = logging.getLogger(__name__)

BASE = Path(__file__).resolve().parent
QA_FILE = BASE / "qa.json"

def load_qa():
    try:
        raw = []
        if QA_FILE.exists():
            raw = json.loads(QA_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.exception("Failed to load qa.json: %s", exc)
        raw = []

    if not raw:
        raw = [
            {"patterns": ["hi", "hello", "hey"], "reply": "Hello! 👋 How can I help you with savings today?"},
            {"patterns": ["deposit", "how to deposit"], "reply": "To deposit, go to Wallet → Deposit and follow the steps."},
        ]

    prepared = []
    for item in raw:
        patterns = item.get("patterns", []) or []
        compiled = []
        for p in patterns:
            p_norm = p.strip()
            # treat likely regexes as regex; else substring
            if p_norm.startswith("^") or any(ch in p_norm for ch in ".*?+[]()\\"):
                try:
                    compiled.append(("regex", re.compile(p_norm, flags=re.IGNORECASE)))
                except re.error:
                    compiled.append(("substr", p_norm.lower()))
            else:
                compiled.append(("substr", p_norm.lower()))
        prepared.append({
            "raw_patterns": patterns,
            "reply": item.get("reply", ""),
            "compiled": compiled,
        })
    return prepared

QA_DATA = load_qa()

def find_reply(user_text):
    if not user_text:
        return ""
    text = user_text.lower()
    for item in QA_DATA:
        for typ, patt in item["compiled"]:
            if typ == "substr":
                if patt in text:
                    return item["reply"]
            elif typ == "regex":
                if patt.search(user_text):
                    return item["reply"]
    if any(w in text for w in ["thank", "thanks"]):
        return "You're welcome! 😊"
    if "help" in text:
        return "Tell me what you need help with — deposits, withdrawals, or account info."
    return "Sorry, I don't know that yet. Try asking about deposits, withdrawals, or working hours."

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def message(request):
    """
    POST JSON: { "message": "Hello" } - Auth required (Bearer token)
    Saves conversation to DB and returns bot reply.
    """
    user = request.user if request and hasattr(request, "user") else None
    user_msg = request.data.get("message", "")
    if user_msg is None:
        return Response({"error": "message field required"}, status=status.HTTP_400_BAD_REQUEST)

    reply = find_reply(user_msg)

    try:
        Conversation.objects.create(
            user=user if user and getattr(user, "is_authenticated", False) else None,
            user_message=user_msg,
            bot_reply=reply
        )
    except Exception:
        logger.exception("Failed to save conversation for user=%s", getattr(user, "pk", None))

    return Response({"reply": reply}, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def history(request):
    """
    GET: returns authenticated user's conversations, paginated.
    Query params:
      - page (int, default=1)
      - page_size (int, default=20)
    """
    user = request.user
    page = int(request.query_params.get("page", 1))
    page_size = int(request.query_params.get("page_size", 20))
    qs = Conversation.objects.filter(user=user).order_by("-created_at")
    paginator = Paginator(qs, page_size)
    try:
        page_obj = paginator.page(page)
    except Exception:
        return Response({"detail": "Invalid page."}, status=status.HTTP_400_BAD_REQUEST)

    serializer = ConversationSerializer(page_obj.object_list, many=True)
    return Response({
        "count": paginator.count,
        "num_pages": paginator.num_pages,
        "page": page,
        "page_size": page_size,
        "results": serializer.data
    }, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAdminUser])
def all_conversations(request):
    """
    Admin-only: return paginated conversations.
    Optional query params:
      - user: username or user id to filter conversations
      - page, page_size
    """
    user_q = request.query_params.get("user", None)
    qs = Conversation.objects.all().order_by("-created_at")

    if user_q:
        try:
            qs = qs.filter(user__id=int(user_q))
        except Exception:
            qs = qs.filter(user__username__icontains=user_q)

    page = int(request.query_params.get("page", 1))
    page_size = int(request.query_params.get("page_size", 20))

    paginator = Paginator(qs, page_size)
    try:
        page_obj = paginator.page(page)
    except Exception:
        return Response({"detail": "Invalid page."}, status=status.HTTP_400_BAD_REQUEST)

    serializer = ConversationSerializer(page_obj.object_list, many=True)
    return Response({
        "count": paginator.count,
        "num_pages": paginator.num_pages,
        "page": page,
        "page_size": page_size,
        "results": serializer.data
    }, status=status.HTTP_200_OK)

class AdminConversationsPagination(PageNumberPagination):
    page_size = 30
    page_size_query_param = "page_size"
    max_page_size = 200

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_list_conversations(request):
    """
    Admin-only: list all conversations (paginated).
    Query params: page, page_size, user (optional filter by user id or username)
    """
    user = request.user
    if not user.is_staff:
        return Response({"detail": "Not authorized."}, status=status.HTTP_403_FORBIDDEN)

    qs = Conversation.objects.all().order_by("-created_at")

    # optional filter by username or id
    user_q = request.query_params.get("user")
    if user_q:
        # try id first
        if user_q.isdigit():
            qs = qs.filter(user__id=int(user_q))
        else:
            qs = qs.filter(user__username__icontains=user_q)

    paginator = AdminConversationsPagination()
    page = paginator.paginate_queryset(qs, request)
    serializer = ConversationSerializer(page, many=True)
    return paginator.get_paginated_response(serializer.data)
