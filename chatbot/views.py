# chatbot/views.py
import json
import re
from pathlib import Path

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import Conversation
from .serializers import ConversationSerializer

BASE = Path(__file__).resolve().parent
QA_FILE = BASE / "qa.json"

def load_qa():
    try:
        if QA_FILE.exists():
            return json.loads(QA_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    # fallback default Q/A if qa.json missing or invalid
    return [
        {"patterns": ["hi", "hello", "hey"], "reply": "Hello! 👋 How can I help you with savings today?"},
        {"patterns": ["deposit", "how to deposit"], "reply": "To deposit, go to Wallet → Deposit and follow the steps."},
    ]

QA_DATA = load_qa()

def find_reply(user_text):
    text = (user_text or "").lower()
    for item in QA_DATA:
        patterns = item.get("patterns", [])
        for p in patterns:
            p_norm = p.lower().strip()
            try:
                # regex-like patterns
                if p_norm.startswith("^") or any(ch in p_norm for ch in ".*?+[]()"):
                    if re.search(p_norm, text):
                        return item.get("reply", "")
                else:
                    if p_norm in text:
                        return item.get("reply", "")
            except re.error:
                if p_norm in text:
                    return item.get("reply", "")
    # fallback heuristics
    if any(w in text for w in ["thank", "thanks"]):
        return "You're welcome! 😊"
    if "help" in text:
        return "Tell me what you need help with — deposits, withdrawals, or account info."
    return "Sorry, I don't know that yet. Try asking about deposits, withdrawals, or working hours."

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def message(request):
    """
    POST JSON: { "message": "Hello" }
    Requires Authorization: Bearer <access_token>
    Saves conversation to DB and returns bot reply.
    """
    user = request.user if request and hasattr(request, "user") else None
    user_msg = request.data.get("message", "")
    if not user_msg:
        return Response({"reply": ""}, status=status.HTTP_200_OK)

    reply = find_reply(user_msg)

    # Save conversation
    try:
        Conversation.objects.create(
            user=user if user and user.is_authenticated else None,
            user_message=user_msg,
            bot_reply=reply
        )
    except Exception:
        # don't break response if DB save fails
        pass

    return Response({"reply": reply}, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def history(request):
    """
    GET: returns authenticated user's last 50 conversations (most recent first)
    """
    user = request.user
    qs = Conversation.objects.filter(user=user).order_by("-created_at")[:50]
    serializer = ConversationSerializer(qs, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)
